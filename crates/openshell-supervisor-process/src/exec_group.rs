// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-group lifetime for SSH exec and shell channels.
//!
//! Each SSH channel that spawns its own child (pipe exec, PTY shell or exec,
//! sftp) places that child at the head of a new process group and tracks it
//! with an [`ExecProcessGroup`]. When the channel closes, or the SSH
//! connection drops, before the child has exited, the whole group receives
//! `SIGTERM` and, if any member is still running after
//! [`EXEC_TERMINATION_GRACE`], `SIGKILL`. A gateway exec deadline or a
//! cancelled exec stream closes the channel, so this is what actually stops
//! the command.
//!
//! The group is only ever signalled while its leader is known not to have
//! been reaped, so a signal can never land on a recycled PID:
//!
//! - The exit waiter observes the leader's exit with `waitid(WNOWAIT)`, which
//!   leaves it a zombie, and only reaps it after recording the exit under the
//!   same lock that signals are sent under.
//! - While termination is in progress the waiter defers reaping, so the
//!   leader's PID, and with it the process group ID, stays reserved until the
//!   final `SIGKILL` has been sent. That lets the escalation reach members
//!   that ignored `SIGTERM` after the leader itself has exited.
//!
//! The leader is registered with `managed_children`, so the supervisor's
//! orphan reaper never reaps it out from under the waiter.

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Process as OcsfProcess, ProcessActivityBuilder,
    SeverityId, StatusId, ocsf_emit,
};
use rustix::process::{WaitId, WaitIdOptions, waitid};
use std::process::{Child, ExitStatus};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// How long a terminated exec's process group has to exit after `SIGTERM`
/// before it is sent `SIGKILL`.
pub const EXEC_TERMINATION_GRACE: Duration = Duration::from_secs(5);

/// How often termination checks whether the process group has exited.
const GROUP_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A spawned SSH channel child that leads its own process group.
pub struct ExecProcessGroup {
    pgid: Pid,
    state: Mutex<GroupState>,
    termination_done: Condvar,
}

#[derive(Default)]
struct GroupState {
    /// The leader has exited. It may still be an unreaped zombie.
    leader_exited: bool,
    /// The waiter is about to reap, or has reaped, the leader. Its PID may be
    /// reused from here on, so the group must not be signalled again.
    reaped: bool,
    /// A termination is in progress and the leader must stay unreaped.
    terminating: bool,
}

impl ExecProcessGroup {
    /// Track `child`, which must have been spawned as the leader of a new
    /// process group (`setsid` or `process_group(0)`), so its PID is also
    /// its process group ID.
    #[must_use]
    pub fn new(child: &Child) -> Arc<Self> {
        let pid = i32::try_from(child.id()).unwrap_or(i32::MAX);
        Arc::new(Self {
            pgid: Pid::from_raw(pid),
            state: Mutex::new(GroupState::default()),
            termination_done: Condvar::new(),
        })
    }

    /// Wait for the leader to exit, then reap it.
    ///
    /// Replaces `child.wait()` for a tracked child. If a termination is in
    /// progress when the leader exits, reaping waits for it to finish.
    ///
    /// # Errors
    ///
    /// Returns an error if reaping the child fails.
    pub fn wait(&self, child: &mut Child) -> std::io::Result<ExitStatus> {
        self.wait_for_leader_exit();
        let mut state = self.lock_state();
        state.leader_exited = true;
        while state.terminating {
            state = self
                .termination_done
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        state.reaped = true;
        drop(state);
        child.wait()
    }

    /// Terminate the process group because its SSH channel went away.
    ///
    /// Sends `SIGTERM` now and `SIGKILL` from a background thread if any
    /// member is still running after [`EXEC_TERMINATION_GRACE`]. Returns
    /// `false` without signalling if the leader has already exited or a
    /// termination is already in progress. Never blocks the caller.
    pub fn terminate(self: &Arc<Self>, reason: &str) -> bool {
        self.terminate_with_grace(reason, EXEC_TERMINATION_GRACE)
    }

    fn terminate_with_grace(self: &Arc<Self>, reason: &str, grace: Duration) -> bool {
        {
            let mut state = self.lock_state();
            if state.leader_exited || state.terminating {
                return false;
            }
            state.terminating = true;
            ocsf_emit!(
                ProcessActivityBuilder::new(openshell_ocsf::ctx::ctx())
                    .activity(ActivityId::Close)
                    .action(ActionId::Denied)
                    .disposition(DispositionId::Blocked)
                    .severity(SeverityId::Low)
                    .status(StatusId::Success)
                    .process(OcsfProcess::new("ssh-exec", i64::from(self.pgid.as_raw())))
                    .message(format!(
                        "SSH exec terminated: {reason} before process exited, sending SIGTERM to process group {}",
                        self.pgid
                    ))
                    .build()
            );
            self.signal_group(&state, Signal::SIGTERM);
        }

        let group = Arc::clone(self);
        let escalation = std::thread::Builder::new()
            .name("openshell-exec-kill".into())
            .spawn(move || group.escalate_after(grace));
        if escalation.is_err() {
            // Without a thread to wait out the grace period, kill now rather
            // than leave the group running or block the caller.
            let mut state = self.lock_state();
            self.signal_group(&state, Signal::SIGKILL);
            state.terminating = false;
            self.termination_done.notify_all();
        }
        true
    }

    /// Wait up to `grace` for the group to exit, `SIGKILL` it if it has not,
    /// then let the waiter reap the leader.
    fn escalate_after(&self, grace: Duration) {
        let deadline = Instant::now() + grace;
        loop {
            if !self.group_running() {
                break;
            }
            if Instant::now() >= deadline {
                let state = self.lock_state();
                ocsf_emit!(
                    ProcessActivityBuilder::new(openshell_ocsf::ctx::ctx())
                        .activity(ActivityId::Close)
                        .action(ActionId::Denied)
                        .disposition(DispositionId::Blocked)
                        .severity(SeverityId::Medium)
                        .status(StatusId::Success)
                        .process(OcsfProcess::new("ssh-exec", i64::from(self.pgid.as_raw())))
                        .message(format!(
                            "SSH exec process group {} still running {}s after SIGTERM, sending SIGKILL",
                            self.pgid,
                            grace.as_secs()
                        ))
                        .build()
                );
                self.signal_group(&state, Signal::SIGKILL);
                break;
            }
            std::thread::sleep(GROUP_EXIT_POLL_INTERVAL);
        }
        self.lock_state().terminating = false;
        self.termination_done.notify_all();
    }

    /// Signal every member of the group. The caller holds the state lock,
    /// which keeps the waiter from reaping the leader concurrently.
    fn signal_group(&self, state: &GroupState, signal: Signal) {
        if state.reaped {
            return;
        }
        match killpg(self.pgid, signal) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
            Err(error) => {
                ocsf_emit!(
                    ProcessActivityBuilder::new(openshell_ocsf::ctx::ctx())
                        .activity(ActivityId::Close)
                        .severity(SeverityId::Medium)
                        .status(StatusId::Failure)
                        .process(OcsfProcess::new("ssh-exec", i64::from(self.pgid.as_raw())))
                        .message(format!(
                            "Failed to send {signal} to SSH exec process group {}: {error}",
                            self.pgid
                        ))
                        .build()
                );
            }
        }
    }

    /// Whether any member of the group is still running (not a zombie).
    fn group_running(&self) -> bool {
        #[cfg(target_os = "linux")]
        if let Some(running) = proc_group_has_running_member(self.pgid) {
            return running;
        }
        // Without /proc the leader stands in for the whole group.
        !self.lock_state().leader_exited
    }

    /// Block until the leader exits, leaving it unreaped.
    fn wait_for_leader_exit(&self) {
        let Some(pid) = rustix::process::Pid::from_raw(self.pgid.as_raw()) else {
            return;
        };
        loop {
            match waitid(
                WaitId::Pid(pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
            ) {
                Err(rustix::io::Errno::INTR) => {}
                // Exited, or no longer waitable (ECHILD); either way it is
                // no longer running.
                Ok(_) | Err(_) => return,
            }
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, GroupState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Scan `/proc` for a non-zombie process in group `pgid`. Returns `None` if
/// `/proc` cannot be read.
#[cfg(target_os = "linux")]
fn proc_group_has_running_member(pgid: Pid) -> Option<bool> {
    let entries = std::fs::read_dir("/proc").ok()?;
    let group = pgid.as_raw().to_string();
    Some(entries.flatten().any(|entry| {
        let name = entry.file_name();
        let Some(process) = name.to_str() else {
            return false;
        };
        if !process.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{process}/stat")) else {
            return false;
        };
        // `pid (comm) state ppid pgrp ...`; comm may contain spaces and
        // parentheses, so split after the last ')'.
        let Some((_, fields)) = stat.rsplit_once(')') else {
            return false;
        };
        let mut fields = fields.split_whitespace();
        let state = fields.next();
        let pgrp = fields.nth(1);
        pgrp == Some(group.as_str()) && !matches!(state, Some("Z" | "X"))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::CommandExt;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;

    const TEST_GRACE: Duration = Duration::from_millis(500);

    /// Spawn `script` under `sh` as a process-group leader, the way
    /// `spawn_pipe_exec` does, and return it with the PID it prints first.
    fn spawn_group_leader(script: &str) -> (Child, i32) {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(script)
            .stdout(Stdio::piped())
            .process_group(0)
            .spawn()
            .expect("spawn sh");
        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("stdout piped"))
            .read_line(&mut line)
            .expect("read grandchild pid");
        let grandchild = line.trim().parse().expect("grandchild pid");
        (child, grandchild)
    }

    /// Run the exit waiter on its own thread, as the SSH spawn paths do.
    fn spawn_waiter(
        group: &Arc<ExecProcessGroup>,
        mut child: Child,
    ) -> mpsc::Receiver<std::io::Result<ExitStatus>> {
        let (tx, rx) = mpsc::channel();
        let group = Arc::clone(group);
        std::thread::spawn(move || {
            let _ = tx.send(group.wait(&mut child));
        });
        rx
    }

    /// Whether `pid` has exited. Orphaned grandchildren are reaped by init,
    /// so a zombie counts as exited.
    fn exited(pid: i32) -> bool {
        #[cfg(target_os = "linux")]
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            let state = stat.rsplit_once(')').map(|(_, f)| f.trim_start());
            return state.is_some_and(|s| s.starts_with('Z') || s.starts_with('X'));
        }
        nix::sys::signal::kill(Pid::from_raw(pid), None) == Err(nix::errno::Errno::ESRCH)
    }

    fn wait_until_exited(pid: i32, within: Duration) -> bool {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if exited(pid) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        exited(pid)
    }

    #[test]
    fn terminate_stops_leader_and_grandchild_with_sigterm() {
        let (child, grandchild) = spawn_group_leader("sleep 300 & echo $!; wait");
        let group = ExecProcessGroup::new(&child);
        let leader = i32::try_from(child.id()).unwrap();
        let waiter = spawn_waiter(&group, child);

        let started = Instant::now();
        assert!(group.terminate_with_grace("test channel closed", Duration::from_secs(30)));

        let status = waiter
            .recv_timeout(Duration::from_secs(10))
            .expect("leader still running after SIGTERM")
            .expect("reap leader");
        assert_eq!(status.signal(), Some(libc::SIGTERM));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "SIGTERM should end the group well before the grace period"
        );
        assert!(exited(leader));
        assert!(
            wait_until_exited(grandchild, Duration::from_secs(5)),
            "grandchild {grandchild} survived its group's SIGTERM"
        );
    }

    #[test]
    fn terminate_escalates_to_sigkill_when_leader_ignores_sigterm() {
        let (child, grandchild) = spawn_group_leader("trap '' TERM; sleep 300 & echo $!; wait");
        let group = ExecProcessGroup::new(&child);
        let waiter = spawn_waiter(&group, child);

        let started = Instant::now();
        assert!(group.terminate_with_grace("test channel closed", TEST_GRACE));

        let status = waiter
            .recv_timeout(Duration::from_secs(10))
            .expect("leader survived SIGKILL escalation")
            .expect("reap leader");
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(started.elapsed() >= TEST_GRACE, "SIGKILL sent before grace");
        assert!(
            wait_until_exited(grandchild, Duration::from_secs(5)),
            "grandchild {grandchild} survived SIGKILL escalation"
        );
    }

    /// The leader honours SIGTERM but a grandchild ignores it. The leader
    /// stays an unreaped zombie until escalation, so the group ID is still
    /// reserved and SIGKILL reaches the grandchild. Needs `/proc` to see
    /// that the group is still running after its leader exits.
    #[cfg(target_os = "linux")]
    #[test]
    fn terminate_kills_grandchild_ignoring_sigterm_after_leader_exits() {
        // The grandchild prints its PID only once its SIGTERM trap is set.
        let (child, grandchild) =
            spawn_group_leader("sh -c 'trap \"\" TERM; echo $$; exec sleep 300' & wait");
        let group = ExecProcessGroup::new(&child);
        let waiter = spawn_waiter(&group, child);

        let started = Instant::now();
        assert!(group.terminate_with_grace("test channel closed", TEST_GRACE));

        let status = waiter
            .recv_timeout(Duration::from_secs(10))
            .expect("waiter never reaped the leader")
            .expect("reap leader");
        assert_eq!(status.signal(), Some(libc::SIGTERM));
        assert!(
            started.elapsed() >= TEST_GRACE,
            "leader was reaped before escalation finished"
        );
        assert!(
            wait_until_exited(grandchild, Duration::from_secs(5)),
            "grandchild {grandchild} ignoring SIGTERM was not killed"
        );
    }

    #[test]
    fn terminate_after_normal_exit_sends_no_signal() {
        let (child, _) = spawn_group_leader("echo 0");
        let group = ExecProcessGroup::new(&child);
        let status = spawn_waiter(&group, child)
            .recv_timeout(Duration::from_secs(10))
            .expect("child did not exit")
            .expect("reap child");
        assert!(status.success());

        assert!(!group.terminate("test channel closed"));
        assert!(!group.lock_state().terminating);
    }

    #[test]
    fn terminate_is_idempotent() {
        let (child, _) = spawn_group_leader("sleep 300 & echo $!; wait");
        let group = ExecProcessGroup::new(&child);
        let waiter = spawn_waiter(&group, child);

        assert!(group.terminate_with_grace("test channel closed", TEST_GRACE));
        assert!(!group.terminate("test connection closed"));
        waiter
            .recv_timeout(Duration::from_secs(10))
            .expect("leader still running")
            .expect("reap leader");
    }
}
