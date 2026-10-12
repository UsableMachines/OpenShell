// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Modes for the per-replica bus eviction sweep, selected by `OPENSHELL_BUS_SWEEP_MODE`.
//!
//! `full`, the default, checks every tracked id against the store on every pass (see
//! `ComputeRuntime::run_bus_eviction_sweep`). The other modes narrow what a pass checks:
//!
//! - `idle` checks only ids with no log activity for [`IDLE_QUIET_PERIOD`], and backs off ids
//!   that it keeps finding present.
//! - `tombstone` records each sandbox-row removal in the store, and each pass reads only the
//!   removals recorded since the previous pass.
//! - `notify` announces each removal with Postgres `NOTIFY`, and every replica frees the named
//!   state as soon as its `LISTEN` connection delivers it.
//!
//! The `tombstone` and `notify` modes also run a full pass every [`BACKSTOP_INTERVAL`] for ids
//! that no removal signal names, such as a failed create or a watch that subscribed after cleanup.

use super::{ComputeRuntime, bus_sweep_interval};
use crate::persistence::{
    ObjectCursor, ObjectType, PersistenceResult, StoreListener, WriteCondition,
};
use openshell_core::proto::Sandbox;
use openshell_core::time::now_ms;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

/// Env override that selects the [`BusSweepMode`]; see `docs/reference/gateway-config.mdx`.
const BUS_SWEEP_MODE_ENV: &str = "OPENSHELL_BUS_SWEEP_MODE";

/// How long an id must go without a subscribe or publish before the `idle` mode checks it.
/// Far longer than a create's row-insert delay, so one absent read is enough to free an id.
const IDLE_QUIET_PERIOD: Duration = Duration::from_mins(5);

/// Longest wait between two `idle` checks of a quiet id that stays present.
const IDLE_MAX_BACKOFF: Duration = Duration::from_mins(10);

/// Object type of a sandbox removal record, written only in the `tombstone` mode.
const TOMBSTONE_OBJECT_TYPE: &str = "sandbox-tombstone";

/// How far before the previous pass each tombstone read starts. Writers stamp rows with their
/// own clocks, and a row can commit after a later-stamped one, so reads must overlap.
const TOMBSTONE_READ_OVERLAP: Duration = Duration::from_mins(1);

/// Age after which any replica deletes a tombstone. Reads look back one pass plus the overlap,
/// so only a sweep stalled for longer than this misses a row, and the backstop covers that.
const TOMBSTONE_TTL: Duration = Duration::from_hours(1);

/// Rows per tombstone read page and per expiry pass.
const TOMBSTONE_PAGE_SIZE: u32 = 500;

/// How often the signal-driven modes run a full pass for ids that no removal signal names.
const BACKSTOP_INTERVAL: Duration = Duration::from_mins(10);

/// Postgres channel that carries sandbox-row removals in the `notify` mode.
const SANDBOX_REMOVED_CHANNEL: &str = "openshell_sandbox_removed";

/// How each sweep pass finds the per-sandbox bus state to free.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum BusSweepMode {
    /// Check every tracked id against the store on every pass.
    #[default]
    Full,
    /// Check only ids without recent log activity, backing off ids that stay present.
    Idle,
    /// Read the removals recorded since the previous pass, with a periodic full pass.
    Tombstone,
    /// Free state when Postgres delivers a removal notification, with a periodic full pass.
    Notify,
}

impl BusSweepMode {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "full" => Some(Self::Full),
            "idle" => Some(Self::Idle),
            "tombstone" => Some(Self::Tombstone),
            "notify" => Some(Self::Notify),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Idle => "idle",
            Self::Tombstone => "tombstone",
            Self::Notify => "notify",
        }
    }
}

/// Resolve the [`BusSweepMode`] from the environment.
pub(super) fn bus_sweep_mode() -> BusSweepMode {
    resolve_bus_sweep_mode(std::env::var(BUS_SWEEP_MODE_ENV))
}

/// Pure resolver for [`bus_sweep_mode`]: an absent value selects the default silently, and a
/// present-but-invalid value is logged and ignored.
fn resolve_bus_sweep_mode(raw: Result<String, std::env::VarError>) -> BusSweepMode {
    let raw = match raw {
        Err(std::env::VarError::NotPresent) => return BusSweepMode::default(),
        Err(std::env::VarError::NotUnicode(_)) => {
            warn!("{BUS_SWEEP_MODE_ENV} is not valid UTF-8; using full");
            return BusSweepMode::default();
        }
        Ok(raw) => raw,
    };
    BusSweepMode::parse(&raw).unwrap_or_else(|| {
        warn!(value = %raw, "invalid {BUS_SWEEP_MODE_ENV}; using full");
        BusSweepMode::default()
    })
}

/// When the `idle` mode last found an id present, and how long it waits before the next check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IdleCheck {
    checked_at_ms: i64,
    backoff_ms: i64,
}

/// Ids due for an `idle` check: quiet for at least `quiet_ms`, and never found present, active
/// since they were last found present, or past their backoff.
fn idle_candidates(
    activity: &HashMap<String, i64>,
    checks: &HashMap<String, IdleCheck>,
    now_ms: i64,
    quiet_ms: i64,
) -> Vec<String> {
    activity
        .iter()
        .filter(|&(id, &last_active_ms)| {
            now_ms - last_active_ms >= quiet_ms
                && checks.get(id).is_none_or(|check| {
                    last_active_ms > check.checked_at_ms
                        || now_ms - check.checked_at_ms >= check.backoff_ms
                })
        })
        .map(|(id, _)| id.clone())
        .collect()
}

/// The next [`IdleCheck`] for an id found present. The backoff doubles up to `max_ms`, and
/// restarts at `base_ms` when the id was active after its previous check.
fn next_idle_check(
    previous: Option<IdleCheck>,
    last_active_ms: i64,
    now_ms: i64,
    base_ms: i64,
    max_ms: i64,
) -> IdleCheck {
    let backoff_ms = match previous {
        Some(previous) if last_active_ms <= previous.checked_at_ms => {
            previous.backoff_ms.saturating_mul(2).min(max_ms)
        }
        _ => base_ms,
    };
    IdleCheck {
        checked_at_ms: now_ms,
        backoff_ms,
    }
}

fn as_ms(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

/// Row key for a tombstone. `objects.id` is unique across every object type, and the sandbox
/// row already uses the bare sandbox id.
fn tombstone_object_id(sandbox_id: &str) -> String {
    format!("{TOMBSTONE_OBJECT_TYPE}:{sandbox_id}")
}

/// The next removal from `listener`; never completes while there is no listener.
async fn next_removal(listener: Option<&mut StoreListener>) -> PersistenceResult<Option<String>> {
    match listener {
        Some(listener) => listener.recv().await,
        None => std::future::pending().await,
    }
}

/// The full pass that signal-driven modes run every [`BACKSTOP_INTERVAL`], with the same
/// two-pass grace as the `full` mode.
struct Backstop {
    last_run: Instant,
    absent_prev: HashSet<String>,
}

impl Backstop {
    fn new() -> Self {
        Self {
            last_run: Instant::now(),
            absent_prev: HashSet::new(),
        }
    }

    fn is_due(&self) -> bool {
        self.last_run.elapsed() >= BACKSTOP_INTERVAL
    }

    async fn run(&mut self, runtime: &ComputeRuntime) {
        self.last_run = Instant::now();
        let absent_prev = std::mem::take(&mut self.absent_prev);
        self.absent_prev = runtime.run_bus_eviction_sweep(absent_prev).await;
    }
}

impl ComputeRuntime {
    /// Run the bus eviction sweep in the configured [`BusSweepMode`] until `cancel` fires.
    pub(super) async fn bus_sweep_loop(self: Arc<Self>, cancel: watch::Receiver<bool>) {
        info!(
            mode = self.bus_sweep_mode.as_str(),
            "starting bus eviction sweep"
        );
        match self.bus_sweep_mode {
            BusSweepMode::Full => self.bus_eviction_sweep_loop(cancel).await,
            BusSweepMode::Idle => self.idle_bus_sweep_loop(cancel).await,
            BusSweepMode::Tombstone => self.tombstone_bus_sweep_loop(cancel).await,
            BusSweepMode::Notify => self.notify_bus_sweep_loop(cancel).await,
        }
    }

    /// Tell the other replicas that this replica removed the sandbox row, in the way the
    /// configured mode listens. Best effort: a missed announcement waits for a backstop pass.
    pub(super) async fn announce_sandbox_removal(&self, sandbox_id: &str) {
        match self.bus_sweep_mode {
            BusSweepMode::Full | BusSweepMode::Idle => {}
            BusSweepMode::Tombstone => {
                let result = self
                    .store
                    .put_if(
                        TOMBSTONE_OBJECT_TYPE,
                        &tombstone_object_id(sandbox_id),
                        sandbox_id,
                        "",
                        &[],
                        None,
                        WriteCondition::MustCreate,
                    )
                    .await;
                if let Err(err) = result
                    && !err.is_expected()
                {
                    warn!(
                        sandbox_id,
                        error = %err,
                        "failed to record sandbox tombstone; a backstop pass will free its state"
                    );
                }
            }
            BusSweepMode::Notify => {
                if let Err(err) = self.store.notify(SANDBOX_REMOVED_CHANNEL, sandbox_id).await {
                    warn!(
                        sandbox_id,
                        error = %err,
                        "failed to announce sandbox removal; a backstop pass will free its state"
                    );
                }
            }
        }
    }

    async fn notify_bus_sweep_loop(self: Arc<Self>, mut cancel: watch::Receiver<bool>) {
        let interval = bus_sweep_interval();
        let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut backstop = Backstop::new();
        let mut listener = None;
        // `SQLite` has no listener; its only replica already frees state when it removes a row.
        let mut wants_listener = true;
        // At most one listen attempt per interval, so a failing database is not hammered.
        let mut listen_due = true;
        loop {
            if wants_listener && listen_due && listener.is_none() {
                listen_due = false;
                match self.store.listen(SANDBOX_REMOVED_CHANNEL).await {
                    Ok(Some(opened)) => {
                        listener = Some(opened);
                        // Removals sent while no listener was open are lost; recheck everything.
                        backstop.run(&self).await;
                    }
                    Ok(None) => wants_listener = false,
                    Err(err) => warn!(
                        error = %err,
                        "notify bus sweep: listen failed; retrying next interval"
                    ),
                }
            }
            tokio::select! {
                _ = cancel.changed() => break,
                removal = next_removal(listener.as_mut()) => match removal {
                    Ok(Some(sandbox_id)) => self.cleanup_removed_sandbox_state(&sandbox_id),
                    Ok(None) => {
                        warn!("notify bus sweep: listener reconnected; rechecking every tracked id");
                        backstop.run(&self).await;
                    }
                    Err(err) => {
                        warn!(error = %err, "notify bus sweep: listener failed; reopening it next interval");
                        listener = None;
                    }
                },
                _ = ticks.tick() => {
                    listen_due = true;
                    if backstop.is_due() {
                        backstop.run(&self).await;
                    }
                }
            }
        }
    }

    async fn tombstone_bus_sweep_loop(self: Arc<Self>, mut cancel: watch::Receiver<bool>) {
        let interval = bus_sweep_interval();
        // State starts empty, so removals recorded before this replica started need no read.
        let mut read_from_ms = now_ms() - as_ms(TOMBSTONE_READ_OVERLAP);
        let mut backstop = Backstop::new();
        loop {
            tokio::select! {
                _ = cancel.changed() => break,
                () = tokio::time::sleep(interval) => {
                    let pass_started_ms = now_ms();
                    if self.free_tombstoned_sandboxes(read_from_ms).await {
                        read_from_ms = pass_started_ms - as_ms(TOMBSTONE_READ_OVERLAP);
                    }
                    if backstop.is_due() {
                        self.expire_tombstones(pass_started_ms - as_ms(TOMBSTONE_TTL)).await;
                        backstop.run(&self).await;
                    }
                }
            }
        }
    }

    /// Free the state of every sandbox with a tombstone stamped at or after `from_ms`. Returns
    /// whether the read completed; after a store error, the next pass reads from `from_ms` again.
    async fn free_tombstoned_sandboxes(&self, from_ms: i64) -> bool {
        let mut cursor = ObjectCursor {
            created_at_ms: from_ms,
            name: String::new(),
            workspace: String::new(),
            id: String::new(),
        };
        loop {
            let tombstones = match self
                .store
                .list_by_type_after(TOMBSTONE_OBJECT_TYPE, Some(&cursor), TOMBSTONE_PAGE_SIZE)
                .await
            {
                Ok(tombstones) => tombstones,
                Err(err) => {
                    warn!(
                        error = %err,
                        "tombstone bus sweep: tombstone read failed; retrying next pass"
                    );
                    return false;
                }
            };
            for tombstone in &tombstones {
                self.cleanup_removed_sandbox_state(&tombstone.name);
            }
            match tombstones.last() {
                Some(last) if tombstones.len() == TOMBSTONE_PAGE_SIZE as usize => {
                    cursor = ObjectCursor::from(last);
                }
                _ => return true,
            }
        }
    }

    /// Delete one page of tombstones stamped before `cutoff_ms`. Every replica runs this with its
    /// backstop, so a backlog drains quickly, and two replicas deleting the same rows is harmless.
    async fn expire_tombstones(&self, cutoff_ms: i64) {
        let oldest = match self
            .store
            .list_by_type_after(TOMBSTONE_OBJECT_TYPE, None, TOMBSTONE_PAGE_SIZE)
            .await
        {
            Ok(oldest) => oldest,
            Err(err) => {
                debug!(error = %err, "tombstone bus sweep: tombstone expiry read failed");
                return;
            }
        };
        let expired: Vec<String> = oldest
            .into_iter()
            .take_while(|tombstone| tombstone.created_at_ms < cutoff_ms)
            .map(|tombstone| tombstone.id)
            .collect();
        if expired.is_empty() {
            return;
        }
        if let Err(err) = self
            .store
            .delete_many(TOMBSTONE_OBJECT_TYPE, &expired)
            .await
        {
            warn!(error = %err, "tombstone bus sweep: tombstone expiry failed");
        }
    }

    async fn idle_bus_sweep_loop(self: Arc<Self>, mut cancel: watch::Receiver<bool>) {
        let interval = bus_sweep_interval();
        let mut checks = HashMap::new();
        loop {
            tokio::select! {
                _ = cancel.changed() => break,
                () = tokio::time::sleep(interval) => {
                    self.run_idle_bus_sweep(&mut checks, now_ms(), interval).await;
                }
            }
        }
    }

    /// One `idle` pass. It frees an absent id at once, and records a backoff for a present one.
    /// A store error frees nothing and leaves every backoff as it was.
    async fn run_idle_bus_sweep(
        &self,
        checks: &mut HashMap<String, IdleCheck>,
        now_ms: i64,
        interval: Duration,
    ) {
        let activity = self.tracing_log_bus.tracked_activity();
        checks.retain(|id, _| activity.contains_key(id));
        let candidates = idle_candidates(&activity, checks, now_ms, as_ms(IDLE_QUIET_PERIOD));
        if candidates.is_empty() {
            return;
        }
        let present = match self
            .store
            .existing_ids(Sandbox::object_type(), &candidates)
            .await
        {
            Ok(present) => present,
            Err(err) => {
                warn!(
                    candidates = candidates.len(),
                    error = %err,
                    "idle bus sweep: store lookup failed; skipped this pass"
                );
                return;
            }
        };
        for id in candidates {
            if present.contains(&id) {
                let check = next_idle_check(
                    checks.get(&id).copied(),
                    activity.get(&id).copied().unwrap_or(0),
                    now_ms,
                    as_ms(interval),
                    as_ms(IDLE_MAX_BACKOFF),
                );
                checks.insert(id, check);
            } else {
                checks.remove(&id);
                self.cleanup_removed_sandbox_state(&id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::new_test_runtime;
    use super::super::tests::sandbox_record;
    use super::*;
    use crate::persistence::Store;
    use openshell_core::proto::SandboxPhase;

    const MINUTE_MS: i64 = 60_000;

    async fn runtime() -> ComputeRuntime {
        new_test_runtime(Arc::new(Store::connect("sqlite::memory:").await.unwrap())).await
    }

    #[test]
    fn resolve_bus_sweep_mode_handles_env_values() {
        use std::env::VarError;
        assert_eq!(
            resolve_bus_sweep_mode(Err(VarError::NotPresent)),
            BusSweepMode::Full
        );
        assert_eq!(
            resolve_bus_sweep_mode(Err(VarError::NotUnicode(std::ffi::OsString::from("x")))),
            BusSweepMode::Full
        );
        assert_eq!(
            resolve_bus_sweep_mode(Ok(" Idle ".to_string())),
            BusSweepMode::Idle
        );
        assert_eq!(
            resolve_bus_sweep_mode(Ok("full".to_string())),
            BusSweepMode::Full
        );
        assert_eq!(
            resolve_bus_sweep_mode(Ok("garbage".to_string())),
            BusSweepMode::Full
        );
    }

    #[test]
    fn idle_candidates_skip_active_ids_and_respect_backoff() {
        let now = 100 * MINUTE_MS;
        let quiet = 5 * MINUTE_MS;
        let activity = HashMap::from([
            ("active".to_string(), now - MINUTE_MS),
            ("never-checked".to_string(), now - 6 * MINUTE_MS),
            ("backing-off".to_string(), now - 30 * MINUTE_MS),
            ("backoff-elapsed".to_string(), now - 30 * MINUTE_MS),
            ("active-since-check".to_string(), now - 6 * MINUTE_MS),
        ]);
        let checks = HashMap::from([
            (
                "backing-off".to_string(),
                IdleCheck {
                    checked_at_ms: now - MINUTE_MS,
                    backoff_ms: 2 * MINUTE_MS,
                },
            ),
            (
                "backoff-elapsed".to_string(),
                IdleCheck {
                    checked_at_ms: now - 3 * MINUTE_MS,
                    backoff_ms: 2 * MINUTE_MS,
                },
            ),
            (
                "active-since-check".to_string(),
                IdleCheck {
                    checked_at_ms: now - 20 * MINUTE_MS,
                    backoff_ms: 30 * MINUTE_MS,
                },
            ),
        ]);

        let mut due = idle_candidates(&activity, &checks, now, quiet);
        due.sort();
        assert_eq!(
            due,
            vec![
                "active-since-check".to_string(),
                "backoff-elapsed".to_string(),
                "never-checked".to_string(),
            ]
        );
    }

    #[test]
    fn next_idle_check_doubles_to_the_cap_and_restarts_after_activity() {
        let base = MINUTE_MS / 2;
        let max = 10 * MINUTE_MS;
        let first = next_idle_check(None, 0, MINUTE_MS, base, max);
        assert_eq!(first.backoff_ms, base);

        let second = next_idle_check(Some(first), 0, 2 * MINUTE_MS, base, max);
        assert_eq!(second.backoff_ms, 2 * base);

        let capped = next_idle_check(
            Some(IdleCheck {
                checked_at_ms: 3 * MINUTE_MS,
                backoff_ms: 8 * MINUTE_MS,
            }),
            0,
            11 * MINUTE_MS,
            base,
            max,
        );
        assert_eq!(capped.backoff_ms, max);

        let after_activity =
            next_idle_check(Some(capped), 12 * MINUTE_MS, 20 * MINUTE_MS, base, max);
        assert_eq!(after_activity.backoff_ms, base);
    }

    #[tokio::test]
    async fn idle_sweep_frees_quiet_absent_ids_and_spares_the_rest() {
        let runtime = runtime().await;
        let sandbox = sandbox_record("sb-live", "sandbox-live", SandboxPhase::Ready);
        runtime.store.put_message(&sandbox).await.unwrap();
        let _live = runtime.tracing_log_bus.subscribe("sb-live");
        let _gone = runtime.tracing_log_bus.subscribe("sb-gone");
        let interval = Duration::from_secs(30);
        let mut checks = HashMap::new();

        // Both ids were active just now, so neither is checked, even though one has no row.
        runtime
            .run_idle_bus_sweep(&mut checks, now_ms(), interval)
            .await;
        let mut tracked = runtime.tracing_log_bus.tracked_ids();
        tracked.sort();
        assert_eq!(tracked, vec!["sb-gone".to_string(), "sb-live".to_string()]);
        assert!(checks.is_empty());

        // Once both are quiet, the absent id is freed at once and the present one backs off.
        let later = now_ms() + as_ms(IDLE_QUIET_PERIOD) + 1_000;
        runtime
            .run_idle_bus_sweep(&mut checks, later, interval)
            .await;
        assert_eq!(
            runtime.tracing_log_bus.tracked_ids(),
            vec!["sb-live".to_string()]
        );
        assert_eq!(
            checks.get("sb-live"),
            Some(&IdleCheck {
                checked_at_ms: later,
                backoff_ms: as_ms(interval),
            })
        );
    }

    #[tokio::test]
    async fn idle_sweep_keeps_state_on_store_error() {
        let runtime = runtime().await;
        let _rx = runtime.tracing_log_bus.subscribe("sb-blip");
        runtime.store.close_for_test().await;
        let mut checks = HashMap::new();

        let later = now_ms() + as_ms(IDLE_QUIET_PERIOD) + 1_000;
        runtime
            .run_idle_bus_sweep(&mut checks, later, Duration::from_secs(30))
            .await;
        assert_eq!(
            runtime.tracing_log_bus.tracked_ids(),
            vec!["sb-blip".to_string()]
        );
        assert!(checks.is_empty());
    }

    async fn tombstone_runtime() -> ComputeRuntime {
        let mut runtime = runtime().await;
        runtime.bus_sweep_mode = BusSweepMode::Tombstone;
        runtime
    }

    async fn has_tombstone(runtime: &ComputeRuntime, sandbox_id: &str) -> bool {
        runtime
            .store
            .get(TOMBSTONE_OBJECT_TYPE, &tombstone_object_id(sandbox_id))
            .await
            .unwrap()
            .is_some()
    }

    #[tokio::test]
    async fn announce_writes_a_tombstone_only_in_tombstone_mode() {
        let full = runtime().await;
        full.announce_sandbox_removal("sb-1").await;
        assert!(!has_tombstone(&full, "sb-1").await);

        let tombstone = tombstone_runtime().await;
        tombstone.announce_sandbox_removal("sb-1").await;
        assert!(has_tombstone(&tombstone, "sb-1").await);
        // A second announcement of the same removal is a no-op, not an error.
        tombstone.announce_sandbox_removal("sb-1").await;
    }

    #[tokio::test]
    async fn sandbox_row_removal_writes_a_tombstone() {
        let runtime = tombstone_runtime().await;
        let sandbox = sandbox_record("sb-del", "sandbox-del", SandboxPhase::Ready);
        runtime.store.put_message(&sandbox).await.unwrap();

        runtime.apply_deleted("sb-del").await.unwrap();
        assert!(has_tombstone(&runtime, "sb-del").await);
    }

    #[tokio::test]
    async fn tombstone_read_frees_only_named_ids() {
        let runtime = tombstone_runtime().await;
        let _gone = runtime.tracing_log_bus.subscribe("sb-gone");
        // No row and no tombstone: the tombstone read never checks rows, so this one stays.
        let _other = runtime.tracing_log_bus.subscribe("sb-other");
        runtime.announce_sandbox_removal("sb-gone").await;

        assert!(
            runtime
                .free_tombstoned_sandboxes(now_ms() - as_ms(TOMBSTONE_READ_OVERLAP))
                .await
        );
        assert_eq!(
            runtime.tracing_log_bus.tracked_ids(),
            vec!["sb-other".to_string()]
        );
    }

    #[tokio::test]
    async fn tombstone_read_skips_rows_before_its_start() {
        let runtime = tombstone_runtime().await;
        runtime.announce_sandbox_removal("sb-old").await;
        let _rx = runtime.tracing_log_bus.subscribe("sb-old");

        assert!(runtime.free_tombstoned_sandboxes(now_ms() + 60_000).await);
        assert_eq!(
            runtime.tracing_log_bus.tracked_ids(),
            vec!["sb-old".to_string()]
        );
    }

    #[tokio::test]
    async fn tombstone_read_pages_through_more_than_one_page() {
        let runtime = tombstone_runtime().await;
        let count = TOMBSTONE_PAGE_SIZE as usize + 5;
        let ids: Vec<String> = (0..count).map(|idx| format!("sb-{idx:04}")).collect();
        for id in &ids {
            runtime.announce_sandbox_removal(id).await;
        }
        let _first = runtime.tracing_log_bus.subscribe(&ids[0]);
        let _last = runtime.tracing_log_bus.subscribe(&ids[count - 1]);

        assert!(
            runtime
                .free_tombstoned_sandboxes(now_ms() - as_ms(TOMBSTONE_READ_OVERLAP))
                .await
        );
        assert!(runtime.tracing_log_bus.tracked_ids().is_empty());
    }

    #[tokio::test]
    async fn tombstone_read_reports_a_store_error() {
        let runtime = tombstone_runtime().await;
        let _rx = runtime.tracing_log_bus.subscribe("sb-blip");
        runtime.store.close_for_test().await;

        assert!(!runtime.free_tombstoned_sandboxes(0).await);
        assert_eq!(
            runtime.tracing_log_bus.tracked_ids(),
            vec!["sb-blip".to_string()]
        );
    }

    #[tokio::test]
    async fn expiry_deletes_only_tombstones_before_the_cutoff() {
        let runtime = tombstone_runtime().await;
        runtime.announce_sandbox_removal("sb-1").await;

        runtime
            .expire_tombstones(now_ms() - as_ms(TOMBSTONE_TTL))
            .await;
        assert!(has_tombstone(&runtime, "sb-1").await);

        runtime.expire_tombstones(now_ms() + 1_000).await;
        assert!(!has_tombstone(&runtime, "sb-1").await);
    }

    #[tokio::test]
    async fn backstop_frees_unannounced_ids_after_two_passes() {
        let runtime = tombstone_runtime().await;
        let _rx = runtime.tracing_log_bus.subscribe("sb-failed-create");
        let mut backstop = Backstop::new();

        backstop.run(&runtime).await;
        assert_eq!(
            runtime.tracing_log_bus.tracked_ids(),
            vec!["sb-failed-create".to_string()]
        );
        backstop.run(&runtime).await;
        assert!(runtime.tracing_log_bus.tracked_ids().is_empty());
    }

    #[tokio::test]
    async fn notify_loop_without_a_listener_stops_on_cancel() {
        let mut runtime = runtime().await;
        runtime.bus_sweep_mode = BusSweepMode::Notify;
        let runtime = Arc::new(runtime);
        // `SQLite` has no other replica, so the announcement is a no-op rather than an error.
        runtime.announce_sandbox_removal("sb-1").await;

        let (cancel_tx, cancel_rx) = watch::channel(false);
        let sweep = tokio::spawn(runtime.clone().notify_bus_sweep_loop(cancel_rx));
        cancel_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), sweep)
            .await
            .expect("the loop stops on cancel")
            .unwrap();
    }

    fn postgres_url() -> String {
        std::env::var("OPENSHELL_TEST_POSTGRES_URL").expect("OPENSHELL_TEST_POSTGRES_URL")
    }

    async fn postgres_runtime(mode: BusSweepMode) -> ComputeRuntime {
        let store = Store::connect(&postgres_url()).await.unwrap();
        let mut runtime = new_test_runtime(Arc::new(store)).await;
        runtime.bus_sweep_mode = mode;
        runtime
    }

    /// Two replicas on one Postgres database: a removal that one announces frees the state that
    /// the other holds. Run like the store's `postgres_` tests.
    #[tokio::test]
    #[ignore = "needs OPENSHELL_TEST_POSTGRES_URL"]
    async fn postgres_tombstone_mode_frees_state_on_another_replica() {
        let writer = postgres_runtime(BusSweepMode::Tombstone).await;
        let reader = postgres_runtime(BusSweepMode::Tombstone).await;
        let id = format!("pg-sb-{}", uuid::Uuid::new_v4());
        let _rx = reader.tracing_log_bus.subscribe(&id);
        let read_from_ms = now_ms() - as_ms(TOMBSTONE_READ_OVERLAP);

        writer.announce_sandbox_removal(&id).await;
        assert!(reader.free_tombstoned_sandboxes(read_from_ms).await);
        assert!(reader.tracing_log_bus.tracked_ids().is_empty());
        writer.expire_tombstones(now_ms() + 1_000).await;
        assert!(!has_tombstone(&writer, &id).await);
    }

    #[tokio::test]
    #[ignore = "needs OPENSHELL_TEST_POSTGRES_URL"]
    async fn postgres_notify_mode_frees_state_on_another_replica() {
        let writer = postgres_runtime(BusSweepMode::Notify).await;
        let reader = Arc::new(postgres_runtime(BusSweepMode::Notify).await);
        let id = format!("pg-sb-{}", uuid::Uuid::new_v4());
        let _rx = reader.tracing_log_bus.subscribe(&id);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let sweep = tokio::spawn(reader.clone().notify_bus_sweep_loop(cancel_rx));

        announce_until_freed(&writer, &reader, &id).await;

        // Drop the listener's connection; the loop must reconnect and keep receiving.
        let admin = sqlx::PgPool::connect(&postgres_url()).await.unwrap();
        let terminated: Vec<bool> = sqlx::query_scalar(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE pid <> pg_backend_pid() AND query ILIKE 'LISTEN%' AND query LIKE $1",
        )
        .bind(format!("%{SANDBOX_REMOVED_CHANNEL}%"))
        .fetch_all(&admin)
        .await
        .unwrap();
        assert!(
            terminated.contains(&true),
            "a listener connection was dropped"
        );
        let next_id = format!("pg-sb-{}", uuid::Uuid::new_v4());
        let _next_rx = reader.tracing_log_bus.subscribe(&next_id);
        announce_until_freed(&writer, &reader, &next_id).await;

        cancel_tx.send(true).unwrap();
        sweep.await.unwrap();
    }

    /// Repeat an idempotent announcement until `reader` frees `id`, because the reader's
    /// listener may not be open yet.
    async fn announce_until_freed(writer: &ComputeRuntime, reader: &ComputeRuntime, id: &str) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while reader
                .tracing_log_bus
                .tracked_ids()
                .iter()
                .any(|tracked| tracked == id)
            {
                writer.announce_sandbox_removal(id).await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the other replica frees the state");
    }
}
