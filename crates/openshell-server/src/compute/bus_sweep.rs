// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Modes for the per-replica bus eviction sweep, selected by `OPENSHELL_BUS_SWEEP_MODE`.
//!
//! `full`, the default, checks every tracked id against the store on every pass (see
//! `ComputeRuntime::run_bus_eviction_sweep`). The other modes narrow what a pass checks:
//!
//! - `idle` checks only ids with no log activity for [`IDLE_QUIET_PERIOD`], and backs off ids
//!   that it keeps finding present.

use super::{ComputeRuntime, bus_sweep_interval};
use crate::persistence::ObjectType;
use openshell_core::proto::Sandbox;
use openshell_core::time::now_ms;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{info, warn};

/// Env override that selects the [`BusSweepMode`]; see `docs/reference/gateway-config.mdx`.
const BUS_SWEEP_MODE_ENV: &str = "OPENSHELL_BUS_SWEEP_MODE";

/// How long an id must go without a subscribe or publish before the `idle` mode checks it.
/// Far longer than a create's row-insert delay, so one absent read is enough to free an id.
const IDLE_QUIET_PERIOD: Duration = Duration::from_mins(5);

/// Longest wait between two `idle` checks of a quiet id that stays present.
const IDLE_MAX_BACKOFF: Duration = Duration::from_mins(10);

/// How each sweep pass finds the per-sandbox bus state to free.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum BusSweepMode {
    /// Check every tracked id against the store on every pass.
    #[default]
    Full,
    /// Check only ids without recent log activity, backing off ids that stay present.
    Idle,
}

impl BusSweepMode {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "full" => Some(Self::Full),
            "idle" => Some(Self::Idle),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Idle => "idle",
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
}
