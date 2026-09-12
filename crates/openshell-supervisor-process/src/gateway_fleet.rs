// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Holding a supervisor session to several gateway replicas at once.
//!
//! A relay comes back on the same connection as the control stream, so the
//! replica holding a sandbox's session is the only one that can serve a relay
//! for it. Connecting to one replica therefore makes that replica a single
//! point of failure for the sandbox, and makes every caller's problem
//! "find the replica" — which no amount of load balancing in front of the
//! gateway can solve, because a `Service` balances connections and there is
//! only one.
//!
//! So connect to a *subset* of replicas instead, chosen by hashing the
//! sandbox id ([`openshell_core::gateway_fleet`]). Then any replica in the
//! subset can serve, and a caller that computes the same subset reaches a
//! session-holding replica without asking anyone.
//!
//! Membership comes from DNS, re-resolved on an interval. Two rules make
//! that safe to act on:
//!
//! * **Add before drop.** When the subset changes, connect to the arrivals
//!   first and keep each departure until it has been absent from the subset
//!   for a whole drain window. The held connections are then a superset of
//!   *every* subset this supervisor computed within that window — not merely
//!   of the last two — so a caller whose view is anything this supervisor has
//!   seen recently picks a replica it is connected to. That distinction is the
//!   whole guarantee under a rolling restart, which is a run of membership
//!   changes spaced more closely than the window. Overlap between subsets
//!   would not be enough: the requirement is on the caller's pick, not on the
//!   sets intersecting.
//!
//!   The other side of the bargain is that the caller's view has to be recent.
//!   The window bounds skew between two *live* views; it cannot cover a caller
//!   that has stopped re-resolving, so sandbox-api stops trusting an
//!   unboundedly old view to *narrow* the candidates (`gateway-fleet.ts`).
//! * **Never act on ignorance.** A failed or empty DNS answer leaves existing
//!   connections alone. Losing a working session because a resolver blipped
//!   would be strictly worse than routing on a slightly stale view, which
//!   costs at most one rejected request.
//!
//! Ignorance is also not a reason to connect *somewhere*. Before the first
//! resolve there is no session and no endpoint worth dialling: with a fleet
//! configured, the configured endpoint is the headless `Service`, so a session
//! opened through it lands on an arbitrary replica — and the caller that has to
//! find it is resolving the same DNS that just failed, so it cannot. A session
//! nobody can route to is worse than none, because the sandbox looks connected.
//! The loop re-resolves instead.
//!
//! With no [`FLEET_DNS_NAME_ENV`](openshell_core::gateway_fleet::FLEET_DNS_NAME_ENV)
//! configured this module holds exactly one session to the configured
//! endpoint, which is what the Docker, Podman and VM drivers want. That
//! endpoint is a single gateway rather than a name that fans out, so dialling
//! it is correct there; it is published as the subset so the unary RPCs have
//! one source of targets either way.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use openshell_core::gateway_fleet::{FleetConfig, resolve_members, subset_for};
use tokio::task::{AbortHandle, JoinSet};
use tracing::{debug, info, warn};

use crate::supervisor_session::{SessionConfig, run_session_loop};

/// Backoff after a DNS failure. Short, because the previous view is still in
/// use and the only cost of being stale is a rejected request that retries.
const RESOLVE_RETRY: Duration = Duration::from_secs(5);

/// The subset this supervisor currently holds sessions to, in preference
/// order, published for the unary RPCs in `run`.
///
/// Process-global because a supervisor process serves exactly one sandbox and
/// therefore has exactly one subset. Passing it through would mean threading
/// a handle into every exit-reporting path for a value that cannot vary.
static CURRENT_SUBSET: OnceLock<Arc<RwLock<Vec<String>>>> = OnceLock::new();

fn current_subset() -> &'static Arc<RwLock<Vec<String>>> {
    CURRENT_SUBSET.get_or_init(|| Arc::new(RwLock::new(Vec::new())))
}

fn publish_subset(endpoints: Vec<String>) {
    if let Ok(mut current) = current_subset().write() {
        *current = endpoints;
    }
}

/// Pick the endpoint for one attempt of a unary RPC that needs a
/// session-holding replica.
///
/// `ReportMainProcessExit` and `FinalizeMainProcessExit` are unary, so they
/// are balanced by the `Service` and can land on a replica holding no session
/// for this sandbox — which answers `failed_precondition` and leaves the
/// supervisor retrying. Addressing a subset member directly avoids that, and
/// rotating on each attempt means a replica that has since died costs one
/// attempt rather than every attempt.
///
/// `None` while membership is unknown, which is only the window before the
/// first resolve completes. There is deliberately no fallback to the
/// configured endpoint: with a fleet configured that name is the headless
/// `Service`, and dialling it would balance this RPC onto a replica holding no
/// session — the failure this function exists to avoid. Single-endpoint mode
/// publishes its one endpoint here instead, so it is not a special case.
///
/// Callers are retry loops, so `None` costs one delay and resolves itself.
#[must_use]
pub(crate) fn endpoint_for_attempt(attempt: usize) -> Option<String> {
    let subset = current_subset().read().ok()?;
    if subset.is_empty() {
        return None;
    }

    Some(subset[attempt % subset.len()].clone())
}

/// A gateway endpoint for a unary RPC issued *before* this sandbox has any
/// session — in practice the startup policy fetch, which runs before
/// [`run`] has resolved anything.
///
/// [`endpoint_for_attempt`] cannot serve that caller: it reads the subset this
/// module publishes, and at startup there is none, so it would answer `None`
/// forever. This resolves membership itself instead.
///
/// The configured endpoint is not a fallback, for the same reason it is not one
/// anywhere else here: with a fleet configured it is the headless `Service`,
/// which is deliberately absent from the gateway's serving certificate, so
/// dialling it fails hostname verification. Single-endpoint mode — no fleet
/// configured, or an endpoint whose scheme and port cannot be reused — is the
/// one case where that endpoint *is* a single gateway, and then it is returned.
///
/// `None` means membership could not be resolved. Callers are retry loops, so
/// that costs a backoff.
pub async fn unary_endpoint(
    configured_endpoint: &str,
    sandbox_id: &str,
    attempt: usize,
) -> Option<String> {
    let Some((scheme, port)) = endpoint_shape(configured_endpoint) else {
        return Some(configured_endpoint.to_string());
    };
    let Some(fleet) = FleetConfig::from_env(port) else {
        return Some(configured_endpoint.to_string());
    };

    let members = match resolve_members(&fleet.dns_name, port).await {
        Ok(members) if !members.is_empty() => members,
        Ok(_) => {
            warn!(
                fleet_dns_name = %fleet.dns_name,
                "gateway fleet resolved to no endpoints; cannot address a replica yet"
            );
            return None;
        }
        Err(error) => {
            warn!(
                fleet_dns_name = %fleet.dns_name,
                error = %error,
                "could not resolve the gateway fleet; cannot address a replica yet"
            );
            return None;
        }
    };

    // The subset this sandbox's sessions will use, so a policy fetch warms the
    // same replicas rather than a third set. Any replica can serve it — it is a
    // store read — so falling back to the full membership is harmless.
    let subset = subset_for(sandbox_id, &members, fleet.subset_size);
    let pool = if subset.is_empty() { members } else { subset };

    Some(member_endpoint(&scheme, &pool[attempt % pool.len()]))
}

/// Split a gateway endpoint URL into the scheme and port to reuse when
/// addressing individual replicas.
///
/// A replica is dialed at the same scheme and port as the configured
/// endpoint, differing only in host — the fleet is uniform by construction,
/// being one Deployment behind one Service.
fn endpoint_shape(endpoint: &str) -> Option<(String, u16)> {
    let (scheme, rest) = endpoint.split_once("://")?;
    let host_and_port = rest.split('/').next().unwrap_or(rest);
    let port = host_and_port.rsplit_once(':')?.1.parse::<u16>().ok()?;
    Some((scheme.to_string(), port))
}

fn member_endpoint(scheme: &str, member: &str) -> String {
    format!("{scheme}://{member}")
}

/// One held session, and when it should be given up.
struct Connection {
    abort: AbortHandle,
    /// Set when the member has left the subset; the session is dropped once
    /// this passes. `None` means the member is still in the subset.
    drop_at: Option<Instant>,
}

/// Run the supervisor's gateway sessions for the lifetime of the sandbox.
///
/// Cancel-safe by construction: every session runs in a [`JoinSet`] owned by
/// this future, and dropping a `JoinSet` aborts its tasks. Callers abort this
/// one task at shutdown and every session goes with it.
pub(crate) async fn run(config: SessionConfig) {
    let Some((scheme, port)) = endpoint_shape(&config.endpoint) else {
        warn!(
            endpoint = %config.endpoint,
            "supervisor session: endpoint has no scheme and port to reuse for fleet members; \
             connecting to the configured endpoint only"
        );
        publish_subset(vec![config.endpoint.clone()]);
        run_session_loop(config).await;
        return;
    };

    let Some(fleet) = FleetConfig::from_env(port) else {
        debug!("supervisor session: no gateway fleet configured; single-endpoint mode");
        // The one endpoint there is, published through the same channel a
        // subset would be, so the unary RPCs have a single source of targets.
        publish_subset(vec![config.endpoint.clone()]);
        run_session_loop(config).await;
        return;
    };

    info!(
        sandbox_id = %config.sandbox_id,
        fleet_dns_name = %fleet.dns_name,
        subset_size = fleet.subset_size,
        "supervisor session: multi-connecting to a gateway subset"
    );

    let mut sessions = JoinSet::new();
    let mut connections: HashMap<String, Connection> = HashMap::new();

    loop {
        let resolved = resolve_members(&fleet.dns_name, fleet.port).await;
        let wait = match resolved {
            Ok(members) if !members.is_empty() => {
                let subset = subset_for(&config.sandbox_id, &members, fleet.subset_size);
                reconcile(
                    &subset,
                    &fleet,
                    &scheme,
                    &config,
                    &mut sessions,
                    &mut connections,
                );
                publish_subset(
                    subset
                        .iter()
                        .map(|member| member_endpoint(&scheme, member))
                        .collect(),
                );
                fleet.refresh
            }
            Ok(_) => {
                // No ready endpoints. Keeping the current sessions is right:
                // they are evidence of reachable replicas that this answer
                // does not have.
                warn!(
                    fleet_dns_name = %fleet.dns_name,
                    held_sessions = connections.len(),
                    "supervisor session: gateway fleet resolved to no endpoints; keeping current sessions"
                );
                RESOLVE_RETRY
            }
            Err(error) => {
                warn!(
                    fleet_dns_name = %fleet.dns_name,
                    %error,
                    held_sessions = connections.len(),
                    "supervisor session: could not resolve the gateway fleet; keeping current sessions"
                );
                RESOLVE_RETRY
            }
        };

        reap_drained(&mut connections);
        drain_finished_sessions(&mut sessions);
        tokio::time::sleep(wait).await;
    }
}

/// Bring held sessions in line with `subset`, arrivals first.
fn reconcile(
    subset: &[String],
    fleet: &FleetConfig,
    scheme: &str,
    config: &SessionConfig,
    sessions: &mut JoinSet<()>,
    connections: &mut HashMap<String, Connection>,
) {
    for member in subset {
        if let Some(connection) = connections.get_mut(member) {
            // Already held. Clear any pending drop: a member that left the
            // subset and came back within the drain window keeps its session
            // rather than being dropped and immediately reconnected.
            connection.drop_at = None;
        } else {
            let endpoint = member_endpoint(scheme, member);
            info!(
                sandbox_id = %config.sandbox_id,
                %endpoint,
                "supervisor session: connecting to a new subset member"
            );
            let mut member_config = config.clone();
            member_config.endpoint = endpoint;
            let abort = sessions.spawn(run_session_loop(member_config));
            connections.insert(
                member.clone(),
                Connection {
                    abort,
                    drop_at: None,
                },
            );
        }
    }

    let deadline = Instant::now() + fleet.drain;
    for (member, connection) in connections.iter_mut() {
        // `drop_at.is_none()` is load-bearing, and both halves of it are.
        //
        // Setting the deadline only on the *first* pass that finds a member
        // absent makes `drop_at` measure continuous absence. That is what
        // makes the held set a superset of every subset computed in the last
        // `drain`: a member of one of those subsets either is in the current
        // subset, or first went absent no earlier than when that subset was
        // computed, so its deadline has not passed. The guarantee therefore
        // survives any number of membership changes inside one window — a
        // rolling restart of the fleet is exactly that — rather than only the
        // single old-to-new transition.
        //
        // Refreshing the deadline on every pass instead would push it forward
        // for as long as the member stayed absent, so the session would never
        // be dropped and the subset would grow without bound. Clearing it on
        // return to the subset (above) is what restarts the measurement.
        if !subset.contains(member) && connection.drop_at.is_none() {
            info!(
                sandbox_id = %config.sandbox_id,
                %member,
                drain_secs = fleet.drain.as_secs(),
                "supervisor session: subset member departed; holding its session to drain"
            );
            connection.drop_at = Some(deadline);
        }
    }
}

/// Drop sessions whose drain window has passed.
fn reap_drained(connections: &mut HashMap<String, Connection>) {
    let now = Instant::now();
    connections.retain(|member, connection| {
        let expired = connection.drop_at.is_some_and(|drop_at| now >= drop_at);
        if expired {
            debug!(%member, "supervisor session: dropping a drained subset member");
            connection.abort.abort();
        }
        !expired
    });
}

/// Collect finished session tasks so the `JoinSet` does not grow.
///
/// A session task only finishes when it is aborted or the gateway closed the
/// stream cleanly during local shutdown; the reconnect loop handles every
/// other outcome itself. An entry left in `connections` for a task that
/// finished on its own is corrected on the next reconcile, which sees the
/// member is still in the subset and holds a `Connection` — so this reaps the
/// task, and liveness of the underlying session is the session loop's job.
fn drain_finished_sessions(sessions: &mut JoinSet<()>) {
    while sessions.try_join_next().is_some() {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_shape_reuses_the_configured_scheme_and_port() {
        assert_eq!(
            endpoint_shape("https://openshell.sandbox.svc.cluster.local:8080"),
            Some(("https".to_string(), 8080))
        );
        assert_eq!(
            endpoint_shape("http://openshell:9090/"),
            Some(("http".to_string(), 9090))
        );
    }

    /// Without an explicit port there is no way to address a peer replica, so
    /// the caller must fall back to single-endpoint mode rather than guess.
    #[test]
    fn endpoint_shape_rejects_an_endpoint_it_cannot_rebuild() {
        assert_eq!(endpoint_shape("https://openshell"), None);
        assert_eq!(endpoint_shape("openshell:8080"), None);
        assert_eq!(endpoint_shape("https://openshell:notaport"), None);
    }

    #[test]
    fn member_endpoint_keeps_the_scheme() {
        assert_eq!(
            member_endpoint("https", "10-42-0-1.openshell-headless.ns.svc:8080"),
            "https://10-42-0-1.openshell-headless.ns.svc:8080"
        );
    }

    /// One test, because the published subset is process-global and tests
    /// share a process: split across two tests these race each other.
    ///
    /// Unknown membership answers `None` rather than the configured endpoint.
    /// With a fleet configured that name is the headless `Service`, so dialling
    /// it would balance a session-bound RPC onto a replica holding no session —
    /// exactly the failure addressing a subset member avoids. The rotation
    /// matters because it stops a subset member that has since died from
    /// failing every retry of an exit report, which would spin until teardown.
    #[test]
    fn endpoint_for_attempt_rotates_over_the_subset_and_never_invents_one() {
        publish_subset(Vec::new());
        assert_eq!(endpoint_for_attempt(0), None);

        publish_subset(vec![
            "https://a:8080".to_string(),
            "https://b:8080".to_string(),
        ]);
        assert_eq!(endpoint_for_attempt(0), Some("https://a:8080".to_string()));
        assert_eq!(endpoint_for_attempt(1), Some("https://b:8080".to_string()));
        assert_eq!(endpoint_for_attempt(2), Some("https://a:8080".to_string()));

        // And it goes back to having no answer rather than to the endpoint.
        publish_subset(Vec::new());
        assert_eq!(endpoint_for_attempt(0), None);
    }

    fn test_config(endpoint: &str) -> SessionConfig {
        SessionConfig {
            endpoint: endpoint.to_string(),
            sandbox_id: "sbx-1".to_string(),
            ssh_socket_path: std::path::PathBuf::from("/nonexistent.sock"),
            netns_fd: None,
            expected_ssh_peer_pid: None,
            terminating: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            instance_id: "instance-1".to_string(),
        }
    }

    fn fleet(drain: Duration) -> FleetConfig {
        FleetConfig {
            dns_name: "openshell-headless.ns.svc".to_string(),
            port: 8080,
            subset_size: 2,
            refresh: Duration::from_secs(20),
            drain,
        }
    }

    #[tokio::test]
    async fn reconcile_connects_to_arrivals() {
        let mut sessions = JoinSet::new();
        let mut connections = HashMap::new();
        let subset = vec!["a:8080".to_string(), "b:8080".to_string()];

        reconcile(
            &subset,
            &fleet(Duration::from_mins(2)),
            "https",
            &test_config("https://base:8080"),
            &mut sessions,
            &mut connections,
        );

        assert_eq!(connections.len(), 2);
        assert!(connections.values().all(|c| c.drop_at.is_none()));
    }

    /// The property containment depends on: on a subset change the departed
    /// member is still held, so the held set is the union of both views.
    #[tokio::test]
    async fn reconcile_holds_a_departed_member_before_dropping_it() {
        let mut sessions = JoinSet::new();
        let mut connections = HashMap::new();
        let fleet = fleet(Duration::from_mins(2));
        let config = test_config("https://base:8080");

        reconcile(
            &["a:8080".to_string(), "b:8080".to_string()],
            &fleet,
            "https",
            &config,
            &mut sessions,
            &mut connections,
        );
        reconcile(
            &["b:8080".to_string(), "c:8080".to_string()],
            &fleet,
            "https",
            &config,
            &mut sessions,
            &mut connections,
        );

        // The union of both views, not just the new one.
        assert_eq!(connections.len(), 3);
        assert!(
            connections["a:8080"].drop_at.is_some(),
            "departed member must drain"
        );
        assert!(connections["b:8080"].drop_at.is_none());
        assert!(connections["c:8080"].drop_at.is_none());

        reap_drained(&mut connections);
        assert_eq!(connections.len(), 3, "the drain window has not passed");
    }

    #[tokio::test]
    async fn reap_drained_drops_a_member_once_its_window_passes() {
        let mut sessions = JoinSet::new();
        let mut connections = HashMap::new();
        let fleet = fleet(Duration::ZERO);
        let config = test_config("https://base:8080");

        reconcile(
            &["a:8080".to_string()],
            &fleet,
            "https",
            &config,
            &mut sessions,
            &mut connections,
        );
        reconcile(
            &["b:8080".to_string()],
            &fleet,
            "https",
            &config,
            &mut sessions,
            &mut connections,
        );
        reap_drained(&mut connections);

        assert_eq!(connections.keys().collect::<Vec<_>>(), vec!["b:8080"]);
    }

    /// A member that leaves and returns within its drain window keeps the
    /// session it already has; dropping and redialing would break relays for
    /// no reason.
    #[tokio::test]
    async fn reconcile_cancels_a_pending_drop_when_a_member_returns() {
        let mut sessions = JoinSet::new();
        let mut connections = HashMap::new();
        let fleet = fleet(Duration::from_mins(2));
        let config = test_config("https://base:8080");

        reconcile(
            &["a:8080".to_string()],
            &fleet,
            "https",
            &config,
            &mut sessions,
            &mut connections,
        );
        reconcile(
            &["b:8080".to_string()],
            &fleet,
            "https",
            &config,
            &mut sessions,
            &mut connections,
        );
        assert!(connections["a:8080"].drop_at.is_some());

        reconcile(
            &["a:8080".to_string()],
            &fleet,
            "https",
            &config,
            &mut sessions,
            &mut connections,
        );
        assert!(connections["a:8080"].drop_at.is_none());
        assert_eq!(connections.len(), 2);
    }
}
