//! Gateway connections whose supervisor session is currently established.
//!
//! A supervisor multi-connects to a subset of the gateway fleet and holds one
//! session per member, each on a channel that already carries the control
//! stream and every relay. Those connections are the best liveness signal this
//! process has: a gateway is in here because it accepted a session and is
//! heartbeating, not because DNS named it.
//!
//! This module publishes them so that work needing *a* gateway — renewing the
//! sandbox JWT, polling settings — borrows one instead of resolving membership
//! and dialing its own. Those workstreams previously did the latter, and each
//! pinned itself to whichever pod it picked at startup: when that pod went
//! away they retried it forever while healthy sessions sat unused beside them.
//!
//! Nothing here ranks. Their RPCs read fleet-wide state rather than anything
//! session-bound, so every established gateway answers identically and the
//! whole policy is "any of them, and on failure the next one". The rotation
//! below exists only to spread load, not to express a preference.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{OnceLock, RwLock};

use crate::grpc_client::AuthedChannel;
use miette::Result;
use tonic::transport::Channel;
use tracing::debug;

/// One gateway this supervisor currently holds a session to.
#[derive(Clone)]
pub struct GatewayChannel {
    pub endpoint: String,
    /// Bearer-authenticated, which is what every steady-state RPC wants.
    pub authed: AuthedChannel,
    /// The same connection without the interceptor, for the one exchange that
    /// must not present a token: the K8s `ServiceAccount` bootstrap that runs
    /// precisely when the token we would have sent is no longer accepted.
    pub plain: Channel,
}

static LIVE: OnceLock<RwLock<HashMap<String, GatewayChannel>>> = OnceLock::new();

/// Rotates the starting point so repeated calls spread across the subset
/// rather than all landing on whichever gateway happens to enumerate first.
static NEXT_START: AtomicUsize = AtomicUsize::new(0);

fn live() -> &'static RwLock<HashMap<String, GatewayChannel>> {
    LIVE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Publish a channel whose session has been accepted.
pub fn register(channel: GatewayChannel) {
    debug!(endpoint = %channel.endpoint, "gateway channels: session established");
    if let Ok(mut map) = live().write() {
        map.insert(channel.endpoint.clone(), channel);
    }
}

/// Withdraw a channel whose session has ended, for any reason.
///
/// Must be called on every exit from a session, including failure: a channel
/// left here after its session died is exactly the stale pin this module
/// exists to remove.
pub fn withdraw(endpoint: &str) {
    debug!(%endpoint, "gateway channels: session ended");
    if let Ok(mut map) = live().write() {
        map.remove(endpoint);
    }
}

/// Every gateway with an established session, in rotating order.
///
/// Empty before the first session is accepted and during a total fleet
/// outage. Both are transient and both are the caller's cue to retry rather
/// than to fail: a supervisor with no session has nothing useful to do anyway.
pub fn established() -> Vec<GatewayChannel> {
    let Ok(map) = live().read() else {
        return Vec::new();
    };

    let mut channels: Vec<GatewayChannel> = map.values().cloned().collect();
    channels.sort_by(|a, b| a.endpoint.cmp(&b.endpoint));
    rotate_for_spread(&mut channels);

    channels
}

/// Advance the shared cursor and rotate `items` onto it.
///
/// Sorting before this is what makes it a rotation at all: ordered by
/// `HashMap` iteration, "start at index n" would pick an arbitrary member each
/// time and could return the same one repeatedly.
fn rotate_for_spread<T>(items: &mut [T]) {
    if items.is_empty() {
        return;
    }
    let start = NEXT_START.fetch_add(1, Ordering::Relaxed) % items.len();
    items.rotate_left(start);
}

/// Run `f` against established gateways until one answers.
pub async fn with_gateway<T, F, Fut>(op_name: &str, f: F) -> Result<T>
where
    F: Fn(GatewayChannel) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    first_to_answer(
        op_name,
        established(),
        |channel| channel.endpoint.clone(),
        f,
    )
    .await
}

/// Try `candidates` in order until one answers.
///
/// An error is the ordinary way to learn a gateway is gone, so a failure moves
/// to the next candidate rather than ending the call. The last error survives
/// when every candidate refuses. An empty candidate list is its own error
/// because it means something different: nothing was tried, so nothing was
/// learned, and the caller should come back rather than treat the operation as
/// having failed on its merits.
async fn first_to_answer<C, T, F, Fut, L>(
    op_name: &str,
    candidates: Vec<C>,
    label: L,
    f: F,
) -> Result<T>
where
    F: Fn(C) -> Fut,
    Fut: Future<Output = Result<T>>,
    L: Fn(&C) -> String,
{
    if candidates.is_empty() {
        return Err(miette::miette!(
            "{op_name}: no gateway session is established yet"
        ));
    }

    let mut last_err = None;
    for candidate in candidates {
        let endpoint = label(&candidate);
        match f(candidate).await {
            Ok(value) => return Ok(value),
            Err(e) => {
                debug!(
                    %endpoint,
                    error = %e,
                    "{op_name}: gateway did not answer; trying another established session"
                );
                last_err = Some(e);
            }
        }
    }

    Err(last_err.expect("loop ran at least once"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The defect this module exists to fix: one dead gateway must cost one
    /// attempt, not the whole operation.
    #[tokio::test]
    async fn moves_past_a_gateway_that_does_not_answer() {
        let tried = Mutex::new(Vec::new());

        let answered = first_to_answer(
            "poll",
            vec!["dead", "alive"],
            |candidate| (*candidate).to_string(),
            |candidate| {
                tried.lock().unwrap().push(candidate);
                async move {
                    if candidate == "alive" {
                        Ok(candidate)
                    } else {
                        Err(miette::miette!("connection refused"))
                    }
                }
            },
        )
        .await
        .expect("the live gateway should have answered");

        assert_eq!(answered, "alive");
        assert_eq!(*tried.lock().unwrap(), vec!["dead", "alive"]);
    }

    /// Every gateway refusing is a real failure, and the reason must survive.
    #[tokio::test]
    async fn reports_the_last_error_when_none_answer() {
        let error = first_to_answer(
            "poll",
            vec!["a", "b"],
            |candidate| (*candidate).to_string(),
            |candidate| async move { Err::<&str, _>(miette::miette!("{candidate} refused")) },
        )
        .await
        .expect_err("no gateway answered");

        assert!(error.to_string().contains("b refused"), "{error}");
    }

    /// Distinct from "everyone refused": nothing was asked, so the caller
    /// should retry rather than conclude the operation cannot succeed.
    #[tokio::test]
    async fn distinguishes_having_no_sessions_at_all() {
        let error = first_to_answer(
            "poll",
            Vec::<&str>::new(),
            |candidate| (*candidate).to_string(),
            |candidate| async move { Ok(candidate) },
        )
        .await
        .expect_err("there was nothing to try");

        assert!(
            error
                .to_string()
                .contains("no gateway session is established"),
            "{error}"
        );
    }

    /// Without the rotation every borrowed RPC lands on the same gateway.
    #[test]
    fn spreads_consecutive_borrows_across_members() {
        let firsts: Vec<&str> = (0..3)
            .map(|_| {
                let mut members = ["a", "b", "c"];
                rotate_for_spread(&mut members);
                members[0]
            })
            .collect();

        assert_eq!(firsts.len(), 3);
        assert_eq!(
            firsts
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            3,
            "three consecutive borrows should touch three different gateways, got {firsts:?}"
        );
    }
}
