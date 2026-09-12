// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::{Ascii, MetadataMap, MetadataValue};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};
use uuid::Uuid;

use openshell_core::proto::{
    GatewayMessage, RelayFrame, RelayInit, RelayOpen, ReportMainProcessExitRequest,
    ReportMainProcessExitResponse, Sandbox, SandboxPhase, SessionAccepted, SshRelayTarget,
    SupervisorMessage, gateway_message, relay_open, supervisor_message,
};
use openshell_core::transport_errors::is_expected_transport_close_status;

use crate::ServerState;
use crate::auth::principal::Principal;
use crate::session_liveness::{
    LIVENESS_RENEWAL_INTERVAL, PeerSessions, SERVING_REPLICA_METADATA_KEY, SessionLiveness,
};

const HEARTBEAT_INTERVAL_SECS: u32 = 15;
const RELAY_PENDING_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound on unclaimed relay channels across all sandboxes. Caps the
/// memory a misbehaving caller can pin by calling `open_relay` repeatedly
/// while the supervisor never claims (or isn't responding). Sized generously
/// so normal bursts pass through; exceeding it returns `ResourceExhausted`.
const MAX_PENDING_RELAYS: usize = 256;
/// Upper bound on concurrent unclaimed relay channels for a single sandbox.
/// Enforces the same shape per sandbox so one misbehaving sandbox can't
/// consume the entire global budget. Sits above the SSH-tunnel per-sandbox
/// cap (20) so tunnel-specific limits still fire first for that caller.
const MAX_PENDING_RELAYS_PER_SANDBOX: usize = 32;

// ---------------------------------------------------------------------------
// Session registry
// ---------------------------------------------------------------------------

/// A live supervisor session handle.
struct LiveSession {
    #[allow(dead_code)]
    sandbox_id: String,
    /// Uniquely identifies this session instance. Used by cleanup to avoid
    /// removing a session that has since been superseded by a reconnect.
    session_id: String,
    tx: mpsc::Sender<GatewayMessage>,
    /// Fires when this session is superseded by a reconnect so the old session
    /// task can exit promptly — dropping its own `tx` clone and closing the
    /// outbound stream. Without this, a concurrent `open_relay` that grabbed
    /// the old session's `tx` just before supersede could still enqueue a
    /// `RelayOpen` onto the stale stream and sit until the relay timeout.
    shutdown: oneshot::Sender<()>,
    /// Set after the supervisor confirms that every expected foreground
    /// attachment has closed and terminal output delivery is complete.
    terminal_delivery_finalized: bool,
    #[allow(dead_code)]
    connected_at: Instant,
}

/// Holds a oneshot sender that will deliver the upgraded relay stream or a
/// target-open failure reported by the supervisor.
type RelayStreamSender = oneshot::Sender<Result<tokio::io::DuplexStream, Status>>;

/// Registry of active supervisor sessions and pending relay channels.
#[derive(Default)]
pub struct SupervisorSessionRegistry {
    /// `sandbox_id` -> live session handle.
    sessions: Mutex<HashMap<String, LiveSession>>,
    /// `channel_id` -> oneshot sender for the reverse CONNECT stream.
    pending_relays: Mutex<HashMap<String, PendingRelay>>,
    /// Cross-replica liveness records for supervisor sessions. `None` in
    /// unit and integration tests that drive the registry without a store —
    /// the registry then behaves exactly as a single-replica gateway.
    liveness: Option<Arc<SessionLiveness>>,
}

struct PendingRelay {
    sender: RelayStreamSender,
    sandbox_id: String,
    relay_open: RelayOpen,
    created_at: Instant,
}

#[derive(Debug)]
pub struct ClaimedRelay {
    pub stream: tokio::io::DuplexStream,
    pub sandbox_id: String,
}

impl std::fmt::Debug for SupervisorSessionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let session_count = self.sessions.lock().unwrap().len();
        let pending_count = self.pending_relays.lock().unwrap().len();
        f.debug_struct("SupervisorSessionRegistry")
            .field("sessions", &session_count)
            .field("pending_relays", &pending_count)
            .finish()
    }
}

impl SupervisorSessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registry that also publishes which replica owns each sandbox's
    /// supervisor session, enabling redirect hints on the no-local-session
    /// path.
    pub fn with_liveness(liveness: Arc<SessionLiveness>) -> Self {
        Self {
            liveness: Some(liveness),
            ..Self::default()
        }
    }

    /// Claim cross-replica liveness of a session and keep the claim fresh
    /// for as long as the returned handle is alive.
    ///
    /// Liveness bookkeeping is strictly advisory: every failure here is
    /// logged and swallowed. A local session that works is better than a
    /// refused request, so a store outage must never tear down or reject a
    /// session that is otherwise serving fine.
    /// `keep_phase_ready` runs after each successful renewal. A replica with a
    /// live session is the authority on that session, and saying so on the
    /// renewal cadence is what stops a row from holding a serving sandbox
    /// down: a phase demoted by some peer's disconnect — because its lookup
    /// raced an expiry — is corrected within one interval by the replica that
    /// can see the connection. It asserts exactly what the connect asserted,
    /// for as long as it stays true.
    pub fn spawn_liveness_record<F, Fut>(
        &self,
        sandbox_id: String,
        session_id: String,
        keep_phase_ready: F,
    ) -> Option<LivenessRenewal>
    where
        F: Fn(String) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let liveness = Arc::clone(self.liveness.as_ref()?);
        let handle = tokio::spawn(async move {
            let mut claim = match liveness.announce(&sandbox_id, &session_id).await {
                Ok(claim) => claim,
                Err(err) => {
                    warn!(
                        sandbox_id = %sandbox_id,
                        session_id = %session_id,
                        replica = %liveness.replica_id(),
                        error = %err,
                        "supervisor session: liveness claim failed — serving locally without a redirect record"
                    );
                    return;
                }
            };
            debug!(
                sandbox_id = %sandbox_id,
                session_id = %session_id,
                replica = %liveness.replica_id(),
                "supervisor session: liveness claimed"
            );

            loop {
                tokio::time::sleep(LIVENESS_RENEWAL_INTERVAL).await;
                if let Err(err) = liveness.renew(&sandbox_id, &mut claim).await {
                    warn!(
                        sandbox_id = %sandbox_id,
                        session_id = %session_id,
                        replica = %liveness.replica_id(),
                        error = %err,
                        "supervisor session: liveness renewal failed — session keeps serving, redirects may point elsewhere"
                    );
                    return;
                }
                keep_phase_ready(sandbox_id.clone()).await;
            }
        });
        Some(LivenessRenewal {
            handle: Some(handle),
        })
    }

    /// Release cross-replica liveness, guarded on `session_id` so a
    /// superseded session cannot delete the serving replica's record.
    pub async fn withdraw_liveness(&self, sandbox_id: &str, session_id: &str) {
        let Some(liveness) = self.liveness.as_ref() else {
            return;
        };
        withdraw_liveness_record(liveness, sandbox_id, session_id).await;
    }

    /// Whether an unexpired liveness record for this sandbox still exists.
    ///
    /// Asked after a session has released its own record, so a `true` answer
    /// means somebody else is still serving the sandbox — another replica, or
    /// a newer session on this one. That is what separates "this session
    /// ended" from "this sandbox lost its supervisor", and only the second is
    /// a phase change.
    ///
    /// With no cross-replica liveness configured the answer is `None` and not
    /// `Unknown`: there is only ever one session, and it is the one that just
    /// ended. A store that cannot answer is `Unknown`, which is not evidence
    /// of a peer and not evidence against one either.
    pub async fn sandbox_peer_sessions(&self, sandbox_id: &str) -> PeerSessions {
        let Some(liveness) = self.liveness.as_ref() else {
            return PeerSessions::None;
        };

        match liveness.lookup(sandbox_id).await {
            Ok(Some(_)) => PeerSessions::Serving,
            Ok(None) => PeerSessions::None,
            Err(error) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    replica = %liveness.replica_id(),
                    error = %error,
                    "supervisor session: liveness lookup failed on disconnect — phase left alone"
                );
                PeerSessions::Unknown
            }
        }
    }

    /// Release liveness without awaiting, for synchronous teardown paths.
    fn withdraw_liveness_detached(&self, sandbox_id: String, session_id: String) {
        let Some(liveness) = self.liveness.clone() else {
            return;
        };
        tokio::spawn(async move {
            withdraw_liveness_record(&liveness, &sandbox_id, &session_id).await;
        });
    }

    /// Register a live supervisor session for the given sandbox.
    ///
    /// If a previous session exists for the same sandbox, its shutdown signal
    /// is fired so the old session task exits promptly. Returns `true` iff a
    /// previous session was superseded.
    pub fn register(
        &self,
        sandbox_id: String,
        session_id: String,
        tx: mpsc::Sender<GatewayMessage>,
        shutdown: oneshot::Sender<()>,
    ) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let previous = sessions.remove(&sandbox_id);
        sessions.insert(
            sandbox_id.clone(),
            LiveSession {
                sandbox_id,
                session_id,
                tx,
                shutdown,
                terminal_delivery_finalized: false,
                connected_at: Instant::now(),
            },
        );
        match previous {
            Some(prev) => {
                // Best-effort — the old task may have already exited.
                let _ = prev.shutdown.send(());
                true
            }
            None => false,
        }
    }

    /// Remove the session for a sandbox, returning its `session_id`.
    fn remove(&self, sandbox_id: &str) -> Option<String> {
        self.sessions
            .lock()
            .unwrap()
            .remove(sandbox_id)
            .map(|session| session.session_id)
    }

    /// Disconnect the current supervisor session for a sandbox.
    ///
    /// Lifecycle stop uses this to ensure a later start must establish
    /// a fresh session before the sandbox can return to Ready.
    pub fn disconnect(&self, sandbox_id: &str) -> bool {
        let session = self.sessions.lock().unwrap().remove(sandbox_id);
        if let Some(session) = session {
            let _ = session.shutdown.send(());
            self.withdraw_liveness_detached(sandbox_id.to_string(), session.session_id);
            true
        } else {
            false
        }
    }

    /// Remove the session only if its `session_id` matches the one we are
    /// cleaning up. Returns `true` if the entry was removed.
    ///
    /// This guards against the supersede race: an old session's task may
    /// finish long after a new session has taken its place. The old task's
    /// cleanup must not evict the new registration.
    fn remove_if_current(&self, sandbox_id: &str, session_id: &str) -> Option<bool> {
        let mut sessions = self.sessions.lock().unwrap();
        let is_current = sessions
            .get(sandbox_id)
            .is_some_and(|s| s.session_id == session_id);
        if is_current {
            return sessions
                .remove(sandbox_id)
                .map(|session| session.terminal_delivery_finalized);
        }
        None
    }

    /// Look up the sender for a supervisor session, answering immediately
    /// when this replica holds none.
    ///
    /// This deliberately does not wait. A replica can only ever report on its
    /// own connections, so "no session here" is the complete and final answer
    /// it has — waiting turns that answer into a delayed version of itself,
    /// and does so on the one process with the least information about where
    /// the session actually is.
    ///
    /// Retry policy therefore belongs to the caller, which is the only party
    /// that knows how long it is willing to wait, whether to ask this replica
    /// again or a different one, and when to re-resolve membership and work
    /// from a fresher view. A gateway-side wait pre-empts all three choices
    /// and can express none of them; sandbox-api's exec loop makes them
    /// explicitly.
    ///
    /// This is also why no subset check is needed here. One existed only to
    /// avoid entering the wait on a replica the session would never reach —
    /// with no wait to avoid, it saved nothing and was a second way of saying
    /// what an immediate `unavailable` already says.
    async fn session_or_unavailable(
        &self,
        sandbox_id: &str,
    ) -> Result<mpsc::Sender<GatewayMessage>, Status> {
        if let Some(tx) = self.lookup_session(sandbox_id) {
            return Ok(tx);
        }

        // A liveness row may name a replica that had this session. It is a
        // hint that biases the caller's next attempt, never a claim this
        // replica can stand behind — the dispatch there is what tests it.
        if let Some(status) = self.serving_replica_redirect_status(sandbox_id).await {
            return Err(status);
        }

        Err(Status::unavailable("supervisor session not connected"))
    }

    /// Build a redirect status when a *different* live replica owns this
    /// sandbox's supervisor session.
    ///
    /// The address travels as `x-openshell-serving-replica` response
    /// metadata on an otherwise ordinary `unavailable` status, and is repeated
    /// in the message text for logs. This is deliberately a hint and not a
    /// contract: a client that ignores the metadata sees exactly the
    /// single-replica behavior it saw before, which is what keeps the change
    /// compatible with upstream clients.
    ///
    /// Returns `None` — leaving today's wait-then-`unavailable` path intact —
    /// when liveness tracking is off, when there is no live record, when the
    /// record is ours (the session may still be connecting), or when the
    /// recorded address is empty or our own.
    async fn serving_replica_redirect_status(&self, sandbox_id: &str) -> Option<Status> {
        let liveness = self.liveness.as_ref()?;

        let record = match liveness.lookup(sandbox_id).await {
            Ok(record) => record?,
            Err(err) => {
                // A store hiccup must not change how a request is answered.
                warn!(
                    sandbox_id = %sandbox_id,
                    error = %err,
                    "supervisor session: liveness lookup failed — falling back to waiting"
                );
                return None;
            }
        };

        if record.replica_id == liveness.replica_id() {
            return None;
        }
        let address = record.advertise_address.trim();
        if address.is_empty() || address == liveness.advertise_address() {
            return None;
        }

        let Ok(header) = address.parse::<MetadataValue<Ascii>>() else {
            warn!(
                sandbox_id = %sandbox_id,
                serving_replica = %record.replica_id,
                serving_address = %address,
                "supervisor session: serving address is not valid header text — falling back to waiting"
            );
            return None;
        };

        info!(
            sandbox_id = %sandbox_id,
            serving_replica = %record.replica_id,
            serving_address = %address,
            "supervisor session: owned by another replica — returning redirect hint"
        );
        let mut metadata = MetadataMap::new();
        metadata.insert(SERVING_REPLICA_METADATA_KEY, header);
        Some(Status::with_metadata(
            tonic::Code::Unavailable,
            format!("supervisor session not connected on this gateway replica; owned by {address}"),
            metadata,
        ))
    }

    /// True if *any* replica holds a supervisor session for this sandbox.
    ///
    /// Sandbox readiness is a fact about the fleet, not about this process.
    /// Deriving it from the local session map was sound only while one replica
    /// held every session: with more than one, a replica that never had the
    /// session would answer "no" and reconcile a healthy sandbox back to
    /// `Provisioning`. The liveness records already carry the answer — a
    /// record exists and is renewed for exactly as long as some replica holds
    /// the session.
    pub async fn session_connected_in_fleet(&self, sandbox_id: &str) -> bool {
        if self.has_session(sandbox_id) {
            return true;
        }
        let Some(liveness) = self.liveness.as_ref() else {
            return false;
        };
        match liveness.lookup(sandbox_id).await {
            Ok(record) => record.is_some(),
            Err(err) => {
                // Fall back to the local answer. Reporting "not connected"
                // because the store hiccuped would regress a healthy
                // sandbox's phase, which is the failure this method exists to
                // prevent.
                warn!(
                    sandbox_id = %sandbox_id,
                    error = %err,
                    "supervisor session: fleet-wide session lookup failed; using the local session map"
                );
                false
            }
        }
    }

    fn lookup_session(&self, sandbox_id: &str) -> Option<mpsc::Sender<GatewayMessage>> {
        self.sessions
            .lock()
            .unwrap()
            .get(sandbox_id)
            .map(|s| s.tx.clone())
    }

    pub fn has_session(&self, sandbox_id: &str) -> bool {
        self.sessions.lock().unwrap().contains_key(sandbox_id)
    }

    pub fn terminal_delivery_finalized(&self, sandbox_id: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .get(sandbox_id)
            .is_some_and(|session| session.terminal_delivery_finalized)
    }

    pub fn finalize_main_process_exit(&self, sandbox_id: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions.get_mut(sandbox_id) else {
            return false;
        };
        session.terminal_delivery_finalized = true;
        true
    }

    pub fn is_current_session(&self, sandbox_id: &str, session_id: &str) -> bool {
        self.sessions
            .lock()
            .unwrap()
            .get(sandbox_id)
            .is_some_and(|session| session.session_id == session_id)
    }

    fn pending_channel_ids(&self, sandbox_id: &str) -> Vec<String> {
        self.pending_relays
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, pending)| pending.sandbox_id == sandbox_id)
            .map(|(channel_id, _)| channel_id.clone())
            .collect()
    }

    /// Open a relay channel and return a receiver for the supervisor-side
    /// stream.
    ///
    /// Sends `RelayOpen` over the supervisor's gRPC session and returns a
    /// oneshot receiver that resolves once the supervisor opens its reverse
    /// HTTP CONNECT to `/relay/{channel_id}`.
    ///
    /// If the session is not registered here, this fails immediately with
    /// `unavailable`. A session may be absent for several reasons — a startup
    /// race before the supervisor's `ConnectSupervisor` handshake completes, a
    /// transient disconnect mid-reconnect, or a session that is live on a
    /// different replica — and none of them are distinguishable from this
    /// process, which is why it states what it knows instead of waiting to see
    /// whether one of them resolves.
    ///
    /// The caller owns the patience. It decides how long to keep trying, which
    /// replica to ask next, and when to re-resolve membership so the next
    /// attempt works from a fresher view — none of which a timeout passed down
    /// here could express.
    pub async fn open_relay(
        &self,
        sandbox_id: &str,
    ) -> Result<
        (
            String,
            oneshot::Receiver<Result<tokio::io::DuplexStream, Status>>,
        ),
        Status,
    > {
        self.open_relay_with_target(
            sandbox_id,
            relay_open::Target::Ssh(SshRelayTarget {}),
            String::new(),
        )
        .await
    }

    pub async fn open_relay_with_target(
        &self,
        sandbox_id: &str,
        target: relay_open::Target,
        service_id: String,
    ) -> Result<
        (
            String,
            oneshot::Receiver<Result<tokio::io::DuplexStream, Status>>,
        ),
        Status,
    > {
        let tx = self.session_or_unavailable(sandbox_id).await?;

        let channel_id = Uuid::new_v4().to_string();
        let relay_open = RelayOpen {
            channel_id: channel_id.clone(),
            target: Some(target),
            service_id,
        };

        // Register the pending relay before sending RelayOpen to avoid a race.
        // Both caps are checked and the insert happens under a single lock hold
        // so two concurrent calls can't both observe "under the cap" and then
        // both insert past it.
        let (relay_tx, relay_rx) = oneshot::channel();
        {
            let mut pending = self.pending_relays.lock().unwrap();
            if pending.len() >= MAX_PENDING_RELAYS {
                return Err(Status::resource_exhausted(format!(
                    "gateway relay capacity reached ({MAX_PENDING_RELAYS} in flight)"
                )));
            }
            let per_sandbox = pending
                .values()
                .filter(|p| p.sandbox_id == sandbox_id)
                .count();
            if per_sandbox >= MAX_PENDING_RELAYS_PER_SANDBOX {
                return Err(Status::resource_exhausted(format!(
                    "per-sandbox relay limit reached ({MAX_PENDING_RELAYS_PER_SANDBOX} in flight for {sandbox_id})"
                )));
            }
            pending.insert(
                channel_id.clone(),
                PendingRelay {
                    sender: relay_tx,
                    sandbox_id: sandbox_id.to_string(),
                    relay_open: relay_open.clone(),
                    created_at: Instant::now(),
                },
            );
        }

        let msg = GatewayMessage {
            payload: Some(gateway_message::Payload::RelayOpen(relay_open)),
        };

        if tx.send(msg).await.is_err() {
            // Session dropped between our lookup and send.
            self.pending_relays.lock().unwrap().remove(&channel_id);
            return Err(Status::unavailable("supervisor session disconnected"));
        }

        Ok((channel_id, relay_rx))
    }

    pub fn fail_pending_relay(&self, channel_id: &str, error: String) -> bool {
        let pending = self.pending_relays.lock().unwrap().remove(channel_id);
        if let Some(pending) = pending {
            let _ = pending.sender.send(Err(Status::unavailable(error)));
            true
        } else {
            false
        }
    }

    /// Claim a pending relay channel. Called by the `/relay/{channel_id}` HTTP handler
    /// when the supervisor's reverse CONNECT arrives.
    ///
    /// Returns the `DuplexStream` half that the supervisor side should read/write.
    // `tonic::Status` is large but is the API surface of gRPC handlers.
    #[allow(clippy::result_large_err)]
    pub fn claim_relay(
        &self,
        channel_id: &str,
        principal: Option<&Principal>,
    ) -> Result<ClaimedRelay, Status> {
        let pending = {
            let mut map = self.pending_relays.lock().unwrap();
            let pending = map
                .get(channel_id)
                .ok_or_else(|| Status::not_found("unknown or expired relay channel"))?;

            if let Some(principal) = principal
                && let Err(status) = crate::auth::guard::ensure_sandbox_principal_scope(
                    principal,
                    &pending.sandbox_id,
                )
            {
                info!(
                    channel_id = %channel_id,
                    sandbox_id = %pending.sandbox_id,
                    "relay stream: rejecting cross-sandbox claim"
                );
                return Err(status);
            }

            if pending.created_at.elapsed() > RELAY_PENDING_TIMEOUT {
                map.remove(channel_id);
                return Err(Status::deadline_exceeded("relay channel timed out"));
            }

            map.remove(channel_id)
                .expect("pending relay existed before removal")
        };

        // Create a duplex stream pair: one end for the gateway bridge, one for
        // the supervisor HTTP CONNECT handler.
        let (gateway_stream, supervisor_stream) = tokio::io::duplex(64 * 1024);

        // Send the gateway-side stream to the waiter (exec handler or forward handler).
        if pending.sender.send(Ok(gateway_stream)).is_err() {
            return Err(Status::internal("relay requester dropped"));
        }

        Ok(ClaimedRelay {
            stream: supervisor_stream,
            sandbox_id: pending.sandbox_id,
        })
    }

    /// Remove all pending relays that have exceeded the timeout.
    pub fn reap_expired_relays(&self) {
        let mut map = self.pending_relays.lock().unwrap();
        map.retain(|_, pending| pending.created_at.elapsed() <= RELAY_PENDING_TIMEOUT);
    }

    /// Clean up all state for a sandbox (session + pending relays).
    pub fn cleanup_sandbox(&self, sandbox_id: &str) {
        if let Some(session_id) = self.remove(sandbox_id) {
            self.withdraw_liveness_detached(sandbox_id.to_string(), session_id);
        }
    }

    pub async fn replay_pending_relays(&self, sandbox_id: &str, tx: &mpsc::Sender<GatewayMessage>) {
        for channel_id in self.pending_channel_ids(sandbox_id) {
            let relay_open = {
                let pending = self.pending_relays.lock().unwrap();
                pending
                    .get(&channel_id)
                    .map(|pending| pending.relay_open.clone())
            };
            let Some(relay_open) = relay_open else {
                continue;
            };
            let msg = GatewayMessage {
                payload: Some(gateway_message::Payload::RelayOpen(relay_open)),
            };
            if tx.send(msg).await.is_err() {
                warn!(sandbox_id = %sandbox_id, channel_id = %channel_id, "supervisor session: failed to replay pending relay to superseding session");
                break;
            }
        }
    }
}

async fn withdraw_liveness_record(liveness: &SessionLiveness, sandbox_id: &str, session_id: &str) {
    match liveness.withdraw(sandbox_id, session_id).await {
        Ok(true) => debug!(
            sandbox_id = %sandbox_id,
            session_id = %session_id,
            "supervisor session: liveness released"
        ),
        Ok(false) => debug!(
            sandbox_id = %sandbox_id,
            session_id = %session_id,
            "supervisor session: liveness record not ours to release"
        ),
        Err(err) => warn!(
            sandbox_id = %sandbox_id,
            session_id = %session_id,
            error = %err,
            "supervisor session: liveness release failed — record expires on its own"
        ),
    }
}

/// Handle to the background task that keeps a session's liveness record
/// fresh. Dropping it stops renewals, so the record ages out on its own if
/// the explicit release never runs.
#[derive(Debug)]
pub struct LivenessRenewal {
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for LivenessRenewal {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Spawn a background task that periodically reaps expired pending relay
/// entries.
///
/// Pending entries are normally consumed either when the supervisor opens its
/// reverse CONNECT (via `claim_relay`) or by the gateway-side waiter timing
/// out. If neither happens — e.g., the supervisor crashed after acknowledging
/// `RelayOpen` but before initiating `RelayStream` — the entry would otherwise
/// sit in the map indefinitely. This sweeper bounds that leak.
pub fn spawn_relay_reaper(state: Arc<ServerState>, interval: Duration) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            state.supervisor_sessions.reap_expired_relays();
        }
    });
}

async fn require_persisted_sandbox(
    store: &Arc<crate::persistence::Store>,
    sandbox_id: &str,
) -> Result<(), Status> {
    let sandbox = store
        .get_message::<Sandbox>(sandbox_id)
        .await
        .map_err(|err| Status::internal(format!("failed to load sandbox: {err}")))?;

    if sandbox.is_none() {
        return Err(Status::not_found("sandbox not found"));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// RelayStream gRPC handler
// ---------------------------------------------------------------------------

/// Size of chunks read from the gateway-side `DuplexStream` when forwarding
/// bytes back to the supervisor over the gRPC response stream.
const RELAY_STREAM_CHUNK_SIZE: usize = 16 * 1024;

type RelayStreamResponse = Response<
    Pin<Box<dyn tokio_stream::Stream<Item = Result<RelayFrame, Status>> + Send + 'static>>,
>;

/// Handle a `RelayStream` RPC from a supervisor.
///
/// The first inbound `RelayFrame` must carry a `RelayInit` identifying the
/// pending relay; subsequent frames carry raw bytes forward to the
/// gateway-side waiter. Bytes flowing the other way are chunked and sent as
/// `RelayFrame::data` messages back over the response stream.
pub async fn handle_relay_stream(
    registry: &SupervisorSessionRegistry,
    request: Request<tonic::Streaming<RelayFrame>>,
) -> Result<RelayStreamResponse, Status> {
    handle_relay_stream_inner(registry, None, request).await
}

pub async fn handle_relay_stream_for_state(
    state: &Arc<ServerState>,
    request: Request<tonic::Streaming<RelayFrame>>,
) -> Result<RelayStreamResponse, Status> {
    handle_relay_stream_inner(&state.supervisor_sessions, Some(Arc::clone(state)), request).await
}

async fn handle_relay_stream_inner(
    registry: &SupervisorSessionRegistry,
    state: Option<Arc<ServerState>>,
    request: Request<tonic::Streaming<RelayFrame>>,
) -> Result<RelayStreamResponse, Status> {
    let principal = request.extensions().get::<Principal>().cloned();
    let mut inbound = request.into_inner();

    // First frame must identify the channel.
    let first = inbound
        .message()
        .await?
        .ok_or_else(|| Status::invalid_argument("empty RelayStream"))?;
    let channel_id = match first.payload {
        Some(openshell_core::proto::relay_frame::Payload::Init(RelayInit { channel_id }))
            if !channel_id.is_empty() =>
        {
            channel_id
        }
        _ => {
            return Err(Status::invalid_argument(
                "first RelayFrame must be init with non-empty channel_id",
            ));
        }
    };

    // Claim the pending relay. Consumes the entry — it cannot be reused.
    let claimed = registry.claim_relay(&channel_id, principal.as_ref())?;
    let sandbox_id = claimed.sandbox_id;
    let supervisor_side = claimed.stream;
    info!(channel_id = %channel_id, sandbox_id = %sandbox_id, "relay stream: claimed pending relay, bridging");

    let (mut read_half, mut write_half) = tokio::io::split(supervisor_side);

    // Supervisor → gateway: drain `inbound` and write to the DuplexStream.
    let channel_id_in = channel_id.clone();
    let sandbox_id_in = sandbox_id;
    let state_in = state.clone();
    tokio::spawn(async move {
        loop {
            match inbound.message().await {
                Ok(Some(frame)) => {
                    let Some(openshell_core::proto::relay_frame::Payload::Data(data)) =
                        frame.payload
                    else {
                        warn!(channel_id = %channel_id_in, "relay stream: received non-data frame after init");
                        break;
                    };
                    if data.is_empty() {
                        continue;
                    }
                    if let Err(e) =
                        tokio::io::AsyncWriteExt::write_all(&mut write_half, &data).await
                    {
                        warn!(channel_id = %channel_id_in, error = %e, "relay stream: write to duplex failed");
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    if let Some(state) = state_in.as_ref()
                        && expected_transport_close_during_sandbox_teardown(
                            state,
                            &sandbox_id_in,
                            &e,
                        )
                        .await
                    {
                        info!(
                            sandbox_id = %sandbox_id_in,
                            channel_id = %channel_id_in,
                            error = %e,
                            "relay stream: expected transport close during sandbox teardown"
                        );
                    } else {
                        warn!(sandbox_id = %sandbox_id_in, channel_id = %channel_id_in, error = %e, "relay stream: inbound errored");
                    }
                    break;
                }
            }
        }
        // Best-effort half-close on the write side so the reader sees EOF.
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut write_half).await;
    });

    // Gateway → supervisor: read the DuplexStream and emit RelayFrame::data messages.
    let (out_tx, out_rx) = mpsc::channel::<Result<RelayFrame, Status>>(16);
    let channel_id_out = channel_id;
    tokio::spawn(async move {
        let mut buf = vec![0u8; RELAY_STREAM_CHUNK_SIZE];
        loop {
            match tokio::io::AsyncReadExt::read(&mut read_half, &mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = RelayFrame {
                        payload: Some(openshell_core::proto::relay_frame::Payload::Data(
                            buf[..n].to_vec(),
                        )),
                    };
                    if out_tx.send(Ok(chunk)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!(channel_id = %channel_id_out, error = %e, "relay stream: read from duplex failed");
                    break;
                }
            }
        }
    });

    let stream = ReceiverStream::new(out_rx);
    let stream: Pin<
        Box<dyn tokio_stream::Stream<Item = Result<RelayFrame, Status>> + Send + 'static>,
    > = Box::pin(stream);
    Ok(Response::new(stream))
}

fn expected_transport_close_during_shutdown(status: &Status, terminating: bool) -> bool {
    terminating && is_expected_transport_close_status(status)
}

fn sandbox_proto_is_terminating(sandbox: &Sandbox) -> bool {
    SandboxPhase::try_from(sandbox.phase()).ok() == Some(SandboxPhase::Deleting)
        || sandbox
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.deletion_timestamp_ms != 0)
}

async fn sandbox_is_terminating_or_gone(state: &Arc<ServerState>, sandbox_id: &str) -> bool {
    match state.store.get_message::<Sandbox>(sandbox_id).await {
        Ok(Some(sandbox)) => sandbox_proto_is_terminating(&sandbox),
        Ok(None) => true,
        Err(err) => {
            debug!(
                sandbox_id,
                error = %err,
                "failed to inspect sandbox state while classifying transport close"
            );
            false
        }
    }
}

async fn expected_transport_close_during_sandbox_teardown(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    status: &Status,
) -> bool {
    expected_transport_close_during_shutdown(
        status,
        sandbox_is_terminating_or_gone(state, sandbox_id).await,
    )
}

async fn expected_transport_close_during_session_teardown(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    status: &Status,
) -> bool {
    let session_no_longer_current = !state
        .supervisor_sessions
        .is_current_session(sandbox_id, session_id);
    expected_transport_close_during_session_state(
        status,
        state.gateway_shutting_down.load(Ordering::Acquire),
        session_no_longer_current,
        sandbox_is_terminating_or_gone(state, sandbox_id).await,
    )
}

fn expected_transport_close_during_session_state(
    status: &Status,
    gateway_shutting_down: bool,
    session_no_longer_current: bool,
    sandbox_terminating_or_gone: bool,
) -> bool {
    expected_transport_close_during_shutdown(
        status,
        gateway_shutting_down || session_no_longer_current || sandbox_terminating_or_gone,
    )
}

// ---------------------------------------------------------------------------
// ConnectSupervisor gRPC handler
// ---------------------------------------------------------------------------

pub async fn handle_connect_supervisor(
    state: &Arc<ServerState>,
    request: Request<tonic::Streaming<SupervisorMessage>>,
) -> Result<
    Response<
        Pin<Box<dyn tokio_stream::Stream<Item = Result<GatewayMessage, Status>> + Send + 'static>>,
    >,
    Status,
> {
    let principal = request.extensions().get::<Principal>().cloned();
    let mut inbound = request.into_inner();

    // Step 1: Wait for SupervisorHello.
    let hello = match inbound.message().await? {
        Some(msg) => match msg.payload {
            Some(supervisor_message::Payload::Hello(hello)) => hello,
            _ => return Err(Status::invalid_argument("expected SupervisorHello")),
        },
        None => return Err(Status::invalid_argument("stream closed before hello")),
    };

    let sandbox_id = hello.sandbox_id.clone();
    if sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }
    if let Some(principal) = principal.as_ref() {
        crate::auth::guard::ensure_sandbox_principal_scope(principal, &sandbox_id)?;
    }
    require_persisted_sandbox(&state.store, &sandbox_id).await?;

    let session_id = Uuid::new_v4().to_string();
    info!(
        sandbox_id = %sandbox_id,
        session_id = %session_id,
        instance_id = %hello.instance_id,
        "supervisor session: accepted"
    );

    // Step 2: Create and register the outbound channel.
    let (tx, rx) = mpsc::channel::<GatewayMessage>(64);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let superseded = state.supervisor_sessions.register(
        sandbox_id.clone(),
        session_id.clone(),
        tx.clone(),
        shutdown_tx,
    );
    if superseded {
        info!(
            sandbox_id = %sandbox_id,
            session_id = %session_id,
            "supervisor session: superseded previous session"
        );
    }

    // Publish this replica as the session's owner and keep the claim fresh for
    // the life of the session. Failures are logged inside the task and never
    // block the handshake.
    let phase_keeper = Arc::clone(state);
    let liveness_renewal = state.supervisor_sessions.spawn_liveness_record(
        sandbox_id.clone(),
        session_id.clone(),
        move |sandbox_id| {
            let state = Arc::clone(&phase_keeper);
            async move {
                if let Err(err) = state
                    .compute
                    .supervisor_session_still_ready(&sandbox_id)
                    .await
                {
                    debug!(
                        sandbox_id = %sandbox_id,
                        error = %err,
                        "supervisor session: could not re-assert Ready while the session is live"
                    );
                }
            }
        },
    );

    // Step 3: Send SessionAccepted.
    let accepted = GatewayMessage {
        payload: Some(gateway_message::Payload::SessionAccepted(SessionAccepted {
            session_id: session_id.clone(),
            heartbeat_interval_secs: HEARTBEAT_INTERVAL_SECS,
        })),
    };
    if tx.send(accepted).await.is_err() {
        // Only evict ourselves — a faster reconnect may already have
        // superseded this registration.
        state
            .supervisor_sessions
            .remove_if_current(&sandbox_id, &session_id);
        drop(liveness_renewal);
        state
            .supervisor_sessions
            .withdraw_liveness(&sandbox_id, &session_id)
            .await;
        return Err(Status::internal("failed to send session accepted"));
    }

    if superseded {
        state
            .supervisor_sessions
            .replay_pending_relays(&sandbox_id, &tx)
            .await;
    }

    if let Err(err) = state
        .compute
        .supervisor_session_connected(&sandbox_id, &hello.instance_id)
        .await
    {
        warn!(
            sandbox_id = %sandbox_id,
            session_id = %session_id,
            error = %err,
            "supervisor session: failed to mark sandbox ready"
        );
    } else {
        state.telemetry.sandbox_session_connected(&sandbox_id);
    }

    // Step 4: Spawn the session loop that reads inbound messages.
    let state_clone = Arc::clone(state);
    let sandbox_id_clone = sandbox_id.clone();
    tokio::spawn(async move {
        let liveness_renewal = liveness_renewal;
        run_session_loop(
            &state_clone,
            &sandbox_id_clone,
            &session_id,
            &tx,
            &mut inbound,
            shutdown_rx,
        )
        .await;
        // Stop renewing before releasing so the release can't race a renewal
        // and leave a resurrected record behind.
        drop(liveness_renewal);
        state_clone
            .supervisor_sessions
            .withdraw_liveness(&sandbox_id_clone, &session_id)
            .await;
        let terminal_finalized = state_clone
            .supervisor_sessions
            .remove_if_current(&sandbox_id_clone, &session_id);
        if let Some(terminal_finalized) = terminal_finalized {
            info!(sandbox_id = %sandbox_id_clone, session_id = %session_id, "supervisor session: ended");
            state_clone
                .telemetry
                .sandbox_session_disconnected(&sandbox_id_clone);
            // Asked after the release above, so this replica's own record is
            // already gone and a hit names a peer still serving the sandbox.
            let peers = state_clone
                .supervisor_sessions
                .sandbox_peer_sessions(&sandbox_id_clone)
                .await;
            if let Err(err) = state_clone
                .compute
                .supervisor_session_disconnected(&sandbox_id_clone, terminal_finalized, peers)
                .await
            {
                warn!(
                    sandbox_id = %sandbox_id_clone,
                    session_id = %session_id,
                    error = %err,
                    "supervisor session: failed to mark sandbox disconnected"
                );
            }
        } else {
            info!(sandbox_id = %sandbox_id_clone, session_id = %session_id, "supervisor session: ended (already superseded)");
        }
    });

    // Return the outbound stream.
    let stream = ReceiverStream::new(rx);
    let stream: Pin<
        Box<dyn tokio_stream::Stream<Item = Result<GatewayMessage, Status>> + Send + 'static>,
    > = Box::pin(tokio_stream::StreamExt::map(stream, Ok));

    Ok(Response::new(stream))
}

pub async fn handle_report_main_process_exit(
    state: &Arc<ServerState>,
    request: Request<ReportMainProcessExitRequest>,
) -> Result<Response<ReportMainProcessExitResponse>, Status> {
    let principal = request.extensions().get::<Principal>().cloned();
    let report = request.into_inner();
    if report.sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }
    if report.instance_id.is_empty() {
        return Err(Status::invalid_argument("instance_id is required"));
    }
    if let Some(principal) = principal.as_ref() {
        crate::auth::guard::ensure_sandbox_principal_scope(principal, &report.sandbox_id)?;
    }
    state
        .compute
        .report_main_process_exit(&report.sandbox_id, &report.instance_id, report.exit_code)
        .await
        .map_err(Status::failed_precondition)?;
    Ok(Response::new(ReportMainProcessExitResponse {}))
}

pub async fn handle_finalize_main_process_exit(
    state: &Arc<ServerState>,
    request: Request<openshell_core::proto::FinalizeMainProcessExitRequest>,
) -> Result<Response<openshell_core::proto::FinalizeMainProcessExitResponse>, Status> {
    let principal = request.extensions().get::<Principal>().cloned();
    let report = request.into_inner();
    if report.sandbox_id.is_empty() {
        return Err(Status::invalid_argument("sandbox_id is required"));
    }
    if report.instance_id.is_empty() {
        return Err(Status::invalid_argument("instance_id is required"));
    }
    if let Some(principal) = principal.as_ref() {
        crate::auth::guard::ensure_sandbox_principal_scope(principal, &report.sandbox_id)?;
    }
    state
        .compute
        .finalize_main_process_exit(&report.sandbox_id, &report.instance_id)
        .await
        .map_err(Status::failed_precondition)?;
    if !state
        .supervisor_sessions
        .finalize_main_process_exit(&report.sandbox_id)
    {
        return Err(Status::failed_precondition(
            "supervisor session is not connected",
        ));
    }
    Ok(Response::new(
        openshell_core::proto::FinalizeMainProcessExitResponse {},
    ))
}

async fn run_session_loop(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    tx: &mpsc::Sender<GatewayMessage>,
    inbound: &mut tonic::Streaming<SupervisorMessage>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let heartbeat_interval = Duration::from_secs(u64::from(HEARTBEAT_INTERVAL_SECS));
    let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);
    // Skip the first immediate tick.
    heartbeat_timer.tick().await;

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                info!(sandbox_id = %sandbox_id, session_id = %session_id, "supervisor session: superseded by reconnect, shutting down");
                break;
            }
            msg = inbound.message() => {
                match msg {
                    Ok(Some(msg)) => {
                        handle_supervisor_message(state, sandbox_id, session_id, msg);
                    }
                    Ok(None) => {
                        info!(sandbox_id = %sandbox_id, session_id = %session_id, "supervisor session: stream closed by supervisor");
                        break;
                    }
                    Err(e) => {
                        if expected_transport_close_during_session_teardown(
                            state,
                            sandbox_id,
                            session_id,
                            &e,
                        )
                        .await
                        {
                            info!(
                                sandbox_id = %sandbox_id,
                                session_id = %session_id,
                                error = %e,
                                "supervisor session: expected transport close during teardown"
                            );
                        } else {
                            warn!(sandbox_id = %sandbox_id, session_id = %session_id, error = %e, "supervisor session: stream error");
                        }
                        break;
                    }
                }
            }
            _ = heartbeat_timer.tick() => {
                let hb = GatewayMessage {
                    payload: Some(gateway_message::Payload::Heartbeat(
                        openshell_core::proto::GatewayHeartbeat {},
                    )),
                };
                if tx.send(hb).await.is_err() {
                    info!(sandbox_id = %sandbox_id, session_id = %session_id, "supervisor session: outbound channel closed");
                    break;
                }
            }
        }
    }
}

fn handle_supervisor_message(
    state: &Arc<ServerState>,
    sandbox_id: &str,
    session_id: &str,
    msg: SupervisorMessage,
) {
    match msg.payload {
        Some(supervisor_message::Payload::Heartbeat(_)) => {
            // Heartbeat received — nothing to do for now.
        }
        Some(supervisor_message::Payload::RelayOpenResult(result)) => {
            if result.success {
                info!(
                    sandbox_id = %sandbox_id,
                    session_id = %session_id,
                    channel_id = %result.channel_id,
                    "supervisor session: relay opened successfully"
                );
            } else {
                let failed = state
                    .supervisor_sessions
                    .fail_pending_relay(&result.channel_id, result.error.clone());
                warn!(
                    sandbox_id = %sandbox_id,
                    session_id = %session_id,
                    channel_id = %result.channel_id,
                    error = %result.error,
                    pending_relay_failed = failed,
                    "supervisor session: relay open failed"
                );
            }
        }
        Some(supervisor_message::Payload::RelayClose(close)) => {
            info!(
                sandbox_id = %sandbox_id,
                session_id = %session_id,
                channel_id = %close.channel_id,
                reason = %close.reason,
                "supervisor session: relay closed by supervisor"
            );
        }
        _ => {
            warn!(
                sandbox_id = %sandbox_id,
                session_id = %session_id,
                "supervisor session: unexpected message type"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::{Identity, IdentityProvider};
    use crate::auth::principal::{SandboxIdentitySource, SandboxPrincipal, UserPrincipal};
    use crate::persistence::Store;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn test_store() -> Arc<Store> {
        Arc::new(crate::persistence::test_store().await)
    }

    /// A store already holding the `sandbox` rows a test claims liveness for,
    /// matching what the compute layer writes in production. `objects.id` is
    /// globally unique, so fixtures without these rows cannot catch an
    /// liveness key that collides with a sandbox's own row.
    async fn store_with_sandboxes(sandbox_ids: &[&str]) -> Arc<Store> {
        let store = test_store().await;
        for sandbox_id in sandbox_ids {
            store
                .put_message(&sandbox_record(sandbox_id, sandbox_id))
                .await
                .expect("sandbox object row should persist");
        }
        store
    }

    fn liveness(store: &Arc<Store>, replica_id: &str, address: &str) -> Arc<SessionLiveness> {
        Arc::new(SessionLiveness::new(
            Arc::clone(store),
            replica_id.to_string(),
            address.to_string(),
            crate::session_liveness::LIVENESS_TTL,
        ))
    }

    fn redirect_hint(status: &Status) -> Option<String> {
        status
            .metadata()
            .get(SERVING_REPLICA_METADATA_KEY)
            .map(|value| value.to_str().unwrap().to_string())
    }

    /// Returns a shutdown sender with its receiver immediately dropped. Tests
    /// that don't observe the shutdown signal can use this to satisfy the
    /// `register` signature without the receiver noise.
    fn make_shutdown() -> oneshot::Sender<()> {
        oneshot::channel::<()>().0
    }

    fn sandbox_record(id: &str, name: &str) -> Sandbox {
        Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: id.to_string(),
                name: name.to_string(),
                created_at_ms: 1_000_000,
                labels: HashMap::new(),
                resource_version: 0,
                annotations: HashMap::new(),
                workspace: "default".to_string(),
                deletion_timestamp_ms: 0,
            }),
            ..Default::default()
        }
    }

    fn pending_relay(
        sandbox_id: &str,
        relay_tx: RelayStreamSender,
        created_at: Instant,
    ) -> PendingRelay {
        PendingRelay {
            sender: relay_tx,
            sandbox_id: sandbox_id.to_string(),
            relay_open: RelayOpen {
                channel_id: "ch-test".to_string(),
                target: Some(relay_open::Target::Ssh(SshRelayTarget {})),
                service_id: String::new(),
            },
            created_at,
        }
    }

    fn sandbox_principal(sandbox_id: &str) -> Principal {
        Principal::Sandbox(SandboxPrincipal {
            sandbox_id: sandbox_id.to_string(),
            source: SandboxIdentitySource::BootstrapJwt {
                issuer: "openshell-gateway:test".to_string(),
            },
            trust_domain: Some("openshell".to_string()),
        })
    }

    fn user_principal(subject: &str) -> Principal {
        Principal::User(UserPrincipal {
            identity: Identity {
                subject: subject.to_string(),
                display_name: None,
                roles: vec![],
                scopes: vec![],
                provider: IdentityProvider::Oidc,
            },
        })
    }

    // ---- registry: register / remove ----

    #[test]
    fn registry_register_and_lookup() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);

        assert!(!registry.register(
            "sandbox-1".to_string(),
            "s1".to_string(),
            tx,
            make_shutdown(),
        ));

        let sessions = registry.sessions.lock().unwrap();
        assert!(sessions.contains_key("sandbox-1"));
    }

    #[test]
    fn registry_supersedes_previous_session() {
        let registry = SupervisorSessionRegistry::new();
        let (tx1, _rx1) = mpsc::channel(1);
        let (tx2, _rx2) = mpsc::channel(1);

        assert!(!registry.register(
            "sandbox-1".to_string(),
            "s1".to_string(),
            tx1,
            make_shutdown(),
        ));
        assert!(registry.register(
            "sandbox-1".to_string(),
            "s2".to_string(),
            tx2,
            make_shutdown(),
        ));
    }

    #[test]
    fn registry_remove() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);
        registry.register(
            "sandbox-1".to_string(),
            "s1".to_string(),
            tx,
            make_shutdown(),
        );

        registry.remove("sandbox-1");
        let sessions = registry.sessions.lock().unwrap();
        assert!(!sessions.contains_key("sandbox-1"));
    }

    #[test]
    fn remove_if_current_removes_matching_session() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);
        registry.register("sbx".to_string(), "s1".to_string(), tx, make_shutdown());

        assert_eq!(registry.remove_if_current("sbx", "s1"), Some(false));
        assert!(!registry.sessions.lock().unwrap().contains_key("sbx"));
    }

    #[test]
    fn remove_if_current_ignores_stale_session_id() {
        let registry = SupervisorSessionRegistry::new();
        let (tx_old, _rx_old) = mpsc::channel(1);
        let (tx_new, _rx_new) = mpsc::channel(1);

        // Old session registers, then is superseded by a new session.
        registry.register(
            "sbx".to_string(),
            "s-old".to_string(),
            tx_old,
            make_shutdown(),
        );
        registry.register(
            "sbx".to_string(),
            "s-new".to_string(),
            tx_new,
            make_shutdown(),
        );

        // Cleanup from the old session task runs late. It must NOT evict the
        // newly registered session.
        assert_eq!(registry.remove_if_current("sbx", "s-old"), None);
        let sessions = registry.sessions.lock().unwrap();
        assert!(
            sessions.contains_key("sbx"),
            "new session must still be registered"
        );
        assert_eq!(sessions.get("sbx").unwrap().session_id, "s-new");
    }

    #[test]
    fn remove_if_current_unknown_sandbox_is_noop() {
        let registry = SupervisorSessionRegistry::new();
        assert_eq!(registry.remove_if_current("sbx-does-not-exist", "s1"), None);
    }

    #[test]
    fn remove_if_current_returns_terminal_finalization_state() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);
        registry.register("sbx".to_string(), "s1".to_string(), tx, make_shutdown());

        assert!(registry.finalize_main_process_exit("sbx"));
        assert!(registry.terminal_delivery_finalized("sbx"));
        assert_eq!(registry.remove_if_current("sbx", "s1"), Some(true));
    }

    // ---- open_relay: happy path and wait semantics ----

    #[tokio::test]
    async fn open_relay_sends_relay_open_to_registered_session() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, mut rx) = mpsc::channel(4);
        registry.register("sbx".to_string(), "s1".to_string(), tx, make_shutdown());

        let (channel_id, _relay_rx) = registry
            .open_relay("sbx")
            .await
            .expect("open_relay should succeed when session is live");

        let msg = rx.recv().await.expect("relay open should be delivered");
        match msg.payload {
            Some(gateway_message::Payload::RelayOpen(open)) => {
                assert_eq!(open.channel_id, channel_id);
                assert!(matches!(open.target, Some(relay_open::Target::Ssh(_))));
            }
            other => panic!("expected RelayOpen, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn open_relay_times_out_without_session() {
        let registry = SupervisorSessionRegistry::new();
        let err = registry
            .open_relay("missing")
            .await
            .expect_err("open_relay should time out");
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }

    /// A session arriving later does not rescue an in-flight call — the
    /// refusal is returned at once and it is the *caller's* next attempt that
    /// succeeds. This is the whole shape of the change: the gateway reports,
    /// the caller decides when to ask again.
    #[tokio::test]
    async fn a_session_arriving_later_is_found_by_the_next_attempt() {
        let registry = Arc::new(SupervisorSessionRegistry::new());

        let first = registry.open_relay("sbx").await;
        assert!(
            first.is_err(),
            "a call made before the session exists must be refused, not held"
        );

        let (tx, mut rx) = mpsc::channel::<GatewayMessage>(4);
        // Keep the receiver alive so the send in open_relay succeeds.
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        registry.register("sbx".to_string(), "s1".to_string(), tx, make_shutdown());

        let retried = registry.open_relay("sbx").await;
        assert!(
            retried.is_ok(),
            "the caller's retry must find the session: {retried:?}"
        );
    }

    #[tokio::test]
    async fn open_relay_fails_when_session_receiver_dropped() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, rx) = mpsc::channel::<GatewayMessage>(4);
        registry.register("sbx".to_string(), "s1".to_string(), tx, make_shutdown());

        // Simulate the supervisor's stream going away between lookup and send:
        // the receiver held by `ReceiverStream` is dropped.
        drop(rx);

        let err = registry
            .open_relay("sbx")
            .await
            .expect_err("open_relay should fail when mpsc is closed");
        assert_eq!(err.code(), tonic::Code::Unavailable);
        // The pending-relay entry must have been cleaned up on failure.
        assert!(registry.pending_relays.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn open_relay_rejects_when_global_cap_reached() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel::<GatewayMessage>(8);
        registry.register(
            "sbx-a".to_string(),
            "s-a".to_string(),
            tx.clone(),
            make_shutdown(),
        );
        registry.register("sbx-b".to_string(), "s-b".to_string(), tx, make_shutdown());

        // Pre-seed pending_relays to exactly the global cap, split across two
        // sandboxes so neither hits the per-sandbox cap first.
        {
            let mut pending = registry.pending_relays.lock().unwrap();
            for i in 0..MAX_PENDING_RELAYS {
                let (oneshot_tx, _) = oneshot::channel();
                let sandbox_id = if i % 2 == 0 { "sbx-a" } else { "sbx-b" };
                pending.insert(
                    format!("channel-{i}"),
                    pending_relay(sandbox_id, oneshot_tx, Instant::now()),
                );
            }
        }

        let err = registry
            .open_relay("sbx-a")
            .await
            .expect_err("open_relay should reject once global cap is reached");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert!(err.message().contains("gateway relay capacity"));
    }

    #[tokio::test]
    async fn open_relay_rejects_when_per_sandbox_cap_reached() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel::<GatewayMessage>(8);
        registry.register("sbx".to_string(), "s".to_string(), tx, make_shutdown());

        {
            let mut pending = registry.pending_relays.lock().unwrap();
            for i in 0..MAX_PENDING_RELAYS_PER_SANDBOX {
                let (oneshot_tx, _) = oneshot::channel();
                pending.insert(
                    format!("channel-{i}"),
                    pending_relay("sbx", oneshot_tx, Instant::now()),
                );
            }
        }

        let err = registry
            .open_relay("sbx")
            .await
            .expect_err("open_relay should reject when per-sandbox cap is reached");
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
        assert!(err.message().contains("per-sandbox relay limit"));

        // A different sandbox still has headroom.
        let (tx2, _rx2) = mpsc::channel::<GatewayMessage>(8);
        registry.register(
            "sbx-other".to_string(),
            "s-other".to_string(),
            tx2,
            make_shutdown(),
        );
        registry
            .open_relay("sbx-other")
            .await
            .expect("different sandbox should still accept new relays");
    }

    #[tokio::test]
    async fn open_relay_uses_newest_session_after_supersede() {
        use tokio::sync::mpsc::error::TryRecvError;

        let registry = SupervisorSessionRegistry::new();
        let (tx_old, mut rx_old) = mpsc::channel::<GatewayMessage>(4);
        let (tx_new, mut rx_new) = mpsc::channel(4);

        // Hold a clone of the old sender so supersede doesn't close the old
        // channel — that way try_recv distinguishes "no message sent" from
        // "channel closed".
        let _tx_old_alive = tx_old.clone();

        registry.register(
            "sbx".to_string(),
            "s-old".to_string(),
            tx_old,
            make_shutdown(),
        );
        registry.register(
            "sbx".to_string(),
            "s-new".to_string(),
            tx_new,
            make_shutdown(),
        );

        let (_channel_id, _relay_rx) = registry
            .open_relay("sbx")
            .await
            .expect("open_relay should succeed");

        let msg = rx_new
            .recv()
            .await
            .expect("new session should receive RelayOpen");
        assert!(matches!(
            msg.payload,
            Some(gateway_message::Payload::RelayOpen(_))
        ));

        // The old session must have received no messages — the channel is
        // still open but empty.
        match rx_old.try_recv() {
            Err(TryRecvError::Empty) => {}
            other => panic!("expected Empty on superseded session, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_signals_shutdown_to_previous_session() {
        let registry = SupervisorSessionRegistry::new();
        let (tx_old, _rx_old) = mpsc::channel::<GatewayMessage>(1);
        let (tx_new, _rx_new) = mpsc::channel::<GatewayMessage>(1);

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        registry.register("sbx".to_string(), "s-old".to_string(), tx_old, shutdown_tx);

        // Supersede with a new session — register must fire the old session's
        // shutdown signal so its task can exit and drop its tx clone.
        let superseded = registry.register(
            "sbx".to_string(),
            "s-new".to_string(),
            tx_new,
            make_shutdown(),
        );
        assert!(superseded, "second register should report supersede");

        // The old session's shutdown receiver must now resolve.
        shutdown_rx
            .await
            .expect("shutdown signal should arrive at superseded session");
    }

    #[tokio::test]
    async fn replay_pending_relays_reissues_open_to_superseding_session() {
        let registry = SupervisorSessionRegistry::new();
        let (tx_old, mut rx_old) = mpsc::channel::<GatewayMessage>(4);
        let (tx_new, mut rx_new) = mpsc::channel::<GatewayMessage>(4);

        registry.register(
            "sbx".to_string(),
            "s-old".to_string(),
            tx_old,
            make_shutdown(),
        );

        let (channel_id, _relay_rx) = registry
            .open_relay("sbx")
            .await
            .expect("open_relay should succeed");

        let original = rx_old
            .recv()
            .await
            .expect("old session should receive initial RelayOpen");
        assert!(matches!(
            original.payload,
            Some(gateway_message::Payload::RelayOpen(_))
        ));

        let superseded = registry.register(
            "sbx".to_string(),
            "s-new".to_string(),
            tx_new,
            make_shutdown(),
        );
        assert!(superseded);

        registry
            .replay_pending_relays("sbx", &registry.lookup_session("sbx").unwrap())
            .await;

        let replayed = rx_new
            .recv()
            .await
            .expect("new session should receive replayed RelayOpen");
        match replayed.payload {
            Some(gateway_message::Payload::RelayOpen(open)) => {
                assert_eq!(open.channel_id, channel_id);
            }
            other => panic!("expected RelayOpen on replay, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn require_persisted_sandbox_rejects_missing_sandbox() {
        let store = test_store().await;

        let err = require_persisted_sandbox(&store, "missing")
            .await
            .expect_err("missing sandbox should be rejected");

        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn require_persisted_sandbox_accepts_existing_sandbox() {
        let store = test_store().await;
        store
            .put_message(&sandbox_record("sbx-1", "sandbox-one"))
            .await
            .expect("sandbox should persist");

        require_persisted_sandbox(&store, "sbx-1")
            .await
            .expect("persisted sandbox should be accepted");
    }

    #[test]
    fn expected_transport_close_is_nonfatal_only_during_shutdown() {
        let status = Status::unknown("h2 protocol error: error reading a body from connection");

        assert!(expected_transport_close_during_shutdown(&status, true));
        assert!(!expected_transport_close_during_shutdown(&status, false));
    }

    #[test]
    fn unexpected_transport_error_stays_fatal_during_shutdown() {
        let status = Status::internal("policy evaluation failed");

        assert!(!expected_transport_close_during_shutdown(&status, true));
    }

    #[test]
    fn gateway_shutdown_makes_session_transport_close_nonfatal() {
        let status =
            Status::unknown("h2 protocol error: error reading a body from connection: broken pipe");

        assert!(expected_transport_close_during_session_state(
            &status, true, false, false,
        ));
    }

    #[test]
    fn sandbox_proto_terminating_detects_deleting_phase() {
        let mut sandbox = sandbox_record("sbx-1", "sandbox-one");
        sandbox.set_phase(SandboxPhase::Deleting as i32);

        assert!(sandbox_proto_is_terminating(&sandbox));
    }

    #[test]
    fn sandbox_proto_terminating_detects_deletion_timestamp() {
        let mut sandbox = sandbox_record("sbx-1", "sandbox-one");
        sandbox.metadata.as_mut().unwrap().deletion_timestamp_ms = 1;

        assert!(sandbox_proto_is_terminating(&sandbox));
    }

    #[test]
    fn sandbox_proto_running_is_not_terminating() {
        let mut sandbox = sandbox_record("sbx-1", "sandbox-one");
        sandbox.set_phase(SandboxPhase::Ready as i32);

        assert!(!sandbox_proto_is_terminating(&sandbox));
    }

    // ---- claim_relay: expiry, drop, wiring ----

    #[test]
    fn claim_relay_unknown_channel() {
        let registry = SupervisorSessionRegistry::new();
        let principal = sandbox_principal("sbx-test");
        let err = registry
            .claim_relay("nonexistent", Some(&principal))
            .expect_err("should err");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[test]
    fn claim_relay_success() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, _relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-1".to_string(),
            pending_relay("sbx-test", relay_tx, Instant::now()),
        );

        let principal = sandbox_principal("sbx-test");
        let result = registry.claim_relay("ch-1", Some(&principal));
        assert!(result.is_ok());
        assert!(!registry.pending_relays.lock().unwrap().contains_key("ch-1"));
    }

    #[test]
    fn claim_relay_rejects_cross_sandbox_principal_without_consuming_channel() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, _relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-cross".to_string(),
            pending_relay("sbx-owner", relay_tx, Instant::now()),
        );

        let attacker = sandbox_principal("sbx-attacker");
        let err = registry
            .claim_relay("ch-cross", Some(&attacker))
            .expect_err("cross-sandbox relay claim must fail");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(
            registry
                .pending_relays
                .lock()
                .unwrap()
                .contains_key("ch-cross"),
            "failed cross-sandbox claim must not consume the channel"
        );
    }

    #[test]
    fn claim_relay_rejects_user_principal() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, _relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-user".to_string(),
            pending_relay("sbx-owner", relay_tx, Instant::now()),
        );

        let err = registry
            .claim_relay("ch-user", Some(&user_principal("alice")))
            .expect_err("users are not supervisor identities");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn relay_open_failure_completes_pending_waiter() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-fail".to_string(),
            pending_relay("sbx-test", relay_tx, Instant::now()),
        );

        assert!(registry.fail_pending_relay("ch-fail", "target refused".to_string()));
        assert!(
            !registry
                .pending_relays
                .lock()
                .unwrap()
                .contains_key("ch-fail")
        );

        let result = relay_rx.await.expect("failure should wake waiter");
        let status = result.expect_err("waiter should receive status failure");
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(status.message(), "target refused");
    }

    #[test]
    fn claim_relay_expired_returns_deadline_exceeded() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, _relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-old".to_string(),
            pending_relay(
                "sbx-test",
                relay_tx,
                Instant::now()
                    .checked_sub(Duration::from_mins(1))
                    .expect("test duration should be before now"),
            ),
        );

        let err = registry
            .claim_relay("ch-old", Some(&sandbox_principal("sbx-test")))
            .expect_err("expired entry must fail");
        assert_eq!(err.code(), tonic::Code::DeadlineExceeded);
        // Entry must have been consumed regardless.
        assert!(
            !registry
                .pending_relays
                .lock()
                .unwrap()
                .contains_key("ch-old")
        );
    }

    #[test]
    fn claim_relay_receiver_dropped_returns_internal() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, relay_rx) = oneshot::channel::<Result<tokio::io::DuplexStream, Status>>();
        drop(relay_rx); // Gateway-side waiter has given up already.
        registry.pending_relays.lock().unwrap().insert(
            "ch-1".to_string(),
            pending_relay("sbx-test", relay_tx, Instant::now()),
        );

        let err = registry
            .claim_relay("ch-1", Some(&sandbox_principal("sbx-test")))
            .expect_err("should err when receiver is gone");
        assert_eq!(err.code(), tonic::Code::Internal);
    }

    #[tokio::test]
    async fn claim_relay_connects_both_ends() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, relay_rx) = oneshot::channel::<Result<tokio::io::DuplexStream, Status>>();
        registry.pending_relays.lock().unwrap().insert(
            "ch-io".to_string(),
            pending_relay("sbx-test", relay_tx, Instant::now()),
        );

        let mut supervisor_side = registry
            .claim_relay("ch-io", Some(&sandbox_principal("sbx-test")))
            .expect("claim should succeed")
            .stream;
        let mut gateway_side = relay_rx
            .await
            .expect("gateway side should receive result")
            .expect("gateway side should receive stream");

        // Supervisor side writes → gateway side reads.
        supervisor_side.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        gateway_side.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // Gateway side writes → supervisor side reads.
        gateway_side.write_all(b"world").await.unwrap();
        let mut buf = [0u8; 5];
        supervisor_side.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
    }

    // ---- reap_expired_relays ----

    #[test]
    fn reap_expired_relays_removes_old_entries() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, _relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-old".to_string(),
            pending_relay(
                "sbx-test",
                relay_tx,
                Instant::now()
                    .checked_sub(Duration::from_mins(1))
                    .expect("test duration should be before now"),
            ),
        );

        registry.reap_expired_relays();
        assert!(
            !registry
                .pending_relays
                .lock()
                .unwrap()
                .contains_key("ch-old")
        );
    }

    #[test]
    fn reap_expired_relays_keeps_fresh_entries() {
        let registry = SupervisorSessionRegistry::new();
        let (relay_tx, _relay_rx) = oneshot::channel();
        registry.pending_relays.lock().unwrap().insert(
            "ch-fresh".to_string(),
            pending_relay("sbx-test", relay_tx, Instant::now()),
        );

        registry.reap_expired_relays();
        assert!(
            registry
                .pending_relays
                .lock()
                .unwrap()
                .contains_key("ch-fresh")
        );
    }

    // -----------------------------------------------------------------------
    // Cross-replica redirect on the no-local-session path
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn a_liveness_row_redirects_without_delay() {
        let store = store_with_sandboxes(&["sbx-redirect"]).await;
        let remote = liveness(&store, "replica-remote", "10-0-0-9.gw.ns.svc:8080");
        remote
            .announce("sbx-redirect", "session-remote")
            .await
            .unwrap();

        let registry =
            SupervisorSessionRegistry::with_liveness(liveness(&store, "replica-local", "local:1"));

        let started = Instant::now();
        let err = registry
            .session_or_unavailable("sbx-redirect")
            .await
            .expect_err("no local session for this sandbox");

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a redirect must be immediate"
        );
        assert_eq!(err.code(), tonic::Code::Unavailable);
        assert_eq!(
            redirect_hint(&err).as_deref(),
            Some("10-0-0-9.gw.ns.svc:8080")
        );
        assert!(
            err.message().contains("10-0-0-9.gw.ns.svc:8080"),
            "message should name the replica for logs: {}",
            err.message()
        );
    }

    /// The contract this registry now keeps: a replica holding no session
    /// answers at once. It cannot observe another replica's connections, so
    /// waiting would only delay the same answer, and how long to keep trying
    /// is the caller's to decide.
    #[tokio::test]
    async fn no_local_session_answers_immediately() {
        let store = store_with_sandboxes(&["sbx-nobody"]).await;
        let registry =
            SupervisorSessionRegistry::with_liveness(liveness(&store, "replica-local", "local:1"));

        let started = Instant::now();
        let err = registry
            .session_or_unavailable("sbx-nobody")
            .await
            .expect_err("session is not registered here");

        assert!(
            started.elapsed() < Duration::from_millis(100),
            "the answer must not be delayed: {:?}",
            started.elapsed()
        );
        assert_eq!(err.code(), tonic::Code::Unavailable);
        assert_eq!(err.message(), "supervisor session not connected");
    }

    /// Including for a sandbox no replica has connected yet. This is the cold
    /// start, and it is answered rather than waited out — sandbox-api retries
    /// on its own schedule and against a freshly resolved fleet, which a
    /// timeout passed in here could not have expressed.
    #[tokio::test]
    async fn a_cold_start_is_answered_rather_than_waited_out() {
        let registry = SupervisorSessionRegistry::new();

        let started = Instant::now();
        let err = registry
            .session_or_unavailable("sbx-never-connected")
            .await
            .expect_err("nothing has connected");

        assert!(started.elapsed() < Duration::from_millis(100));
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }

    /// A liveness row naming a peer is the better answer, so it replaces the
    /// bare refusal when one exists.
    #[tokio::test]
    async fn a_named_replica_beats_the_bare_refusal() {
        let store = store_with_sandboxes(&["sbx-served-elsewhere"]).await;
        let remote = liveness(&store, "replica-remote", "10-0-0-9.gw.ns.svc:8080");
        remote
            .announce("sbx-served-elsewhere", "session-remote")
            .await
            .unwrap();

        let registry =
            SupervisorSessionRegistry::with_liveness(liveness(&store, "replica-local", "local:1"));

        let err = registry
            .session_or_unavailable("sbx-served-elsewhere")
            .await
            .expect_err("no local session");

        assert_eq!(
            redirect_hint(&err).as_deref(),
            Some("10-0-0-9.gw.ns.svc:8080")
        );
    }

    // -----------------------------------------------------------------------
    // Sandbox readiness is a fact about the fleet, not about this process
    // -----------------------------------------------------------------------

    /// The bug this exists to prevent: a replica that never held the session
    /// answering "not connected" and reconciling a healthy sandbox back to
    /// `Provisioning`.
    #[tokio::test]
    async fn session_connected_in_fleet_sees_a_peer_replicas_session() {
        let store = store_with_sandboxes(&["sbx-remote-session"]).await;
        let remote = liveness(&store, "replica-remote", "10-0-0-9.gw.ns.svc:8080");
        remote
            .announce("sbx-remote-session", "session-remote")
            .await
            .unwrap();

        let registry =
            SupervisorSessionRegistry::with_liveness(liveness(&store, "replica-local", "local:1"));

        assert!(!registry.has_session("sbx-remote-session"));
        assert!(
            registry
                .session_connected_in_fleet("sbx-remote-session")
                .await
        );
    }

    #[tokio::test]
    async fn session_connected_in_fleet_is_false_with_no_session_anywhere() {
        let store = store_with_sandboxes(&["sbx-nobody"]).await;
        let registry =
            SupervisorSessionRegistry::with_liveness(liveness(&store, "replica-local", "local:1"));

        assert!(!registry.session_connected_in_fleet("sbx-nobody").await);
    }

    /// Without liveness tracking the only answer available is the local one,
    /// which is what a single-replica gateway had all along.
    #[tokio::test]
    async fn session_connected_in_fleet_falls_back_to_the_local_session() {
        let registry = SupervisorSessionRegistry::new();
        let (tx, _rx) = mpsc::channel(1);
        let (shutdown, _shutdown_rx) = oneshot::channel();
        registry.register(
            "sbx-local".to_string(),
            "session-1".to_string(),
            tx,
            shutdown,
        );

        assert!(registry.session_connected_in_fleet("sbx-local").await);
        assert!(!registry.session_connected_in_fleet("sbx-other").await);
    }

    #[tokio::test]
    async fn wait_for_session_does_not_redirect_when_owner_is_us() {
        let store = store_with_sandboxes(&["sbx-self-owned"]).await;
        let local = liveness(&store, "replica-local", "local:1");
        local
            .announce("sbx-self-owned", "session-local")
            .await
            .unwrap();

        let registry = SupervisorSessionRegistry::with_liveness(local);
        let err = registry
            .session_or_unavailable("sbx-self-owned")
            .await
            .expect_err("session is not registered yet");

        assert_eq!(err.code(), tonic::Code::Unavailable);
        assert_eq!(err.message(), "supervisor session not connected");
        assert!(redirect_hint(&err).is_none());
    }

    #[tokio::test]
    async fn wait_for_session_does_not_redirect_without_an_owner() {
        let store = store_with_sandboxes(&["sbx-unowned"]).await;
        let registry =
            SupervisorSessionRegistry::with_liveness(liveness(&store, "replica-local", "local:1"));

        let err = registry
            .session_or_unavailable("sbx-unowned")
            .await
            .expect_err("session is not registered");

        assert_eq!(err.code(), tonic::Code::Unavailable);
        assert_eq!(err.message(), "supervisor session not connected");
        assert!(redirect_hint(&err).is_none());
    }

    #[tokio::test]
    async fn wait_for_session_does_not_redirect_to_an_empty_address() {
        let store = store_with_sandboxes(&["sbx-no-address"]).await;
        let remote = liveness(&store, "replica-remote", "");
        remote
            .announce("sbx-no-address", "session-remote")
            .await
            .unwrap();

        let registry =
            SupervisorSessionRegistry::with_liveness(liveness(&store, "replica-local", "local:1"));
        let err = registry
            .session_or_unavailable("sbx-no-address")
            .await
            .expect_err("session is not registered");

        assert_eq!(err.code(), tonic::Code::Unavailable);
        assert_eq!(err.message(), "supervisor session not connected");
        assert!(redirect_hint(&err).is_none());
    }

    #[tokio::test]
    async fn wait_for_session_does_not_redirect_to_our_own_address() {
        let store = store_with_sandboxes(&["sbx-same-address"]).await;
        // Same advertised address under a different replica id — e.g. a
        // restarted pod that reused its IP. Redirecting to ourselves would
        // just loop the caller back here.
        let remote = liveness(&store, "replica-previous", "10-0-0-1.gw.ns.svc:8080");
        remote
            .announce("sbx-same-address", "session-old")
            .await
            .unwrap();

        let registry = SupervisorSessionRegistry::with_liveness(liveness(
            &store,
            "replica-local",
            "10-0-0-1.gw.ns.svc:8080",
        ));
        let err = registry
            .session_or_unavailable("sbx-same-address")
            .await
            .expect_err("session is not registered");

        assert_eq!(err.message(), "supervisor session not connected");
        assert!(redirect_hint(&err).is_none());
    }

    #[tokio::test]
    async fn wait_for_session_prefers_the_local_session_over_a_remote_owner() {
        let store = store_with_sandboxes(&["sbx-local-wins"]).await;
        let remote = liveness(&store, "replica-remote", "10-0-0-9.gw.ns.svc:8080");
        remote
            .announce("sbx-local-wins", "session-remote")
            .await
            .unwrap();

        let registry =
            SupervisorSessionRegistry::with_liveness(liveness(&store, "replica-local", "local:1"));
        let (tx, _rx) = mpsc::channel(1);
        registry.register(
            "sbx-local-wins".to_string(),
            "session-local".to_string(),
            tx,
            make_shutdown(),
        );

        registry
            .session_or_unavailable("sbx-local-wins")
            .await
            .expect("a working local session must win over a stale liveness record");
    }

    /// The assertion that would have caught the metadata being dropped: drive
    /// the real entry point the exec handler calls (`open_relay`), wrap the
    /// error with the real production wrapper, and read the hint back the way
    /// a client does. Both halves were individually correct while the chain
    /// was broken, so only an end-to-end check over both is sufficient.
    #[tokio::test]
    async fn a_redirect_survives_the_relay_open_wrapper_a_client_sees() {
        let store = store_with_sandboxes(&["sbx-e2e"]).await;
        let remote = liveness(
            &store,
            "replica-remote",
            "10-42-0-243.openshell-headless.sandbox.svc.cluster.local:8080",
        );
        remote.announce("sbx-e2e", "session-remote").await.unwrap();

        let registry =
            SupervisorSessionRegistry::with_liveness(liveness(&store, "replica-local", "local:1"));

        let inner = registry
            .open_relay("sbx-e2e")
            .await
            .expect_err("no local session, so open_relay must fail with the redirect");
        let wrapped = crate::grpc::sandbox::relay_open_failure(&inner);

        assert_eq!(
            redirect_hint(&wrapped).as_deref(),
            Some("10-42-0-243.openshell-headless.sandbox.svc.cluster.local:8080"),
            "the client keys off the metadata, not the message text"
        );
        assert_eq!(wrapped.code(), tonic::Code::Unavailable);
    }

    #[tokio::test]
    async fn a_plain_session_timeout_reaches_the_client_without_a_hint() {
        let store = store_with_sandboxes(&["sbx-e2e-none"]).await;
        let registry =
            SupervisorSessionRegistry::with_liveness(liveness(&store, "replica-local", "local:1"));

        let inner = registry
            .open_relay("sbx-e2e-none")
            .await
            .expect_err("no session and no owner, so this times out as before");
        let wrapped = crate::grpc::sandbox::relay_open_failure(&inner);

        assert!(redirect_hint(&wrapped).is_none());
        assert_eq!(wrapped.code(), tonic::Code::Unavailable);
    }

    #[tokio::test]
    async fn registry_without_liveness_keeps_single_replica_behavior() {
        let registry = SupervisorSessionRegistry::new();
        let err = registry
            .session_or_unavailable("sbx-no-tracking")
            .await
            .expect_err("session is not registered");
        assert_eq!(err.code(), tonic::Code::Unavailable);
        assert_eq!(err.message(), "supervisor session not connected");
        assert!(redirect_hint(&err).is_none());
    }

    #[tokio::test]
    async fn withdraw_liveness_from_a_superseded_session_keeps_the_current_record() {
        let store = store_with_sandboxes(&["sbx-supersede"]).await;
        let local = liveness(&store, "replica-local", "local:1");
        local
            .announce("sbx-supersede", "session-old")
            .await
            .unwrap();
        local
            .announce("sbx-supersede", "session-new")
            .await
            .unwrap();

        let registry = SupervisorSessionRegistry::with_liveness(Arc::clone(&local));
        registry
            .withdraw_liveness("sbx-supersede", "session-old")
            .await;

        let record = local
            .lookup("sbx-supersede")
            .await
            .unwrap()
            .expect("current liveness record must survive");
        assert_eq!(record.session_id, "session-new");
    }
}
