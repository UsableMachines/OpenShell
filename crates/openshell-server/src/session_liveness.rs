// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cross-replica liveness of supervisor sessions.
//!
//! A supervisor session is a long-lived bidirectional gRPC stream, so it lives
//! in the memory of exactly one gateway replica. Requests that need to talk to
//! a sandbox (exec, SSH relay, port forward) only work on the replica holding
//! that sandbox's session. With more than one replica behind a load balancer,
//! a request can land anywhere.
//!
//! This module records that a replica held a session for a sandbox as of a
//! moment, so a replica without a local session can point the caller at one
//! that had it rather than waiting out its session timeout and failing.
//!
//! A row is liveness, not ownership. Several replicas legitimately serve one
//! sandbox, each writes only its own row, and a row is a lagging account of
//! something another process owns — so it may bias an attempt and may never
//! refuse one. The connection is the only authority on where a sandbox is
//! reachable, and dispatching is what tests the claim.
//!
//! Shape mirrors [`crate::compute::lease`] — a TTL'd JSON payload written
//! through `put_if` CAS. No protobuf definition is involved.

use crate::persistence::{ObjectRecord, PersistenceError, Store, WriteCondition};
use openshell_core::time::now_ms;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tonic::Status;
use tracing::debug;

const LIVENESS_OBJECT_TYPE: &str = "supervisor-session-liveness";

/// What the liveness rows say about a sandbox after a session releases its
/// own record.
///
/// Three values rather than two because the store not answering is not the
/// same claim as the store answering "nobody". A phase is one row for the
/// whole fleet, and only the first two justify writing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSessions {
    /// An unexpired row names a replica: somebody is still serving.
    Serving,
    /// The store answered, and no unexpired row exists.
    None,
    /// The store could not be asked, or could not answer.
    Unknown,
}

/// Row key for a sandbox's liveness record.
///
/// `objects.id` is the table's *whole* primary key — it is globally unique
/// across every object type, not scoped by `object_type`. A sandbox already
/// occupies the row whose id is the sandbox id, so keying this record on the
/// bare sandbox id makes every `MustCreate` collide with that sandbox's own
/// row while `get(LIVENESS_OBJECT_TYPE, …)` still reports nothing (it filters by
/// type), which is unrecoverable. Any new object type has to namespace its
/// ids the same way. `name` needs no prefix: `objects_name_uq` is scoped by
/// `(object_type, workspace, name)`, so the bare sandbox id stays usable as
/// the human-facing key.
///
/// Every read, write, and delete of an liveness row must go through this.
fn liveness_object_id(sandbox_id: &str, replica_id: &str) -> String {
    format!("{LIVENESS_OBJECT_TYPE}:{sandbox_id}:{replica_id}")
}

/// Read-then-CAS attempts a single [`SessionLiveness::announce`] will make
/// before giving up. Each retry means another replica wrote first; a handful
/// is plenty, because a row is written on supervisor connect and a supervisor
/// connects to one replica at a time.
const ANNOUNCE_CAS_ATTEMPTS: usize = 8;

/// How long a liveness record is believed without a renewal.
///
/// Matched to the reconciler lease (30s TTL / 10s renewal) so both HA
/// mechanisms fail over on the same timescale and operators only have one
/// number to reason about. Three renewal attempts fit inside the TTL, so a
/// single slow or failed store write does not make a live session look
/// gone; conversely a replica that dies leaves a row that stops being
/// believed after at most `LIVENESS_TTL` rather than wedging the sandbox.
pub const LIVENESS_TTL: Duration = Duration::from_secs(30);

/// Interval between liveness renewals while a session is live.
pub const LIVENESS_RENEWAL_INTERVAL: Duration = Duration::from_secs(10);

/// Overall budget for withdrawing this replica's rows during graceful shutdown.
///
/// Deliberately far shorter than any sane `terminationGracePeriodSeconds`:
/// the kubelet SIGKILLs us when the grace period runs out regardless, and a
/// row left behind expires after [`LIVENESS_TTL`] anyway, so spending shutdown
/// time here has a hard ceiling on its value. Missing the deadline is a
/// warning, never a failure.
pub const LIVENESS_RELEASE_ALL_TIMEOUT: Duration = Duration::from_secs(3);

/// Response metadata key carrying the address of a replica that held a
/// session for this sandbox.
///
/// Advisory in the strong sense: it biases the next attempt and never
/// refuses one. A client that ignores it sees exactly the pre-HA behavior —
/// an `unavailable` status after the session wait timeout.
pub const SERVING_REPLICA_METADATA_KEY: &str = "x-openshell-serving-replica";

/// Build a wrapping [`Status`] that keeps `inner`'s serving-replica hint.
///
/// `Status::unavailable(msg)` and friends construct a brand-new `Status`, so
/// every trailer on the original is discarded and only the `Display` text
/// survives. That silently defeats the redirect: the address still shows up in
/// the message, which is for logs, while the metadata the client keys off is
/// gone. Any layer that re-wraps a status originating from the relay path must
/// route through here.
///
/// Only this one key is copied. Cloning `inner`'s whole metadata map would
/// have the wrapper forward trailers it never meant to promise — a caller
/// could act on a header the outer layer knows nothing about, and the set
/// would grow silently as inner layers gain metadata. Propagating a specific
/// key is a decision; inheriting a map is an accident. When a second key
/// eventually needs forwarding, it should be added here explicitly.
pub fn wrap_status_preserving_redirect_hint(
    inner: &Status,
    code: tonic::Code,
    message: impl Into<String>,
) -> Status {
    let mut wrapped = Status::new(code, message);
    if let Some(hint) = inner.metadata().get(SERVING_REPLICA_METADATA_KEY) {
        wrapped
            .metadata_mut()
            .insert(SERVING_REPLICA_METADATA_KEY, hint.clone());
    }
    wrapped
}

#[derive(Debug, Error)]
pub enum LivenessError {
    /// A row already occupies this record's key. Distinct from [`Self::Conflict`]
    /// on purpose: this says nothing about a competing replica — the colliding
    /// row may belong to an entirely different object type, since `objects.id`
    /// is globally unique. See [`liveness_object_id`].
    #[error("an objects row already exists with liveness key {key}")]
    KeyTaken { key: String },
    #[error("liveness record changed between our read and our write")]
    Conflict,
    #[error("gave up claiming liveness after {attempts} attempts")]
    Contended { attempts: usize },
    #[error("persistence error: {0}")]
    Store(#[from] PersistenceError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LivenessPayload {
    replica_id: String,
    advertise_address: String,
    session_id: String,
    renewed_at_ms: i64,
}

/// A decoded liveness record.
#[derive(Debug, Clone)]
pub struct LivenessRecord {
    pub replica_id: String,
    /// `host:port` at which the owning replica's gRPC endpoint is reachable.
    /// Empty when the replica could not determine its own routable address.
    pub advertise_address: String,
    pub session_id: String,
    #[allow(dead_code)]
    pub renewed_at_ms: i64,
    pub resource_version: u64,
    pub updated_at_ms: i64,
}

/// Handle to an liveness record this replica holds, carrying the CAS version
/// needed to renew it.
#[derive(Debug)]
pub struct LivenessHandle {
    session_id: String,
    resource_version: u64,
}

impl LivenessHandle {
    #[allow(dead_code)]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[allow(dead_code)]
    pub fn resource_version(&self) -> u64 {
        self.resource_version
    }
}

/// Outcome of [`SessionLiveness::release_all_owned`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseAllSummary {
    /// Records this replica removed.
    pub released: usize,
    /// Records left alone because they no longer name this replica and
    /// session — a supervisor reconnected elsewhere and superseded us.
    pub skipped: usize,
    /// Records we could not read or delete. These expire on their own.
    pub failed: usize,
}

/// Reads and writes per-sandbox supervisor-session liveness records.
#[derive(Debug)]
pub struct SessionLiveness {
    store: Arc<Store>,
    replica_id: String,
    advertise_address: String,
    ttl: Duration,
    /// `sandbox_id` -> `session_id` for every record this replica has claimed
    /// and not yet released. Shutdown needs to know what to clean up, and the
    /// per-record guards still run, so a drifted entry is harmless.
    owned: Mutex<HashMap<String, String>>,
}

impl SessionLiveness {
    pub fn new(
        store: Arc<Store>,
        replica_id: String,
        advertise_address: String,
        ttl: Duration,
    ) -> Self {
        Self {
            store,
            replica_id,
            advertise_address,
            ttl,
            owned: Mutex::new(HashMap::new()),
        }
    }

    pub fn replica_id(&self) -> &str {
        &self.replica_id
    }

    /// This replica's advertised `host:port`, or empty when unresolvable.
    pub fn advertise_address(&self) -> &str {
        &self.advertise_address
    }

    /// Record that *this* replica holds a supervisor session for a sandbox.
    ///
    /// One row per (sandbox, replica), not one row per sandbox. A supervisor
    /// connects to every member of the sandbox's subset, so several replicas
    /// legitimately hold a session at once and "the owner" is not a single
    /// fact. A shared row would make them fight over it: whichever wrote last
    /// would hold a resource version the others do not, so every other
    /// replica's [`Self::renew`] would fail for the life of the session — and
    /// if the winner then died, its row would expire while a replica that is
    /// still serving has no row at all, which reads as "nobody is connected"
    /// and regresses a healthy sandbox's phase.
    ///
    /// With a row each, a replica only ever writes its own, so CAS contention
    /// is with itself (a reconnect racing its own cleanup) and the retry loop
    /// below effectively never spins. Reads that want "is anyone serving this
    /// sandbox" list the rows instead — see [`Self::lookup`].
    pub async fn announce(
        &self,
        sandbox_id: &str,
        session_id: &str,
    ) -> Result<LivenessHandle, LivenessError> {
        let payload_bytes = self.encode(session_id)?;

        for _ in 0..ANNOUNCE_CAS_ATTEMPTS {
            let condition = match self.read_own(sandbox_id).await? {
                Some(record) => WriteCondition::MatchResourceVersion(record.resource_version),
                None => WriteCondition::MustCreate,
            };

            match self.put(sandbox_id, &payload_bytes, condition).await {
                Ok(resource_version) => {
                    self.owned
                        .lock()
                        .unwrap()
                        .insert(sandbox_id.to_string(), session_id.to_string());
                    return Ok(LivenessHandle {
                        session_id: session_id.to_string(),
                        resource_version,
                    });
                }
                // Our own row changed between the read and the write —
                // a reconnect racing its own cleanup. Re-read and overwrite;
                // this replica holds the live session either way.
                Err(LivenessError::Conflict | LivenessError::KeyTaken { .. }) => {}
                Err(e) => return Err(e),
            }
        }

        Err(LivenessError::Contended {
            attempts: ANNOUNCE_CAS_ATTEMPTS,
        })
    }

    /// Refresh the record's timestamp so the claim stays authoritative.
    pub async fn renew(
        &self,
        sandbox_id: &str,
        claim: &mut LivenessHandle,
    ) -> Result<(), LivenessError> {
        let payload_bytes = self.encode(&claim.session_id)?;
        claim.resource_version = self
            .put(
                sandbox_id,
                &payload_bytes,
                WriteCondition::MatchResourceVersion(claim.resource_version),
            )
            .await?;
        Ok(())
    }

    /// Drop the liveness record, but only when we still own it *and* the
    /// record names `session_id`.
    ///
    /// Both guards matter. A superseded session's cleanup can run long after a
    /// reconnect installed a newer session — possibly on a different replica —
    /// and an unguarded delete there would erase the serving replica's record and
    /// send every subsequent request into the wait-then-fail path.
    ///
    /// Returns `true` when a record was removed.
    pub async fn withdraw(
        &self,
        sandbox_id: &str,
        session_id: &str,
    ) -> Result<bool, LivenessError> {
        self.forget_owned(sandbox_id, session_id);

        let Some(record) = self.read_own(sandbox_id).await? else {
            return Ok(false);
        };
        if record.replica_id != self.replica_id || record.session_id != session_id {
            return Ok(false);
        }

        match self
            .store
            .delete_if(
                LIVENESS_OBJECT_TYPE,
                &liveness_object_id(sandbox_id, &self.replica_id),
                record.resource_version,
            )
            .await
        {
            Ok(deleted) => Ok(deleted),
            Err(PersistenceError::Conflict { .. }) => Err(LivenessError::Conflict),
            Err(e) => Err(LivenessError::Store(e)),
        }
    }

    /// Release every record this replica still owns.
    ///
    /// Called during graceful shutdown so other replicas stop redirecting to
    /// a pod that is going away. Without this, a rolling restart would point
    /// callers at a dead pod for up to [`LIVENESS_TTL`], even though the
    /// supervisor has already reconnected somewhere that could serve them.
    ///
    /// Each record goes through the same `session_id`-guarded CAS delete as
    /// [`Self::release`], so a record another replica has since claimed is
    /// counted as skipped rather than deleted. Errors are tallied, never
    /// propagated: the caller is on the shutdown path and an unreleased
    /// record expires on its own.
    pub async fn release_all_owned(&self) -> ReleaseAllSummary {
        let owned: Vec<(String, String)> = {
            let mut owned = self.owned.lock().unwrap();
            owned.drain().collect()
        };

        let mut summary = ReleaseAllSummary::default();
        for (sandbox_id, session_id) in owned {
            match self.withdraw(&sandbox_id, &session_id).await {
                Ok(true) => summary.released += 1,
                Ok(false) => summary.skipped += 1,
                Err(err) => {
                    summary.failed += 1;
                    debug!(
                        sandbox_id = %sandbox_id,
                        session_id = %session_id,
                        error = %err,
                        "supervisor session: shutdown liveness release failed"
                    );
                }
            }
        }
        summary
    }

    /// [`Self::release_all_owned`] under an overall deadline.
    ///
    /// Returns `None` when the budget ran out, in which case the caller should
    /// log and carry on: whatever is left expires after [`LIVENESS_TTL`]. The
    /// bound lives here rather than at the call site so the shutdown path
    /// cannot accidentally lose it.
    pub async fn withdraw_all_within(&self, budget: Duration) -> Option<ReleaseAllSummary> {
        bounded_release(budget, self.release_all_owned()).await
    }

    /// Stop tracking a sandbox for shutdown release, but only when the tracked
    /// session is the one being released — a superseded session must not
    /// un-track the claim that replaced it.
    fn forget_owned(&self, sandbox_id: &str, session_id: &str) {
        let mut owned = self.owned.lock().unwrap();
        if owned
            .get(sandbox_id)
            .is_some_and(|tracked| tracked == session_id)
        {
            owned.remove(sandbox_id);
        }
    }

    /// A replica currently holding a supervisor session for this sandbox.
    ///
    /// Several may hold one at once, so this answers "somebody is serving
    /// this, and here is one of them" rather than naming a unique owner. The
    /// freshest unexpired row wins: all of them are serving, and the one
    /// renewed most recently is the one least likely to be mid-shutdown.
    ///
    /// `None` when no row exists or every row has expired — an expired row
    /// names a replica that stopped renewing, so redirecting to it would be
    /// worse than waiting.
    pub async fn lookup(&self, sandbox_id: &str) -> Result<Option<LivenessRecord>, LivenessError> {
        let now_ms = now_ms();
        let ttl_ms = self.ttl_ms();

        Ok(self
            .read_all(sandbox_id)
            .await?
            .into_iter()
            .filter(|record| !record_is_expired(now_ms, record.updated_at_ms, ttl_ms))
            .max_by_key(|record| record.renewed_at_ms))
    }

    /// Every replica this sandbox has a session row for, expired or not.
    ///
    /// A `list` scoped to the sandbox: liveness rows carry the sandbox id as
    /// their workspace, so this is an indexed read bounded by the subset size
    /// rather than a scan of every session in the fleet.
    async fn read_all(&self, sandbox_id: &str) -> Result<Vec<LivenessRecord>, LivenessError> {
        let records = self
            .store
            .list(LIVENESS_OBJECT_TYPE, sandbox_id, OWNER_ROW_LIST_LIMIT, 0)
            .await
            .map_err(LivenessError::Store)?;

        records.into_iter().map(decode_liveness_record).collect()
    }

    /// Read *this* replica's row for a sandbox, without applying the TTL.
    ///
    /// The write paths use this: a replica claims, renews and releases only
    /// its own row, so they need its resource version and nobody else's.
    async fn read_own(&self, sandbox_id: &str) -> Result<Option<LivenessRecord>, LivenessError> {
        let record = self
            .store
            .get(
                LIVENESS_OBJECT_TYPE,
                &liveness_object_id(sandbox_id, &self.replica_id),
            )
            .await
            .map_err(LivenessError::Store)?;
        let Some(record) = record else {
            return Ok(None);
        };

        Ok(Some(decode_liveness_record(record)?))
    }

    fn encode(&self, session_id: &str) -> Result<Vec<u8>, LivenessError> {
        let payload = LivenessPayload {
            replica_id: self.replica_id.clone(),
            advertise_address: self.advertise_address.clone(),
            session_id: session_id.to_string(),
            renewed_at_ms: now_ms(),
        };
        serde_json::to_vec(&payload)
            .map_err(|e| LivenessError::Store(PersistenceError::Encode(e.to_string())))
    }

    async fn put(
        &self,
        sandbox_id: &str,
        payload_bytes: &[u8],
        condition: WriteCondition,
    ) -> Result<u64, LivenessError> {
        match self
            .store
            .put_if(
                LIVENESS_OBJECT_TYPE,
                &liveness_object_id(sandbox_id, &self.replica_id),
                // `name` then `workspace` — the store takes them in that
                // order. Name is the replica and workspace is the sandbox,
                // which is what makes `read_all` an indexed per-sandbox list
                // and what keeps two replicas' rows from colliding on the
                // (object_type, workspace, name) uniqueness constraint.
                &self.replica_id,
                sandbox_id,
                payload_bytes,
                None,
                condition,
            )
            .await
        {
            Ok(result) => Ok(result.resource_version),
            Err(PersistenceError::UniqueViolation { .. }) => Err(LivenessError::KeyTaken {
                key: liveness_object_id(sandbox_id, &self.replica_id),
            }),
            Err(PersistenceError::Conflict { .. }) => Err(LivenessError::Conflict),
            Err(e) => Err(LivenessError::Store(e)),
        }
    }

    fn ttl_ms(&self) -> i64 {
        i64::try_from(self.ttl.as_millis()).unwrap_or(i64::MAX)
    }
}

/// Apply the shutdown budget to release work.
///
/// Split out from [`SessionLiveness::withdraw_all_within`] so the
/// bound can be tested against work that provably never finishes, which no
/// real store can be made to do on demand.
async fn bounded_release(
    budget: Duration,
    work: impl Future<Output = ReleaseAllSummary>,
) -> Option<ReleaseAllSummary> {
    tokio::time::timeout(budget, work).await.ok()
}

/// Upper bound on liveness rows read for one sandbox.
///
/// Rows are per replica in the sandbox's subset, so the real count is the
/// subset size. Sized well above any sane subset so a leaked row from a
/// replica that died without releasing cannot hide a live one.
const OWNER_ROW_LIST_LIMIT: u32 = 64;

fn decode_liveness_record(record: ObjectRecord) -> Result<LivenessRecord, LivenessError> {
    let payload: LivenessPayload = serde_json::from_slice(&record.payload)
        .map_err(|e| PersistenceError::Decode(e.to_string()))?;

    Ok(LivenessRecord {
        replica_id: payload.replica_id,
        advertise_address: payload.advertise_address,
        session_id: payload.session_id,
        renewed_at_ms: payload.renewed_at_ms,
        resource_version: record.resource_version,
        updated_at_ms: record.updated_at_ms,
    })
}

/// True if an liveness record's age exceeds its TTL.
///
/// Clamps at zero so a `updated_at_ms` in the future (clock skew between
/// replicas) reads as age zero rather than saturating negative.
fn record_is_expired(now_ms: i64, updated_at_ms: i64, ttl_ms: i64) -> bool {
    let age_ms = now_ms.saturating_sub(updated_at_ms).max(0);
    age_ms >= ttl_ms
}

/// Resolve the address other replicas should use to reach this gateway.
///
/// `OPENSHELL_ADVERTISE_ADDRESS` is a full `host:port` override and wins when
/// set. Otherwise the address is built from `POD_IP` and
/// `OPENSHELL_ADVERTISE_DNS_SUFFIX`: a gateway Deployment fronted by a
/// headless Service gives every pod the per-pod DNS name
/// `<dashed-pod-ip>.<headless-svc>.<ns>.svc.cluster.local`, which — unlike the
/// pod IP — survives being resolved from anywhere in the cluster.
///
/// Whichever form is used, the resulting name must appear in the gateway's
/// own server-certificate SANs, or a TLS client that follows the redirect
/// fails hostname verification and the hint is worse than useless. The
/// defaults in `openshell_bootstrap::pki` cover the service name in the
/// `openshell` namespace only, so a deployment that renames the Service, uses
/// a different namespace, or relies on per-pod DNS has to issue the gateway
/// cert with SANs (or a wildcard) matching what this function produces.
///
/// Returns an empty string when neither is available. Liveness tracking still
/// records the claim in that case (so `lookup` can report *which* replica owns
/// a sandbox for logs and debugging) but no redirect is ever emitted.
pub fn advertise_address(grpc_port: u16) -> String {
    build_advertise_address(
        std::env::var("OPENSHELL_ADVERTISE_ADDRESS").ok().as_deref(),
        std::env::var("POD_IP").ok().as_deref(),
        std::env::var("OPENSHELL_ADVERTISE_DNS_SUFFIX")
            .ok()
            .as_deref(),
        grpc_port,
    )
}

fn build_advertise_address(
    override_address: Option<&str>,
    pod_ip: Option<&str>,
    dns_suffix: Option<&str>,
    grpc_port: u16,
) -> String {
    if let Some(address) = override_address.map(str::trim).filter(|a| !a.is_empty()) {
        return address.to_string();
    }

    let pod_ip = pod_ip.map(str::trim).filter(|ip| !ip.is_empty());
    let dns_suffix = dns_suffix
        .map(|s| s.trim().trim_matches('.'))
        .filter(|s| !s.is_empty());

    match (pod_ip, dns_suffix) {
        (Some(pod_ip), Some(dns_suffix)) => {
            let dashed = pod_ip.replace(['.', ':'], "-");
            format!("{dashed}.{dns_suffix}:{grpc_port}")
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_store() -> Arc<Store> {
        Arc::new(crate::persistence::test_store().await)
    }

    /// Mirror production: the compute layer has already written a `sandbox`
    /// object whose `objects.id` *is* the sandbox id. Every store-backed test
    /// seeds this, because a fixture without it cannot catch an liveness row
    /// that collides with the sandbox's own row.
    async fn seed_sandbox_object(store: &Arc<Store>, sandbox_id: &str) {
        let sandbox = openshell_core::proto::Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: sandbox_id.to_string(),
                name: sandbox_id.to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        store
            .put_message(&sandbox)
            .await
            .expect("sandbox object row should persist");
    }

    /// A store already populated with the `sandbox` rows a test will claim
    /// liveness for.
    async fn store_with_sandboxes(sandbox_ids: &[&str]) -> Arc<Store> {
        let store = test_store().await;
        for sandbox_id in sandbox_ids {
            seed_sandbox_object(&store, sandbox_id).await;
        }
        store
    }

    fn liveness(
        store: Arc<Store>,
        replica_id: &str,
        address: &str,
        ttl: Duration,
    ) -> SessionLiveness {
        SessionLiveness::new(store, replica_id.to_string(), address.to_string(), ttl)
    }

    /// The bug this schema detail caused on a live cluster: `objects.id` is
    /// globally unique, the sandbox already owns the row keyed by its own id,
    /// so an liveness row keyed on the bare sandbox id could never be
    /// created — while `get(LIVENESS_OBJECT_TYPE, …)` kept reporting nothing
    /// because it filters by type, so the claim retried a precondition that
    /// could not succeed and every session logged a failed claim.
    #[tokio::test]
    async fn announce_succeeds_when_the_sandbox_object_row_already_exists() {
        let sandbox_id = "1f8b4fc9-2c4d-4f2a-9f1e-0b6d3a5c7e91";
        let store = test_store().await;
        seed_sandbox_object(&store, sandbox_id).await;

        let o = liveness(store, "replica-1", "10-0-0-1.gw.ns.svc:8080", LIVENESS_TTL);
        o.announce(sandbox_id, "session-a")
            .await
            .expect("claiming must not collide with the sandbox's own objects row");

        let record = o
            .lookup(sandbox_id)
            .await
            .unwrap()
            .expect("liveness record should exist alongside the sandbox row");
        assert_eq!(record.replica_id, "replica-1");
        assert_eq!(record.session_id, "session-a");
    }

    fn status_with_redirect(address: &str) -> Status {
        let mut metadata = tonic::metadata::MetadataMap::new();
        metadata.insert(SERVING_REPLICA_METADATA_KEY, address.parse().unwrap());
        Status::with_metadata(
            tonic::Code::Unavailable,
            "supervisor session not connected on this gateway replica",
            metadata,
        )
    }

    fn redirect_hint(status: &Status) -> Option<String> {
        status
            .metadata()
            .get(SERVING_REPLICA_METADATA_KEY)
            .map(|value| value.to_str().unwrap().to_string())
    }

    #[test]
    fn wrapping_a_redirect_keeps_the_hint() {
        let inner = status_with_redirect("10-0-0-9.gw.ns.svc:8080");
        let wrapped = wrap_status_preserving_redirect_hint(
            &inner,
            tonic::Code::Unavailable,
            format!("supervisor relay failed: {inner}"),
        );

        assert_eq!(
            redirect_hint(&wrapped).as_deref(),
            Some("10-0-0-9.gw.ns.svc:8080"),
            "the redirect hint must survive re-wrapping or the client sees a plain error"
        );
        assert_eq!(wrapped.code(), tonic::Code::Unavailable);
        assert!(wrapped.message().starts_with("supervisor relay failed: "));
    }

    #[test]
    fn wrapping_a_plain_status_adds_no_metadata() {
        let inner = Status::unavailable("supervisor session not connected");
        let wrapped = wrap_status_preserving_redirect_hint(
            &inner,
            tonic::Code::Unavailable,
            "supervisor relay failed: boom",
        );

        assert!(
            redirect_hint(&wrapped).is_none(),
            "a redirect must never be fabricated for a status that had none"
        );
        assert!(wrapped.metadata().is_empty());
    }

    #[test]
    fn wrapping_forwards_only_the_redirect_key() {
        let mut inner = status_with_redirect("10-0-0-9.gw.ns.svc:8080");
        inner
            .metadata_mut()
            .insert("x-openshell-unrelated", "leaked".parse().unwrap());

        let wrapped =
            wrap_status_preserving_redirect_hint(&inner, tonic::Code::Unavailable, "wrapped");
        assert!(redirect_hint(&wrapped).is_some());
        assert!(
            wrapped.metadata().get("x-openshell-unrelated").is_none(),
            "the wrapper must not forward trailers it never meant to promise"
        );
    }

    #[test]
    fn liveness_object_id_is_namespaced_away_from_the_sandbox_row() {
        let sandbox_id = "1f8b4fc9-2c4d-4f2a-9f1e-0b6d3a5c7e91";
        let key = liveness_object_id(sandbox_id, "replica-1");
        assert_ne!(
            key, sandbox_id,
            "objects.id is globally unique — an unprefixed key collides with the sandbox's own row"
        );
        assert!(key.starts_with(LIVENESS_OBJECT_TYPE));
        assert!(key.contains(sandbox_id));
    }

    /// Two replicas holding a session for one sandbox must land on separate
    /// rows. Sharing one is what made every replica but the last-writer fail
    /// to renew for the life of the session.
    #[test]
    fn liveness_object_id_separates_replicas() {
        assert_ne!(
            liveness_object_id("sbx-1", "replica-1"),
            liveness_object_id("sbx-1", "replica-2")
        );
    }

    #[tokio::test]
    async fn announce_records_replica_and_address() {
        let store = store_with_sandboxes(&["sbx-1"]).await;
        let o = liveness(store, "replica-1", "10-0-0-1.gw.ns.svc:8080", LIVENESS_TTL);
        let claim = o
            .announce("sbx-1", "session-a")
            .await
            .expect("should claim");
        assert!(claim.resource_version() > 0);

        let record = o
            .lookup("sbx-1")
            .await
            .unwrap()
            .expect("record should exist");
        assert_eq!(record.replica_id, "replica-1");
        assert_eq!(record.advertise_address, "10-0-0-1.gw.ns.svc:8080");
        assert_eq!(record.session_id, "session-a");
    }

    /// A supervisor connects to every member of its subset, so two replicas
    /// holding a session for one sandbox is the normal case, not a conflict.
    /// Each keeps its own row and `lookup` reports the freshest.
    #[tokio::test]
    async fn two_replicas_hold_a_session_for_the_same_sandbox() {
        let store = store_with_sandboxes(&["sbx-move"]).await;
        let o1 = liveness(store.clone(), "replica-1", "a:1", LIVENESS_TTL);
        let o2 = liveness(store.clone(), "replica-2", "b:2", LIVENESS_TTL);

        o1.announce("sbx-move", "session-a").await.unwrap();
        o2.announce("sbx-move", "session-b").await.unwrap();

        let holders = o1.read_all("sbx-move").await.unwrap();
        assert_eq!(holders.len(), 2, "each replica must keep its own row");

        // Both are serving; the freshest is the one least likely to be
        // mid-shutdown, and either is a usable redirect target.
        let record = o2
            .lookup("sbx-move")
            .await
            .unwrap()
            .expect("a holder should exist");
        assert_eq!(record.replica_id, "replica-2");
        assert_eq!(record.advertise_address, "b:2");
        assert_eq!(record.session_id, "session-b");
    }

    #[tokio::test]
    async fn concurrent_claims_converge_on_one_valid_record() {
        let store = store_with_sandboxes(&["sbx-race"]).await;
        let mut tasks = Vec::new();
        for i in 0..5 {
            let s = store.clone();
            tasks.push(tokio::spawn(async move {
                let o = liveness(
                    s,
                    &format!("replica-{i}"),
                    &format!("h-{i}:1"),
                    LIVENESS_TTL,
                );
                o.announce("sbx-race", &format!("session-{i}")).await
            }));
        }

        let mut wins = 0;
        for task in tasks {
            if task.await.unwrap().is_ok() {
                wins += 1;
            }
        }
        assert_eq!(wins, 5, "each replica writes its own row, so none contend");

        // Every row must be internally consistent: a torn write would pair one
        // replica's id with another's address or session.
        let o = liveness(store, "observer", "obs:1", LIVENESS_TTL);
        let holders = o.read_all("sbx-race").await.unwrap();
        assert_eq!(holders.len(), 5);
        for record in holders {
            let claimant = record
                .replica_id
                .strip_prefix("replica-")
                .expect("recorded replica should be one of the claimants");
            assert_eq!(record.advertise_address, format!("h-{claimant}:1"));
            assert_eq!(record.session_id, format!("session-{claimant}"));
        }
    }

    /// Expiry, not eviction, is what stops a row counting: a replica cannot
    /// remove a peer's row, so a peer that died leaves one behind and `lookup`
    /// has to age it out.
    #[tokio::test]
    async fn an_expired_peer_row_stops_being_a_redirect_target() {
        let store = store_with_sandboxes(&["sbx-steal"]).await;
        let dead = liveness(store.clone(), "replica-1", "a:1", Duration::ZERO);
        let observer = liveness(store.clone(), "replica-2", "b:2", Duration::ZERO);

        dead.announce("sbx-steal", "session-a").await.unwrap();

        assert_eq!(
            observer.read_all("sbx-steal").await.unwrap().len(),
            1,
            "the row is still stored"
        );
        assert!(
            observer.lookup("sbx-steal").await.unwrap().is_none(),
            "an expired row names a replica that stopped renewing"
        );
    }

    #[tokio::test]
    async fn late_withdraw_from_a_superseded_session_keeps_the_new_record() {
        let store = store_with_sandboxes(&["sbx-late-release"]).await;
        let o1 = liveness(store.clone(), "replica-1", "a:1", LIVENESS_TTL);
        let o2 = liveness(store.clone(), "replica-2", "b:2", LIVENESS_TTL);

        o1.announce("sbx-late-release", "session-a").await.unwrap();
        o2.announce("sbx-late-release", "session-b").await.unwrap();

        // Replica-1's session task finally winds down and releases. It can
        // only reach its own row, so replica-2's is untouchable by
        // construction — where a shared row made this a guard that had to
        // hold.
        assert!(o1.withdraw("sbx-late-release", "session-a").await.unwrap());

        let record = o2
            .lookup("sbx-late-release")
            .await
            .unwrap()
            .expect("the peer's record must survive another replica's release");
        assert_eq!(record.replica_id, "replica-2");
        assert_eq!(record.session_id, "session-b");
    }

    #[tokio::test]
    async fn reconnect_on_same_replica_reclaims() {
        let store = store_with_sandboxes(&["sbx-reconnect"]).await;
        let o = liveness(store, "replica-1", "a:1", LIVENESS_TTL);
        o.announce("sbx-reconnect", "session-a").await.unwrap();
        o.announce("sbx-reconnect", "session-b")
            .await
            .expect("same replica should be able to re-claim");

        let record = o.lookup("sbx-reconnect").await.unwrap().unwrap();
        assert_eq!(record.session_id, "session-b");
    }

    #[tokio::test]
    async fn lookup_returns_none_for_expired_record() {
        let store = store_with_sandboxes(&["sbx-expired"]).await;
        let o = liveness(store, "replica-1", "a:1", Duration::ZERO);
        o.announce("sbx-expired", "session-a").await.unwrap();

        assert!(o.lookup("sbx-expired").await.unwrap().is_none());
        assert!(
            o.read_own("sbx-expired").await.unwrap().is_some(),
            "record should still be stored, just not authoritative"
        );
    }

    #[tokio::test]
    async fn lookup_returns_none_when_absent() {
        let store = store_with_sandboxes(&["sbx-missing"]).await;
        let o = liveness(store, "replica-1", "a:1", LIVENESS_TTL);
        assert!(o.lookup("sbx-missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn renew_keeps_the_row_fresh() {
        let store = store_with_sandboxes(&["sbx-renew"]).await;
        let o = liveness(store, "replica-1", "a:1", LIVENESS_TTL);
        let mut claim = o.announce("sbx-renew", "session-a").await.unwrap();
        let v1 = claim.resource_version();

        o.renew("sbx-renew", &mut claim).await.unwrap();
        assert!(claim.resource_version() > v1);

        let record = o.lookup("sbx-renew").await.unwrap().unwrap();
        assert_eq!(record.resource_version, claim.resource_version());
    }

    /// The regression this keying exists to prevent.
    ///
    /// With one shared row, a peer's claim bumped the resource version and
    /// every subsequent renewal from this replica failed — for the life of the
    /// session, once per renewal interval. Worse than the noise: if the peer
    /// then died, its row expired while this replica was still serving, and
    /// "is anyone connected" answered no for a healthy sandbox.
    #[tokio::test]
    async fn a_peer_claim_does_not_break_our_renewal() {
        let store = store_with_sandboxes(&["sbx-lost"]).await;
        let o1 = liveness(store.clone(), "replica-1", "a:1", LIVENESS_TTL);
        let o2 = liveness(store.clone(), "replica-2", "b:2", LIVENESS_TTL);

        let mut claim = o1.announce("sbx-lost", "session-a").await.unwrap();
        o2.announce("sbx-lost", "session-b").await.unwrap();

        o1.renew("sbx-lost", &mut claim)
            .await
            .expect("a peer holding its own session must not invalidate ours");

        // And our row still names our session, not the peer's.
        let ours = o1.read_own("sbx-lost").await.unwrap().unwrap();
        assert_eq!(ours.replica_id, "replica-1");
        assert_eq!(ours.session_id, "session-a");
    }

    /// A replica may only delete its own row. That is what makes the
    /// cross-replica hazard structural rather than guarded: there is no write
    /// a peer can issue that removes a live holder's record.
    #[tokio::test]
    async fn withdrawing_our_row_leaves_a_peers_row_intact() {
        let store = store_with_sandboxes(&["sbx-peer-release"]).await;
        let o1 = liveness(store.clone(), "replica-1", "a:1", LIVENESS_TTL);
        let o2 = liveness(store.clone(), "replica-2", "b:2", LIVENESS_TTL);

        o1.announce("sbx-peer-release", "session-a").await.unwrap();
        o2.announce("sbx-peer-release", "session-b").await.unwrap();

        assert!(o1.withdraw("sbx-peer-release", "session-a").await.unwrap());

        let holders = o2.read_all("sbx-peer-release").await.unwrap();
        assert_eq!(holders.len(), 1);
        assert_eq!(holders[0].replica_id, "replica-2");
        assert_eq!(
            o2.lookup("sbx-peer-release")
                .await
                .unwrap()
                .expect("the surviving holder is still a redirect target")
                .session_id,
            "session-b"
        );
    }

    #[tokio::test]
    async fn release_removes_our_current_record() {
        let store = store_with_sandboxes(&["sbx-release"]).await;
        let o = liveness(store, "replica-1", "a:1", LIVENESS_TTL);
        o.announce("sbx-release", "session-a").await.unwrap();

        assert!(o.withdraw("sbx-release", "session-a").await.unwrap());
        assert!(o.read_own("sbx-release").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn withdraw_with_stale_session_id_keeps_current_record() {
        let store = store_with_sandboxes(&["sbx-stale"]).await;
        let o = liveness(store, "replica-1", "a:1", LIVENESS_TTL);
        o.announce("sbx-stale", "session-old").await.unwrap();
        o.announce("sbx-stale", "session-new").await.unwrap();

        assert!(
            !o.withdraw("sbx-stale", "session-old").await.unwrap(),
            "a superseded session must not release the current claim"
        );
        let record = o
            .lookup("sbx-stale")
            .await
            .unwrap()
            .expect("current liveness record must survive a stale release");
        assert_eq!(record.session_id, "session-new");
    }

    #[tokio::test]
    async fn release_from_other_replica_is_a_no_op() {
        let store = store_with_sandboxes(&["sbx-foreign"]).await;
        let o1 = liveness(store.clone(), "replica-1", "a:1", LIVENESS_TTL);
        let o2 = liveness(store.clone(), "replica-2", "b:2", LIVENESS_TTL);

        o1.announce("sbx-foreign", "session-a").await.unwrap();
        assert!(!o2.withdraw("sbx-foreign", "session-a").await.unwrap());
        assert!(o1.lookup("sbx-foreign").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn withdraw_when_absent_reports_false() {
        let store = store_with_sandboxes(&["sbx-none"]).await;
        let o = liveness(store, "replica-1", "a:1", LIVENESS_TTL);
        assert!(!o.withdraw("sbx-none", "session-a").await.unwrap());
    }

    #[test]
    fn expiry_clamps_future_timestamps_to_age_zero() {
        let now = 1_000_000;
        let future = now + 86_400_000;
        assert!(!record_is_expired(now, future, 1_000));
        assert!(record_is_expired(now, future, 0));
        assert!(!record_is_expired(now, now, 1_000));
        assert!(record_is_expired(now, now, 0));
    }

    #[test]
    fn advertise_address_prefers_explicit_override() {
        assert_eq!(
            build_advertise_address(
                Some("gateway-0.gw.openshell.svc.cluster.local:9443"),
                Some("10.1.2.3"),
                Some("gw.openshell.svc.cluster.local"),
                8080,
            ),
            "gateway-0.gw.openshell.svc.cluster.local:9443"
        );
    }

    #[test]
    fn advertise_address_builds_dashed_pod_dns() {
        assert_eq!(
            build_advertise_address(
                None,
                Some("10.1.2.3"),
                Some("gw.openshell.svc.cluster.local"),
                8080,
            ),
            "10-1-2-3.gw.openshell.svc.cluster.local:8080"
        );
    }

    #[test]
    fn advertise_address_tolerates_suffix_dots_and_ipv6() {
        assert_eq!(
            build_advertise_address(None, Some("10.1.2.3"), Some(".gw.ns.svc."), 8080),
            "10-1-2-3.gw.ns.svc:8080"
        );
        assert_eq!(
            build_advertise_address(None, Some("fd00::1"), Some("gw.ns.svc"), 8080),
            "fd00--1.gw.ns.svc:8080"
        );
    }

    #[test]
    fn advertise_address_empty_without_configuration() {
        assert!(build_advertise_address(None, None, None, 8080).is_empty());
        assert!(build_advertise_address(Some("  "), Some("10.1.2.3"), None, 8080).is_empty());
        assert!(build_advertise_address(None, Some("10.1.2.3"), Some(" "), 8080).is_empty());
        assert!(build_advertise_address(None, None, Some("gw.ns.svc"), 8080).is_empty());
    }

    #[tokio::test]
    async fn withdraw_all_removes_every_row_this_replica_wrote() {
        let store = store_with_sandboxes(&["sbx-all-0", "sbx-all-1", "sbx-all-2"]).await;
        let o = liveness(store, "replica-1", "a:1", LIVENESS_TTL);
        for i in 0..3 {
            o.announce(&format!("sbx-all-{i}"), &format!("session-{i}"))
                .await
                .unwrap();
        }

        let summary = o.release_all_owned().await;
        assert_eq!(
            summary,
            ReleaseAllSummary {
                released: 3,
                skipped: 0,
                failed: 0,
            }
        );
        for i in 0..3 {
            assert!(o.read_own(&format!("sbx-all-{i}")).await.unwrap().is_none());
        }

        // Idempotent: a second pass has nothing left to do.
        assert_eq!(o.release_all_owned().await, ReleaseAllSummary::default());
    }

    /// Shutdown must clear this replica's rows and only its own, so a peer
    /// still serving the same sandbox stays a redirect target. With a shared
    /// row this depended on a guard; with a row each it is structural, and
    /// this pins the outcome either way.
    #[tokio::test]
    async fn withdraw_all_leaves_a_peers_row_intact() {
        let store = store_with_sandboxes(&["sbx-shared", "sbx-ours-only"]).await;
        let o1 = liveness(store.clone(), "replica-1", "a:1", LIVENESS_TTL);
        let o2 = liveness(store.clone(), "replica-2", "b:2", LIVENESS_TTL);

        // sbx-shared is in both replicas' subsets; sbx-ours-only is in one.
        o1.announce("sbx-shared", "session-a").await.unwrap();
        o1.announce("sbx-ours-only", "session-c").await.unwrap();
        o2.announce("sbx-shared", "session-b").await.unwrap();

        let summary = o1.release_all_owned().await;
        assert_eq!(
            summary,
            ReleaseAllSummary {
                released: 2,
                skipped: 0,
                failed: 0,
            },
            "a replica releases exactly the rows it wrote"
        );

        let record = o2
            .lookup("sbx-shared")
            .await
            .unwrap()
            .expect("a peer still serving must survive this replica's shutdown");
        assert_eq!(record.replica_id, "replica-2");
        assert_eq!(record.session_id, "session-b");

        // The sandbox only this replica served now has no holder at all,
        // which is correct: nothing is serving it.
        assert!(o2.lookup("sbx-ours-only").await.unwrap().is_none());
        assert!(o1.read_own("sbx-ours-only").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn release_all_owned_reports_store_failures_instead_of_propagating() {
        let store = store_with_sandboxes(&["sbx-broken-1", "sbx-broken-2"]).await;
        let o = liveness(store.clone(), "replica-1", "a:1", LIVENESS_TTL);
        o.announce("sbx-broken-1", "session-a").await.unwrap();
        o.announce("sbx-broken-2", "session-b").await.unwrap();

        // Stand in for a store that has gone away mid-shutdown.
        store.close_for_test().await;

        let summary = o
            .withdraw_all_within(LIVENESS_RELEASE_ALL_TIMEOUT)
            .await
            .expect("a failing store must not stall the shutdown release");
        assert_eq!(summary.failed, 2);
        assert_eq!(summary.released, 0);
    }

    #[tokio::test]
    async fn withdraw_all_within_gives_up_when_the_work_outlasts_its_budget() {
        // A store that never answers. The caller must get `None` and carry on
        // rather than hang until the kubelet SIGKILLs it.
        let stalled = std::future::pending::<ReleaseAllSummary>();
        assert!(
            bounded_release(Duration::from_millis(10), stalled)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn withdraw_all_within_returns_the_summary_when_it_finishes() {
        let store = store_with_sandboxes(&["sbx-budget"]).await;
        let o = liveness(store, "replica-1", "a:1", LIVENESS_TTL);
        o.announce("sbx-budget", "session-a").await.unwrap();

        let summary = o
            .withdraw_all_within(LIVENESS_RELEASE_ALL_TIMEOUT)
            .await
            .expect("release should finish well inside its budget");
        assert_eq!(summary.released, 1);
    }

    #[tokio::test]
    async fn per_session_release_untracks_so_shutdown_has_nothing_to_do() {
        let store = store_with_sandboxes(&["sbx-tracked"]).await;
        let o = liveness(store, "replica-1", "a:1", LIVENESS_TTL);
        o.announce("sbx-tracked", "session-a").await.unwrap();
        assert!(o.withdraw("sbx-tracked", "session-a").await.unwrap());

        assert_eq!(o.release_all_owned().await, ReleaseAllSummary::default());
    }

    #[tokio::test]
    async fn a_superseded_session_withdraw_does_not_untrack_the_new_row() {
        let store = store_with_sandboxes(&["sbx-retrack"]).await;
        let o = liveness(store, "replica-1", "a:1", LIVENESS_TTL);
        o.announce("sbx-retrack", "session-old").await.unwrap();
        o.announce("sbx-retrack", "session-new").await.unwrap();

        // The old session's late release is a no-op and must leave the new
        // claim tracked, or shutdown would leave the record behind.
        assert!(!o.withdraw("sbx-retrack", "session-old").await.unwrap());
        assert_eq!(
            o.release_all_owned().await,
            ReleaseAllSummary {
                released: 1,
                skipped: 0,
                failed: 0,
            }
        );
        assert!(o.read_own("sbx-retrack").await.unwrap().is_none());
    }
}
