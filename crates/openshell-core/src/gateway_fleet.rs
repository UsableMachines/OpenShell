// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway fleet membership, and which replicas serve a given sandbox.
//!
//! A supervisor session is affine to the gateway replica holding it: the
//! relay a gateway asks for comes back as an HTTP/2 stream on the *same*
//! connection as the control stream, so only that replica can serve it. The
//! way to stop that being a routing problem is for a supervisor to hold a
//! session to several replicas at once, and for callers to address one of
//! those replicas directly.
//!
//! Which replicas is decided by hashing rather than by agreement, so nothing
//! has to be exchanged and no component has to be reachable for another to
//! make progress. Every participant needs three things to agree:
//!
//! 1. **The same membership.** The A records of the gateway's headless
//!    Service, which enumerate its ready pods. DNS is the only membership
//!    source available to a supervisor — it has no Kubernetes API access by
//!    design and gets none.
//! 2. **The same name for a member.** [`member_address`] builds the per-pod
//!    address `<dashed-pod-ip>.<headless-service>:<port>`, matching what a
//!    gateway advertises for itself. A member is identified by the string
//!    used to dial it, so agreement on the identity and agreement on the
//!    route are the same fact.
//! 3. **The same subset function.** [`subset_for`] is rendezvous hashing
//!    over SHA-256, chosen so a second implementation can reproduce it from
//!    this description alone — `sandbox-api` has one in TypeScript.
//!
//! Note what the hash is *not* for. It never has to be right for a request to
//! be routed correctly: a gateway that is not in a sandbox's subset says so
//! immediately, and the caller tries the next member. Disagreement costs a
//! round trip, not a failure.
//!
//! # The headless Service name is also the per-pod suffix
//!
//! For a headless Service, `<svc>.<ns>.svc.cluster.local` resolves to every
//! ready pod IP, and each pod is *also* addressable at
//! `<dashed-pod-ip>.<svc>.<ns>.svc.cluster.local`. One name therefore serves
//! as both the membership query and the per-pod suffix, which is why this
//! module takes a single `dns_name` rather than two values that would have to
//! be kept equal.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

use sha2::{Digest, Sha256};

/// Headless Service DNS name whose A records enumerate the gateway fleet.
///
/// Unset means single-endpoint mode: callers connect to whatever endpoint
/// they were configured with and this module stays out of the way. That is
/// the correct behavior for the Docker, Podman and VM drivers, for local
/// development, and for any single-replica deployment.
pub const FLEET_DNS_NAME_ENV: &str = "OPENSHELL_FLEET_DNS_NAME";

/// Number of gateway replicas that hold a session for each sandbox.
pub const FLEET_SUBSET_SIZE_ENV: &str = "OPENSHELL_FLEET_SUBSET_SIZE";

/// How often membership is re-resolved from DNS.
pub const FLEET_REFRESH_SECS_ENV: &str = "OPENSHELL_FLEET_REFRESH_SECS";

/// How long a supervisor keeps a session to a replica that has left the
/// subset. See [`FleetConfig::drain`].
pub const FLEET_DRAIN_SECS_ENV: &str = "OPENSHELL_FLEET_DRAIN_SECS";

/// Two replicas per sandbox: one may be lost without the sandbox becoming
/// unreachable, which is the whole point, and the stream cost is the smallest
/// that buys it.
pub const DEFAULT_SUBSET_SIZE: usize = 2;

/// Default DNS re-resolve interval.
///
/// Frequent enough that a new replica picks up its share of sessions in well
/// under the liveness TTL, cheap enough to be unremarkable — a DNS query per
/// sandbox per interval, answered by the node-local cache.
pub const DEFAULT_REFRESH: Duration = Duration::from_secs(20);

/// Default grace period before a departed subset member is dropped.
///
/// Long enough to cover the skew between two components' views of membership,
/// which is bounded by the record TTL plus a re-resolve interval on each side.
/// Held connections are the only cost, and only during churn.
pub const DEFAULT_DRAIN: Duration = Duration::from_mins(2);

/// Fleet-mode configuration. Absent means single-endpoint mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetConfig {
    /// Headless Service name: both the membership query and the per-pod
    /// suffix. See the module docs.
    pub dns_name: String,
    /// gRPC port every replica listens on.
    pub port: u16,
    /// Replicas per sandbox.
    pub subset_size: usize,
    /// DNS re-resolve interval.
    pub refresh: Duration,
    /// Grace period before a session to a departed subset member is dropped.
    ///
    /// A membership change moves a sandbox's subset, and the two sides notice
    /// at different times. Connecting to the new members *before* dropping
    /// the old ones means that during the window a supervisor's connections
    /// are the union of both views — so a caller's pick from either view is
    /// one it holds, whichever view the caller has. Overlap alone would not
    /// give that: the requirement is on the pick, not on the sets.
    pub drain: Duration,
}

impl FleetConfig {
    /// Read fleet configuration from the environment.
    ///
    /// Returns `None` when [`FLEET_DNS_NAME_ENV`] is unset or empty, which
    /// selects single-endpoint mode. A malformed size or interval falls back
    /// to its default rather than failing: a typo in a tuning value must not
    /// stop a sandbox from connecting.
    #[must_use]
    pub fn from_env(port: u16) -> Option<Self> {
        Self::from_values(
            std::env::var(FLEET_DNS_NAME_ENV).ok().as_deref(),
            std::env::var(FLEET_SUBSET_SIZE_ENV).ok().as_deref(),
            std::env::var(FLEET_REFRESH_SECS_ENV).ok().as_deref(),
            std::env::var(FLEET_DRAIN_SECS_ENV).ok().as_deref(),
            port,
        )
    }

    fn from_values(
        dns_name: Option<&str>,
        subset_size: Option<&str>,
        refresh_secs: Option<&str>,
        drain_secs: Option<&str>,
        port: u16,
    ) -> Option<Self> {
        let dns_name = dns_name
            .map(|name| name.trim().trim_matches('.'))
            .filter(|name| !name.is_empty())?;

        Some(Self {
            dns_name: dns_name.to_string(),
            port,
            subset_size: parse_positive(subset_size).unwrap_or(DEFAULT_SUBSET_SIZE),
            refresh: parse_secs(refresh_secs).unwrap_or(DEFAULT_REFRESH),
            // A zero drain is meaningful — "drop immediately" — so it is
            // accepted here where a zero subset size is not.
            drain: parse_secs_allowing_zero(drain_secs).unwrap_or(DEFAULT_DRAIN),
        })
    }
}

fn parse_positive(value: Option<&str>) -> Option<usize> {
    value?.trim().parse::<usize>().ok().filter(|v| *v > 0)
}

fn parse_secs(value: Option<&str>) -> Option<Duration> {
    parse_positive(value).map(|secs| Duration::from_secs(secs as u64))
}

fn parse_secs_allowing_zero(value: Option<&str>) -> Option<Duration> {
    value?.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// Build the address of one fleet member.
///
/// This is the member's *identity* as well as its route: every component
/// derives it the same way from an IP, so they agree on membership without
/// exchanging anything.
///
/// The dashed form matches Kubernetes' per-pod headless records and the
/// address a gateway advertises for itself. IPv6 is dashed the same way for
/// consistency with that advertised form; a cluster running the gateway on
/// IPv6 pod networking needs its own record shape and is not supported here.
#[must_use]
pub fn member_address(ip: IpAddr, dns_name: &str, port: u16) -> String {
    let dashed = ip.to_string().replace(['.', ':'], "-");
    let dns_name = dns_name.trim().trim_matches('.');
    format!("{dashed}.{dns_name}:{port}")
}

/// Resolve current fleet membership from DNS.
///
/// Returns member addresses in sorted order. Sorting is not required for
/// correctness — [`subset_for`] breaks score ties by member name — but it
/// makes membership comparable between polls, so a change can be detected
/// without a set difference.
///
/// An empty result is returned as `Ok(vec![])` rather than an error: a
/// headless Service that answers with no ready endpoints is a real state,
/// distinct from being unable to ask. Callers treat "cannot ask" and "nobody
/// there" differently — neither is a reason to discard a working connection.
/// A name nobody publishes at all is the first of those, not the second.
///
/// The nameservers are queried directly rather than through `getaddrinfo`.
/// Membership is re-resolved on an interval precisely to notice a replica
/// arriving or leaving, and a platform resolver cache can return a view older
/// than that interval without saying so. See [`crate::fleet_dns`].
///
/// A records only. The dashed per-pod names this builds are IPv4 shaped, and
/// a cluster running the gateway on IPv6 pod networking needs its own record
/// shape before anything here would help it.
pub async fn resolve_members(dns_name: &str, port: u16) -> std::io::Result<Vec<String>> {
    let name = dns_name.trim().trim_matches('.');
    // Absolute, so no search list applies: the caller's name is already fully
    // qualified and completing it further could only find something else.
    let addresses = crate::fleet_dns::resolve_a(&format!("{name}.")).await?;

    // Through a BTreeSet: a Service can publish the same address twice, and
    // the result must be stable.
    let members: BTreeSet<String> = addresses
        .into_iter()
        .map(|address| member_address(address, dns_name, port))
        .collect();
    Ok(members.into_iter().collect())
}

/// The replicas that serve `sandbox_id`, in preference order.
///
/// Rendezvous hashing: score every member against the sandbox id and take the
/// highest `subset_size`. Adding or removing a member changes at most one
/// entry of any subset, so membership churn moves as few sessions as it can.
///
/// The returned order is the order a caller should try, and every member of
/// the subset can serve — a caller needs the set, not a specific node.
///
/// # Reproducing this
///
/// A member's score is the first 8 bytes, big-endian, of
/// `SHA-256(member || 0x00 || sandbox_id)`. Members sort by score descending,
/// ties by member name ascending. The `0x00` separator keeps the concatenation
/// unambiguous, so no member/sandbox pair can collide with another by
/// straddling the boundary.
#[must_use]
pub fn subset_for(sandbox_id: &str, members: &[String], subset_size: usize) -> Vec<String> {
    let mut scored: Vec<(u64, &String)> = members
        .iter()
        .map(|member| (member_score(member, sandbox_id), member))
        .collect();

    scored.sort_by(|(left_score, left), (right_score, right)| {
        right_score.cmp(left_score).then_with(|| left.cmp(right))
    });

    scored
        .into_iter()
        .take(subset_size)
        .map(|(_, member)| member.clone())
        .collect()
}

fn member_score(member: &str, sandbox_id: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(member.as_bytes());
    hasher.update([0u8]);
    hasher.update(sandbox_id.as_bytes());
    let digest = hasher.finalize();

    let mut score = [0u8; 8];
    score.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(score)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members(count: usize) -> Vec<String> {
        (1..=count)
            .map(|i| {
                member_address(
                    format!("10.42.0.{i}").parse().unwrap(),
                    "openshell-headless.sandbox.svc.cluster.local",
                    8080,
                )
            })
            .collect()
    }

    #[test]
    fn member_address_matches_the_kubernetes_per_pod_record_shape() {
        assert_eq!(
            member_address(
                "10.42.0.150".parse().unwrap(),
                "openshell-headless.sandbox.svc.cluster.local",
                8080
            ),
            "10-42-0-150.openshell-headless.sandbox.svc.cluster.local:8080"
        );
    }

    /// The chart may render the suffix with a trailing dot or stray spacing;
    /// a member address that differs by punctuation is a *different member*
    /// to every hash, so normalization has to happen here and not at call
    /// sites.
    #[test]
    fn member_address_normalizes_the_dns_name() {
        let canonical = member_address(
            "10.42.0.1".parse().unwrap(),
            "openshell-headless.ns.svc",
            80,
        );
        assert_eq!(
            member_address(
                "10.42.0.1".parse().unwrap(),
                " openshell-headless.ns.svc. ",
                80
            ),
            canonical
        );
    }

    #[test]
    fn subset_is_the_requested_size_and_drawn_from_the_members() {
        let members = members(5);
        let subset = subset_for("sbx-1", &members, 2);
        assert_eq!(subset.len(), 2);
        assert_ne!(subset[0], subset[1]);
        for member in &subset {
            assert!(members.contains(member));
        }
    }

    #[test]
    fn subset_is_stable_for_the_same_inputs() {
        let members = members(5);
        assert_eq!(
            subset_for("sbx-1", &members, 2),
            subset_for("sbx-1", &members, 2)
        );
    }

    /// Member *order* must not change the answer: two components resolving
    /// the same fleet in a different order have to pick the same subset.
    #[test]
    fn subset_ignores_member_ordering() {
        let members = members(5);
        let mut reversed = members.clone();
        reversed.reverse();
        assert_eq!(
            subset_for("sbx-1", &members, 2),
            subset_for("sbx-1", &reversed, 2)
        );
    }

    #[test]
    fn subset_saturates_at_the_fleet_size() {
        let members = members(2);
        assert_eq!(subset_for("sbx-1", &members, 5).len(), 2);
        assert!(subset_for("sbx-1", &[], 2).is_empty());
    }

    /// The bounded-movement property subsetting depends on: losing one
    /// replica must not reshuffle a sandbox onto two new ones, or a rolling
    /// restart would move every session repeatedly.
    #[test]
    fn removing_one_member_moves_at_most_one_subset_entry() {
        let members = members(6);
        for id in 0..200 {
            let sandbox_id = format!("sbx-{id}");
            let before = subset_for(&sandbox_id, &members, 3);
            for removed in 0..members.len() {
                let mut smaller = members.clone();
                smaller.remove(removed);
                let after = subset_for(&sandbox_id, &smaller, 3);
                let departed = before.iter().filter(|m| !after.contains(m)).count();
                assert!(
                    departed <= 1,
                    "removing {} moved {departed} entries for {sandbox_id}",
                    members[removed]
                );
            }
        }
    }

    /// Different sandboxes must not all land on the same replicas, or
    /// subsetting concentrates load instead of spreading it.
    #[test]
    fn subsets_spread_across_the_fleet() {
        let members = members(6);
        let mut counts = std::collections::HashMap::new();
        for id in 0..600 {
            for member in subset_for(&format!("sbx-{id}"), &members, 2) {
                *counts.entry(member).or_insert(0usize) += 1;
            }
        }
        assert_eq!(counts.len(), members.len());
        // 600 sandboxes x 2 slots over 6 members is 200 each; allow wide
        // slack so this asserts "spread", not a distribution quality bar.
        for (member, count) in counts {
            assert!(
                (100..=320).contains(&count),
                "{member} took {count} of 1200 slots"
            );
        }
    }

    /// Pins the wire contract the TypeScript implementation in `sandbox-api`
    /// has to reproduce. If this changes, that one is wrong until it changes
    /// too — and the two sides silently stop agreeing on routing.
    #[test]
    fn member_score_is_the_documented_digest_prefix() {
        assert_eq!(member_score("gateway-a", "sbx-1"), {
            let mut hasher = Sha256::new();
            hasher.update(b"gateway-a\0sbx-1");
            let digest = hasher.finalize();
            u64::from_be_bytes(digest[..8].try_into().unwrap())
        });
    }

    /// The separator has to make the concatenation unambiguous, or a member
    /// name ending in a sandbox-id prefix scores as a different pair.
    #[test]
    fn member_and_sandbox_id_cannot_straddle_the_separator() {
        assert_ne!(member_score("ab", "c"), member_score("a", "bc"));
    }

    #[test]
    fn no_fleet_dns_name_means_single_endpoint_mode() {
        assert!(FleetConfig::from_values(None, None, None, None, 8080).is_none());
        assert!(FleetConfig::from_values(Some("  "), None, None, None, 8080).is_none());
    }

    #[test]
    fn fleet_config_defaults_the_tuning_values() {
        let config =
            FleetConfig::from_values(Some("openshell-headless.ns.svc"), None, None, None, 8080)
                .expect("dns name given");
        assert_eq!(config.subset_size, DEFAULT_SUBSET_SIZE);
        assert_eq!(config.refresh, DEFAULT_REFRESH);
        assert_eq!(config.drain, DEFAULT_DRAIN);
    }

    /// A typo in a tuning value must not stop a sandbox connecting, so bad
    /// input falls back to the default instead of failing.
    #[test]
    fn fleet_config_falls_back_on_unusable_tuning_values() {
        let config = FleetConfig::from_values(
            Some("openshell-headless.ns.svc"),
            Some("nonsense"),
            Some("0"),
            Some("-1"),
            8080,
        )
        .expect("dns name given");
        assert_eq!(config.subset_size, DEFAULT_SUBSET_SIZE);
        assert_eq!(config.refresh, DEFAULT_REFRESH);
        assert_eq!(config.drain, DEFAULT_DRAIN);
    }

    /// Zero drain is a deliberate setting — drop departed members at once —
    /// and is distinguishable from unset.
    #[test]
    fn fleet_config_accepts_a_zero_drain() {
        let config = FleetConfig::from_values(
            Some("openshell-headless.ns.svc"),
            None,
            None,
            Some("0"),
            8080,
        )
        .expect("dns name given");
        assert_eq!(config.drain, Duration::ZERO);
    }

    /// The golden vectors, byte for byte, against the checked-in file that
    /// sandbox-api's mirror of this function also reads.
    ///
    /// A test that re-derives the expected order from the same primitives —
    /// sha256, the `0x00` separator, the big-endian first eight bytes — passes
    /// on both sides of a divergence, because each side re-derives against
    /// itself. Only a literal both implementations must reproduce fails when
    /// they drift, which is the seam this whole scheme depends on: a mismatch
    /// costs an extra round trip per exec and raises no error anywhere.
    ///
    /// Regenerate with `cargo run --example subset_vectors` only when the
    /// wire contract is deliberately changing, and change the copy under
    /// `backend/sandbox/api/src/openshell/` in the same change.
    #[test]
    fn subset_for_reproduces_the_golden_vectors() {
        let fixture = include_str!("../tests/fixtures/subset_vectors.txt");
        let members: Vec<String> = (1..=7)
            .map(|i| format!("10-42-0-{i}.openshell-headless.sandbox.svc.cluster.local:8080"))
            .collect();

        let mut checked = 0;
        for line in fixture.lines().filter(|l| !l.trim().is_empty()) {
            let mut parts = line.split('|');
            let sandbox_id = parts.next().expect("sandbox id field");
            let subset_size: usize = parts
                .next()
                .expect("subset size field")
                .parse()
                .expect("subset size parses");
            let expected = parts.next().expect("expected subset field");

            let actual = subset_for(sandbox_id, &members, subset_size).join(",");
            assert_eq!(
                actual, expected,
                "subset drifted for {sandbox_id}/{subset_size}"
            );
            checked += 1;
        }

        assert_eq!(checked, 15, "the fixture lost cases");
    }

    #[tokio::test]
    async fn resolve_members_reports_a_name_it_cannot_ask_about() {
        let error = resolve_members("openshell-headless.invalid", 8080).await;
        assert!(
            error.is_err(),
            "an unresolvable name must not read as an empty fleet"
        );
    }

    #[tokio::test]
    async fn resolve_members_builds_addresses_from_resolved_ips() {
        let members = resolve_members("localhost", 8080)
            .await
            .expect("localhost resolves");
        assert!(!members.is_empty());
        for member in &members {
            assert!(
                member.ends_with(".localhost:8080"),
                "unexpected member {member}"
            );
        }
    }
}
