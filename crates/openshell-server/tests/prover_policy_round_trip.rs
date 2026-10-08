// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Regression for the incident where the gateway prover rejected every
//! mechanistic advisor proposal with "parse policy failed: parsing policy
//! YAML": the supervisor's binary placeholder `-` was copied verbatim into
//! the proposed rule's `binaries` list, and `serialize_sandbox_policy`
//! emits it as the plain YAML scalar `path: -`, which libyaml re-parses as
//! a block-sequence indicator. The placeholder is now filtered at the
//! source (`mechanistic_mapper::is_unknown_binary`, covered by that
//! crate's `test_generate_proposals_placeholder_binary_is_unknown`).
//!
//! This test pins the gateway-side contract independently: the candidate
//! policy the prover validates for a standard mechanistic proposal — the
//! chart's baseline policy merged with an advisor-proposed `allow` rule
//! that has NO binaries — must survive the exact round-trip
//! `run_prover_findings` performs: `merge_policy` →
//! `serialize_sandbox_policy` → prover `parse_policy_str`.
use openshell_core::proto::{
    FilesystemPolicy, LandlockPolicy, NetworkEndpoint, NetworkPolicyRule, ProcessPolicy,
    SandboxPolicy,
};
use openshell_policy::{PolicyMergeOp, merge_policy, serialize_sandbox_policy};
use openshell_prover::policy::parse_policy_str;

fn chart_baseline_policy() -> SandboxPolicy {
    SandboxPolicy {
        version: 1,
        filesystem: Some(FilesystemPolicy {
            include_workdir: true,
            read_only: [
                "/usr",
                "/app",
                "/lib",
                "/lib64",
                "/bin",
                "/sbin",
                "/proc",
                "/dev/urandom",
                "/etc",
                "/var/lib/dpkg",
                "/var/log",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            read_write: ["/sandbox", "/tmp", "/dev/null"]
                .into_iter()
                .map(String::from)
                .collect(),
        }),
        landlock: Some(LandlockPolicy {
            compatibility: "best_effort".to_string(),
        }),
        process: Some(ProcessPolicy {
            run_as_user: "sandbox".to_string(),
            run_as_group: "sandbox".to_string(),
        }),
        ..Default::default()
    }
}

#[test]
fn mechanistic_candidate_policy_survives_prover_round_trip() {
    // The rule shape the (fixed) mechanistic mapper emits for a 443 CONNECT
    // denial with an unresolvable binary: advisor-proposed endpoint, no
    // binaries list.
    let rule = NetworkPolicyRule {
        name: "allow_example_com_443".to_string(),
        endpoints: vec![NetworkEndpoint {
            host: "example.com".to_string(),
            port: 443,
            ports: vec![443],
            advisor_proposed: true,
            ..Default::default()
        }],
        binaries: vec![],
    };

    let merged = merge_policy(
        chart_baseline_policy(),
        &[PolicyMergeOp::AddRule {
            rule_name: "allow_example_com_443".to_string(),
            rule,
        }],
    )
    .expect("merge")
    .policy;

    let yaml = serialize_sandbox_policy(&merged).expect("serialize");
    let model = parse_policy_str(&yaml)
        .unwrap_or_else(|e| panic!("prover must parse the candidate policy YAML: {e:?}"));
    assert_eq!(model.network_policies.len(), 1);
}

#[test]
fn ca_endpoints_survive_prover_round_trip() {
    // Scenario-4 preflight: an advisor rule carrying upstream_ca_pem (PEM
    // is multiline) must survive the same round-trip. The merge layer
    // validates PEM usability, so this is a real self-signed test CA
    // (CN=Scenario4 Test CA, generated with `openssl req -x509`, 30 days).
    let pem = "-----BEGIN CERTIFICATE-----\n\
MIIC+DCCAeCgAwIBAgIUNEncXTLhXQA4KBuy9ftpw916z5AwDQYJKoZIhvcNAQEL\n\
BQAwHDEaMBgGA1UEAwwRU2NlbmFyaW80IFRlc3QgQ0EwHhcNMjYxMDA2MjIxMTAz\n\
WhcNMjYxMTA1MjIxMTAzWjAcMRowGAYDVQQDDBFTY2VuYXJpbzQgVGVzdCBDQTCC\n\
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOWjtqT4lhauCFHVwWriaE/d\n\
ZGtuwdoEpwOoVuXnZNQpGpS3ixnqgj9TkrXZ+FpR00HKLKZBi3l+unTld0PPKuX2\n\
PQemNPVQjr0qC/CL4lINO+lgZhfj/P/F9PGba8Hn/Xb61uyOKT0bemlv4FkcwlWH\n\
Pz+Z4TwuI8kFqoFOyKCNsaL2QunuHkHMXV5YXPhRm1DDoXBhsc54T3iUwoT6NGre\n\
d3q56X2nUMbCprjRHbnyo7ojQUZSKR7LulILJut2fkXPKnZiC8DbRZ677TylmMPg\n\
unN4gNqcqDyThgcEU9q7CRIOcJrwem/jrSzHutle6rJbPSy7eNJvHrT4UKkVOl8C\n\
AwEAAaMyMDAwHQYDVR0OBBYEFFEQDdwGHtgjBzqMDGovE/GtocmQMA8GA1UdEwEB\n\
/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAA9SL33DKzU3WcA1xMg8j/ytcDQB\n\
ssVipgLXjPB63udmu+r/p0Pff7hHychWZLipTrEmecoDzo5NzivFJ/S5U5e5LfPv\n\
02JKXQyRztxPdOW2xQCOx3JHAljiU/ONBVEwxkbnL6jMyOzE4wWyzQpgdZf9RzW3\n\
S5hY8l/LtmqVrccQ/Krq0IoYIp5wz3QdWZqLjo48ckEiRr/Q+vpDK4WQ8RVUqDyK\n\
r4k+hyyDcMqhRI/PzW0h8WKOONv7dAKD1KnBwT6cm3Bd8J3k2tDbf4FHCVkNEOmj\n\
YP4/4Z280GURxsg2At97z3Tl05WTvsb1rwZ4KvK7OQJcoyMAPmFFGg5ocSI=\n\
-----END CERTIFICATE-----\n";
    let rule = NetworkPolicyRule {
        name: "allow_ca_host_8443".to_string(),
        endpoints: vec![NetworkEndpoint {
            host: "ca-host.internal".to_string(),
            port: 8443,
            ports: vec![8443],
            upstream_ca_pem: pem.to_string(),
            advisor_proposed: true,
            ..Default::default()
        }],
        binaries: vec![],
    };
    let merged = merge_policy(
        chart_baseline_policy(),
        &[PolicyMergeOp::AddRule {
            rule_name: rule.name.clone(),
            rule,
        }],
    )
    .expect("merge")
    .policy;
    let yaml = serialize_sandbox_policy(&merged).expect("serialize");
    let model = parse_policy_str(&yaml)
        .unwrap_or_else(|e| panic!("prover must parse CA-bearing candidate policy: {e:?}"));
    assert_eq!(model.network_policies.len(), 1);
    let ep = &model.network_policies.values().next().unwrap().endpoints[0];
    assert_eq!(ep.host, "ca-host.internal");
}
