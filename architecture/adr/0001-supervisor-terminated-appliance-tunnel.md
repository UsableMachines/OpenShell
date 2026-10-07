# 1. Supervisor-terminated customer appliance tunnel

Date: 2026-10-02

Status: Proposed

## Context

Customer private services require a route from a sandbox to a customer appliance. A tunnel inside the workload would let decrypted packets leave the supervisor's policy point. A shared cluster exit would also couple customer routes and keys across sandboxes. The supervisor already authorizes explicit proxy destinations, inspects supported application traffic, and rewrites endpoint-bound credentials.

## Decision

Each sandbox supervisor owns its own userspace WireGuard interface and TCP stack. Its policy names the appliance's exact UDP endpoint and an inner destination endpoint that references the tunnel. The appliance endpoint is a supervisor-only transport exception; workload TCP cannot use it. The inner host and port remain ordinary policy objects. Destination validation and applicable L7 and credential handling stay in the existing proxy path, with the tunnel replacing only the final upstream TCP transport. A failed tunnel has no direct or corporate-proxy fallback.

The policy carries a reference to a sandbox-scoped provider credential containing the private key. The supervisor suppresses that environment key before workload startup and resolves it only in its own credential state. Key bytes do not enter policy persistence, policy introspection, or the workload environment. The first implementation accepts one named tunnel, one IPv4 literal destination and port, and one route bound to the initial policy generation. A later policy generation refuses tunnel dials until sandbox restart.

## Consequences

The supervisor remains the enforcement point for inner destinations. Tunnel keys and decrypted packets stay outside the workload. The appliance must expose a reachable WireGuard UDP listener and trust the supervisor peer key and tunnel source address. CONNECT establishes the upstream TCP stream after endpoint and address authorization, before its existing TLS and L7 request inspection; stricter pre-dial application authorization would require a separate CONNECT flow change. Tunnel DNS, hot reload and key rotation, multiple routes, IPv6, and alternate TCP carriers remain future work.
