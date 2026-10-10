---
name: openshell-policy-advisor
description: Use when an OpenShell sandbox returns policy_denied, mentions policy.local, or needs a narrow network policy proposal.
---

# OpenShell Policy Advisor

When a request fails with `policy_denied` or `upstream_tls_failed`, read the `advisor` object in the response. The supervisor creates a pending proposal and includes its `proposal_id`. Tell the user what failed and which proposal needs review. For API details, read `/etc/openshell/skills/policy_advisor.md`. Wait on `http://policy.local/v1/proposals/{proposal_id}/wait?timeout=300`; retry only after approval with `policy_reloaded: true`.

For a self-signed internal HTTPS service, an endpoint proposal may include `upstream_ca_pem` containing the service owner's PEM CA certificate bundle. Scope it to the exact host and port. This requires developer review even in auto mode.

For `upstream_tls_failed` with `certificate_verification_failed`, the draft has an empty `upstream_ca_pem` slot. Ask the user or service owner for the verified CA PEM so a reviewer can add it to the existing proposal. Do not disable TLS verification or copy an unverified certificate from the failed connection. If no `proposal_id` is present, report that proposal submission failed; do not claim a card exists.
