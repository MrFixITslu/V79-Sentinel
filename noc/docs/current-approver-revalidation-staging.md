# Sentinel current administrator authorization — isolated staging

Date: 2026-10-10 AST. NOT CONNECTED TO PRODUCTION.

`noc/sentinel_reviewer_status.py` checks the NOC SQLite approval issuance
ledger against the named currently enabled administrator, the current
`admin` role, enrolled MFA, accepted MFA counter, exact approval UUID,
approval time, the approved owner Hub organization and Sentinel customer,
and the ten-minute validity window. A missing/malformed issuance record or
missing table is denied, not accepted.

The verifier is a **pure local NOC check**. It is not an authenticated
network API, not wired to V79Tiquet, and does not issue keys or change
administrator accounts. Staging tests verify immediate revocation,
role downgrades, MFA removal, expired approvals and cross-tenant/malformed
scopes. Production live ticket creation stays OFF without a separate
reviewed authenticated service-to-service transport that queries it.

The existing Tiquet receiver already requires an independent
`authorizeApprover` callback on every ticket.create delivery; it must
remain unwired and fail closed until this trusted check is made reachable
through separately approved, private service identity controls.
