# Stage 2 — Resend founder-only notification adapter (SOURCE-ONLY, 28 October 2026)

**NO EMAIL SENT. NO LIVE TOKEN/KEY, NO SERVER DEPLOYMENT, NO HUB/WIPAY ACCESS.** This adapter only formats an isolated Resend-compatible transactional email and records its local request intent and provider-acceptance metadata in a disposable or independently approved SQLite receiver store.

## Provider account readiness (read-only account inspection)
Resend `v79sl.com` supports outbound sending, with DKIM and two sending SPF CNAME checks verified. The domain is `partially_failed` due to separate link-tracking CNAME issues. Link tracking should remain OFF for system/security alerts; don't edit DNS, enable opens/clicks, or claim email deliverability without a real test.

A verified domain does **not** confer permission to invent a From address: owner must choose the exact sender address and approve the known founder recipient before live tests. A valid From address on a sending-enabled domain is not itself a proof of delivery.

## Brainstorm (3 paths) and REDTEAM
1. Put Resend API credentials in Sentinel monitor and send emails on every DOWN — REJECTED: live secrets leakage, duplicate storms and single-host blindness.
2. Treat Resend's `send-email` success as the existing Ed25519 founder ACK — REJECTED: provider acceptance is not mailbox delivery or founder acknowledgement, and Resend does not produce the app's signed ACK.
3. **Selected:** isolated durable, fixed-route Resend *request adapter*, stable per-event idempotency, strict sender and recipient allowlists, no network code, and explicit separation of provider-acceptance from `ACKED` state.

## Implementation
- `noc/isolated_resend_founder_adapter.py` requires an active founder lease from PR #24, matching payload hash, an explicit same-domain sender and founder recipient, and a protected sender/recipient allowlist from owner-approved configuration. Produces only `from`, `to`, `subject`, `text`, and stable `idempotencyKey`. It does not import Resend client, call email API, read secrets, configure webhooks or send messages.
- A separate SQLite `resend_founder_submission` table records immutable request SHA-256, stable idempotency key, event ID and first reservation time. Retried claims produce byte-identical requests. Any payload/config mismatch is HOLD. Attempts at or beyond 23h after first reservation are HOLD, avoiding Resend's documented 24h idempotency key retention expiry.
- `record_resend_submission_response()` records a response-shaped provider email ID only if called by a future independently authenticated Resend client. This **does not change** founder queue state to ACKED or prove that anything reached the recipient's mailbox.
- All test addresses are FICTIONAL fixtures. Synthetic tests use ephemeral keys, isolated SQLite and zero network traffic.
- Repo CI `sentinel-resend-founder-contract.yml` runs the entire isolated source→receiver→founder protocol suite plus adapter tests.

## Release and operational security HOLDs
- **Real test needs explicit From selection**, owner-approved recipient, and an externally authenticated client. A successful API response still requires `get_email` or verified Resend `email.delivered` evidence; no automatically generated local Ed25519 founder ACK may be fabricated.
- Resend idempotency keys last approximately **24 hours**. Transport retries beyond that interval risk duplicate email. This adapter stops at 23h; manual operator reconciliation required.
- Webhook events must verify original raw-body Svix signature, timestamp and replay identity against pinned provider signing secret; public internet endpoint and secret rotation require independent review. A webhook that claims `delivered` is provider delivery evidence, not evidence the founder read the email.
- Existing PR #24 signed ACK protocol requires a separately provisioned trusted recipient signing key and authenticated receipt; Resend cannot replace it. Do not mark ACKED merely because Resend accepted the send or email was delivered.
- Off-host monitoring to catch Dell outages, actual source-origin attestation, GitGuardian/independent reviewer clearance, protected signing and owner-only recipient creds, restore/rollback and immutable digest remain P1 HOLD. Do not merge/deploy this draft automatically.

References: Resend Idempotency Keys (2025-05-01), Resend Webhooks documentation. **No provider email sent or production changed by this development artifact.**
