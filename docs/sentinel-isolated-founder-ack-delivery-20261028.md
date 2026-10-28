# Sentinel P1 — isolated founder-only delivery and signed acknowledgement contract

**Draft only; source-only; no network, sender, customer account, SMTP, webhook, Resend or live alerts.** This document is an engineering contract, NOT authority to activate it on the Dell.

## Top three designs / selection
1. Send an email for every five-minute UP/DOWN report — REJECTED: floods, ambiguous status, lost messages, unverifiable recipient response.
2. Call external webhook before committing any state — REJECTED: crashes and duplicate send semantics; forged HTTP 200 can masquerade as delivery confirmation.
3. **SELECTED:** extend atomic pending signed-advisory outbox with a fixed founder-only route, change-only staging, durable claim leases/retries, and a cryptographically pinned Ed25519 ACK for a specific event, payload hash and unique lease nonce. No transport implementation exists. Provision a future owner-only delivery endpoint after independent review.

## Contract
- `noc/isolated_founder_delivery_protocol.py` only accepts a durable SQLite receiver database containing the signed-advisory outbox. Schema initialisation is explicit and only appropriate for a brand-new isolated scratch/approved database.
- The route ID is exactly `v79-founder-primary`; no email address, customer route or arbitrary URL can be selected from an observation.
- Signed `REPORTED_*_UNVERIFIED` status is **not** an independently verified service observation. It cannot claim actual protection or measured recovery.
- First all-UP advisory is a **suppressed baseline**, not proof of health. Repeated identical status snapshots are suppressed; changed fault/warning and later claimed recovery each create a pending review-only delivery job. This is not yet a complete event grouping/alert storm solution.
- `claim_founder_delivery` issues one durable 60-second lease with random nonce and payload SHA-256; multiple workers cannot claim concurrently. A lease is NOT proof that a message was sent. No network call exists.
- A future approved recipient must sign an ACK with a *separately pinned* Ed25519 endpoint private key. `accept_signed_founder_ack` verifies the pinned public key and exact event ID, fixed route, lease nonce, payload hash, accepted time and active lease before recording ACK. The simulated ACK key is ephemeral in CI.
- Failed simulated attempts return to PENDING with bounded exponential backoff (30 seconds initially, capped at 3600s) and stop in PAUSED manual-review after five attempts. Expired leases can be reclaimed; an expired previously leased delivery cannot use its old ACK.
- No private keys, tokens, customer details, raw IPs, unbounded messages or raw URL observations are stored in the founder-delivery queue. It never calls the provider, sends mail, changes Hub, creates Tiquet tickets, or restarts anything.

## REDTEAM and HOLD
1. **Recipient spoofing and compromised founder route:** fixed route ID and pinned ACK key are necessary but not sufficient: endpoint ownership, key custody, rotation, deletion/revocation, mTLS/authenticated transport and founder MFA remain unproven. Do not substitute a spoofable HTTP 200 or callback with an arbitrary address.
2. **At least once versus exactly once:** a crash after actual external delivery but before recording ACK can cause a duplicate on retry. A future provider must enforce persistent idempotency by `eventId`, and return the SAME authenticated ACK for repeats. Local leases alone do not guarantee exactly-once delivery.
3. **Blindness:** same-host monitor outage cannot produce its own down event; integrate independent off-host observation and classify stale/unknown before any trust promotion. A signed advisory is just a signed claim and cannot prove real probes.
4. **Incident lifecycle:** transition suppression uses the full set of reported signals. Further review needed for flapping, multiple incidents, rate limits, planned maintenance, stale/out-of-order events and suppressed hazards.
5. **Compromised SQLite/signer:** no trust in mixed NOC or monitor writable volumes; independent access control, origin attestation, immutable high-water/counter, recovery and transactional outbox review remain required. A compromised signer can sign fictitious measurements.
6. **Founder-only delivery** is NOT yet implemented as a real connection; there is no real email/webhook address, host access, OAuth, Resend authorization, subscription, delivery receipt or measured end-to-end alert. No Tiquet auto-incident, payment or Hub admin credentials permitted.
7. Existing PRs #21-23 remain draft and unmerged; inherited GitGuardian and independent security review, immutable exact build digest, supervised fault→delivery→recovery proof and separate owner authorization are still mandatory before any production integration.

**Acceptance:** synthetic tests demonstrate ACK forgery denial, fixed routing, durable replay/dedup/lease/backoff, no network activation. Passing isolated CI is not a production release gate.
