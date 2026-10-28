# Private Sentinel signer: source review and activation hold

**28 October 2026 — SIGNER NOT INSTALLED. No private signing key created, no production database changed, no monitoring process changed, no email sent.**

## Accepted live facts

- Founder verified existing Dell monitor source matches GitHub main, is nonroot and `--live`, with locally reported seven-target HTTPS HEAD reachability.
- One-shot 7-target ephemeral Ed25519 compatibility rehearsal **passed**: seven locally reported UP, age 197 seconds. Output explicitly recorded `SOURCE_PROVENANCE=NOT_ATTESTED`, `DURABLE_SIGNING_REPLAY=NOT_ACTIVE`, and `OWNER_ALERT_DELIVERY=NOT_ACTIVE`.
- Existing NOC is simulated-only; its Docker health is not evidence of a genuine authenticated collector.
- Sentinel PR #20 isolated bridge tests passed at previously reviewed commit `9ae431a8b5b6b290c22f892633c662cdcc8ebdc5`.

## Three options considered; /REDTEAM

| Option | Assessment |
|---|---|
| Put a permanent private signer inside the simulated NOC | Reject: demo/live data confusion, key proximity to staging services |
| Give a continuous host signer access to the Docker socket | Reject: Docker control is effectively elevated host privilege; unacceptable for an unattended security collector |
| **Operator-controlled, no-network private signer + one durable review-only ledger** | **Chosen for source development**, not yet authorised for production |

### Unverified source candidate

`noc/owner_private_candidate.py` was added to draft PR #20 for review, without installing or running it. Its intended contract is:

1. Read only an already supplied bounded monitor snapshot. This function does **not** establish which process collected it.
2. Refuse missing or unsafe private signing key: no root execution, exact Ed25519 raw key size, owner-only directory/file mode, symlink/hardlink rejection and an independently registered SHA-256 pin of the public key.
3. Use a single existing protected, full-synchronous file-backed SQLite ledger for a monotonic report sequence and review-only incident proposals.
4. Reject duplicate/reset cycle, stale report, invalid signature, unapproved target or inconsistent HTTP claim.
5. Never dispatch notifications, allow privileged actions, create customer tickets, alter Hub/Tiquet, or claim that a signed sample proves the physical HTTPS probe happened.

### Important independent checks still missing

- **Security regression gate NOT MET:** a proposed synthetic private-key test file was blocked before repository creation by a tool safety check. No workaround was attempted; do not treat syntax checking or other CI green checks as acceptance.
- **Source provenance NOT MET:** passing an arbitrary JSON payload into this signer would authenticate only the signing operation. The **actual live collector** must be pinned and its process identity and local-only data path independently verified before any persistent signer is deployed.
- **Key custody NOT MET:** no owner-created or owner-approved private key or pin exists. Never paste raw keys or fingerprints derived from untrusted input into conversation logs or GitHub.
- **Durable replay recovery NOT MET:** monitor's process-local cycle may reset on restart. This must halt for owner reconciliation, never automatically re-enrol or reset cursor. Receiver crash, concurrency, full outbox and file permission issues require verified isolated tests.
- **Off-host availability NOT MET:** nothing hosted solely on Dell can detect Dell losing power or all network paths. Off-host independent source must classify missed reports UNKNOWN and test expected blind-spot behaviour.
- **Alert delivery NOT MET:** Resend sending authentication exists, but recipient receipt is unproven. No mail test before explicit founder approval and trusted evidence chain; restrict to one harmless recipient with bounded retry/idempotency.
- **Existing GitGuardian/security hold NOT MET:** PR #14's historical failed independent security gate is not waived by PR #20.

## Release decision

**NO-GO** for installation, background signer, key provisioning, unattended Docker access, signed operational-protection claims, NOC live promotion and mail.

**Permitted now:** source review, syntax checks, read-only host inventory, synthetic isolated tests when accepted by security controls, and a separate off-host watchdog design. Any production activation requires an exact SHA, founder approval, independent security acceptance and a scoped non-destructive negative/restore demonstration.

## Handoff

The next action is to complete an independently accepted test suite for the candidate signer and a trusted source-provenance design. Until those pass, keep the verified live monitor running unchanged and continue using only the previously successful one-shot ephemeral rehearsal.
