# Sentinel Stage 2 P1 — isolated sender replay ledger and key mount policy (28 October 2026)

**SOURCE-ONLY, OFF BY DEFAULT. NOT A DEPLOYMENT OR LIVE PROTECTION CLAIM.**

## Three options / choice
1. In-memory sender counter — rejected: restart or crash can reset and reuse a number.
2. Reuse monitor/NOC's ordinary writable `/app/data` — rejected: weak boundaries, ambiguous shared restore and key custody.
3. **Selected:** a separate, explicitly initialised SQLite sender ledger with `BEGIN IMMEDIATE` and `synchronous=FULL`; validate/sign while holding the transaction, commit its monotonic sequence before returning a signed envelope, and reject monitor-cycle resets. Pair it with a **metadata-only** signer-key mount preflight that never opens secret bytes.

## Implemented isolated code
- `noc/isolated_sender_counter.py`: explicit scratch schema and `sign_with_atomic_sender_counter()`. Requires caller-provided *file-backed* SQLite connection and Ed25519 signer, exact source-bound receipt, collector identity, approved targets. Only the collector ID and last cycle persist. It has no container integration or network.
- `noc/isolated_key_mount_policy.py`: metadata-only checks for non-root key ownership, single-link regular 0400/0600 file, private 0500/0700 approved directory, no symlinks, traversal, group/world access. Does not read or generate keys; does **not** attest process identity or a valid Ed25519 key.
- `noc/tests/test_isolated_sender_custody.py`: synthetic-only tests for concurrency, restart, missing/unsafe database, invalid source, distinct receiver replay database, symlink/hardlink/traversal and wrong ownership or mode. No real secret or actual service.
- `.github/workflows/sentinel-isolated-sender-custody.yml`: no-network, no-live-service CI for the above and earlier source-bound security tests.

## REDTEAM boundary and remaining HOLD conditions
- **Do not use with NOC status JSON or external receipts.** The source-bound in-process hook must be reviewed and pinned to an immutable signed image and real probe before trusted status can ever be claimed.
- The sender counter is tied to *monitor cycle*, not wall time. Monitor restart/reset is an explicit **HOLD** until owner-supervised re-enrolment; never silently advance/restart from 0. A signer DB rollback, clock drift, stale observation, untrusted key, partial source failure, or storage outage must produce UNKNOWN; an independent immutable/high-water anchor is needed to detect coordinated rollback of sender AND receiver.
- The key guard checks in-mount metadata only. It does not validate external directory ancestry, overlay/mount namespace, file descriptor races, encryption, hardware key custody, secret rotation, private-key format or key provenance. These require independent review; the future signer may not load keys from Hub or WiPay environment variables or logs.
- Sender commit may succeed and external dispatch fail: sequence gaps are safe but owner alert loss is NOT. Implement atomic receiver replay + inbox/outbox with idempotent delivery and measured fault→recovery tests before any notifications.
- An isolated SQLite file is not an approved production volume. Use a separate owner-managed volume and independent recovery; never initialize schema in live NOC/monitor/customer/Hub DB without explicit release authorisation.
- No action on Tiquet, POS, FFPRO, payment or host security controls; no new external network targets or auto-remediation.
- Parent GitGuardian and independent security review must be reconciled, and the rollout must use a new approved immutable image with preflight, rollback, and owner authorisation. Do not merge/deploy merely because CI passes.

**Review gate:** tests and static checks PASS; draft source only; runtime signing, notifications, Hub/COO telemetry and customer security remain HOLD.
