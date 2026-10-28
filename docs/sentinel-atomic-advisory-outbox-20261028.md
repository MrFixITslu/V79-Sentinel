# Sentinel Stage 2 P1 — atomic signed advisory inbox/outbox (28 October 2026)

**SOURCE-ONLY DRAFT. Not live monitoring, not alert delivery, not Hub/COO integration and NOT approved for deployment.**

## Design choice and REDTEAM
1. First commit replay counter, later insert notification/event — **rejected:** crash between commits permanently discards an accepted report.
2. Send an alert while holding a database lock — **rejected:** networking is unreliable, creates duplicates, leaks signer capabilities and stalls verification.
3. **Selected:** single `BEGIN IMMEDIATE` SQLite transaction validates the signed snapshot, advances a per-collector replay checkpoint, inserts one minimal **PENDING** advisory event, and commits together. If the outbox insert fails, replay state rolls back. There is **no dispatcher**.

## Code
- `noc/isolated_atomic_advisory_outbox.py`: explicit scratch-only schema; validates signatures, pinned key, collector identity, allowlisted target scope and freshness. Stores only collector ID, sequence, observed UTC timestamp, and a bounded, sanitized list of names and `REPORTED_*_UNVERIFIED`/review signals. Does not store signatures, raw URLs, messages, customer details, IPs or credentials.
- `noc/tests/test_isolated_atomic_advisory_outbox.py`: in-memory ephemeral keys, isolated sender and receiver SQLite paths, missing-outbox rollback, replay, restart, concurrent delivery attempts, forged identity, unsafe receiver DB, no network/action tests.
- `.github/workflows/sentinel-atomic-advisory-outbox.yml`: test and static isolation gate, no account/service credentials.

## Important boundaries
- A signed report remains `SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE`, **not independent proof that a real sensor probed the services**. The in-process producer identity, actual TLS HEAD probe, runtime digest, and external monitor remain unverified.
- The outbox is a **pending advisory**, NOT an incident, owner alert or trustworthy healthy status. It has no Hub/COO access, remote receiver, email/Resend, Tiquet, WiPay or automatic remediation.
- The signer key is not generated, loaded or rotated here. The key-mount policy is only metadata preflight; independent key custody, process isolation and immutable source review remain HOLD.
- A future dispatcher requires founder-only authentication, strict event idempotency, retries, bounded delay, deduplication, acknowledgement and delivered-at receipts; no duplicate storm or privileged actions.
- Coordinated sender+receiver rollback requires a separate immutable/high-water anchor; a downed host requires independent off-host observation and UNKNOWN classification.
- Missing outbox schema or unsafe DB returns UNKNOWN, never an all-clear. Do not initialise this in production NOC, Hub or Tiquet DBs.
- Independent security review, GitGuardian remediation, exact digest, guarded release and separate owner approval are still required. This PR is intentionally draft and not to be merged/deployed as a release.

**Only synthetic automated tests can pass this milestone. Production status remains HOLD.**
