# Sentinel Stage 2 — isolated SQLite journal durability security correction (28 October 2026)

**SOURCE ONLY / REVIEW ONLY.** No owner key, production DB, monitoring configuration, NOC container, Hetrix monitor, Resend send, Hub access, or runtime action is changed by this branch.

## Three options and chosen approach
1. **Leave FULL synchronisation checks alone** — rejected. SQLite journal_mode=OFF and journal_mode=MEMORY are file-backed modes that weaken crash-safe replay and outbox updates, even if PRAGMA synchronous=FULL is set.
2. **Copy ad hoc journal checks into each module** — rejected. Multiple implementations can drift and create mismatched guarantees.
3. **Chosen:** a shared pure fail-closed SQLite durability guard used by the sender, receiver replay, pending-outbox, and founder-delivery pipelines, with adversarial OFF/MEMORY tests in isolation.

## Implemented code
- noc/isolated_sqlite_durability.py requires: real absolute file-backed main DB, idle connection, synchronous FULL/EXTRA, and durable rollback journal DELETE/TRUNCATE/PERSIST or WAL. It refuses OFF/MEMORY, memory databases and idle check violations.
- noc/isolated_sender_counter.py, noc/owned_replay_checkpoint.py, noc/isolated_atomic_advisory_outbox.py , noc/isolated_founder_delivery_protocol.py and noc/owned_alert_state.py now use that guard; the separate Resend contract inherits it from the founder protocol.
- noc/tests/test_isolated_sqlite_durability.py proves every stage rejects OFF/MEMORY before signing, replay acknowledgement, queue acceptance, delivery lease or provider submission. It also verifies positive supported journaling, bad sync/memory DBs and active transactions.
- .github/workflows/sentinel-sqlite-durability-review.yml runs the full stacked source-only suite.

## REDTEAM: what this does NOT prove
- Filesystem and storage controller must actually honour fsync; FULL only requests it. No immutable audit anchor, off-host replay rollback defence or full filesystem permissions check is supplied.
- Symlink/TOCTOU, journal/write-ahead log file permissions, data-dir ownership, disk corruption, restoring stale sender+receiver DB snapshots and unexpected SQLite library build options remain unsolved.
- Valid signatures still do not prove an actual real HTTPS probe. Collected data are review-only until binary provenance, dedicated key custody and independent receiver controls are accepted.
- GitGuardian PR #14 failed check and independent review issue #3 remain unresolved; closing an old PR or green synthetic CI does not clear them.
- All earlier branches/PRs #21-26 are stacked development drafts. **Do not treat this as a production security signoff or merge/deploy automatically.** Existing Hetrix independent website monitoring and verified one-off founder alert drill remain the allowed production state.

## Next required review
Private GitGuardian owner inspection; independent human review of exact-source release; supervised authenticated in-process probe + protected key and receiver test in a non-production sandbox; persist and compare sender/receiver checkpoint across restart/backup/restore with safe rollback; immutable digest and founder approval for any installation.

**Decision: local durability gap addressed in source, but commercial/production signing HOLD.**

## Stacked release review scope
GitHub compare main...fix/p1-isolated-journal-durability-gate-20261028 showed **120 commits ahead of main across 67 files** during this review. This is NOT a small production release. Every ancestor draft #21–#26 and earlier source work must undergo exact-tree review and an explicitly approved immutable build before any merge/release; CI scoped to this isolated test family does not constitute whole-tree integration approval.

The alternate private owner signer lane (noc/owner_private_candidate.py → noc/owned_alert_state.py) was also checked. Its private advisory ledger now uses the shared durable journal gate while retaining its stricter 0600 file/0700 owner-directory requirements. The separate sentinel-private-signer-promotion-gate.yml intentionally remains a **NO-GO** because the independent dedicated private signer security suite is missing; this patch does not waive that gate.
