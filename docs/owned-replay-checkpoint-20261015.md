# Sentinel P1 durable signed-report replay candidate — not live

**Status: development only.** Hub + Tiquet are the commercial priority; Sentinel remains founder-only internal protection work, currently not verified live. This change has no real probes, alerts, Hub events or client tickets.

## Three options and REDTEAM
1. Trust a signed report once per *process*: rejected; replay becomes possible after a restart and across worker processes.
2. Store a memory cache or trust the claimed signed sequence: rejected; forged duplicates, concurrent workers and process restarts can bypass it.
3. **Selected:** use a protected, file-backed SQLite sequence checkpoint with a single atomic BEGIN IMMEDIATE transaction, validate Ed25519 + scope/freshness, then commit only a *strictly increasing* sequence. Reject in-memory/synchronous=NORMAL/OFF, missing DB, invalid signature and concurrent duplicate updates.

## Scope
- `noc/owned_replay_checkpoint.py`: requires an externally supplied SQLite connection on an actual file, synchronous=FULL or stronger, and an explicitly precreated minimal sequence table. This module never opens its own database path, creates a new privileged collector account, probes the network or emails anyone.
- `prepare_owned_replay_store()`: explicit schema creation in a disposable or independently authorized DB; not automatically run during verification or Hub startup.
- `evaluate_and_checkpoint_owned_evidence()`: immutable pinned collector identity + public key supplied by caller, verifies signed envelope and owned scope, atomically stores collector ID, accepted timestamp and monotonic sequence only. DOES NOT persist raw URLs/status, tokens, signatures, logs or credentials.
- Tests include restart persistence, replay, tampering, stale, absent schema, memory/unsafe synchronous setting, faulty key, caller-active transaction and two concurrent verification calls. All test files stay in temporary directories and use synthetic ephemeral signing keys.

## Residual risk and release gates
- A signed envelope proves its pinned signing key signed that bytestring; **a compromised source key could still claim fictitious measurements**. Status remains SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE, with executive trust, continuous protection, notifications, ticket creation and commercial customer readiness all false.
- SQLite durability assumes trusted filesystem permissions, functioning storage barriers, backups and a single protected local writer path. Key rotation, anti-replay state migration, failed storage semantics, multi-host scaling and deletion/restore rollback need independent review.
- If a checkpoint is committed and downstream processing fails, the same report will be intentionally rejected on retry. A future trusted processor must use transactional outbox or separate delivered-event idempotency; do not silently bypass sequence validation.
- Reject attempts to initialize this table inside an existing production DB without explicit release approval, data backup and restore test.
- **Gate:** resolve Sentinel parent PR #14 GitGuardian failure; independently review parent #16 and #17, real authorized collector and key custody, signed-read-only Hub ingestion, restored checkpoint behavior and actual alert-to-founder delivery. No merges or production release authorized by this draft.

See [Sentinel issue #15](https://github.com/MrFixITslu/V79-Sentinel/issues/15) and earlier [signed evidence PR #17](https://github.com/MrFixITslu/V79-Sentinel/pull/17).
