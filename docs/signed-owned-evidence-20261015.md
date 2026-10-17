# P1 Sentinel signed V79-owned observation contract — not a deployed collector

**Draft only.** This module has NO collector, persistent anti-replay ledger, alert delivery, Hub/COO integration, or production installation. A valid digital signature is **not proof that a sensor really made the claimed probe**.

## Brainstorm and REDTEAM
1. Accept ordinary "mode:live" JSON from the existing NOC — rejected, because a synthetic or forged report could claim service health.
2. Trust an HTTP health endpoint as machine identity — rejected; an HTTP 200 does not authenticate the sensor or service observations.
3. **Selected:** a narrowly scoped, pinned Ed25519 public-key verifier for exact V79-owned snapshots. The signature binds named collector, monotonic sequence and the entire observation. Every authorized report is still marked **PENDING OPERATOR ACCEPTANCE**, with customerReady=false and continuousMonitoringVerified=false.

## Contract
- Verification module: noc/signed_owned_evidence.py.
- Caller supplies a **trusted, pinned 32-byte public key** and expected collector ID separately. Never read a key from the unsigned envelope as authority.
- Payload: version=1, collectorId, sequence and snapshot signed using canonical sorted, compact UTF-8 JSON, with an 86-character base64url-encoded 64-byte Ed25519 signature.
- Caller supplies last_seen_sequence from a future *durable* per-collector replay-state store; missing or older/equal sequence fails closed. The verifier does not persist that sequence and thus does **not** certify replay prevention across process restarts.
- Scope/freshness must also pass the existing V79-owned HTTPS advisory gate. Only exact approved V79 target names+URLs are allowed. Signed demo, stale, far-future, malformed, or wrong-scope evidence remains UNKNOWN.
- Limits: 32KiB canonical payload, one pinned key, bounded collector ID, no raw untrusted HTTP messages returned.
- Even valid signatures return only SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE; no trusted COO status, generated alert, ticket creation or customer readiness.
- Pinned verification dependency cryptography==45.0.7; CI uses synthetic ephemeral Ed25519 keys created only in memory.

## Production blocking gates
- Resolve the earlier private NOC parent [PR #14](https://github.com/MrFixITslu/V79-Sentinel/pull/14) GitGuardian hold without exposing details or bypassing the scanner.
- Independently review the signed-source threat model, key custody, rotation, collector process isolation and protection against forged measurements by a compromised collector.
- Design durable atomic anti-replay checkpoint storage and authenticated read-only Hub/COO ingestion, preserving tenant/owner separation.
- Verify actual owned target checks, exact running source, freshness transitions, backup/rollback, alarms and notification delivery in an approved isolated pilot.
- Obtain owner authorization for any installed service or new secret. Never equate passing CI with actual protection.

Related source chain: [Sentinel #15](https://github.com/MrFixITslu/V79-Sentinel/issues/15) and [draft PR #16](https://github.com/MrFixITslu/V79-Sentinel/pull/16).
