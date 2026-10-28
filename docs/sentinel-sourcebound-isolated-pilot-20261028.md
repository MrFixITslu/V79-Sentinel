# V79 Sentinel Stage 2 — isolated source-bound signed-advisory pilot (28 Oct 2026)

**STATE: SOURCE-ONLY / OFF BY DEFAULT / NOT DEPLOYED.** Never describe this as trusted live monitoring or active security protection. Stage 1 HTTPS availability checks are running separately. This branch changes no deployment files, running services, Compose model, credentials, production databases, alerts or customer workflows.

## Evaluated approaches
1. Sign NOC `/api/status` — **rejected**. That endpoint can repeat cached, stale, synthetic or spoofed JSON without proving a real probe.
2. Install a signer directly into production monitor — **rejected** pending security-source review, key custody, replay storage, alerts and exact-digest release.
3. **Chosen:** a source-only, pure, disabled signer adapter for the existing optional `monitor_forever(..., evidence_sink=...)` in-process projection. `project_probe_cycle` is invoked only after `probe_many` and successful monitor telemetry recording. This adapter does not register itself as a sink or receive network traffic.

## Code and synthetic proof
- `noc/isolated_signed_probe_pilot.py` defines `sign_review_receipt(...)`; requires explicitly provided private key, exact collector identity and previous cycle, rejects malformed and stale scope, and signs only a minimal seven-service claim. There is no private-key loading, key creation, network, DB write, API, email, Docker or execution path.
- `noc/tests/test_isolated_signed_probe_pilot.py` verifies the source projection → signed envelope → pinned receiver → SQLite replay checkpoint. All keys are ephemeral; database is temporary. Valid signatures remain `SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE`. Replay, counterfeit and stale inputs are rejected. No customer or payment data is used.
- `.github/workflows/sentinel-sourcebound-signed-pilot.yml` runs isolated source/signature/replay tests for PRs against the monitor proof branch. CI is a development proof, not live deployment evidence.

## REDTEAM / required release gates
1. **Collector authenticity:** receipt-shaped data is forgeable; the code proves validation and signature integrity, not that the originating process genuinely performed the probes. Review immutable source, in-process call path and release digest. A compromised source process can still falsely sign UP.
2. **Key management:** use owner-approved provisioned key with strict process and read-only secret access, separate from NOC and monitor's ordinary writable `/app/data`. Define key rotation and revocation. Do not place private keys in GitHub, logs or API responses.
3. **Monotonic state:** this adapter accepts `previous_cycle` but never persists it. The future supervised caller must get this from durable trusted storage and handle process restarts/reset through manual re-enrolment. Receiver must use `evaluate_and_checkpoint_owned_evidence` with `synchronous=FULL`, protected file-backed SQLite, and independent restore/rollback controls.
4. **No duplicated dispatch:** avoid committing a replay number before losing the event in delivery. Implement atomic outbox or downstream idempotent delivery before founder alerts. Prove healthy→fault→recovery with bounded deduplication.
5. **Blindness/unknown:** monitoring host can fail; stale observations must become UNKNOWN, not UP. An independent outside-the-host observer is needed for host outages.
6. **Boundaries:** allowlist V79-owned 7 public HTTPS HEAD endpoints only. These are reachability probes, not backend integrity or cyber intrusion detection. Do not grant Hub, Tiquet, admin or WiPay write tokens to the signer.
7. **Release gates:** independent security review and GitGuardian/source clearance, exact immutable image approval, guarded preflight/recovery and explicit owner release approval before production changes. No automatic restarts, ticket creation, broad scans or customer use.

**Acceptance for this branch:** synthetic test PASS, minimal auditable diff, source-only PR kept draft. No merge or production switch as part of the isolated pilot.
