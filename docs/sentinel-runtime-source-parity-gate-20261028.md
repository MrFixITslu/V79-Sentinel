# Sentinel runtime image and source parity — owner review gate

**28 October 2026 · Source-only draft PR #20 · NO LIVE RUN / NO DEPLOY**

This gate prepares the next owner-reviewed release checkpoint. It can identify a stale, mismatched or unapproved *reported* runtime, but cannot independently attest a physical host, signed process identity or security incident.

## Why this gate

Prior live evidence for `v79-sentinel-dell-monitor` established a historical container image, non-root UID and source hashes for `sentinel.py` and `monitor_core.py`. Subsequent draft source changes now add a third file (`noc/inprocess_probe_receipt.py`) and DNS-pinned HTTPS logic. **Do not claim the Dell is running these draft improvements.**

Three options considered:
1. **Promote the current draft straight to Dell:** REJECT. No new image/UID/runtime hash evidence and previously identified signer-source gates remain open.
2. **Start another monitoring service to gain runtime evidence:** REJECT. It does not verify the existing process, duplicates work and creates a second identity/secrets boundary.
3. **Selected:** compare a separately owner-pinned manifest with fresh, restricted, read-only container evidence; reject any mismatch and return only an operator-review candidate. Preserve current monitoring and G2 services.

## Source-only acceptance contract

Module: `noc/runtime_source_parity_gate.py` — `evaluate_runtime_source_parity(observed, expected, now=...)`.

The owner must pin **expected** values from a separately reviewed, immutable build/release record. Values copied from the same running container being inspected are **not independent pins**. Required: exact container name `v79-sentinel-dell-monitor`; candidate release image ID `sha256:` + 64 lowercase hex characters; explicit non-root UID and GID; and exact reviewed Git blob SHA-1s for these three paths:

- `sentinel.py`
- `monitor_core.py`
- `noc/inprocess_probe_receipt.py`

The **observed** claim must contain only the fixed nine keys: `container`, `image_id`, `uid`, `gid`, `running`, `health`, `argv`, `sources`, `captured_at`. The gate rejects wrong/unknown keys, non-healthy or stopped containers, wrong image, wrong UID/GID, non-exact three-part Python `sentinel.py --live` argv, changed/missing/extra sources, nonregular files, symlink files and snapshots older than five minutes or more than 30 seconds in the future. Each observed source entry contains only `git_blob`, `regular`, `symlink`, never raw source bytes. Image IDs and SHA-1 file content digests are **matching identifiers**, not digital signatures.

No `docker inspect` environment variables, `docker logs`, mounted secrets, private signing keys, auth cookies, tokens, customer database rows, screenshots or arbitrary console output should be collected or pasted into chat/GitHub. Do not run an unreviewed helper from the internet on production. All production collection must use explicit read-only, owner-approved commands from a trusted account, and independent verification of the resulting evidence's origin is still required.

### Allowed outcomes

- `UNKNOWN` / `READ_ONLY_RUNTIME_EVIDENCE_UNVERIFIED`: missing, stale, unexpected, unpinned or mismatched evidence. **Stop**; do not correct automatically, repair services, restart containers or rotate signing keys.
- `SOURCE_PARITY_CANDIDATE_FOR_OWNER_REVIEW` / `METADATA_AND_DIGEST_CLAIMS_MATCH_NOT_ATTESTED`: the supplied metadata and digest **claims** match the separately pinned manifest. Still **not authorised to release**. The module's `sourceProvenanceVerified`, `imageSignatureVerified`, `collectorProcessAttested`, `sourceSignatureValid`, `independentOffhostObserverVerified`, `safeToDeploy`, `alertsDispatched` and `ticketCreationEnabled` flags **remain false** even on a match.

Tests: `noc/tests/test_runtime_source_parity_gate.py`, 13 offline cases including altered release digest, root user, disabled process, tampered source digest, symlinks, extra keys, stale/future timestamps, unapproved CLI modes and no secret echo. The source-only bridge CI workflow syntax-checks both files and runs the suite. No generated signing keys, network probes, privileged reads, emails or Docker operations are part of these tests.

## Remaining gates after a parity candidate

1. Independently verify actual Dell build/image/files, non-root executing process, trusted origin and approved manifest. A self-reported JSON snapshot is not attestation.
2. Prove one source of durable monotonic cycle / anti-replay state, protected signer custody, pinned receiving identity and measured in-process origin.
3. Prove a truly off-Dell heartbeat observer and explicit `MONITORING_BLIND` handling. External Hetrix 9/9 public-URL reachability checks are already separate coverage, not proof of Dell host status.
4. Exercise a non-disruptive candidate incident → deduplicated founder-only alert in an isolated environment, preserving the already successful one-off Resend-to-Gmail delivery proof.
5. Owner security and release approval; only then consider a guarded signed Sentinel deployment. No public publishing, no auto-remediation, no customer/Tiquet modifications.

**Decision:** SOURCE PARITY GATE PREPARED. Production release **HOLD**.