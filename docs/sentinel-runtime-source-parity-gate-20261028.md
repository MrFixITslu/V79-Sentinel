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

The owner must pin **expected** values from a separately reviewed, immutable build/release record. Values copied from the same running container being inspected are **not independent pins**. Required: exact container name `v79-sentinel-dell-monitor`; candidate release image ID `sha256:` + 64 lowercase hex characters; explicit non-root UID and GID; and **both** exact SHA-256 content digests and reviewed Git blob SHA-1s for these three paths:

- `sentinel.py`
- `monitor_core.py`
- `noc/inprocess_probe_receipt.py`

The **observed** claim must contain only the fixed nine keys: `container`, `image_id`, `uid`, `gid`, `running`, `health`, `argv`, `sources`, `captured_at`. The gate rejects wrong/unknown keys, non-healthy or stopped containers, wrong image, wrong UID/GID, any command other than the exact Python `sentinel.py --live` default invocation or the Dell's explicitly loopback-only seven-part `python sentinel.py --live --bind 127.0.0.1 --port 8787` argv, changed/missing/extra sources, nonregular files, symlink files and snapshots older than five minutes or more than 30 seconds in the future. Each expected source entry contains `sha256` (64 lowercase hex, mandatory) and `git_blob` (40 lowercase hex); each observed source entry contains those same hashes plus `regular` and `symlink`, never raw source bytes. **SHA-256 is the primary content integrity check**; Git blob SHA-1 is secondary repository parity. Neither digest is a cryptographic process attestation or a publisher signature.

No `docker inspect` environment variables, `docker logs`, mounted secrets, private signing keys, auth cookies, tokens, customer database rows, screenshots or arbitrary console output should be collected or pasted into chat/GitHub. Do not run an unreviewed helper from the internet on production. All production collection must use explicit read-only, owner-approved commands from a trusted account, and independent verification of the resulting evidence's origin is still required.

### Allowed outcomes

- `UNKNOWN` / `READ_ONLY_RUNTIME_EVIDENCE_UNVERIFIED`: missing, stale, unexpected, unpinned or mismatched evidence. **Stop**; do not correct automatically, repair services, restart containers or rotate signing keys.
- `SOURCE_PARITY_CANDIDATE_FOR_OWNER_REVIEW` / `METADATA_AND_DIGEST_CLAIMS_MATCH_NOT_ATTESTED`: the supplied metadata and digest **claims** match the separately pinned manifest. Still **not authorised to release**. The module's `sourceProvenanceVerified`, `imageSignatureVerified`, `collectorProcessAttested`, `sourceSignatureValid`, `independentOffhostObserverVerified`, `safeToDeploy`, `alertsDispatched` and `ticketCreationEnabled` flags **remain false** even on a match.

Tests: `noc/tests/test_runtime_source_parity_gate.py`, 16 offline cases including altered release digest, root user, disabled process, tampered source digest, symlinks, extra keys, stale/future timestamps, unapproved CLI modes and no secret echo. The source-only bridge CI workflow syntax-checks both files and runs the suite. No generated signing keys, network probes, privileged reads, emails or Docker operations are part of these tests.

## Remaining gates after a parity candidate

1. Independently verify actual Dell build/image/files, non-root executing process, trusted origin and approved manifest. A self-reported JSON snapshot is not attestation.
2. Prove one source of durable monotonic cycle / anti-replay state, protected signer custody, pinned receiving identity and measured in-process origin.
3. Prove a truly off-Dell heartbeat observer and explicit `MONITORING_BLIND` handling. External Hetrix 9/9 public-URL reachability checks are already separate coverage, not proof of Dell host status.
4. Exercise a non-disruptive candidate incident → deduplicated founder-only alert in an isolated environment, preserving the already successful one-off Resend-to-Gmail delivery proof.
5. Owner security and release approval; only then consider a guarded signed Sentinel deployment. No public publishing, no auto-remediation, no customer/Tiquet modifications.

## 28 October — owner-observed Dell Docker metadata, not source attestation

The owner supplied a read-only `docker inspect` on the existing running Dell:
- `/v79-sentinel-dell-monitor` running and Docker health `healthy`
- exact image ID `sha256:c9ae010b7971496855785f275bda9e40e33617044376e2225d5488e2fbfdc6fc`
- `Config.User=10001:10001` (configured non-root)
- `Config.Cmd=["python","sentinel.py","--live","--bind","127.0.0.1","--port","8787"]` (explicit loopback listener)

This is **positive read-only configured-runtime evidence**, NOT independent verification of the actual `/proc` executing process, immutable image publisher signature, active file hashes, source provenance or a candidate new release image. The running image identifier is the previously observed historical image. It MUST NOT be assumed to contain the newer draft evidence tap, DNS-pinned HTTPS transport, or parity gate.

The draft parity evaluator originally restricted `argv` to exactly three elements, falsely rejecting the legitimate existing loopback-only Docker configuration. Options /REDTEAM: modify production to fit test (REJECT), allow all CLI flags (REJECT), permit only the exact safe observed `--bind 127.0.0.1 --port 8787` sequence as an additional fixed contract (SELECTED). This is source-only and preserves a strict rejection for wildcard bindings, wrong/reordered/duplicated flags, altered port and shell wrappers. Added two focused positive/negative tests; all gate outputs still lack authority to deploy, sign or send. **No live monitor or server changes.**

**Independent CI final readback:** 4/4 GitHub Actions workflows completed SUCCESS on code SHA `956afaf5ffa8498402dcc7b730c96e41e60c59f0`: legacy bridge run `40759133091` (job log explicitly `Ran 16 tests ... OK` for the parity suite), private signer gate `40759133064`, full isolated regression `40759133061`, private Docker staging `40759133087`. These are synthetic/source tests only; the Dell was not changed.

**Decision:** SOURCE PARITY GATE PREPARED. Production release **HOLD**.

## 28 October — owner-confirmed live PID1 and legacy source baseline

Following the previous read-only `docker inspect`, the owner ran a **read-only, in-container `/proc/1` and source-file hash inspection** against the *existing* healthy `v79-sentinel-dell-monitor`. Results:

| Runtime/source | Owner-observed value | Interpretation |
| --- | --- | --- |
| `/proc/1/status` effective, real, saved, filesystem UIDs | `10001 10001 10001 10001` | Actual PID1 UID evidence: non-root |
| `/proc/1/cmdline` equals expected seven-argument command | `True` | Actual PID1 command matches configured loopback `127.0.0.1:8787` invocation |
| `sentinel.py` SHA-256 | `d28ab9c5a1b06c7936e71f3b85d42ecb329397430a5c0983139f6db81629e048` | Owner measured in running container |
| `sentinel.py` Git blob SHA-1 | `26011d0301f768cf91e6badcc65f3c40bb07f2dd` | **Matches GitHub `main` exact file blob** independently fetched |
| `monitor_core.py` SHA-256 | `6c97012e7568d73f06482c9feda90e2a3f5f829a388e36ce60787dfccba94d46` | Owner measured in running container |
| `monitor_core.py` Git blob SHA-1 | `baacdb0858897a6d5547ac93674d6f39e4dfdbf0` | **Matches GitHub `main` exact file blob** independently fetched |
| `noc/inprocess_probe_receipt.py` | `MISSING_OR_UNSAFE` | Not accessible as a safe regular file at the expected path; the read-only test does not distinguish missing from a symlink or nonregular file. Expected for the older image, **not** a site outage. |

Previous Docker inspect also showed image `sha256:c9ae010b7971496855785f275bda9e40e33617044376e2225d5488e2fbfdc6fc`, configured UID:GID `10001:10001`, container RUNNING and HEALTHY. Actual UID and command now add **stronger legacy runtime parity evidence**, but are still not trusted release-signer attestation or a proof the entire container image is immutable/uncompromised. Neither exact two-file legacy SHA-1 match nor the owner-supplied SHA-256 values prove draft fixes are installed. GitHub `main` blob IDs independently confirmed for the two existing files. Do not infer third file contents or claim it definitely does not exist from `MISSING_OR_UNSAFE` alone.

**/REDTEAM three choices:** (1) keep legacy image indefinitely: preserves health but leaves new security hardening out of runtime; (2) deploy draft immediately: REJECT, risks active monitoring/G2 and lacks source/image/key and rollback proofs; (3) SELECT: freeze this known-good baseline and build a **separate, immutable candidate image** with independently pinned digest and complete three-file dual hashes, then inspect the candidate without replacing the live container. Do not use the current historic image digest as an expected pin for the new release or generate a signer/alert key during candidate preparation.

**Gate results:** LEGACY PID1 / TWO-SOURCE BASELINE PARITY **PASS**, based on owner-supplied fresh read-only evidence. NEW CANDIDATE IMAGE PARITY **NOT TESTED** (no candidate image digest, no 3rd file). Signed source provenance, off-host Dell-down observer, controlled automatic owner incident alert, image provenance and production promotion all **HOLD**. No deployment, restart, NPM/Hetrix/G2/WiPay change or email was triggered by this inspection.
