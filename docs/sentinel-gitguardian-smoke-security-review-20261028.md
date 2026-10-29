# P1 security review: GitGuardian staging smoke credential finding — 28 Oct 2026

**OPEN SECURITY INCIDENT / SOURCE-ONLY REMEDIATION. NOT SCANNER-CLEARED.**

## Exact finding from the GitGuardian comment on historical draft PR #14

- Private dashboard finding ID: **38116562**
- Detector: **Generic Password**
- Finding state shown in historical comment: **Triggered**
- Historical commit: `6c84d54f985136c62e2df5b23fa955c7d20aff19`
- File: `deploy/docker/smoke-private-pilot.py`
- Current main and draft tree both carry the same original file blob before this patch.

Reviewing the tracked source at that commit shows the synthetic local pilot script calls a loopback-only NOC login and reads its password from a local file rather than containing a directly assigned plain-text account password. **This DOES NOT prove the detector is a false positive.** A private GitGuardian finding-detail inspection remains required to identify the matched line/value, determine actual exposure, and rotate/revoke credentials if indicated. Never copy raw values, credential excerpts or hashes that could be sensitive into a GitHub issue or chat. Never mark ignored/false positive simply to clear a release gate.

## Three options /REDTEAM
1. Dismiss or suppress the scanner — REJECT: hides an unresolved credential incident and could leave historical exposure.
2. Rename the password field or alter literals just to make scanning green — REJECT: false assurance; staging credential handling stays risky.
3. **Selected:** harden the staging-only secret-file read with component-wise O_NOFOLLOW/O_DIRECTORY and a bounded FD read; test adversarial file metadata, symlinks, hardlinks and content limits; keep GitGuardian finding unresolved pending provider review.

## Implemented on source-only review branch
- `deploy/docker/smoke-private-pilot.py`: read staging credential through stable directory FDs; reject final and parent symlinks, nonregular files, multi-linked files, group/world access, unexpected owner, oversized or malformed content. Never log secret bytes, path or exception content. Staging login contract unchanged; no production key or user credentials are created.
- `noc/tests/test_private_smoke_secret_file.py`: synthetic fixture only (runtime generated, never actual secrets); good-file path, symlinks, hardlink, FIFO, directory, modes, bad data, path traversal, no leaks.
- `.github/workflows/sentinel-private-smoke-secret-review.yml`: synthetic security test + prior isolated signer/replay/Resend/observer regressions, no actual NOC deployment.

## Remaining mandatory gates before any promotion
1. Founder or authorised security specialist opens the **private** GitGuardian incident and inspects matched line(s), historical exposure, validity and remediation status; revoke/rotate if genuine, then rescan and record CLOSED only after explicit independent verification.
2. Independent reviewer per issue #3 assesses exact SHA, complete 120+ commit stacked diff, key custody, real in-process collector source integrity and audit of every privileged path.
3. Dedicated private-signer promotion workflow is separately blocked by its missing source-specific security suite. This change does not remove that NO-GO.
4. Key rotation / rollback / independent host blindness and live failure tests require specific operator approval. No production Docker or systemd changes, Hub/Tiquet/WiPay writes, customer monitoring or live Sentinel alerts in this branch.

**Disposition:** one local credential-file risk mitigated in draft, historical GitGuardian incident still OPEN pending private review. Avoid confusing passing tests with a secret-incident disposition or independent security approval.
