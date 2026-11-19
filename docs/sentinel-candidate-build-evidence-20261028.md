# Sentinel candidate image — isolated GitHub build acceptance (28 October 2026)

**Source-only draft PR #20 • NO REGISTRY PUSH • NO PROD DEPLOYMENT • NO LIVE NETWORK PROBES**

## Decision /REDTEAM

Three options were considered: (1) rebuild or replace the healthy Dell container immediately — REJECT: changes production and risks ongoing monitoring/G2; (2) publish a release image and wire the signer now — REJECT: source and key custody, review, off-host detection, and shipping approval not proven; (3) SELECT: build a local-only candidate on a GitHub-hosted runner using an allowlisted, fresh Docker context, verify non-root process and source bytes in a demo-mode container with network **none**, then delete it. This improves release preparedness without changing the Dell.

## Reproducible recipe and observed single-build results

Implementation: `images/sentinel-candidate.Dockerfile` plus `.github/workflows/sentinel-isolated-candidate-image.yml`. Exact source checkout SHA for observed run: `359225f1f889aa8c20f1b96b64131a8ec144469e`; GitHub Actions candidate workflow run `40762993639`. Build platform `linux/amd64`. The runner pulled `python:3.12-slim-bookworm`, resolved it at build time and passed the explicit immutable base reference `python@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337` to Docker. **Important:** because the workflow resolves a mutable tag at execution time and pip installs the version-pinned `cryptography==45.0.7` without independently pinned wheel hashes, identical bytes across later rebuilds are *not* proven. Treat as an isolated **trial image**, not a signed reproducible release. The base digest and install dependencies must be independently reviewed and hard-pinned before release.

Build context is newly created in the runner and explicitly copied from exactly **15** reviewed source/config/UI files; it is not the full repository, `.env`, build secrets, Docker socket, production data or any key material. `COPY` uses only that context. The image is non-root UID:GID `10001:10001`, has `/app/data` owned by that user and an explicit loopback-only future live `CMD` without `EXPOSE`; no actor enabled live probing.

GitHub log shows ephemeral trial image ID `sha256:2bf2ccdca53e53da5b8c23ef910a30dc3d1b15cf25624b3d5bcb2164b74a26d2` (local Docker image config ID, **not** a registry manifest digest or a deployed/persisted artifact). The smoke-test container overrides the future live `CMD` to demo mode and runs under `--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--pids-limit 64`, `--memory 256m` and bounded private `tmpfs`. The test asserted `api/status.mode=demo`, `last_check=None`, `cycle=0`, `error=None`; local demo endpoint OK; effective UID/GID 10001; `noc/inprocess_probe_receipt.py` exists. The GitHub workflow explicitly deleted the test container and locally tagged image afterward. **No registry artifact, live HTTP probes, off-host watch, email, key, customer action or Dell change.**

### Owner-review source manifest from GitHub runner (candidate, NOT live Dell)

| Source file | SHA-256 from image and allowlisted checkout, matched | Git blob ID |
| --- | --- | --- |
| `sentinel.py` | `28350c24bf6413e6f5128748b823e841dee6bb6ea838c384e9ac23adcefab33d` | `65697e1365f9b63cafd3613d634feba546c5d6e9` |
| `monitor_core.py` | `4e175f32fa05253f6e87acb2bdb36ad2e7fefd3b394f9c19d00937b38f011c47` | `9ea37fa4ef5bf9bf3ec79ae32851ab9fc3fb69c9` |
| `noc/inprocess_probe_receipt.py` | `9672151b7c776e9f6de2ecba96115069b0242a7d6842c65f7b212d0830cd6cd5` | `39d10aa7aa6bd01541777a9e1665dc106f54c78b` |

These are the **draft candidate** files and differ deliberately from the owner-verified older Dell container (`sentinel.py` SHA256 `d28ab9...`; `monitor_core.py` SHA256 `6c9701...`; third module unavailable). Do not compare the old healthy image against these new candidate pins as though it should pass.

## Remaining release blockers

- Build outcome is only a GitHub-hosted temporary trial: no permanent versioned OCI image with distributable registry digest or independently signed provenance/SBOM. A future reviewed and approved build will need fixed base digest and locked dependency hashes, protected source/CI provenance and independent artifact verification. **Do not push image publicly, publish a release, install or switch production without explicit owner approval.**
- Demo-mode `--network none` health is not evidence that real `--live` HTTPS probes work in the new image; those must be proven using approved non-disruptive supervised checks when appropriate, without touching the live Hub/Tiquet/G2.
- `sourceProvenanceVerified`, `imageSignatureVerified`, independent off-host Dell power-failure detection, controlled signed evidence receiver, durable replay, automated incident-to-founder mail and real-event de-duplication remain **NOT VERIFIED**. Manual one-off Resend-to-Gmail test was previously acknowledged by founder, not automated incident pipeline.
- Current Dell legacy monitor remains healthy and unchanged; no new third file or draft DNS pin is deployed there. G2 release recovery remains accepted independently.

**Decision: Candidate TRIAL BUILD AND NO-NETWORK DEMO SMOKE ACCEPTED. Distribution, runtime switching, trusted signing, and autonomous incident alerts are still HOLD.**

## Final independent CI readback

All **5/5** GitHub Actions workflow runs attached to substantive candidate workflow source SHA `359225f1f889aa8c20f1b96b64131a8ec144469e` completed **SUCCESS**: candidate image isolated build / no-network demo smoke `40762993639`, legacy proof bridge `40762993539`, private signer security gate `40762993343`, isolated regression `40762993328`, and private Docker staging tests `40762993498`. This completes CI review for the **temporary candidate build recipe**, not production release authorisation. The trial image was intentionally deleted and is not distributable from GitHub; no persistent signed image exists.

## 28 October — SHA-256-locked base and full Python wheel closure (source-only)

**/REDTEAM of the proposed retention:** GitHub repository `MrFixITslu/V79-Sentinel` was independently checked through connected GitHub `get_repo` and reports `visibility=public`. Uploading or pushing an image there must **not** be described as a private, retained artifact. Three routes: (1) publish to this repository now (REJECT no private storage/owner approval); (2) deploy directly from a build or from the Dell (REJECT running-image disruption, no signed artifact); (3) SELECT lock and verify every distributable input offline in a short-lived GitHub Actions runner and leave release retention blocked until owner-approved private storage is established.

**Inputs now explicitly pinned:** `images/sentinel-candidate.Dockerfile` fixes base `python@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337`, rather than accepting dynamic `python:3.12-slim-bookworm` tag resolution. Image platform `linux/amd64`. `images/sentinel-candidate-requirements.lock` fixes the full wheel dependency closure for CPython 3.12: `cryptography==45.0.7` sha256 `b6a0e535baec27b528cb07a119f321ac024592388c5681a5ced167ae98e9fff3`; `cffi==2.0.0` sha256 `3e17ed538242334bf70832644a32a7aae3d83b57567f9fd60a26257e992b79ba`; `pycparser==2.23` sha256 `e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934`. Exact wheels were downloaded in isolated GitHub audit run `40763769585` and SHA-256 printed. No source distributions. Build now uses `pip install --require-hashes --only-binary=:all: --no-deps` with the three explicit pinned packages, followed by `pip check`. This is intentionally Linux/amd64-specific; platform changes require new reviewed hashes.

CI source changes: public wheel-hash audit workflow `4fe221c307b288aa4d2456036d5ae04fcd985706`; lock file `566aa137ffda62056e63cd6a38036c29216e5cc7`; Dockerfile fixed base and pip verification `b1cf01a0cb2b67fcfca487aabc188f379280d36b`; candidate workflow now pulls only pinned digest and builds from **16** allowlisted files `fe25dccf8e54bfdab96038fe8407188f10d99c3c`.

**Locked isolated candidate CI result on source commit `fe25dccf8e54bfdab96038fe8407188f10d99c3c`:** GitHub candidate job run `40763979427` showed pinned base download PASS, `ALLOWLIST_FILE_COUNT=16`, installation of exactly cffi 2.0.0, cryptography 45.0.7, pycparser 2.23 with required hashes, nonroot/loopback future command PASS, demo-mode `--network none` smoke PASS, source SHA256 and Git blob comparison PASS. Ephemeral image config ID `sha256:57b4c651bba633ead9c304b3ac9ce3ad3244968b3c16002ea9db02492dc001ad` (not a registry digest, signed signature or reusable artifact). All three source bytes match previous checked-out candidate manifests. The runner then deleted the candidate container and tagged image. **No production image, registry push, signing key, NOC live mode, email, customer data or Docker service on the Dell was involved.**

**Release constraints:** a byte-reproducibility guarantee requires at least two independent identical builds and a signed OCI manifest/ref, which have NOT been demonstrated; pinning only inputs does not certify byte-for-byte identical image IDs. Need a separately authenticated owner-controlled *private* artifact store / registry, independent digest verification after transfer, signer-key custody and source-probe attestation, separate offhost down detector, and supervised source/alert acceptance before any production switch. Do not use public GitHub Actions artifacts as supposedly private. Existing live Dell monitoring is healthy; G2 remains untouched. Final workflow results should be read back independently; document below when complete.
