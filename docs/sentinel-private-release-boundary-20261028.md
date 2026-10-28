# Sentinel private OCI release boundary — 28 October 2026

**SOURCE DESIGN PREPARED • PRIVATE REPO AND GHCR NOT VERIFIED CREATED • NO IMAGE PUSH • NO PRODUCTION DEPLOY**

## Three options and /REDTEAM

1. Push GHCR image directly from the public `MrFixITslu/V79-Sentinel` Actions workflow: **REJECT**. GitHub documents that workflow-created package visibility and access can inherit the workflow repository. Public package exposure risks cannot be treated as acceptable.
2. Store candidate only on the production Dell: **REJECT**. No independent recovery if Dell fails; also increases local container/image custody blast radius.
3. **SELECTED**: a dedicated owner-controlled **private** `MrFixITslu/V79-Sentinel-Release` repo with a manual, owner-only workflow and private GitHub Container Registry package. Build at a pinned, independently tested public source commit; verify repository and package privacy via authenticated API before upload, and verify package privacy and digest round-trip after upload. This is separate from production deployment and signer approval.

## Verified source baseline for publisher design

- Audited locked public source candidate SHA `39dfcff98ed790e18ff24ec43a0fcade90e67981`, all six independent CI workflows SUCCESS after owner fixed `cryptography==50.0.2`.
- Pinned base `python@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337`; candidate Dockerfile builds from exactly 16 allowlisted files, no private secrets.
- Candidate source SHA-256: `sentinel.py` `28350c24bf6413e6f5128748b823e841dee6bb6ea838c384e9ac23adcefab33d`; `monitor_core.py` `4e175f32fa05253f6e87acb2bdb36ad2e7fefd3b394f9c19d00937b38f011c47`; `noc/inprocess_probe_receipt.py` `9672151b7c776e9f6de2ecba96115069b0242a7d6842c65f7b212d0830cd6cd5`.
- The first audited ephemeral `cryptography 50.0.2` image was deleted after networkless demo testing; its local Docker config ID is NOT a persistent, signed registry manifest digest.

## Source-only private bootstrap prepared (not activated)

A downloadable ZIP was prepared in the ChatGPT conversation with exactly these files: `.github/workflows/publish-private-review.yml`, `ci/private_release_policy.py`, `ci/test_private_release_policy.py`, and `README.md`. The workflow exists only in the downloaded bootstrap ZIP and **has not been installed in any repository**. No credentials, signing keys, or customer information are in the ZIP. Local offline policy suite: **6/6 tests PASS**, plus static validation of manual-only workflow trigger, private repo identity, source pin, private checks pre/post push, demo-only/no-network smoke and lack of production Dell commands.

The template requires an exactly named private repo, `workflow_dispatch` initiated by GitHub actor `MrFixITslu` on `main`, and an explicit `PRIVATE-REVIEW-CANDIDATE-ONLY` confirmation. GitHub `GITHUB_TOKEN` has `contents:read`, `packages:write` only in the private repo. The repo must respond as `private=true` to GitHub's authenticated API. The GHCR package `v79-sentinel-candidate` must be missing or independently verified PRIVATE before first upload and must verify PRIVATE after. Package remains review-only, uniquely tagged and verified by immutable registry SHA-256 digest after a pull. Never run from the PUBLIC source repository, auto-trigger from PRs, pass PATs via chat, expose host secrets or trigger production actions.

**Important remaining exposure risk:** even with pre/post checks, newly created package privacy must be verified by the owner because accidental first-publication visibility cannot be undone retroactively. Do not claim registry privacy or verified release digest before real successful private repo workflow and authenticated package checks. GitHub source repository and default workflows remain public; do not connect the published package to the public source repository for inherited permissions.

**Plan-dependent signing:** GitHub native Artifact Attestations for private repositories require GitHub Enterprise Cloud (per GitHub Docs, as reviewed on 28 October 2026). No account entitlement has been verified. The bootstrap intentionally DOES NOT claim image signing or build provenance. Choose independently protected cosign signing or Enterprise attestation only after reviewing key management, plan entitlement, and private disclosure risk. A digest proves byte identity, NOT authorisation or genuine physical HTTPS probe provenance.

## Current acceptance

| Gate | Result |
|---|---|
| Source-only private publisher template and 6 negative policy tests | **PREPARED / PASS LOCAL** |
| Dedicated private repository visibility/access | **NOT VERIFIED / BLOCKED** |
| Owner manual approval + private GHCR upload | **NOT DONE** |
| Registry digest pull round-trip and post-push private visibility | **NOT DONE** |
| Independent signed release provenance / key custody | **NO-GO** |
| Trusted in-process signed telemetry, offhost Dell-down observer, automatic founder alerts | **NO-GO** |
| Running Dell legacy monitor / G2 / existing V79 apps | **UNCHANGED** |

**Next owner action:** create a *Private* repository named `MrFixITslu/V79-Sentinel-Release` at `https://github.com/new`, grant the connected GitHub app access if necessary, then the prepared workflow and policy files can be reviewed/installed there. No attempt to create a repository was made by the assistant, because the connected GitHub tools do not expose repository creation; a direct lookup returned 404 (nonexistence or insufficient connector access).

References: GitHub Docs 'Publishing and installing a package with GitHub Actions', 'Configuring a package's access control and visibility', 'Using artifact attestations to establish provenance for builds'.

**Decision: PRIVATE RELEASE WORKFLOW PREPARED BUT NOT INSTALLED; NO IMAGE PUBLISHED; NO DELL CHANGES; PRODUCTION SIGNER/AUTOMATED SECURITY ALERTS HOLD.**