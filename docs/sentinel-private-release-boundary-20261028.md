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

## 28 October — private repository created and release controls installed (NO RUN)

Owner created `MrFixITslu/V79-Sentinel-Release` on GitHub. The connected GitHub API independently verified repository visibility **private**, admin/push access available, default branch `main`, unarchived. Before installation repo was empty. Reviewed the previously delivered bootstrap ZIP and confirmed four expected files, exact archive/folder bytes, and offline `6/6` policy tests PASS.

Three approaches /REDTEAM: (1) install publisher in public `V79-Sentinel` (REJECT because package visibility can inherit public access); (2) push immediately from private repo (REJECT before package visibility and signing acceptance); (3) **SELECTED** install only the manual-release controls in the verified private repo, with NO dispatch. GitHub created the private README to initialise empty main, then installed `ci/private_release_policy.py`, `ci/test_private_release_policy.py`, `.github/workflows/publish-private-review.yml` as separately recorded commits. Connected GitHub read-back confirmed exact four paths on main, repository remains PRIVATE, workflow `on: workflow_dispatch` only (no push/PR/schedule), exactly pinned source SHA `39dfcff98ed790e18ff24ec43a0fcade90e67981`, expected GitHub owner+repo/branch guard, pre/post private GHCR checks, no `ssh`/Dell command, networkless nonroot demo smoke, and `packages: write` only in the manual private repo.

Private repo installation commits: README `e19ab1d937f4b9260cbc20c288cb49fb1ce1c94f`; private release policy `fe688231c5c7609b4260fb8f908a427c56cbe4d4`; six offline policy tests `ad6a82acfae621fb927fc3fd61193c8fff5a062a`; manual-only workflow `55107075f8f5a108e68a21ffcab493cd36e2ae54`. **NO `workflow_dispatch` was invoked, NO GHCR package created or uploaded, NO private registry digest verified, NO secrets provisioned, NO signer key produced, and NO Dell/G2/customer app deployment made.**

FIRST-PUBLICATION /REDTEAM remains important: the pre-push GitHub Packages API permits 404 when package not yet created, but 404 can also represent an inaccessible package; even a post-upload PRIVATE result cannot retroactively erase a brief exposure. Require independent owner review of package settings/access inheritance before any first manual dispatch. Ensure private repository's Actions policy grants only trusted owner access and that `GITHUB_TOKEN` package permission is actually supported; fail closed rather than creating PATs or relaxing checks. Workflow is a review-image publisher, NOT signing or production activation. Need independent private GHCR digest custody, provenance/signing, live source process origin, durable anti-replay, off-host Dell-down observer and founder alert acceptance as separate release gates.

**State: PRIVATE RELEASE CONTROLS INSTALLED AND READ BACK; PUBLISHING AND PRODUCTION RELEASE HOLD.**

## 28 October — first-publication GHCR privacy red-team and nonpublishing preflight

Current GitHub docs clarify that **a new GHCR container package is private by default**, while **repository-linked package access permissions may be inherited**; this is not a guarantee of the actual current package's settings. Sources: https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry and https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility .

Three options /REDTEAM: (1) run manual publisher immediately — REJECT until package/Actions access confirmation; (2) block forever on an absent package (404 can be an absent *or inaccessible* package; does not verify privacy) — REJECT as a useful preflight; (3) SELECT install a distinct **owner-manual, READ-ONLY** privacy preflight with `contents:read`, `packages:read`, no Docker/push, fail-closed on wrong identity or a public package, and explicitly report ambiguous 404 as 'ABSENT_OR_INACCESSIBLE'. Owner can inspect result and settings before considering a separate publishing dispatch. No auto trigger was introduced.

Private repository `MrFixITslu/V79-Sentinel-Release` was independently reverified PRIVATE/admin-visible. Added private code `ci/private_preflight.py`, 7 synthetic no-network negative/positive cases in `ci/test_private_preflight.py` in addition to existing 6 publisher policy tests, and manual `.github/workflows/verify-private-preflight.yml` with no upload/push/pull/live side effects. Expanded `ci/private_release_policy.py` with distinct owner confirmation `PRIVATE-PREFLIGHT-ONLY` (publisher still requires `PRIVATE-REVIEW-CANDIDATE-ONLY`). Scope-reduced the publishing workflow's `GH_TOKEN` environment from job-wide to only three explicit API/push steps; GitHub still grants `packages:write` to the **publishing job** but not the read-only preflight. `README.md` now documents exact owner UI steps and cautions.

Private installation commits: policy `52be14e538554ff7dede502563a7dd29c75589fa`; preflight script `ed8329490ff787ac780e069c2cf9a9723a1baed8`; seven tests `4b4b73e9c09194fb054e5465d82b57afc41f5840`; publisher token narrowing `e48a837225973077fd7f7ae256079e634698e743`; owner-manual preflight workflow `94ccad58955e56b073fc2fecbf0836be52dcc945`; README `507ce9924f644cfe0d03458dae2493f2a2240cd4`. Connected GitHub read-back confirmed all seven private repository files and privacy PRIVATE, and both workflows remain **manual-only**, with preflight no Docker/publish and `packages:read` only. **13 tests defined, not yet executed in a GitHub workflow after these changes; do not claim PASS**. GitHub connected API cannot dispatch workflows or read current Actions settings on this account. Owner must run the read-only workflow, inspect authenticated output and UI Actions access rules; stop on denial/public package.

**No private GHCR image or digest created, no workflow run, no key, no change to Dell/G2/NPM/Hub/Hetrix/WiPay. Private publication and all production security automation remain HOLD.**

## 28 October — owner-initiated private registry read-only preflight verified PASS

Connected GitHub API listed manual `workflow_dispatch` run [`40769206918`](https://github.com/MrFixITslu/V79-Sentinel-Release/actions/runs/40769206918) on private repo `MrFixITslu/V79-Sentinel-Release`, branch `main`, actor `MrFixITslu`, source/control head `507ce9924f644cfe0d03458dae2493f2a2240cd4`. Conclusion `success`, all job steps completed successfully.

Fetched job `123101523049` logs independently: **13/13 offline synthetic policy tests OK**. Authenticated read-only privacy query returned exactly `PREFLIGHT_READ_ONLY=PRIVATE_REPO_VERIFIED_PACKAGE_ABSENT_OR_INACCESSIBLE`, plus `PUBLISH_AUTHORISED=NO` and `PRODUCTION_DEPLOY_AUTHORISED=NO`. Repository is independently confirmed PRIVATE via connected GitHub `get_repo`. The GHCR package response is 404: it may be absent or inaccessible to this token; **do not label a package private, published, or non-existent based on this result**. No workflow artifacts were produced.

Three next approaches /REDTEAM: (1) treat 404 + successful preflight as permission to publish automatically — REJECT; (2) skip image custody entirely and deploy from source to Dell — REJECT; (3) SELECT keep first-publish on owner-controlled manual confirmation after reviewing package default private visibility, inheritance and Actions permissions, with post-push privacy/digest validation and separate signer release gate. The current GitHub connector provides no authorised workflow dispatch action; no publish was attempted. The manual publication workflow already installed is distinct and **has not been run as part of this preflight**.

**State: FIRST-PUBLICATION READ-ONLY PREFLIGHT ACCEPTED; PRIVATE GHCR PACKAGE PRIVACY/ACTUAL IMAGE CUSTODY UNVERIFIED; IMAGE RELEASE/DELL DEPLOYMENT/AUTOMATED OWNER INCIDENT ALERTS HOLD.**

## 28 Oct 2026 — guarded monitor deployed; remaining signer/offhost/alerts NOT activated

The owner ran pinned, checksum-verified guarded Dell monitor-only cutover. Terminal receipt confirmed checks: source hashes PASS, network-none demo PASS, seven pinned TLS HTTPS one-shot checks PASS (0 warnings), original Dell NOC/ingress IDs and data mounts unchanged, new monitor healthy, fresh 7-target LIVE sample PASS, `SENTINEL_MONITOR_ONLY_DEPLOYMENT=PASS`. Recovery Compose bytes stored locally at `/home/firelion/V79-Sentinel-Dell-Owned-v1/.compose.private.monitor-before-20261028T213847Z.json`; old image retained. This is owner-supplied terminal proof (not independent in-chat Dell connection). New monitor is deployed, NOT the signer and alerts. No new changes made in this update.

Connected external account read: nine Hetrix website monitors active UP, but `has_agent=false` (NOT off-host Dell machine-health verification); Resend domain sending-enabled, status `partially_failed`. Remaining 3-milestone release plan: 1 MONITOR DONE; 2 signer-key custody, replay-resistant authenticated real probe and independent off-host down watcher PENDING; 3 automated founder incident and recovery emails, privacy/DNS/dedup acceptance PENDING. Protect existing monitor and production services; fail closed on missing evidence. No claim of complete autonomous security deployment.
