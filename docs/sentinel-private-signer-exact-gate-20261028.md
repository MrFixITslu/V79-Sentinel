# Sentinel P1 — private signer exact-gate reconciliation (2026-10-28)

**SOURCE-ONLY / NO MERGE / NO DEPLOY / NO REAL SIGNER KEY.**

## Why this branch exists
The older release notes said the dedicated private-signer test suite was missing. A fresh GitHub source check on the current development lineage confirms `noc/tests/test_owner_private_candidate.py` **exists**. This does not establish that its dedicated CI gate passed on the current exact tree.

Three options considered: (1) mark historical GitGuardian #38116562 false-positive and deploy automatically — rejected because the user's classification was observational and the scanner state is not independently verified; (2) rely only on the 107-test generic isolated suite — rejected because the dedicated private signer path and fault modes were not exercised by that workflow; (3) **chosen**, expand the dedicated, isolated test gate and explicitly retain the source-provenance/review hold.

## Targeted REDTEAM cases
- `journal_mode=OFF` or `MEMORY` when `synchronous=FULL` must never allow persistent private-signer acceptance.
- A simulated SQLite review-outbox insert failure must roll back both replay sequence and intermediate fault-state counters; retry may work after recovery.
- Two concurrent attempts signing the same observation must produce at most one accepted review-only result.
- A forged but well-formed `mode=live` Python dictionary may pass local signing; it must **never** claim verified physical sampling, true service health, trusted Hub evidence, automatic alerts, or a customer incident.

## Changes
- Expanded `noc/tests/test_owner_private_candidate.py` with isolated, disposable fixture-only negative tests.
- Updated `.github/workflows/sentinel-private-signer-promotion-gate.yml` to run the dedicated signer tests **and** the separate durable SQLite regression suite. Its job is explicitly labelled *synthetic-private-signer-tests-only* to prevent mistaken independent-review claims. Static gate checks source-level false trust flags; it does not attest the executable.

## Release blocker inventory
- GitGuardian finding #38116562 was reported by founder as **a code reference to a password**, consistent with likely false positive. Exact current GitGuardian dashboard disposition is **NOT VERIFIED** by this repository connection; do not suppress/checkmark automatically.
- Independent human review #3 remains open. A CI success is not independent human approval, nor proof of signed immutable binaries, real probe provenance, protected owner key custody, or restored high-water anti-rollback.
- Source changes stack on draft PRs #21–#28, which remain unmerged; broad ancestor integration and guarded rollout would require separate exact SHA/recovery proofs and owner authorisation.
- No actual password or key is accessed or published; tests generate disposable Ed25519 fixture keys under temporary paths only. No production receiver, Hub, Tiquet, WiPay, Hetrix, Resend, Docker or host modifications.

**Decision:** dedicated tests may validate the isolated private signer path; production signing and trusted telemetry remain **NO-GO** until provenance, security review and private finding triage are resolved.
