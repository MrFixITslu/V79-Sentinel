# Sentinel P1 — in-process probe-to-signed-review bridge (29 Oct 2026)

**REVIEW-ONLY OFFLINE ENGINEERING MODULE. No monitored Dell Docker, NOC, disk mount, signer key, service or email was changed.**

## What is already live

Owner's Dell monitor healthy with seven local owned HTTPS HEAD targets (all reported HTTP 200), pinned three source SHA256 files and local NOC read-only Mission Control bridge. NOC main dashboard `/readyz`: `collector=simulated-only`, `integrations=disabled`. Existing Hetrix 9/9 independent external web checks and DOWN/UP inbox drill work separately. No signed production incident integration was enabled.

## Three options and /REDTEAM

1. Enable signer directly with current existing production container or read `/api/status` JSON and sign it: REJECT. Externally supplied JSON can be fabricated; production key custody, process/image identity and receiver rollback have not been independently accepted.

2. Install new co-located NOC signer or attach Docker socket to NOC: REJECT. Would expand privileged attack surface and risk mislabeling simulated incidents as verified.

3. CHOSEN: implement a **composable, opt-in, no-network, no-key-loader** test adapter from the **existing `monitor_forever(evidence_sink=...)` probe boundary** to protected separate SQLite signer and receiver ledgers; prove actual monitor-loop injection via monkeypatched `probe_many` with all incidents explicitly `review-only`. Do not register the bridge in `sentinel.main()`. This is preparation for an eventually independently approved IPC/transport design, not a usable production signer.

## What changed

- `noc/isolated_inprocess_review_bridge.py` requires separately supplied Ed25519 signer object, explicit independently pinned public key, fixed exact target scope, valid collector and two distinct, durable file-backed SQLite handles. It never creates/loads a secret, creates a connection, sends a packet or starts a service.

- The callback signs the sanitized in-process receipt with the existing atomic sender sequence contract, immediately verifies and stores through the existing pinned receiver/outbox contract; both sides preserve `sourceProvenanceVerified=false`, `physicalProbeAttested=false`, `trustedForExecutiveUse=false`, `alertsDispatched=false`, `ticketCreationEnabled=false`, `productionApproved=false`.

- A receiver rejection consumes the already committed sender sequence but creates **no** delivered alert; a later duplicate/reset must not silently repair that gap. Monitor loop catches sink failure without interrupting availability sampling.

- A test exercises the **actual `sentinel.monitor_forever` callback** after monkeypatching probe_many and monitor status; validates one in-process signed record, exact 7-target allowlist, sensitive input stripping, replay/reset denials, forged pin, unsafe same-file/memory stores, failed receiver insert rollback, default-off behavior and inability to claim actual probe provenance.

- A GitHub-only CI workflow reruns stacked offline signing-to-founder, database durability, external Hetrix comparison and mission-bridge tests. `sentinel.main` is checked not to register the adapter; no real HTTPS request is sent.

## Remaining hard release gates

1. A separate, owner-protected private signer key/UID/mount and immutable public key pin established **out of band**. No key material in GitHub, ChatGPT, Docker inspect, env vars, public paths or logs.

2. Production receiver should be a separately owned process/host with authenticated IPC and pinned signer process identity; this in-process rehearsal uses receiver in the SAME Python interpreter and **cannot** prove source honesty or protect against compromise of that process.

3. Durable boot identity / monotonic sequence across monitor container restarts without resetting or rolling back both DBs; owner-approved isolated restore test and release manifest.

4. A separate tested off-host Dell-down observer; a Dell-local monitor cannot detect complete loss of its own host. Hetrix existing external website alerts cover HTTP reachability only.

5. After independent review of entire stacked draft PR ancestry and release SHA, guarded deployment via a real private immutable image, distinct volumes/mounts, nonroot UIDs, small blast radius and owner-approved negative/recovery test. GitGuardian #38116562 was observed by owner as a password **code reference**, but dashboard final disposition is not verified.

6. Only then enable real founder-only signed delivery with idempotent Resend and actual receipt confirmation. Provider HTTP acceptance is not email delivery or a cryptographically signed founder acknowledgement; Hub/COO and Tiquet actions remain separately blocked.

**Decision: source-hook integration can now be validated via CI but trusted signed production protection remains HOLD. No automatic deployment, key generation, host access, issue-closing or merge authorised.**