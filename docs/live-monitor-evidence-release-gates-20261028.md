# Sentinel live-monitor evidence bridge — controlled release gates

**28 October 2026 • SOURCE CANDIDATE ONLY • NOT INSTALLED • NO LIVE ALERT DELIVERY**

## Facts established on the V79-owned server

The owner observed `v79-sentinel-dell-monitor` running as UID:GID `10001:10001`, launched with `--live`, image `sha256:c9ae010b7971496855785f275bda9e40e33617044376e2225d5488e2fbfdc6fc`. A single locally reported sample read `mode=live`, `cycle=17`, `last_check=2026-10-28T02:26:48Z`, seven HTTPS HEAD targets `up`, and no engine error, age 262 seconds. `sentinel.py` and `monitor_core.py` exact source file blobs match V79-Sentinel/main; the original diagnostic used literal backslash-zero instead of the required Git NUL delimiter, now corrected in review. **A running HTTPS monitor is NOT the same as a signed, independently verified monitoring and alerting system.** A successful HEAD response is not proof of authenticated app function.

The distinct private NOC explicitly reports `collector=simulated-only` and `integrations=disabled`. Do not relabel demo dashboards, bootstrap the staging NOC into production, attach customer sites, bypass closed blocked PR #14/GitGuardian, or install draft security watch PR #19 as a workaround.

## Three options and /REDTEAM selection

1. Enable existing simulated NOC as genuine alerts: reject — fabricates attestation and may generate customer incidents.
2. Rebuild three-container Sentinel suite: reject — avoid downtime, backup/recovery, proxy-network and identity blast radius.
3. **Chosen:** retain live 7-target HTTPS monitor and add a *separate, private, read-only evidence lane*. Never let monitoring approve execution, create Tiquet records, mutate Hub, expose host secrets or spend money.

### Source-only prototype in PR #20

- `noc/legacy_monitor_proof.py`: exact seven V79-owned targets; validate recent live status, 2xx/3xx claims, cycle, timestamp, certificate warnings and no source error; project a minimal snapshot without messages/cookies/user data. Optional private Ed25519 signer signs an **advisory candidate**, not a proven physical probe.
- `noc/signed_owned_evidence.py`: recipient checks exact pinned public key, collector ID, signature, scope and signed timestamp; returns **`SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE`**, never operational protection.
- `noc/owned_alert_state.py`: owner-private file-backed SQLite with synchronous FULL; atomic transaction for replay sequence, two consecutive reports at least four minutes apart, and a proposed **review-only** incident. Two healthy readings to propose recovery; warnings do not clear failures. Unique outbox keys prevent double proposals. **Never sends email.**
- Existing `noc/owned_replay_checkpoint.py` provides an independent receiver-side replay contract; do not open two active replay cursors for the same collector without a reconciliation/ownership plan. The new state-machine transaction is the *single combined checkpoint plus proposed-incident path* for a future operator.
- `passive_heartbeat` classifies stale/silent reports `UNKNOWN`. It must run **outside** the monitored Dell; running it on the Dell is not availability protection.
- CI: synthetic in-memory private key generation only, all negative and concurrency tests run in isolated GitHub-hosted runners; no credentials, network probing or emails.

### Required owner-supplied production checks, in order

1. **Read-only current parity**: confirm two exact source files, running image, container paths and 7-target monitor cycle again after any infrastructure change. Verify container and private-network reachable paths without exporting cookies or secrets. Current parity is known at the historic observation, not guaranteed forever.
2. **Independent source-of-measurement**: provision *owner-protected* local-key custody and prove signer receives only the pinned actual live-monitor process result, not a user-supplied JSON replay. Confirm process identity and permissions. Do not classify signature alone as proof of real probes. Never create or print private keys in chat/GitHub/CI.
3. **Single durable state owner**: owner-private `0700` directory and `0600` SQLite, `PRAGMA synchronous=FULL`, strict sequence, no automatic reset when the monitor restarts, one receiver. Test forced crash between receipt and outbox commit. Freshness expires at 10 minutes, unknown is not UP.
4. **Off-host failure observer**: install a separately supervised watchdog outside the Dell, owned by V79 Digital, with a stable always-on network. Its inability to see fresh externally authenticated updates must trigger `UNKNOWN/monitoring blind`; do not claim that the self-hosted monitor can detect the Dell being fully powered off.
5. **Founder-only notifications**: connected Resend domain currently has sending enabled, DKIM and two SPF records verified but overall `partially_failed` from tracking DNS. Test one harmless owner-approved synthetic advisory using a fixed owner recipient and explicit idempotency key, strict retry/backoff/limit, no real customer data. Distinguish *provider accepted* from *confirmed recipient delivered*. No auto-sends until signed evidence, complete audit and opt-in.
6. **Acceptance**: demonstrate an owner-controlled known target failure and recovery, two-sample thresholds and no duplicate alerts; separate monitor outage blind-spot event; verified owner inbox receipt; resource limits and off-host telemetry integrity. Never disrupt the live Hub/Tiquet/WiPay/G2 workloads for tests.
7. **Approval**: security-review hold and existing owner approval gates apply before any merge, first monitoring config/secret creation, schedule, email dispatch, NPM route or release. No unnecessary broad rollback or backup rehearsals during the source-only phase.

## Operational claims allowed today

| Capability | Evidence | Status |
|---|---|---|
| HTTPS HEAD reachability | 7/7 locally reported fresh | **LIVE, UNSIGNED** |
| Installed monitor source | two runtime sources matched GitHub | **PARITY VERIFIED** |
| NOC demo source | explicitly simulated | **STAGING ONLY** |
| Signed probe origin | no deployed key custody or signing sampler proof | **NOT VERIFIED** |
| Durable proposed incidents | source-only tests, not installed | **NOT ACTIVE** |
| Resend sending | authenticated domain records | **SENDING POSSIBLE, DELIVERY UNTESTED** |
| Independent full-Dell outage alarm | no deployed off-host watchdog | **NOT ACTIVE** |
| Complete G2 approved task | worker idle polls verified, no new task E2E | **NOT TESTED** |

**Release decision: HOLD.** Do not treat CI, dashboard health or an API response as production end-to-end evidence. No code in this PR performs a live network probe, task action or email delivery.

## 28 October — interim external monitoring acceptance (HetrixTools, read-only verified)

**Scope and meaning:** independent third-party HTTP(S) availability checks for the nine V79-owned public front doors, **not** signed Sentinel collector provenance, host availability proof, application login health, threat detection, backup recovery, or verified delivered email. Do not label this as signed Sentinel production.

After the owner corrected the canonical CombatZone domain to `combatzone.v79sl.com`, the existing HetrixTools monitor was updated **in place** (monitor `31703f7d9a044f18d310da16710dc391`), from obsolete `lasertag.v79sl.com` to `https://combatzone.v79sl.com/`. Its creation identity/history, one-minute cadence, 3-region check, TLS certificate and hostname validation, alerts/thresholds, and existing founder email contact list were preserved. No Nginx, Hub, LaserTag/CombatZone container, G2, or WiPay setting was changed. Owner's direct Dell probe of canonical site returned HTTPS 200 with TLS certificate verification success; generated NPM `30.conf` hosts the canonical domain.

Connected HetrixTools API afterwards reported **9/9 active monitors UP** (one-minute checks):

| External service | HTTPS endpoint | Latest reported status |
| --- | --- | --- |
| Hub | `https://hub.v79sl.com/` | UP |
| Tiquet | `https://tiquet.v79sl.com/` | UP |
| Vision79 Website | `https://v79sl.com/` | UP |
| FFPRO | `https://ffpro.v79sl.com/` | UP |
| Academy | `https://academy.v79sl.com/` | UP |
| Marketing | `https://marketing.v79sl.com/` | UP |
| POS | `https://pos.v79sl.com/` | UP |
| Games | `https://games.v79sl.com/` | UP |
| CombatZone | `https://combatzone.v79sl.com/` | UP from New York, London and São Paulo |

Provider account limit: 9/15 uptime slots used; all current monitors lack a Hetrix server-agent SID. The default contact list includes the founder's already verified email `vision79slu@gmail.com`. **Email configured and verified ≠ owner received a downtime notification.** A Gmail search found one Hetrix verification email but no confirmed outage alert. No intentionally failed real target, test email or synthetic notification was sent. The previous `lasertag.v79sl.com` TLS SNI failures were caused by monitoring the obsolete domain and **must not be reported as a confirmed outage of CombatZone**.

**Three routes /REDTEAM:** (1) treat external HTTPS 200 as proof of Sentinel security: REJECT; (2) run private signer or fake the NOC staging data as trusted: REJECT, active signer/source custody gate absent; (3) ACCEPT external web availability as limited independent coverage while separately proving founder alert receipt and host/off-host failure visibility, and keeping source-only signer/key review gated. Do not create a duplicate monitor or replace existing site routing.

**Open acceptance actions** (independent of established G2 marker archival recovery):

- A founder-approved *non-disruptive* single-recipient notification/delivery test, with actual inbox evidence, no customer data and no auto-retry flood.
- A continuously running, separately hosted source of Dell-failure/monitoring-blindness evidence (the Hetrix HTTPS checks are external service-reachability, but cannot attribute all simultaneous failures specifically to Dell power vs ISP/reverse proxy).
- Optional least-privilege Hetrix server agent for Dell CPU/RAM/disk and backup freshness only after installation/credential and resource security review; no agent installed yet.
- Private signed collector production work remains **NO-GO**: verify physical source and process identity, protected pin/key ancestry, one durable sequence/outbox, accepted dedicated security tests, historical PR #14 security review, and supervisor/cost constraints. The PR #14 draft was closed, which **does not mean** its GitGuardian concern was cleared.
- Remote Desktop Commander listed Dell online but a subsequent read-only execution returned a **monthly quota exhausted** error; do not retry/reconnect or count a Dell resource/backup audit as performed.
- All five scheduled ChatGPT automation slots are already occupied; an additional hourly incident watch was refused by the plan. No existing automation was overwritten.

**Production state:** external HTTPS reachability coverage ACCEPTED (limited), G2 incident archival ACCEPTED separately, signed Sentinel/NOC activation and founder alert delivery still **HOLD**. No production changes were made by this source-only note.

## 28 October — signer custody security suite implemented; test-only acceptance PASS

On draft/source-only PR #20, added `noc/tests/test_owner_private_candidate.py` with 14 synthetic isolated security tests (temporary Ed25519 fixture key and SQLite ledger in GitHub runner only; NO production signer key, service, network, email or monitor writes). Coverage: signed candidate remains review-only, no send or privileged action, persistent replay cursor across restart, exact-once review outbox, tampered/forged/demo reports rejected, owner-only allowlist/collector scope, mismatched or missing public key pin, unsafe key permissions or wrong key length, world/group-accessible private directory, key/final-directory/ancestor symlink path refusal, private durable ledger requirements, non-root signer requirements and stale/future timestamp rejection.

Fixes in `noc/owner_private_candidate.py`: legitimate `pathlib.Path` inputs now pass type validation (`isinstance` instead of a mistaken exact `Path` type check); protected signing directory path is opened one segment at a time from `/` through directory file descriptors with `O_NOFOLLOW`, rejecting any ancestor symlink rather than checking only final component. No runtime configuration changed.

**Independent CI evidence:** exact draft head `64e510316fc8b8051eb234bb6e4d7199e4f48565`. `Sentinel private signer promotion NO-GO gate` workflow run `40754038132` completed **SUCCESS**; its `Run dedicated private signer security suite in isolation` and fail-closed missing-suite prerequisite both individually succeeded. `Sentinel legacy monitor proof bridge` workflow also successful. Final independent workflow check after the code commit: all **four** GitHub Actions runs finished SUCCESS at exact SHA `64e510316fc8b8051eb234bb6e4d7199e4f48565`: isolated regression run `40754038188`, Docker staging checks run `40754038071`, legacy monitor proof bridge run `40754038070`, private-signer security suite run `40754038132`. These are SOURCE TESTS ONLY; no merge, production deployment, signing identity proof or auto-alert activation occurred. Production remains NO-GO.

**Security /REDTEAM:** Tests certify only that isolated signer candidate *refuses unsafe inputs and persists review candidates under permitted conditions*. They do NOT authenticate physical HTTP/TLS probe origin; a signed arbitrary JSON report is not proof the live Dell collector observed its claims. No owner-private production key was created, no persistent authorized source with encrypted custody established, no independently running off-host watch service, no autonomous alert sender or incident/Tiquet integration. Do not merge or deploy this draft as production Sentinel based on the green test job alone; require separate real-probe provenance attestation, durable source-to-receiver validation, offhost heartbeat, sender outbox and incident approval/circuit breakers, and owner go/no-go decision.

Founder separately verified one-time manual transactional test alert **received** via Resend/Gmail; email endpoint transport PASS, but no automated Sentinel incident-to-mail test was executed. Hetrix independently reports 9/9 owned public SaaS HTTPS endpoints UP; these external checks do not establish host telemetry.

## 28 October — source-only measured-cycle tap attached to legacy Sentinel probe loop (disabled by default)

Red-team comparison: **(1)** signing public `/api/status` JSON rejected because any replay/malformed text could be treated as an observation; **(2)** adding a second independently polling agent rejected due duplicate probes, different source, cost and deployment blast radius; **(3)** adopted a minimal opt-in source-only candidate projection on the **existing** `sentinel.monitor_forever()` loop **after** `monitor_core.probe_many(targets)` returns and **after** `store.record()` and the original dashboard state update complete.

Draft branch changes:

- `noc/inprocess_probe_receipt.py` defines `project_probe_cycle(...)`: normalizes only completed loop result objects against the pinned V79 HTTPS target allowlist, checks consistent 2xx/3xx UP codes, cert warnings, exact target completeness, cycle, recent UTC stamp and removes arbitrary messages, IPs, customer fields/history. Emits `IN_PROCESS_PROBE_CANDIDATE_ONLY` and explicit `False` for provenance, signature, replay, offhost observer, executive trust, host-up, email and incident write claims. **It never makes a network call or signs/sends/writes data.**
- `sentinel.py` has an optional `evidence_sink=None` argument on the same 5-minute monitor loop. `main()` still calls that loop with NO sink. A review sink supplied explicitly in future source tests gets one sanitized candidate after successful sampling; failures are caught and logged with a fixed redacted warning, without terminating sampling. There is no new HTTP route, public endpoint, deployment secret, CLI flag, producer key, external queue or alert sender.
- `noc/tests/test_inprocess_probe_receipt.py`: nine no-network synthetic regression cases for safe redaction and untrusted security flags, default-off, single in-loop candidate, sink exception isolation, falsely-reported UP and incomplete/scope rejection, store-error no emission, staleness/invalid cycle rejection, and forbidden send/key/HTTP operations.
- `.github/workflows/sentinel-live-monitor-proof.yml` now triggers on changed `sentinel.py`, candidate module and tests, parses their syntax and runs the dedicated suite alongside existing bridge tests. Related source-only commits `63c52c738425a93120443d79deae5e7cb152c6fa`, `7ec851c607da56295ee8b41071f0956d03323de0`, `8f49e9b2396bba3b7a782595702fee9fbf935ba6`, `404f7f6e9de72cac44f2ece5c5f7dd65df78a74c`.

**Acceptance limits /REDTEAM:** A code path immediately after `probe_many()` is a *stronger software provenance design* than signing user-supplied status JSON, but it still cannot independently establish genuine physical probe operation or cryptographic process identity. Malicious replacement code, compromised container, modified DNS or arbitrary sink would bypass trust; production signing only after runtime image/source and user identity/UID proof, protected production key, one durable monotonic producer cycle across restart, separately pinned receiver and independent offhost observer. No automated sends or threat guarantees. The classic demo NOC remains explicitly simulated; manual founder Resend test received, but Sentinel real-incident auto-alert path not validated. **Deployment/merge remains HOLD.**

GitHub Actions are the only validation performed here; do not claim any live Dell or network test. The connected Dell remote execution quota remains exhausted. Source branch and CI results must be independently reviewed before any production change.

**CI final readback for substantive measured-cycle hook commit `404f7f6e9de72cac44f2ece5c5f7dd65df78a74c`: 4/4 SUCCESS.** Existing CI runs: legacy in-process probe/bridge suite `40755197083`; private signer security suite `40755197141`; isolated regression `40755197041`; private Docker staging tests `40755197120`. All four completed successfully. These are GitHub-hosted synthetic source tests ONLY, not deployed monitoring or trusted probe attestation.

## 28 October — HTTPS DNS rebinding / transport pinning hardening, draft-source only

### Red-team of the actual HTTPS measurement source

Three routes were compared before the change: (1) activate existing candidate signatures despite no physical source integrity (REJECT: cannot trust unbound data); (2) duplicate external monitoring in a new service (REJECT: unnecessary load, cost, extra trust perimeter; Hetrix already gives 9/9 independent external reachability); (3) selected: harden the exact network read performed by the existing non-root in-process HTTPS collector, with no second probe or extra runtime activity.

**Identified threat:** `monitor_core._safe_addresses(hostname)` checked that DNS answers were all public, but the later `http.client.HTTPSConnection(hostname, 443).connect()` could resolve hostname again internally. A DNS-rebinding / TOCTOU split allows the actual connection to go to a different address than the prevalidated public DNS answers (potentially internal/private). Even a valid signature on a later report would not certify that the intended destination was checked.

**Source-only fix on draft PR #20:** `monitor_core.PinnedPublicHTTPSConnection` takes only an exact bounded set of public IP literals returned by `_safe_addresses`, creates the TCP socket directly to those numeric IPs without a second hostname resolution, and retains the original `hostname` for TLS SNI and default PKI hostname verification. Rejects a proxy/tunnel route, empty/non-public/oversized IP sets; tries the remaining already validated public IPs if one fails; closes failed TLS sockets. The existing `probe()` still uses a standard certificate-validating SSL context, HEAD, timeouts, response classification and no redirects. It is **NOT deployed**.

**Independent adversarial tests:** `noc/tests/test_dns_pinned_https_probe.py` adds nine no-network checks: numeric TCP destination + original hostname SNI, no hostname re-resolution, private/loopback/metadata/unspecified IP refusal, tunnel refusal, vetted alternate-IP fallback, failed-TLS socket cleanup, mixed public-private DNS rejection, full `probe()` path uses pinned transport and default SSL validation, and TLS failure never reports UP. The existing isolated bridge workflow triggers on `monitor_core.py` and the new tests and runs the regression suite with no production network calls. Source commits `bb61c027dd99fa7d863a9e1a9b3745ab3e599cfe`, `e80df47515375d9cb857c83e7817fe41a80378d3`, `17905e5b2cab9dc52a5e5be8931bd33fdb8f95c7`.

**Production release gates remain HOLD:** this code only strengthens the integrity of the intended HTTPS *destination*; it is not proof that the deployed container runs the reviewed binary, that the server is uncompromised, that signing keys are privately bound to this process, or that signed reports can be independently verified and stored across restarts. Validate all independent CI conclusions before source acceptance; runtime/image digest and UID/proc verification, protected real-source signer, off-host failure observer, and controlled live automated owner alerts remain separately required. No private key, live app setting, NPM, Docker/G2 or payment system was changed.

**Final GitHub Actions result for DNS-pinning code**: on exact source commit `17905e5b2cab9dc52a5e5be8931bd33fdb8f95c7` all four independent source-only workflows completed **SUCCESS**: isolated regression `40756228784`, private Docker staging `40756228700`, legacy bridge with nine new DNS-pin tests `40756228796`, and private signer gate `40756228715`. Tests did **not** make real network probes or install any Dell code. The DNS rebinding fix is source-reviewed and tested, **not yet applied to running image**. Production signer, off-host watchdog and autonomous alert activation remain NO-GO pending actual runtime parity and independent source attestation.

## 28 October — runtime identity/source-digest parity candidate gate (source-only, default NO-GO)

Three approaches /REDTEAM: direct draft deployment rejected (no verified image or provenance), duplicate observer rejected (does not attest the original collector), fail-closed read-only comparison against separately owner-pinned immutable release manifest selected.

Added `noc/runtime_source_parity_gate.py` and 14 offline negative/positive tests (`noc/tests/test_runtime_source_parity_gate.py`). Input requires only a fixed, minimal runtime snapshot for `v79-sentinel-dell-monitor`: exact **expected** image ID (sha256), non-root UID/GID, running and healthy status, exact `sentinel.py --live` Python process arguments, and **both SHA-256 content digests and Git blob SHA-1 identifiers** for `sentinel.py`, `monitor_core.py`, `noc/inprocess_probe_receipt.py`. Signed owner-expected reference must be established **out of band**, never copied from the untrusted running container. Snapshot freshness <=300 seconds, clock skew <=30 seconds; symlink, directory, extra/source-mismatch, stale status, wrong process, demo, wrong image or root fails CLOSED.

Even a completely matching snapshot returns `SOURCE_PARITY_CANDIDATE_FOR_OWNER_REVIEW` with `sourceProvenanceVerified=False`, `imageSignatureVerified=False`, `collectorProcessAttested=False`, `sourceSignatureValid=False`, `safeToDeploy=False`, `alertsDispatched=False`. This is an operator-review comparison, **not** cryptographic attestation and not a production safety certificate. No tool reads live Docker, filesystem, secrets, process images or email. Read-only future operator runbook: [sentinel-runtime-source-parity-gate-20261028.md](sentinel-runtime-source-parity-gate-20261028.md). Red-team hardening changed the initially proposed SHA-1-only source comparison to **mandatory SHA-256 plus Git blob ID** for every source path, with new negative tests refusing SHA-256 mismatch even if the Git identifier matches. Related additional commits: `14189d081680d738f96035bfd02e62b14eaa59c8` (source guard) and `62b31d92709c8f8dc53c8b861effb17ea02c67f0` (14-case tests), runbook commit `ee322038dc6e9995943acb04ddb843f2703a3708`. Treat earlier 13-test run as superseded by new code.

Code commits: gate `da9cf8cc7938148db5a9cc46f4a6df6469299541`, 13-test suite `f1059642c1f3561c7304496e204f2aa4c18d72e0`, synthetic test fixture correction `08086e2cf1b71c25ed716fd0586d9cb2e5709dbf`, strict running argv `c582b44dc4bfac10c13c1d1045ea8743a2a89b50`, independent CI wiring `ca7a4cb05d7f3f9ccfea88b1ab7a7554d34f80cf`, owner runbook `ca84861efbb68d37f950e29d80e063d6dcd3384b`.

Test outcome: independent `Sentinel legacy monitor proof bridge` at code SHA `ca7a4cb05d7f3f9ccfea88b1ab7a7554d34f80cf` run `40757433912` **SUCCESS** including new 13-test security suite. Independent private signer gate run `40757433895` **SUCCESS**. Isolated regression and private Docker staging were still pending at last inspection; verify their final conclusions separately. No merge/deployment or authenticated live host observation was performed. Dell remote execution unavailable due monthly connector quota; do not retry/reconnect. Existing 9/9 Hetrix public HTTPS sites UP (last observation), manually delivered founder test email confirmed; signed source and off-host critical alert remain HOLD.
