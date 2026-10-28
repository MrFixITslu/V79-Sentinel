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

**Independent CI evidence:** exact draft head `64e510316fc8b8051eb234bb6e4d7199e4f48565`. `Sentinel private signer promotion NO-GO gate` workflow run `40754038132` completed **SUCCESS**; its `Run dedicated private signer security suite in isolation` and fail-closed missing-suite prerequisite both individually succeeded. `Sentinel legacy monitor proof bridge` workflow also successful. Remaining parallel Docker staging and isolated regression workflow checks were still pending when this note was written; inspect their final status before any merge. Production remains NO-GO.

**Security /REDTEAM:** Tests certify only that isolated signer candidate *refuses unsafe inputs and persists review candidates under permitted conditions*. They do NOT authenticate physical HTTP/TLS probe origin; a signed arbitrary JSON report is not proof the live Dell collector observed its claims. No owner-private production key was created, no persistent authorized source with encrypted custody established, no independently running off-host watch service, no autonomous alert sender or incident/Tiquet integration. Do not merge or deploy this draft as production Sentinel based on the green test job alone; require separate real-probe provenance attestation, durable source-to-receiver validation, offhost heartbeat, sender outbox and incident approval/circuit breakers, and owner go/no-go decision.

Founder separately verified one-time manual transactional test alert **received** via Resend/Gmail; email endpoint transport PASS, but no automated Sentinel incident-to-mail test was executed. Hetrix independently reports 9/9 owned public SaaS HTTPS endpoints UP; these external checks do not establish host telemetry.
