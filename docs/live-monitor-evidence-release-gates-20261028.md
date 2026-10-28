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
