# V79 Digital — independent external uptime pilot
**28 October 2026 | Source-only operational plan | NOT CONFIGURED / NOT ACTIVE**

## Objective
Provide an independent watcher of V79-owned public services that remains able to
observe a possible Dell network/power outage while Sentinel and G2 are unavailable.
This is **not** the Sentinel signed-collector identity, not authenticated app
health, and not a substitute for a verified backup/recovery plan.

## Three options and /REDTEAM
1. Acer workstation monitoring: reject for 24/7; laptop sleep/offline = blind spot.
2. On-Dell Uptime Kuma / self-hosted cron: reject as sole off-host solution;
   a Dell power or NIC outage also stops the observer.
3. **Recommended: independent hosted multi-region HTTPS checks.** Free hosted
   HetrixTools account *if the owner explicitly creates/connects it*; no
   credentials or account are present in this repository. Independent checks
   and founder email notifications stay entirely outside Hub and WiPay.

External reference:
- https://hetrixtools.com/uptime-monitor/ (current advertised free tier:
  15 uptime monitors, one-minute checks, up to four locations, email,
  HTTPS/SSL validation, retries and majority-based outages)
- https://docs.hetrixtools.com/add-a-website-uptime-monitor/ (setup)
- https://docs.hetrixtools.com/add-a-cron-job-monitor-heartbeat-monitor/
  (future optional cron heartbeat)
Provider limits, site accessibility and behaviour must be independently
verified during owner setup. The account must be founder-owned.

## Approved scope — initial pilot
| Pilot name | Public HTTPS endpoint | Intended scope | Allowed requests |
|---|---|---|---|
| V79 Hub - external front door | `https://hub.v79sl.com/` | Public login landing reachability only | Safe idempotent GET with normal TLS |
| V79 Tiquet - external front door | `https://tiquet.v79sl.com/` | Public landing/login reachability only | Safe idempotent GET with normal TLS |

Do not authenticate, crawl, submit forms, contact customer accounts,
query billing, or add synthetic login/transaction tests. Only two domains are
preapproved for initial setup; remaining five V79 websites must be added later
on separate owner review. Never add 127.0.0.1, private IPs, admin panels, non-V79
domains, test-account pages or API credentials.

## Suggested operator configuration
- Monitor type: Website / HTTPS; independent hosted probe (no Dell agent).
- Frequency: 1 minute, within provider free tier if verified at signup.
- Locations: 3 geographically separated regions (e.g. New York, London,
  São Paulo), **if selectable and working**. Confirm outage by at least 2/3
  locations, with provider retries. This is not a guarantee of causation.
- Timeout: 10 seconds per location (tune after measured normal response).
- Redirects: allow only those necessary for the real login page; review
  redirect destination stays V79-owned and HTTPS. Never disable TLS checks.
- Acceptable status: establish baseline for each public entry point: 200
  or a legitimate HTTPS redirect as supported by provider; do not
  indiscriminately treat every 3xx/4xx/5xx as success.
- Failure warning: require multi-location confirmation and a short failure
  window to avoid transient alerts (initially ~2-3 minutes if supported).
  Notify again on recovery; suppress repeated alerts/floods.
- Recipient contact list: one **confirmed founder-owned email only**;
  choose `vision79slu@gmail.com` after owner confirms contact list. Enable
  no SMS/voice/third-party subscriptions until cost and consent checked.
- Visibility: **private dashboard only**; do not publish status page,
  customer incident reports, site metadata or public outage history.
- No webhooks into Hub/Tiquet, no server commands, no auto deploy, no
  signing-key sharing, no broad security scanning or customer monitoring.

## Acceptance tests (no deliberate production outage)
1. Owner signs up and verifies email; no credentials copied to GitHub/ChatGPT.
2. Create exactly two allowlisted public-HTTPS monitors.
3. Verify independent remote checks are actually running in the vendor UI;
   collect bounded timestamps, checks, response classification and regions,
   **not** private account tokens.
4. Trigger one harmless **provider notification test**, if the vendor supports
   this, to founder inbox. Do not intentionally disable Hub/Tiquet, DNS,
   certificates, payments or reverse proxy as an "outage" test.
5. Verify sender, provider delivery event (if offered), **actual founder inbox
   receipt**, no unintended customers notified, and expected recovery paths.
6. Leave the external service flagged `EXTERNAL_FRONTDOOR_MONITOR`, not
   `APP_HEALTH_VERIFIED` or `SENTINEL_SIGNED_REPORT_TRUSTED`.
7. Review response-time and notifications after baseline; don't assert a
   guaranteed SLA or full Dell-outage certainty from HTTP failures alone.
8. Once this pilot is independently proven, optionally add a provider heartbeat
   for a distinct Dell-owned scheduled read-only worker. A heartbeat URL is
   a private capability; treat it as a secret and do not place it in code,
   logs, issue comments or outbound GitHub Actions metadata.

## Release gates still closed
- `noc/owner_private_candidate.py` has **no accepted dedicated key-custody
  tests**. The dedicated private signer promotion gate must remain failing.
- The signer still takes caller-supplied 'live' JSON; signing alone does not
  prove actual probe execution. Source-provenance acceptance is separate.
- Existing old Acer→Dell signed check is just TCP:443, not seven-app HTTPS,
  and not dependable when Acer is sleeping/offline.
- Resend domain sender verification does not prove delivered founder email.
  This independent provider's founder email test should be accepted **on its
  own**, not silently treated as a Resend or Sentinel notification proof.
- No production changes, alerts, keys, systemd units or external monitors were
  created by this source-only document.

## Definition of done
Founder can show independent provider evidence for both Hub/Tiquet front doors,
a successfully delivered founder-only notification, and honest UNKNOWN vs
externally unreachable classifications. The signed internal Sentinel telemetry
lane remains a distinct security project, gated on accepted tests.
