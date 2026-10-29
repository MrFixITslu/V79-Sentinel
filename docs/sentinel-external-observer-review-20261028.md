# Sentinel P1 — external off-host website observer comparison (28 October 2026)

**READ-ONLY / SOURCE-ONLY / NOT DEPLOYED.** This is a validation adapter, not a Hetrix API client, webhook, mail sender or trusted security sensor. A programmatically forged provider-shaped dictionary can still lie.

## Verified live account configuration (read-only)
The connected Hetrix account currently has **9 active V79-owned public website monitors**, each reporting UP, with external checks from New York, London and São Paulo at 1-minute configured frequency. All use the same owner-only email contact list (vision79slu@gmail.com), require **two of three locations** to confirm an outage and **three minutes** before alerting. SSL/hostname verification is enabled. Two monitors are V79 Games and CombatZone, outside the Sentinel local seven-app monitor. No Hetrix configuration change was made.

A historical Vision79 Website downtime lasting approximately 174 seconds ended before the three-minute alert threshold. This is useful evidence of recovery history, **not** a confirmation that outage emails work.

## Three designs and REDTEAM
1. Automatically send additional Resend email on every local Sentinel DOWN: rejected — would duplicate Hetrix native notifications, amplify false alarms and still miss Dell-wide outages.
2. Promote any Hetrix JSON response to authenticated independent security evidence: rejected — values, timestamps or account API calls by themselves don't prove immutable origin, process integrity or full app security.
3. **SELECTED:** keep Hetrix native off-host monitoring as the primary reachability/outage alert; add a pure, fail-closed **cross-source review** that compares an explicitly provided fresh external multi-location report to the local signed **advisory**, never elevates trust and never sends email.

## Files
- `noc/isolated_external_observer_gate.py`: exact owned name→URL map, exact alert policy, fixed three external locations, freshness, active status and founder contact-list existence. Returns redacted external observations, or UNKNOWN for missing/stale/out-of-policy monitors. A comparison function maps external provider names to local seven Sentinel names, classifies agreement/disagreement for human review only. Both functions keep `trustedForExecutiveUse=false` and `resendNotificationAllowed=false`.
- `noc/tests/test_isolated_external_observer_gate.py`: synthetic two-region down, three-region up, disagreements, stale reports, wrong targets/contacts, policy changes, forged trust, no network/dispatch tests.
- `.github/workflows/sentinel-external-observer-gate.yml`: isolated CI extending the previous 84-test source-bound/resend protocol suite.

## Unresolved gates
- API source authentication, readonly-scoped token handling and log sanitization must be independently audited before integration; untrusted caller input cannot be promoted.
- Off-host website GET/HTTPS availability is not server resource monitoring, independent database validation, host intrusion prevention or customer app-transaction testing. `has_agent=false` on these website monitors.
- Do not create a synthetic website outage by taking down production. To prove real fault+recovery delivery, use a separately authorised private test endpoint/monitor, a documented safe test-notification feature or existing bona fide outage messages; avoid unnecessary outages or notification storms.
- A second Resend alert is NOT authorised for the same reachability incident. Reserve Resend for separately scoped Sentinel security/host events after sender key/recipient acknowledgement, off-host heartbeat, quota/rate limit, source provenance and independent review.
- No change to production Dell/NOC, site content, routes, Hetrix thresholds, contact lists, Resend, Hub/WiPay, external monitoring accounts or live alerts. Draft PR #26 stacked after #25; must not merge/deploy on CI alone.
