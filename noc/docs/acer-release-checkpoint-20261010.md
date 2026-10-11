# V79 Sentinel NOC — Acer staging checkpoint

Date: 2026-10-10 UTC (2026-10-09 Saint Lucia time)
Source revision: `45ed37d`
Environment: Acer `firelion-Aspire-A315-51`, standalone project at
`/home/firelion/V79-Sentinel/sentinel`

## Verified scope

- New NOC service: `v79-sentinel-noc.service`, loopback-only HTTP port 8788
- Original Sentinel service: loopback-only HTTP port 8787, healthy and unchanged
- Simulated customer/site/asset/check/agent inventory with private-IP overlap isolation
- Provider-only password login, HttpOnly session, origin/CSRF checks and logout
- No Hub, Tiquet, CombatZone or production integration (mock outbox holds events locally)
- Consecutive-failure alarm generation, incident grouping and recovery evidence
- Offline Edge simulator SQLite queue, ordered delivery, exact acknowledgements and revocation
- Heartbeats report agent connectivity only; they do not assert network devices are healthy
- Maintenance windows suppress only new incidents; monitoring evidence is retained
- Bounded authenticated incident CSV report; simulated label, formula escaping and no agent credentials

## Test evidence

- Complete NOC automated regression: **37 passed, 0 failed**, including authentication,
  cross-customer injection, duplicate private IPs, offline replay, revocation,
  signed-in maintenance, incident state, report security and spreadsheet injection
- Source: `python3 -m unittest discover -s noc/tests -p 'test_*.py'`
- Python compile, Node syntax checks and Git whitespace checks: PASS
- Chrome UI smoke after NOC restart: operator login, dashboard cards, asset/maintenance
  forms, incident view and sign-out: PASS, 0 uncaught JavaScript errors
- Anonymous NOC dashboard/CSV: HTTP 401, correctly blocked
- Local authenticated incident CSV: HTTP 200, 1 simulated incident exported
- NOC `/readyz`: reports simulated-only collection and disabled integrations
- Original Sentinel `/healthz`: HTTP 200
- Both listeners remained bound to 127.0.0.1
- Tailscale Serve: NOT enabled; requires owner-approved privileged command.
  No public Tailscale Funnel service was configured.

## Recovery evidence

- Pre-release SQLite online backup: `data/backups/noc-staging-premaintenance-20261010T035205Z.sqlite3`
- SHA-256: `6ca3dd96972a31ad0d07217a96704d04e563e2b0c9aa4913fa718d8f3844feed`
- The backup was checked with `PRAGMA integrity_check=ok`; it contains two
  simulated customers and two agents. File permissions: owner-only.
- Following service restart, current NOC database integrity check: `ok`.
- No rollback was necessary; preserve backup for a supervised restoration drill.

## Deployment / access

- Acer only, via systemd user service. No production V79 host was accessed or changed.
- Local dashboard: `http://127.0.0.1:8788`
- Username: `noc-admin`, private password stays under
  `/home/firelion/.config/v79-sentinel/noc-admin-password`.
- Tailnet address will be `https://firelion-aspire-a315-51.tailcbdd5b.ts.net/`
  after owner approval and privilege activation. Do not use Funnel.

## Enterprise blockers before real-customer onboarding

- Standalone MFA and role-segregated operator accounts
- Enrolled remote agent identities with verified certificate lifecycle, scoped targets,
  queue reconciliation and real network-probe consent
- Production-grade durable data migrations, storage retention, monitoring engine liveness
- Independent detection of site WAN loss versus agent outage
- Verified backup restore, backup offsite plan, independent monitoring watchdog
- Auditability of changes and incident notes, on-call escalation, alert suppression
- Security review and tenant-isolation penetration tests
- Real Hub/Tiquet and other V79 integrations require explicit future user authorization

This release is an isolated development checkpoint, **not** an enterprise production release.
