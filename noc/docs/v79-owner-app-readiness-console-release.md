# V79 Sentinel — Authenticated first-party service readiness panel

**Acer release candidate:** `feature/noc-semantic-readiness-console-20261010`

The user-authorized V79 first-party monitor publishes read-only service
readiness from fixed HTTPS health endpoints every 15 minutes. The owner NOC
reads that owner-only snapshot next to basic public `HEAD /` reachability
and exact gateway/Dell TCP connectivity observations.

## Why this update matters

A successful homepage response or TLS handshake does not prove an app is
healthy. In particular, POS returns HTTP 200 for the homepage but its
`/api/health` endpoint replies HTTP 401 without Hub authentication.
The dashboard must show POS as **protected / unverified**, never green.

The verified health catalog is deliberately fixed:

- Website GET `https://v79sl.com/api/ready`, JSON status ready
- Hub GET `https://hub.v79sl.com/api/health`, JSON status ok
- Tiquet GET `https://tiquet.v79sl.com/api/health`, JSON status healthy
- FFPRO GET `https://ffpro.v79sl.com/api/health`, JSON ok true
- Marketing GET `https://marketing.v79sl.com/api/health`, JSON status ok
- Academy GET `https://academy.v79sl.com/healthz`, JSON status ok
- POS GET `https://pos.v79sl.com/api/health`, HTTP 401 protected, not verified
- Gaming Studio J GET `https://games.v79sl.com/healthz`, text ok

No credentials, redirects, arbitrary URLs, app modifications, user actions,
POST requests, ticket dispatch, database writes or external provider access.

## Security and accuracy

- Public NOC `GET /api/v1/owner-pilot` remains an *authenticated provider
  administrator only* endpoint. The operator login, cookies, sessions, MFA,
  CSRF and separate simulation APIs are unchanged.
- The app-readiness evidence must be owner-only, bounded and valid. It must
  match the exact expected first-party hostname/path catalog and unique app
  names; forged `ready` claims without confirmed TLS/HTTP 200/expected payload
  are rejected.
- Each app has a separate semantic state (`ready`, `protected`, `failed`,
  `unverified`) and status. A missing/stale snapshot is **unverified**,
  not green. Data is considered fresh only for up to 40 minutes.
- Real TCP and readiness panels are visibly distinct from demonstration
  customers/incidents. A failed readiness retrieval doesn't log out a
  valid operator and does not fabricate an incident or close a ticket.
- Even a genuine endpoint status is a limited readiness signal. It does not
  prove login, checkout, worker health, external billing or end-user workflow.

## Deployment / rollback

1. Test the new six readiness projection cases, existing owner view,
   authentication RBAC and isolated Chrome browser checks.
2. Complete the full NOC regression.
3. Back up the NOC SQLite DB online and save the active user service file,
   verify integrity and preserve all accounts/sessions.
4. Change **only** Acer `v79-sentinel-noc.service` working directory to
   `/home/firelion/V79-Sentinel/owner-readiness-console-staging`.
5. Restart the service, verify `/readyz`, protected route response 401
   anonymously, valid existing admin login, eight semantic app states,
   five own-LAN pilot checks, login persistence and logout via Chrome.
6. If any release gate fails, restore the original service file and
   restart; no database migration is required.
7. Leave Tiquet, Hub, website and other production apps untouched.

The deep readiness collector is separately installed as
`v79-sentinel-app-readiness.timer` and keeps the private report up to date.
