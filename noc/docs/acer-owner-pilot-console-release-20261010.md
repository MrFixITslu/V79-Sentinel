# Sentinel NOC real-owner pilot panel — Acer controlled release

## Purpose

Display V79 Digital's *actual* owner-authorized, read-only network evidence
inside the already authenticated standalone Sentinel NOC dashboard without
mixing it into synthetic demonstration customers or incidents.

## Data sources (read-only)

- `/home/firelion/V79-Sentinel/secure-edge-transport-staging/data/v79-owned-pilot/last-observation.json`
- `app-checks-latest.json`
- `impactiq-latest.json`
- `certificate-health.json`

All sources must be owner-only regular files in an owner-only directory and
fit size limits. Symlinks and unexpected local IP/port combinations are
rejected. Source databases, agent enrollment secrets and private keys are
never read by the dashboard route.

## Authorization

`GET /api/v1/owner-pilot` requires a valid existing NOC login AND
`role=admin`. Anonymous users receive HTTP 401 and read-only technicians/
viewers receive HTTP 403. Responses use `Cache-Control: no-store` and
restrict scripts to same origin. There is **no new account**, login method
or payment integration. No change to the live pilot's TLS receiver.

## State and accuracy

The owner pilot displays a strict visual distinction from the simulated
multi-customer NOC counters. Missing/stale checks cannot be displayed as
healthy, and if the live evidence is unavailable the panel displays an
explicit warning **without logging out the user**. The UI refreshes this
owner-only panel every 60 seconds.

- Gateway: TCP ports 53 and 80
- Dell: TCP ports 22, 80 and 443
- Eight public V79 app entry-point checks are annotated as *HTTP/TLS reachability*,
  not full service functionality or SLAs.
- TLS expiry is informational and stale/invalid status is not shown as good.
- Hub, Tiquet, POS, website, marketing and other V79 production apps remain
  untouched; no tickets, users or production records are created.

## Release verification gates

- Complete NOC regression tests pass.
- Owner-only projection, stale-data, file permissions and cross-tenant
  authorization tests pass.
- Chrome isolated login, live data panel, error/fail-open-login regression and
  logout tests pass.
- Verify owner NOC database online backup and owner-only service-config
  rollback file **before restarting**.
- Switch only Acer user service `v79-sentinel-noc.service` to the isolated,
  committed `owner-pilot-console-staging` worktree. Preserve the original
  NOC SQLite DB and separate pilot telemetry DB exactly.
- Verify both original monitor at 8787 and new NOC at 8788 remain loopback only;
  verify live Acer owner pilot ingress at 8791 and scheduled collectors remain
  healthy; verify full authenticated real pilot response.
- Do not expose to public WAN, create Tailscale Funnel or enable direct
  customer monitoring without separate authorization.

## Rollback

1. Restore the backed-up original `v79-sentinel-noc.service` file or set
   `WorkingDirectory=/home/firelion/V79-Sentinel/noc-security-staging`.
2. `systemctl --user daemon-reload`
3. `systemctl --user restart v79-sentinel-noc.service`
4. Validate `/readyz`, original login and port 8787.

The code change is additive and does not require database migration or
restoring the backup. Only restore NOC data if actual database corruption is
detected; never overwrite newer data gratuitously.
