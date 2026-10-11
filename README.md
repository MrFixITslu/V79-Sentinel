# V79 Sentinel v0.4 — authentication-aware local command center

**Environment:** Acer Aspire laptop (development/staging). NOT installed on the headless Dell or the live-style V79 server.

## Open the dashboard
While signed into the Acer desktop, visit **http://127.0.0.1:8787**.
The service runs as a **systemd user service** named `v79-sentinel.service`; it is configured to start when `firelion` logs into the Acer and restart on failure. User lingering is disabled, so it does not boot unattended before login.

## Currently functional
1. Read-only HTTPS HEAD availability checks for seven allowlisted V79 websites every five minutes.
2. HTTP response latency, DNS timing, TLS expiry and a SQLite history of sampled availability.
3. A targeted reachability/SSH check of the known new Dell at `192.168.100.136`. A MAC identity match is required.
4. A complete desktop/mobile browser QA baseline using the Acer's installed Chrome and pinned Playwright Core.
5. Local report viewer and 14 screenshot links under "Automated browser QA" on the dashboard.
6. CSV monitoring report, status-change timeline, responsive dashboard.

**Browser QA is only for unauthenticated public pages.** It does not fill forms, log in, click controls, or test protected workflows. Non-GET/HEAD requests are blocked. Console 401 errors can arise from normal unauthenticated access, so the dashboard marks them "review", NOT "broken". A public page HTTP 200 does not mean all application features work.

## QA baseline (2026-10-09; v0.4)
- 14 browser checks completed (7 sites × desktop/mobile): **4 PASS, 8 AUTH REQUIRED, 2 REVIEW, 0 FAIL**.
- Website and Academy passed both checked viewports.
- Hub, Tiquet, Marketing and POS return known 401 responses from guest identity/session checks or redirect protected visitors to the Hub. These remain **AUTH REQUIRED**, never an authenticated-test pass.
- FFPRO correctly redirects unauthenticated visitors to the Hub and denies guest-only account API requests, but Chrome logs a separate `beforeunload` warning in both viewports: **REVIEW**.
- **Unknown HTTP 401**, failed navigation, unexpected resource errors and other JavaScript errors remain visible, not silently suppressed.
- Captured evidence stays under `data/qa-runs/`; the last complete report is `data/qa-latest.json`. All screenshot files remain local to the Acer.
- A seven-gate **protected-workflow QA preflight** is staged at `qa/protected-qa-policy.json`. Every gate is currently false; authenticated automation is disabled. No test users or credentials have been created.

## Run browser QA again (manually)
```bash
cd /home/firelion/V79-Sentinel/sentinel
bash scripts/run-qa-safely.sh
```
Or one site at a time:
```bash
bash scripts/run-qa-safely.sh --service Website
```
A single-service report is saved as a separate run without overwriting the completed seven-service dashboard report. The runner uses a 240-second overall timeout and only one browser context at a time. Each result is checkpointed to disk. No daily Chrome timer is enabled because of earlier Acer instability.

## Service management on the Acer
The Desktop Commander shell may not have user-session DBus environment variables. If needed:
```bash
export XDG_RUNTIME_DIR=/run/user/1000
export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
systemctl --user status v79-sentinel.service
systemctl --user restart v79-sentinel.service
systemctl --user stop v79-sentinel.service
```
Changing the Acer's systemd user unit **does not** modify V79 services, customer accounts, or the Dell.

## Tests
```bash
cd /home/firelion/V79-Sentinel/sentinel
PYTHONPATH=. python3 scripts/test_monitor.py
PYTHONPATH=. python3 scripts/test_qa_results.py
bash scripts/smoke-test.sh
node --check web/app.js
node --check qa/run.js
```
`node scripts/test_qa_dashboard.js 8787` runs a local visual browser test and saves a dashboard screenshot.

## Security and limits
- Dashboard binds to `127.0.0.1:8787` only and has no authentication: **never expose publicly**.
- All HTTPS monitoring targets must belong to `v79sl.com` and resolve to public addresses.
- Monitoring history is stored at `data/sentinel.sqlite3` with a 30-day observation retention policy.
- A single known Dell address is checked; the V79 server at `192.168.100.163` is excluded.
- No vulnerability scans, active attacks, privileged SSH login, automated code repair, or production changes.
- The QA baseline is manual for now; health checks run automatically while the Acer's user session is active.
- `deploy/` contains future Docker packaging. The container does NOT include Chrome/QA runner and needs an additional host-side QA execution plan. The lab MAC probe may also require host network access on a future Docker host.

## Dell blocker
The new Dell replies at `192.168.100.136`, but SSH is closed. A one-time console, confirmed USB boot support or external access to its internal disk is still needed before we can move Sentinel there safely.

## Release files
- `sentinel.py`: local monitoring web service
- `monitor_core.py`: HTTPS checks and observations
- `lab_probe.py`: single-known-host Dell readiness
- `qa_results.py`: safe QA report/screenshot loading
- `qa/run.js`: Playwright Core QA runner
- `web/`: dashboard frontend
- `scripts/`: repeatable tests and manual QA launcher
- `data/`: **local state and evidence, not included in source archives**

Version history: v0.1 simulated dashboard → v0.2 live health + TLS → v0.3 browser QA and screenshot reports → v0.4 explicit guest authentication classification and guarded test-account preflight.
