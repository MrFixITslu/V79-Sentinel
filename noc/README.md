# V79 Sentinel NOC — Acer staging

**Status:** Provider-only NOC prototype, running separately from the original Sentinel monitor.

- Old public-website monitor: `http://127.0.0.1:8787` (Acer only)
- New NOC: `http://127.0.0.1:8788` (Acer only)
- Private Tailscale URL once Serve is approved: `https://firelion-aspire-a315-51.tailcbdd5b.ts.net/`
- NOC service: `systemctl --user status v79-sentinel-noc.service`
- Data: `data/noc-staging.sqlite3` (excluded from Git)
- Source and tests: `noc/store.py`, `noc/server.py`, `noc/tests/test_noc.py`
- Dashboard: `noc/web/`
- Login username: `noc-admin`. Initial local password is stored only on Acer at
  `/home/firelion/.config/v79-sentinel/noc-admin-password` (mode 0600).
  **Never copy the password into source control, GitHub, support tickets, screenshots or chat.**
- To access from another machine, the account owner must approve Tailscale Serve
  from `https://login.tailscale.com/f/serve?node=nVaQGMm3D121CNTRL`.
  The link is **private to the tailnet**. Do NOT use Tailscale Funnel or
  publish the unauthenticated legacy dashboard.
- The new NOC has separate authentication, HttpOnly cookies, CSRF checks on
  mutations, origin verification and a loopback-bound listening socket.
  This is a development baseline, **not production-ready MFA or SSO**.

## Implemented

- Provider-managed customers, sites, assets and explicitly configured checks.
- Same private IP address may exist at separate customer sites without collision.
- Locally generated Edge Agent IDs, hashed credentials, revocation and bounded
  simulated telemetry submissions. No active scanning or agent remote shell.
- Atomic cross-site batch rejection and idempotent sequence handling.
- Consecutive failures to trigger alarm, consecutive recoveries for resolution.
- Deduplicated incidents by customer/site/failure domain.
- Operator-only incident acknowledgement and immutable history rows.
- Integration outbox is **not connected** to V79Tiquet, Hub or any other app.
- Clearly labeled example data for a hotel and office; no real customer data.

## Boundaries

- This is a staging prototype. Do not enroll remote customer networks yet.
- No Hub, Tiquet, CombatZone or other V79 deployment was modified.
- No public network listener was opened.
- MFA, agent rotation, durable offline queues, migrations, role separation,
  enterprise observability and full browser accessibility review remain TODO.

## Verification

Run from Sentinel root:

```bash
python3 -m unittest noc.tests.test_noc -v
python3 -m py_compile noc/server.py noc/store.py
node --check noc/web/app.js
```

Simulated measurements and demo state are never represented as live alarms.

## Next engineering milestones

1. Proper encrypted remote-agent transport with enrollment approvals, scoped
   checks, durable spool, certificate rotation and offline replay rules.
2. Introduce mature migrations and a relational store appropriate to volume.
3. Add NOC roles, password rotation and MFA before onboarding real operators.
4. Improve ImpactIQ dependencies, alert suppression, maintenance windows and
   out-of-band watchdog coverage.
5. End-to-end incident lifecycle / tenant isolation tests and UI accessibility.
6. Future adapters for V79Tiquet and Hub, kept disabled until approved.

## Edge offline replay and maintenance (2026-10-09 development cycle)

### Safety properties now tested

- Agent simulator queues observations durably in a local SQLite spool, including across simulator restarts. Oldest queued sequence is sent first.
- The NOC refuses sequence gaps; clients cannot advance the cursor past missing data.
- Exact sequence and observation-count acknowledgement is required before removing a queued entry. Timeouts preserve entries and retransmission is idempotent.
- Telemetry POST redirects are forbidden so a bearer credential is never forwarded to a new destination.
- A heartbeat only updates agent connectivity; it makes no assertion that customer equipment is healthy. Revoked agents cannot heartbeat or ingest telemetry.
- Operators can configure a time-limited site maintenance window. New incidents within that site are suppressed, but observations, check state and any pre-existing incidents remain intact.
- NOC now presents simulated incident history, acknowledgement, recovery evidence, a mock integration-event count and provider-only lab inventory forms.
- Site maintenance can only be scheduled by an authenticated NOC admin with correct origin and CSRF token. Maximum duration is 14 days in the staging implementation.

### Current limitations and enterprise gates

- Simulator is **NOT** deployed in live customer networks; configured network asset addresses are inventory only.
- Production-grade secure agent enrollment, mutually authenticated transport, TLS credential rotation, device check allowlists, clock skew handling, delivery checkpoints and queue reconciliation remain outstanding.
- Simulated mean detection-to-recovery duration is not yet SLA/MTTR; historical evidence is never claimed to be business-performance data.
- Tailscale Serve still requires privileged activation on Acer. Use Tailscale Serve only, never Funnel or an internet-wide listening socket.
- Operator MFA, comprehensive access role enforcement, and independent red-team/security audit are prerequisites before customer onboarding.
- The real V79 Hub/Tiquet/Marketing/Academy/POS/CombatZone integrations remain completely disabled.

## ValueProof reporting prototype

- Provider-authenticated `GET /api/v1/reports/incidents.csv` provides a bounded incident export (latest 5,000 incidents).
- Includes customer/site, title, severity, workflow state, timestamps, dependency domain and related checks.
- Clearly marks the export as **SIMULATED_SENTINEL_INCIDENTS** and **NOT_SLA_VERIFIED**.
- CSV cells are escaped and leading spreadsheet formula operators are neutralized.
- No agent credentials, password hashes or platform API tokens are included.
- Export is only available after standalone operator login. Report access is not public.
- The file is intended for lab validation, not a customer report or billing decision.

## Standalone operator security and MFA milestone (2026-10-10)

- **Provider-only roles:** `admin` can configure inventory, monitoring sites and agents and create/disable operators; `operator` can acknowledge incidents; `viewer` can inspect read-only NOC state. All protected routes enforce permissions on the server, not only the UI.
- Admin creation/disabling actions require the administrator's current password and the session's same-origin CSRF token. Disabled operators immediately lose all existing sessions.
- Optional RFC 6238 (SHA-1, 30-second, 6-digit) TOTP can be enrolled by each operator from the Operator Security section. Enrollment requires the current password, expires after 10 minutes, and is limited to five invalid confirmation attempts.
- Once confirmed, all the operator's sessions are invalidated. Subsequent sign-in requires the correct password **and** a fresh one-time code. Replaying the same TOTP counter is rejected.
- **The existing Acer `noc-admin` is not automatically enrolled or locked out.** An operator must choose to enroll it interactively.
- Existing SQLite admin/session records are preserved by additive-only schema migrations. Security tests explicitly verify migration and authenticated role boundaries.
- Authenticator secrets are currently stored in the owner-only Acer staging SQLite database. Production rollout additionally requires secret encryption/key management, a supervised account recovery process, credential rotation, comprehensive login audit/rate limiting, independent security assessment, and preferably phishing-resistant WebAuthn.
- This does **not** connect Sentinel to Hub login, customer identity or other deployed V79 apps.
- Do not publish the NOC directly to the public Internet or enroll real customer technicians. Tailscale Serve remains a separately authorized private-access step.
