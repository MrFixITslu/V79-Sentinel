# V79 Sentinel NOC — Acer security deployment receipt

Date: 2026-10-10
Deployed source commit: `24fb2b9`
Active source checkout: `/home/firelion/V79-Sentinel/noc-security-staging`
Stable rollback source: `/home/firelion/V79-Sentinel/sentinel` at `98ed6b3`
Only modified service: `v79-sentinel-noc.service`, Acer user systemd.

## Release contents

- Backend RBAC for admin / operator / read-only viewer.
- Authenticated admin user provisioning and disabling, including session revocation.
- Opt-in TOTP MFA setup with code replay prevention and a five-try enrollment limit.
- Eight one-time recovery codes, shown once and stored only as hashes.
- Browser session-error handling that preserves valid sign-in when the security
  settings endpoint experiences a temporary non-authentication failure.
- Additive schema migration preserving existing admin and session rows.
- Existing accounts are **not** auto-enrolled in MFA.

## Passing gates

- 49 unit / HTTP integration tests, zero failures.
- Synthetic browser: local admin login, security API 503 regression, MFA enrollment,
  8 recovery codes, recovery-code reuse rejection, second recovery-code success,
  zero browser JavaScript errors.
- Temporary security test resources cleaned up.
- Migration trial against a disposable copy of Acer NOC SQLite database preserved
  existing account hashes, users, sessions, customers and incidents.
- Verified pre-release SQLite snapshot and systemd unit backups completed.
- Post-release NOC backend readiness 200; API and frontend MFA route matched.
- Post-release SQLite integrity check `ok`; pre/post admin/customer/site/agent/incident
  counts matched; all existing admin MFA settings remained disabled.
- Original Sentinel monitor remained healthy and bound to localhost.
- No Tailscale Serve configured; no internet-wide access.

## Recovery references

- Database backup:
  `/home/firelion/V79-Sentinel/sentinel/data/backups/noc-pre-security-20261010T043151Z.sqlite3`
- SHA256:
  `0eda004e2ef1b5ba1347e61010a2dc4eaceac4380d9b75f28c5979497b6235d7`
- Saved unit:
  `/home/firelion/V79-Sentinel/sentinel/data/backups/v79-sentinel-noc-pre-security-20261010T043151Z.service`
- Rollback: restore saved unit to the Acer user's systemd unit directory,
  reload systemd user services and restart **only** `v79-sentinel-noc.service`.
  Previous code ignores added columns; do not overwrite the database except during
  a supervised restore drill.

## How to review

- On Acer: `http://127.0.0.1:8788`
- Existing username: `noc-admin`
- Existing password is unchanged and remains only on Acer in the owner-only file
  `~/.config/v79-sentinel/noc-admin-password`; do not paste it into chat.
- Admin panel now includes staff management and optional MFA. MFA enrollment
  should be done interactively with an authenticator app; store eight recovery
  codes privately before leaving the screen.
- New NOC isn't public; private Tailscale Serve is a separate privileged action.

## Still not enterprise release-ready

Current MFA seeds in SQLite are protected by filesystem permissions but not yet
encrypted at rest. Before customer operations: durable migration versioning,
WebAuthn or strong account recovery, key rotation, audited access management,
proper remote-agent certificate issuance/revocation, permitted target enforcement,
observability, red-team security testing and real-network scope authorization.
No Hub/Tiquet/CombatZone integrations were enabled.
