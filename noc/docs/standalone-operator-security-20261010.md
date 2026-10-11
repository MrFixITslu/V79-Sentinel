# Sentinel Operator Security — isolated Acer release candidate

**Source worktree:** `/home/firelion/V79-Sentinel/noc-security-staging`
**Branch:** `feature/noc-operator-security-20261010`
**Stable Acer NOC:** `http://127.0.0.1:8788` is a separate checkout and remains in service.
**Live Hub/Tiquet/other products:** do not touch.

## Implemented in the candidate

- `admin`, `operator` and `viewer` permission checks enforced on API endpoints.
- Provider administrator can add an operator (strong initial password and admin-password recheck), list nonsecret operator metadata, disable accounts and revoke disabled users' sessions.
- `operator` can acknowledge incidents, but cannot create customers, agents or users; `viewer` can read the NOC only.
- Each operator can voluntarily enroll in TOTP MFA with password confirmation, expiration, 5-attempt limit and session invalidation. Existing `noc-admin` is **not automatically enabled**.
- After confirming MFA, eight unique recovery codes are shown **only once**. Only SHA-256 hashes are stored. Redeeming a recovery code marks it used atomically with the new login session; code reuse fails.
- Six-digit TOTP codes reject replay. Password-only sign-in fails once MFA is enabled.
- Frontend errors while fetching security settings do not incorrectly log out a valid NOC operator. This prevents recurrence of the previously observed dashboard-flashes-back-to-login bug.
- Additive schema changes preserve existing operator accounts, passwords, customers, incidents and sessions, as proven by migration rehearsal on a disposable copy.
- TOTP setup/recovery is for a **private, simulated Acer test environment**. Real customer networks remain disconnected.

## Automated verification

```bash
cd /home/firelion/V79-Sentinel/noc-security-staging
python3 -m unittest discover -s noc/tests -p 'test_*.py'
python3 noc/tests/run_isolated_security_browser.py
node --check noc/web/app.js
git diff --check
```

The browser harness generates a throwaway administrator and secret, starts a separate
loopback NOC instance on port 8790, verifies sign-in/MFA/recovery/logout, and tears
down all synthetic identities and credentials. **It never uses the real Acer admin account.**

## Verified release-candidate evidence

- All **49** NOC regression tests passed with zero failures.
- End-to-end isolated Chrome run passed: operator login, MFA enrollment,
  eight one-time recovery codes, rejected reuse and successful second-code login.
- Injecting HTTP 503 on `/api/v1/mfa/status` did **not** sign out a valid operator.
- Full browser integration cleaned up its temporary database and credentials.
- Copy-based migration drill preserved the existing administrator, sessions,
  customer and incident records; existing MFA settings stayed disabled.
- The production-host V79 applications have not been modified.

## Enterprise security gates still outstanding

- MFA secret encryption at rest and auditable key rotation
- Fully supervised operator recovery and password rotation / account unlock
- Phishing-resistant WebAuthn, stronger brute-force rate limiting and login auditing
- Strict API validation, peer review, CSRF/origin deployment review and penetration test
- Device authentication + mTLS before connecting real customer networks
- Independent watchdog, restore drills, backups and data retention

Do not advertise this candidate as enterprise production-ready or enable Hub/Tiquet
integration. Do not promote any unfinished frontend without its matching backend.
