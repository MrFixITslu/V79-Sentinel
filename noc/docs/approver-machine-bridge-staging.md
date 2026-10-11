# V79 Sentinel current-approver service bridge — isolated release staging

Date: 2026-10-10 AST.
**Default OFF. No production Tiquet ingest; no live service secret provisioned.**

## Purpose and independent authorities

An Ed25519 signature proves the administrator approved a particular qualified
incident at issuance time, but NOT that the administrator is still enabled.
Tiquet must query the NOC just before every ticket.create and each replay,
independently of the Hub's scoped machine entitlement and the incident
signature.

The NOC machine route `POST /api/v1/sentinel/service/approver/check` is enabled
ONLY when *both* `SENTINEL_REVIEW_ENABLED=1` and
`SENTINEL_APPROVER_SERVICE_ENABLED=1`, with a separately provisioned
`SENTINEL_APPROVER_SERVICE_SECRET_FILE` pointing to an owner-only,
non-symlink regular file mode 0600 (48–1024 printable bytes). The deployed
NOC service DOES NOT enable the machine route or define the secret path.

The route rejects browser Origin/Cookie/Authorization, nonlocal direct
connections, non-JSON requests, oversized bodies, incorrect machine ID,
invalid HMAC-SHA256 signatures, or timestamps more than 120 seconds off.
The HMAC covers HTTP method, exact route, timestamp and SHA-256 body digest.
It returns only `{allowed: bool, validForSeconds: 0 or 5}`.
The current operator ledger, role, revocation, MFA enrollment, exact approval
UUID, exact customer/organization and time window are rechecked per request.

The Tiquet checker `server/sentinelNocApproverChecker.js` is wired ONLY when
`V79_SENTINEL_INGEST_ENABLED=1` AND
`V79_TIQUET_SENTINEL_APPROVER_CHECK_ENABLED=1`, and requires
`V79_SENTINEL_NOC_URL` as an HTTPS origin and
`V79_SENTINEL_NOC_SHARED_SECRET` as an independent machine credential.
No human session or JWT is used. No permission caching, no redirects,
strict 3.5-second timeout, fail-closed on all errors. The existing
independent Hub entitlement callback remains REQUIRED.

## Test evidence

- 3 NOC private-bridge tests passed, including a real local HTTP route
  exercised by the *actual* Node V79Tiquet checker, immediate role revocation,
  spoofed Origin/Cookie, incorrect signature, unsafe file-mode rejection.
- 3 V79Tiquet machine-checker tests passed; checked exact signed scope,
  no cached permission after revocation, HTTPS policy, malformed grants,
  redirect/malformed/unreachable denial.
- Python NOC full regression 104/104 passed; Tiquet Node full unit suite
  47/47 passed; TypeScript lint passed.
- Python owner-signed event placed in a synthetic SQLite outbox was accepted
  by the real JavaScript V79Tiquet verifier, with tampering, tenant mismatch,
  expired proof and revoked verification-key rejection.
- Sender recognizes a valid idempotent Tiquet 'duplicate' response with exact
  correlation/job ID and records delivery; mismatched receipts remain retries.

## VERIFIED live infrastructure blocker — PRIVATE ROUTING

Read-only reachability from Dell `v79sl` host and the Tiquet container to
`https://firelion-aspire-a315-51.tailcbdd5b.ts.net/healthz`
failed: the Dell host could not resolve the private NOC hostname, and the
container could not reach it. Thus live reviewer checks have **NO verified
private HTTPS path**. Do not change DNS/firewall/SSH/Tailscale Serve in a
release without separate reviewed owner approval.

## Before internal pilot Tiquet dispatch

1. Establish and validate a **private TLS-authenticated, identity-restricted**
   route from the Dell Tiquet container to Acer NOC, with trusted certificate,
   no public exposure, no disabled TLS validation, and monitored availability.
2. Provision separate Tiquet-NOC service HMAC secret with 0600/secret-store
   handling and audited rotation, independent of the Sentinel-Tiquet and
   Hub machine credentials. Turn on service routes only after test.
3. Review exact NOC, Hub, Tiquet commits and DB migrations. Keep Hub machine
   grants denied by default; issue only one V79 Digital scoped grant with
   explicit owner MFA authorization and expiry/revoke plan.
4. Install the NOC Ed25519 **public** approval key in Tiquet; keep the NOC
   private key on the Acer. Keep the independent Edge observer key separate.
5. Run isolated full-PostgreSQL duplicate/recovery tests, private-network
   end-to-end negative tests, independent security audit and rollback drill.
6. Obtain explicit owner authorization for **one supervised internal ticket**
   for `V79 Sentinel Pilot` before any live writes. No auto ticket closure.

**No live machines, accounts, tickets, network settings, or subscription
records were modified by developing this service bridge.**
