# Sentinel supervised approval issuer — disconnected NOC staging prototype

Date: 2026-10-10 AST. Owner policy: V79 Digital internal pilot; supervised tickets.
Status: ISOLATED CODE ONLY; not imported by live NOC server, not deployed.

Module: noc/sentinel_approval_issuer.py
Branch: feature/owner-supervised-ticket-issuer-20261010

## Signing contract

The module requires an explicitly confirmed decision from a current NOC
administrator, a fresh non-replayed TOTP, one exact incident event, a
separately verified evidence record, and an owner-only Ed25519 signer.

- Administrator account is enabled, assigned role admin, and enrolled in TOTP.
- Fresh TOTP counter exceeds the account's previously accepted counter.
  The counter, approval issuance receipt and NOC audit event commit together.
- The caller must authenticate the administrator session and enforce
  same-origin/CSRF controls. THIS MODULE EXPOSES NO LIVE ROUTE OR UI.
- Independent evidence verification must return exactly True. Merely
  labeling a JSON event PRODUCTION_VERIFIED does not qualify it.
  The default missing verifier rejects all attempts.
- The private signing key must be a regular 0600 owner-only PEM file. Symlink,
  incorrect file owner/type or insecure permissions fail closed.
- Signed claims include event SHA256, UUID event/incident/customer/reviewer,
  exact Hub organization and Tiquet client, approval ID, MFA verified timestamp,
  approval timestamp, and expiry (10 minutes).
- Tiquet accepts configured PUBLIC Ed25519 verification keys only.
  The private key must never reside in the Tiquet runtime.

## Testing

The isolated NOC Python regression suite passed 75/75 (including four new
issuer tests). A Python-generated approval was accepted by the actual
Tiquet Node.js verifier with the matching public key, while a modified
event was rejected. Ephemeral tests do not create real business tickets.

Tiquet also requires current live Hub service authorization and current
authorization of the approving operator at delivery; neither callback is
connected in the live Tiquet runtime, so tickets remain disabled.

## Remaining blockers

1. Authenticated NOC/Hub browser review UI with incident evidence presentation,
   explicit decision confirmation, server-side CSRF protection and MFA.
2. Real owner-network, signed verified-evidence authority. Mock evidence is
   SIMULATED_ONLY and must never be relabeled as real incident evidence.
3. Dedicated signing-key issuance, custody, private storage, rotation and
   revocation; no production signer key has been provisioned.
4. Independent Hub service entitlement and NOC approver-status callbacks.
5. Durable delivery outbox with backoff, human audit/dispatch confirmation,
   and final independent security assessment.

No production services, real users, MFA secrets or production database changed.
