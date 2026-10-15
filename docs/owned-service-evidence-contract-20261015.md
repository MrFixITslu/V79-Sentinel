# P1 Sentinel owned-service evidence — nondeploying G2.21 candidate

**Status:** isolated reviewable source only. NOT a monitoring collector, alert sender, scheduled task, authenticated Executive evidence, or deployed app. It does not remove the GitGuardian blocker on the parent [Sentinel PR #14](https://github.com/MrFixITslu/V79-Sentinel/pull/14).

## Three strategies and REDTEAM
1. Use the NOC's reported seven "UP" statuses as proof of protection — rejected; the NOC readiness still declares simulated-only and integrations disabled.
2. Activate an unsupervised collector, notifications and ticket creation directly — rejected; identity, authorized targets, freshness, secrets and reviewer approval are not settled.
3. **Selected:** independently test a narrow V79-owned HTTP observation *advisory contract*, with every source labeled **untrusted** until proper signed device/collector provenance and authenticated integration exist.

REDTEAM: Anyone could forge JSON with mode=live or attach a signature-looking field. Therefore even well-formed, current snapshots show REPORTED_NOT_AUTHENTICATED and trustedForExecutiveUse=false. A single HEAD failure may reflect authentication/maintenance and is not a confirmed incident. Stale (>10 minutes), future (>2 minutes), wrong scope, duplicate targets, malformed fields, demo mode and collector errors always show UNKNOWN. No notifications or automatic Tiquet tickets are dispatched.

## Code and tests
- noc/owned_https_evidence_gate.py: deterministic, bounded, zero-network classifier. Requires exact approved V79-domain HTTPS target names+URLs. Outputs only fixed labels and names; no raw logs, IPs, HTTP headers, user messages, secrets or untrusted payload content. It never promotes the advisory data into signed/trusted telemetry.
- noc/tests/test_owned_https_evidence_gate.py: synthetic negative tests including unsigned "live", stale/future data, missing/duplicate/out-of-scope targets, cert expiry, injected messages, forged trust booleans and malformed records.
- .github/workflows/sentinel-owned-service-evidence.yml: independent tests and AST parsing only. No build, image publish, Docker deployment, live probing or secrets.

## Integration gates
1. Fix inherited GitGuardian security check privately without publishing matched values.
2. Preserve exact Acer active G2.21 source and recovery backup. Confirm current installed runtime before any Sentinel deployment.
3. Authenticate and cryptographically bind a reviewed service collector identity, owned-target set and timestamp; one-shot probes must not leak client or device information.
4. Complete isolated paired NOC/HUB/COO tests. Only then consider mapping advisory results into signed COO records; never treat this module itself as proof of security protection.
5. Explicit owner and independent security signoff for any external/customer exposure.

Commercially launched products remain **Hub + Tiquet only**. All other apps, including Sentinel, stay internal until their gates pass.
