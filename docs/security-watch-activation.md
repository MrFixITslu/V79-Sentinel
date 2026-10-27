# Sentinel Security Watch — activation checklist (NOT YET APPROVED)

**Do not use this as a command to start monitoring while the current V79 deployment or backup is active.** These are future requirements to follow after the owner has verified live server identity, the installed Sentinel release and recovery.

## Why monitoring must be split

- **Host telemetry**: explicit SSH/sudo journal signals on the V79 server. Needs least-privilege access to the host's genuine journal. No public SSH access is created.
- **Application telemetry**: optional root-owned JSONL reverse-proxy login/auth denial feed under `/var/log/v79-security/`. Root ownership and no group/world writes required. Only exact authentication paths/status 401/403/429 are counted; expected guest `/api/auth/me` is excluded.
- **Alerting**: durable, deduplicated pending security event records; optionally sent via Resend to one founder-owned email after SMTP-domain and delivery test verification. *API accepted* is not *recipient received*.
- **Testing**: existing HEAD-based HTTPS health + guarded passive ZAP baseline for isolated 127.0.0.1 staging clone on disposable **GitHub-hosted runner only**. Never run ZAP from the production Dell against its running services. The launcher requires a reviewed immutable ZAP image digest, an approved isolated staging clone, and two per-run approvals.

## Configuration sketch (no credentials in Git)

An owner-provisioned JSON policy, **permission 0600**, on the confirmed live host:
```json
{
  "enabled": false,
  "hostname": "REPLACE_WITH_VERIFIED_HOSTNAME",
  "approved_ssh_origins": [],
  "approved_privileged_actors": [],
  "email_enabled": false,
  "alert_from": "alerts@REPLACE_WITH_VERIFIED_SENDING_DOMAIN",
  "alert_to": "REPLACE_WITH_FOUNDER_VERIFIED_RECIPIENT",
  "proxy_log_path": "/var/log/v79-security/REPLACE_WITH_VERIFIED_ACCESS_AUDIT.jsonl"
}
```

The provider credentials and HMAC key are **only** loaded from a dedicated owner-controlled secret environment, never this file or GitHub issues. Runtime double gates: `SENTINEL_SECURITY_WATCH_ENABLED=1` and, separately, `SENTINEL_SECURITY_ALERTS_ENABLED=1` plus `email_enabled=true`. All default to **OFF**. The optional proxy log property must be omitted until an actual trusted source is installed and verified.

## Non-disruptive rollout sequence after current deployment

1. Check the Dell's actual hostname, published ports, Sentinel container identities, CPU/RAM and deployment/backup status read-only. Verify no old Acer monitoring service can be mistaken for the running Dell collector.
2. Confirm current SSH journal tag formats, permissions, host log rotations, owner allowlisted VPN/Tailscale sources and authorized privileged users. First test with synthetic records, then run the read-only watcher once with email disabled. A journal query with no recent entries means **UNKNOWN**, not proof of clean access.
3. Add trusted proxy JSON audit (request ID, UTC timestamp, method, normalized route, status code and remote source IP only). No cookies, body, query strings, bearer tokens or real customer emails in the feed. Ensure retention/encryption/storage constraints. Forwarded events must have trusted integrity at transport.
4. Validate separate short-batch failures, source-unavailable alerts, deduplication, offline delivery queue and actual screenshot/dashboard provenance. Never auto-block a source or kill a container.
5. Verify Resend sending-domain DKIM/SPF and an owner-approved synthetic alert receipt, then enable owner-only email alerts. Ensure sender verification, suppression and time-of-day handling are intentional.
6. Arrange a separate approved window for disposable staging clones. Run the guarded ZAP baseline on isolated ephemeral CI against loopback only. Record scanner digest, app revision, fixture provenance, findings and human triage.
7. Complete authenticated two-tenant checks across Hub, Tiquet, Marketing, POS, FFPRO, Academy and website before expanding public access. Preserve existing controlled beta boundaries.

## Sizing and REDTEAM

- Every journal poll consumes a maximum of 300 entries and 512 KiB, checks once per minute; SQLite purges old correlation samples and writes compact pseudonyms. No Docker socket, no root collector, no packet capture, no FIM agent and no automatic firewall actions.
- False positives (owner travelling, legitimate deployments, tests) are still possible. Approved SSH CIDRs and roles need review; do not suppress unapproved logins merely because a release is in progress.
- Host compromise could hide or forge local logs. Secure off-host log forwarding and an independent missed-heartbeat alarm are prerequisites for a strong incident-detection claim.
- No security tool can promise detecting **every** unauthorised access event. Alert messages explicitly say investigation required.
- The prior Sentinel PR #14 had a GitGuardian blocker and source/runtime parity was unresolved. This isolated candidate is not permission to bypass that gate or merge its stacked commits.

**Release: HOLD / source-only prototype; no live probes, emails, scan jobs or deployment.**
