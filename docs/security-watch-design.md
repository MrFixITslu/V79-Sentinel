# V79 Sentinel Security Watch — founder-only isolated prototype

**State: STAGED SOURCE ONLY / NOT COLLECTING LIVE LOGS / NO EMAIL SENT / NO PEN TEST EXECUTED.**

## Components
- `noc/security_watch.py`: tenant/host-bound event validation and SQLite security alerts. Only the named V79-owned host allowlist is eligible. Five SSH failures in 10 minutes, fifteen login failures in five minutes, a successful SSH sign-in outside approved source IPs, and unexpected privilege activity create review alerts. A login from an unknown source is **suspicious**, not proof of compromise.
- `noc/security_log_sources.py`: bounded parsers for trusted, local SSH/sudo journal entries or structured proxy login failures. Parsed events are pseudonymised; passwords, tokens, full HTTP URLs and raw logs are not persisted.
- `noc/security_mailer.py`: Resend HTTPS API adapter for a founder-only email recipient. Explicitly disabled unless configured; never stores or prints keys. Uses one fixed HTTPS endpoint, bounded content, stable idempotency keys, and a durable delivery outbox. The mailer's success only confirms API acceptance, not end-user inbox receipt.
- `noc/security_scan_policy.py`: disallows full/active scans and arbitrary targets, including cloud metadata addresses. The only approved ZAP baseline scope is disposable **loopback staging** with an explicit human approval marker. Production checks remain one allowlisted HTTPS HEAD request, without crawling, cookies or form submissions.

## Prerequisites before enabling on the live Dell
1. **Do not touch current deployment or backup.** Obtain exact running Sentinel/host identity, Docker/Podman composition, proxy route and persisted volume parity.
2. Fix the previously identified Sentinel PR #14 GitGuardian blocking finding privately. Do not open secrets in issues or bypass scanning; this branch is not a replacement for the canonical G2.21 NOC design.
3. Establish a read-only, **trusted** log feed from SSH/sudo journal and HTTPS/application access-denial logs. Prefer a dedicated unprivileged collector identity with journal/log read access. No privileged container, host Docker socket, raw packet capture or shell automation. An untrusted log can be forged; authenticate the feed if forwarded.
4. Confirm monitored hostnames and authorized SSH source IP/CIDRs (current owner VPN/Tailscale and authorised devices). Document deployment activity separately. During deployment, do not mute unknown SSH success or privileged activity; deduplication avoids storms.
5. Supply a separate event HMAC key via owner-managed secret provisioning, not Git. Keep security database mode 0600, encrypted off-host backups and retention/restore policy.
6. Verify `v79sl.com` sending-domain ownership and Resend DKIM/SPF before enabling. Inject sending API key from secret storage, configure verified sender + owner-recipient, and test one **approved synthetic notification** with its provider receipt. API acceptance is not delivery proof; monitor failures and expire unrecoverable alerts.
7. Only after owner approves a dedicated staged window, use the **passive** ZAP baseline against disposable local clones on loopback. OWASP ZAP baseline crawls using a spider; despite not attacking, it may issue GETs. Thus **no ZAP spider on production**. App-specific authenticated pen tests follow separately with consent and restore capability.
8. Test end-to-end trusted SSH/event data, stale/missing log signal, confirmed provider receipt, mobile NOC visibility, error budgets, CPU/RAM, restarts, fail-closed defaults, and independent host recovery.

## REDTEAM / threat model
- Forged monitoring events could trigger false alerts; do not trust arbitrary app/client-supplied JSON.
- Alerts might reveal account information; mail text intentionally contains no source IP, actor name, secrets, customer personal data or raw events. Full forensic access must remain owner-only.
- Alert fatigue: severity thresholds, per-principal 30-minute suppression and an outbox capped to five send attempts. A suppress/delay marker must never hide collected evidence.
- Host takeover can tamper with local logs; eventual secure off-host forwarded evidence is a separate requirement.
- Stale collection or empty sources are **UNKNOWN**, never represented as protected/healthy. Synthetic CI tests are **not** evidence of live sensor protection.
- No automatic IP bans, Fail2ban rules, SSH changes, Docker restarts, code execution, firewall edits, provider publication, payment calls, or customer-domain scans.

## Scope and relationships
This additive library does not modify running NOC web handlers, accepted Dashboard G2.21 artifacts, existing release processes or docker-compose. It can only become an operational feature following a verified deployed-source mapping and explicit deployment approval. The founder's V79 security audit register is V79hub issue #213.

**Standards:** OWASP ASVS 5.0 security logging and error handling, structured clocked audit events, alert source integrity, and owner-bound notification.
