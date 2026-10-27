"""Founder-only optional Sentinel security watcher. DISABLED by default.

Runs NO scans, no shell, no Docker access, no log writes and no mail unless
both an owner-approved local configuration and explicit environment gate allow.
Requires journalctl read permission granted to an unprivileged service account.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time

from .security_watch import SecurityWatch
from .security_log_sources import parse_journal_entry, safe_process_records
from .security_mailer import send_security_notification

MAX_JOURNAL_BYTES=512_000
MAX_EVENTS=300
JOURNAL_COMMAND=(
    "journalctl","--no-pager","--output=json","--since=10 minutes ago",
    "--lines=300","--identifier=sshd","--identifier=ssh","--identifier=sudo"
)

def load_owner_policy(file, hostname):
    path=Path(file)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Approved regular owner policy required")
    if (path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
        raise ValueError("Owner policy must be private (chmod 600)")
    data=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data,dict) or set(data) != {
        "enabled","hostname","approved_ssh_origins","approved_privileged_actors",
        "email_enabled","alert_from","alert_to"
    }:
        raise ValueError("Exact security watch configuration required")
    if data["enabled"] is not True or data["hostname"] != hostname:
        raise ValueError("Security watch not approved for this exact host")
    if not isinstance(data["approved_ssh_origins"],list) or not isinstance(data["approved_privileged_actors"],list):
        raise ValueError("Approved IP/actor lists required")
    if type(data["email_enabled"]) is not bool:
        raise ValueError("Explicit email enable or disable required")
    for prop in ("alert_from","alert_to"):
        if not isinstance(data[prop],str):
            raise ValueError("Owner email configuration required")
    return data

def read_journal():
    """Only fixed journalctl command; never user-supplied flags or escalation."""
    result=subprocess.run(JOURNAL_COMMAND, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=8, check=False)
    if result.returncode != 0:
        raise RuntimeError("Trusted journal source unavailable (UNKNOWN, not healthy)")
    if len(result.stdout) > MAX_JOURNAL_BYTES:
        raise RuntimeError("Journal batch too large; visibility incomplete")
    records=[]
    for line in result.stdout.splitlines():
        if not line or len(line)>8192:
            continue
        try:
            entry=json.loads(line)
            if isinstance(entry,dict):
                records.append(entry)
        except (ValueError,UnicodeDecodeError):
            continue
    return records

def cycle(watch, config, records, *, alerts_allowed=False, sender=None):
    status=safe_process_records(watch,records,parse_journal_entry,host=config["hostname"],maximum=MAX_EVENTS)
    status["email_sent"]=0
    status["email_pending"]=len(watch.pending())
    # Notifying from in-memory test feeds is intentionally impossible unless
    # both independently configured permissions are granted.
    if not alerts_allowed or not config["email_enabled"]:
        return status
    import os
    key=os.environ.get("SENTINEL_SECURITY_RESEND_API_KEY")
    transport_kwargs={} if sender is None else {"transport":sender}
    for alert in watch.pending(limit=3):
        success=send_security_notification(
            alert,enabled=True,api_key=key,from_address=config["alert_from"],
            to_address=config["alert_to"],**transport_kwargs)
        # A provider outage must not discard the pending security alert.
        watch.mark_attempt(alert["id"],success)
        if success:
            status["email_sent"]+=1
    status["email_pending"]=len(watch.pending())
    return status

def main(argv=None):
    cli=argparse.ArgumentParser(description="Opt-in, nonprivileged Sentinel SSH security review")
    cli.add_argument("--owner-policy",required=True)
    cli.add_argument("--db",required=True)
    cli.add_argument("--loop",action="store_true",help="Poll journal every minute until stopped")
    args=cli.parse_args(argv)
    if os.environ.get("SENTINEL_SECURITY_WATCH_ENABLED")!="1":
        print("SECURITY_WATCH=DISABLED_NO_ENV_APPROVAL")
        return 2
    host=socket.gethostname()
    policy=load_owner_policy(args.owner_policy,host)
    hmac_secret=os.environ.get("SENTINEL_SECURITY_HMAC_KEY","").encode("utf-8")
    watch=SecurityWatch(args.db,hosts={host},key=hmac_secret,
                        approved_ssh_origins=policy["approved_ssh_origins"],
                        approved_privileged_actors=policy["approved_privileged_actors"])
    while True:
        try:
            feed=read_journal()
            summary=cycle(watch,policy,feed,
                          alerts_allowed=os.environ.get("SENTINEL_SECURITY_ALERTS_ENABLED")=="1")
            # A zero-event response is never proof that privileged journals
            # are accessible or that all applications are monitored.
            source_state="read_only_query_returned_events" if feed else "UNKNOWN_NO_RECENT_JOURNAL_EVENTS"
            print(json.dumps({"mode":"ssh_sudo_only","visibility":source_state,
                              **summary},sort_keys=True),flush=True)
        except (RuntimeError,ValueError,subprocess.TimeoutExpired) as error:
            # No raw journal or secrets in errors; unknown input is not a PASS.
            print(json.dumps({"mode":"actual_journal","visibility":"UNKNOWN",
                              "error_type":type(error).__name__}),flush=True)
            if not args.loop:
                return 3
        if not args.loop:
            return 0
        time.sleep(60)

if __name__=="__main__":
    raise SystemExit(main())
