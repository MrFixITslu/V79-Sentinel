"""Read-only parsers for trustworthy locally forwarded SSH/sudo and proxy logs.

No shell commands, Docker socket access or HTTP requests. Parsers discard raw
messages/paths before storing events. Not proof of origin integrity on their own.
"""
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from .security_watch import SecurityEvent

SSH_ATTEMPT = re.compile(
    r"(?:Failed password for (?:invalid user )?|Accepted (?:publickey|password) for )"
    r"([A-Za-z0-9_.@-]{1,80}) from ([0-9a-fA-F:.]+) port \d+"
)
SUDO_SESSION = re.compile(
    r"pam_unix\(sudo:session\): session opened for user root by "
    r"([A-Za-z0-9_.@-]{1,80})"
)
ALLOWED_AUTH_ROUTES = frozenset({
    "/api/auth/login", "/api/auth/register", "/api/auth/reset-password",
    "/api/auth/refresh", "/login", "/api/login"
})


def _id(prefix, identifier):
    return hashlib.sha256((prefix + ":" + str(identifier)).encode("utf-8")).hexdigest()


def parse_journal_entry(raw, *, host):
    """Accept journald -o json SSH/sudo records, never arbitrary system logs."""
    if not isinstance(raw, dict):
        return None
    identifier = raw.get("SYSLOG_IDENTIFIER") or ""
    # journald's trusted _UID field prevents an ordinary local user from
    # fabricating sshd/sudo entries with 'logger -t sshd'.
    if identifier not in ("sshd", "ssh", "sudo") or str(raw.get("_UID", "")) != "0":
        return None
    cursor = raw.get("__CURSOR")
    micros = raw.get("__REALTIME_TIMESTAMP")
    message = raw.get("MESSAGE")
    if not (isinstance(cursor, str) and 1 <= len(cursor) <= 500 and
            isinstance(message, str) and len(message) <= 4096 and
            isinstance(micros, str) and micros.isdigit()):
        return None
    ts = int(micros)//1000000
    if identifier in ("sshd","ssh"):
        match = SSH_ATTEMPT.search(message)
        if not match:
            return None
        actor, ip = match.groups()
        try: ipaddress.ip_address(ip)
        except ValueError: return None
        kind = "ssh_failed" if "Failed password" in message else "ssh_accepted"
        source = "sshd"
        origin = ip
    else:
        match = SUDO_SESSION.search(message)
        if not match:
            return None
        actor = match.group(1)
        origin = ""
        kind = "sudo"
        source = "sudo"
    return {"event_id":_id("journal",cursor),"ts":ts,"host":host,
            "source":source,"kind":kind,"origin":origin,"actor":actor}


def parse_proxy_access_json(raw, *, host):
    """Parser for structured, owner-controlled Nginx log forwarding.

    Only explicit login/registration/recovery endpoints trigger a failure
    signal. Generic 401 on /api/auth/me is expected and must not flood alerts.
    """
    if not isinstance(raw,dict):
        return None
    method=raw.get("method")
    route=raw.get("path")
    status=raw.get("status")
    request_id=raw.get("event_id")
    ip=raw.get("remote_addr")
    stamp=raw.get("timestamp")
    if method != "POST" or route not in ALLOWED_AUTH_ROUTES or type(status) is not int or status not in (401,403,429):
        return None
    if not isinstance(request_id,str) or not 1 <= len(request_id) <= 128:
        return None
    try:
        ipaddress.ip_address(ip)
        ts=int(datetime.fromisoformat(stamp.replace("Z","+00:00")).timestamp())
    except (ValueError,AttributeError,TypeError,OverflowError):
        return None
    return {"event_id":_id("proxy",request_id),"ts":ts,"host":host,
            "source":"proxy","kind":"http_auth_denied","origin":ip,"actor":""}


def safe_process_records(watch, records, parser, *, host, maximum=300):
    """Bound a batch and return alert counts; never return or print raw log data."""
    if maximum < 1 or maximum > 300:
        raise ValueError("Invalid bounded log batch")
    count=alerts=rejected=0
    for raw in records:
        if count >= maximum:
            break
        count+=1
        event=parser(raw,host=host)
        if event is None:
            continue
        try:
            if watch.ingest(event):
                alerts+=1
        except (ValueError,KeyError):
            rejected+=1
    return {"processed":count,"new_alerts":alerts,"rejected":rejected}
