"""V79-owned, read-only security event correlation. NO host actions or scans.

Only accepts events normalised by a trusted local collector. A suspicious event
is an alert for operator investigation, NEVER proof of an intrusion.
"""
from __future__ import annotations
import hashlib
import hmac
import ipaddress
import json
import re
import sqlite3
import time
from dataclasses import dataclass
from contextlib import contextmanager
from pathlib import Path

KINDS = frozenset({
    "ssh_failed", "ssh_accepted", "sudo", "http_auth_denied",
    "app_auth_denied", "privileged_change", "source_heartbeat"
})
SOURCES = frozenset({"sshd", "sudo", "proxy", "application", "docker", "collector"})
SOURCE_KINDS = {
    "sshd": {"ssh_failed", "ssh_accepted"},
    "sudo": {"sudo"},
    "proxy": {"http_auth_denied"},
    "application": {"app_auth_denied", "privileged_change"},
    "docker": {"privileged_change"},
    "collector": {"source_heartbeat"},
}
HOST_RX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,100}$")
ACTOR_RX = re.compile(r"^[a-zA-Z0-9_.@-]{0,100}$")


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    ts: int
    host: str
    source: str
    kind: str
    origin: str = ""
    actor: str = ""

    @staticmethod
    def from_record(record, allowed_hosts, now=None):
        if not isinstance(record, dict) or set(record) - {
            "event_id", "ts", "host", "source", "kind", "origin", "actor"
        }:
            raise ValueError("Unexpected security event fields")
        host, source, kind = (record.get(k) for k in ("host", "source", "kind"))
        if not isinstance(host, str) or host not in allowed_hosts or not HOST_RX.fullmatch(host):
            raise ValueError("Unapproved monitored host")
        if source not in SOURCES or kind not in KINDS or kind not in SOURCE_KINDS[source]:
            raise ValueError("Unapproved event/source combination")
        event_id = record.get("event_id")
        if not isinstance(event_id, str) or not re.fullmatch(r"[a-f0-9]{64}", event_id):
            raise ValueError("Event must have deterministic SHA256 identity")
        ts = record.get("ts")
        clock = int(now if now is not None else time.time())
        if type(ts) is not int or ts < clock - 600 or ts > clock + 120:
            raise ValueError("Stale or future security event")
        origin = record.get("origin") or ""
        if not isinstance(origin, str) or len(origin) > 55 or any(ord(c) < 33 for c in origin):
            raise ValueError("Invalid origin")
        if origin:
            try:
                ipaddress.ip_address(origin)
            except ValueError as error:
                raise ValueError("IP address origin expected") from error
        actor = record.get("actor") or ""
        if not isinstance(actor, str) or not ACTOR_RX.fullmatch(actor):
            raise ValueError("Invalid actor")
        return SecurityEvent(event_id, ts, host, source, kind, origin, actor)


class SecurityWatch:
    """SQLite-backed bounded event correlation; never stores raw log lines."""
    def __init__(self, path, *, hosts, key, approved_ssh_origins=(),
                 approved_privileged_actors=(), clock=None):
        self.hosts = frozenset(hosts)
        if not self.hosts or len(self.hosts) > 12 or not all(
            isinstance(h, str) and HOST_RX.fullmatch(h) for h in self.hosts
        ):
            raise ValueError("Explicit valid owned host allowlist required")
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("Separate >=32-byte event pseudonymisation key required")
        self.key = key
        self.approved = tuple(ipaddress.ip_network(v, strict=False)
                              for v in approved_ssh_origins)
        self.admins = frozenset(approved_privileged_actors)
        self.clock = clock or time.time
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS security_samples (
                event_id TEXT PRIMARY KEY, ts INTEGER NOT NULL,
                host TEXT NOT NULL, kind TEXT NOT NULL,
                principal_digest TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS ix_security_samples
                ON security_samples(host,kind,principal_digest,ts);
            CREATE TABLE IF NOT EXISTS security_alerts (
                id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                created INTEGER NOT NULL, severity TEXT NOT NULL,
                host TEXT NOT NULL, rule TEXT NOT NULL,
                summary TEXT NOT NULL, delivery TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0, last_attempt INTEGER);
            CREATE INDEX IF NOT EXISTS ix_security_alert_pending
                ON security_alerts(delivery,created);
            """)
        try:
            Path(self.path).chmod(0o600)
        except OSError:
            pass

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=3)
        db.execute("PRAGMA busy_timeout=3000")
        try:
            with db:
                yield db
        finally:
            db.close()

    def _digest(self, text):
        return hmac.new(self.key, text.encode("utf-8"), hashlib.sha256).hexdigest()

    def _known_origin(self, origin):
        if not origin:
            return False
        ip = ipaddress.ip_address(origin)
        return any(ip in net for net in self.approved)

    def ingest(self, record):
        now = int(self.clock())
        event = SecurityEvent.from_record(record, self.hosts, now=now)
        principal = self._digest(event.origin or event.actor or "unknown")
        with self.db() as db:
            db.execute("DELETE FROM security_samples WHERE ts < ?", (now - 3600,))
            exists = db.execute("SELECT 1 FROM security_samples WHERE event_id=?",
                                (event.event_id,)).fetchone()
            if exists:
                return None
            db.execute(
                "INSERT INTO security_samples VALUES (?,?,?,?,?)",
                (event.event_id, event.ts, event.host, event.kind, principal)
            )
            if event.kind == "source_heartbeat":
                return None
            rule = severity = message = None
            if event.kind == "ssh_accepted" and not self._known_origin(event.origin):
                rule, severity, message = ("unexpected_ssh_login", "high",
                    "SSH login from a source outside the approved access list; investigate")
            elif event.kind in ("sudo", "privileged_change") and event.actor not in self.admins:
                rule, severity, message = ("unexpected_privileged_activity", "high",
                    "Privileged activity by an unapproved actor; investigate")
            else:
                spec = {
                    "ssh_failed": (5, 600, "ssh_login_failures", "medium"),
                    "http_auth_denied": (15, 300, "web_login_failures", "medium"),
                    "app_auth_denied": (10, 300, "application_access_denials", "medium"),
                }.get(event.kind)
                if spec:
                    limit, window, name, level = spec
                    count = db.execute("""
                        SELECT COUNT(*) FROM security_samples
                         WHERE host=? AND kind=? AND principal_digest=? AND ts>=?
                    """, (event.host, event.kind, principal, now-window)).fetchone()[0]
                    if count >= limit:
                        rule, severity = name, level
                        message = f"{name.replace('_',' ').capitalize()}: {count} events in the monitored window"
            if not rule:
                return None
            # One alert per host/rule/pseudonymous actor every 30 minutes.
            # No unbounded per-request notifications and no suppression of log storage.
            fingerprint = self._digest(f"{event.host}:{rule}:{principal}")
            prior = db.execute("""
                SELECT id FROM security_alerts WHERE fingerprint=?
                  AND created>=? LIMIT 1
            """, (fingerprint, now-1800)).fetchone()
            if prior:
                return None
            identifier = self._digest(f"{fingerprint}:{now}")
            db.execute("""
                INSERT INTO security_alerts
                    (id,fingerprint,created,severity,host,rule,summary)
                VALUES(?,?,?,?,?,?,?)
            """, (identifier, fingerprint, now, severity, event.host, rule, message))
            return {
                "id": identifier, "ts": now, "host": event.host,
                "severity": severity, "rule": rule, "summary": message,
                "evidence": "local_log_correlated", "confirmed_intrusion": False
            }

    def pending(self, limit=10, now=None):
        if not 1 <= limit <= 20:
            raise ValueError("Bounded pending notification batch required")
        now = int(self.clock() if now is None else now)
        with self.db() as db:
            rows = db.execute("""
                SELECT id,created,severity,host,rule,summary,attempts,last_attempt
                FROM security_alerts WHERE delivery='pending' AND attempts<5
                  AND (last_attempt IS NULL OR last_attempt<=?)
                ORDER BY created ASC LIMIT ?
            """, (now-60, limit)).fetchall()
        return [dict(zip(("id","ts","severity","host","rule","summary","attempts","last_attempt"), r))
                for r in rows]

    def mark_attempt(self, alert_id, delivered):
        if not isinstance(alert_id, str) or not re.fullmatch(r"[a-f0-9]{64}", alert_id):
            raise ValueError("Invalid alert receipt")
        with self.db() as db:
            changed = db.execute("""
                UPDATE security_alerts
                   SET delivery=CASE WHEN ? THEN 'delivered' ELSE 'pending' END,
                       attempts=attempts+1, last_attempt=?
                 WHERE id=? AND delivery='pending'
            """, (1 if delivered else 0, int(self.clock()), alert_id))
            return changed.rowcount == 1


def event_identity(source, line, offset):
    """Deterministic file identity for read-only collector forwarding."""
    if not isinstance(source, str) or not isinstance(line, str) or type(offset) is not int:
        raise ValueError("Invalid local log identity")
    return hashlib.sha256(f"{source}:{offset}:{line}".encode("utf-8")).hexdigest()
