"""OFF-BY-DEFAULT founder-only advisory delivery protocol: NO NETWORK.

All actions operate only on an explicitly approved ISOLATED SQLite receiver
database. No email, HTTP, Hub, secrets loader, account access or real alerts.
A report signature still does not prove that the collector made a real probe.
Transport implementation and credentials intentionally do not exist here.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import secrets
import sqlite3

from .isolated_sqlite_durability import is_durable_isolated_sqlite

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FOUNDER_ROUTE = "v79-founder-primary"
MAX_ATTEMPTS = 5
LEASE_SECONDS = 60
MAX_DELAY_SECONDS = 3600
ALLOWED_SIGNALS = frozenset((
    "REPORTED_UP_UNVERIFIED", "REPORTED_DOWN", "REVIEW_REPORTED",
))
QUEUE_STATES = ("PENDING", "LEASED", "ACKED", "PAUSED")


def _durable(conn):
    return is_durable_isolated_sqlite(conn)

def _route(route):
    if route != FOUNDER_ROUTE or type(route) is not str:
        raise ValueError("UNAUTHORIZED_FOUNDER_ROUTE")


def _clock(now_epoch):
    if type(now_epoch) is not int or not 1 <= now_epoch <= 4_102_444_800:
        raise ValueError("INVALID_TRUSTED_CLOCK")


def prepare_founder_delivery_store(conn):
    """Explicit schema install in a separate test/operator-approved receiver DB."""
    if not _durable(conn):
        raise ValueError("ISOLATED_DURABLE_DB_REQUIRED")
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    if "signed_advisory_outbox" not in {r[0] for r in tables}:
        raise ValueError("VERIFIED_ADVISORY_OUTBOX_REQUIRED")
    conn.execute("""CREATE TABLE IF NOT EXISTS founder_delivery_cursor (
        route_id TEXT NOT NULL,
        collector_id TEXT NOT NULL,
        last_sequence INTEGER NOT NULL,
        last_fingerprint TEXT NOT NULL,
        last_attention INTEGER NOT NULL CHECK(last_attention IN (0,1)),
        PRIMARY KEY(route_id,collector_id)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS founder_delivery_queue (
        event_id TEXT PRIMARY KEY,
        route_id TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'PENDING'
            CHECK(state IN ('PENDING','LEASED','ACKED','PAUSED')),
        attempts INTEGER NOT NULL DEFAULT 0,
        next_due INTEGER NOT NULL DEFAULT 0,
        lease_hash TEXT,
        lease_until INTEGER,
        ack_at INTEGER
    )""")
    conn.commit()


def _decode(row):
    data = json.loads(row)
    if (not isinstance(data, dict)
            or set(data) != {"status", "trustedForExecutiveUse",
                             "alertsDispatched", "services"}
            or data["status"] != "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE"
            or data["trustedForExecutiveUse"] is not False
            or data["alertsDispatched"] is not False
            or not isinstance(data["services"], list)
            or not 1 <= len(data["services"]) <= 20):
        raise ValueError("INVALID_SIGNED_ADVISORY_SHAPE")
    seen = set()
    for entry in data["services"]:
        if (not isinstance(entry, dict)
                or set(entry) != {"name", "signal"}
                or type(entry["name"]) is not str
                or not 1 <= len(entry["name"]) <= 80
                or entry["name"] in seen
                or type(entry["signal"]) is not str
                or entry["signal"] not in ALLOWED_SIGNALS):
            raise ValueError("INVALID_OWNER_ADVISORY_ROW")
        seen.add(entry["name"])
    return sorted(data["services"], key=lambda x: x["name"])


def stage_next_founder_advisory(conn, *, route_id, collector_id,
                                now_epoch):
    """Durably inspect one next sequence; enqueue changes only.

    The first all-up report is a silent baseline. Subsequent identical
    fault claims are suppressed. A reported recovery after a fault produces
    a separate review-only advisory; it is NOT verified recovery.
    """
    _route(route_id)
    _clock(now_epoch)
    if not _durable(conn) or type(collector_id) is not str or not collector_id:
        raise ValueError("UNTRUSTED_STORE_OR_COLLECTOR")
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT last_sequence,last_fingerprint,last_attention "
            "FROM founder_delivery_cursor WHERE route_id=? AND collector_id=?",
            (route_id, collector_id),
        ).fetchone()
        previous = row[0] if row else 0
        next_row = conn.execute(
            "SELECT event_id,sequence,advisory_json FROM signed_advisory_outbox "
            "WHERE collector_id=? AND sequence>? AND state='PENDING' "
            "ORDER BY sequence ASC LIMIT 1", (collector_id, previous),
        ).fetchone()
        if next_row is None:
            conn.rollback()
            return "NO_EVENT"
        event_id, sequence, source = next_row
        if (type(sequence) is not int or sequence <= previous
                or event_id != f"{collector_id}:{sequence}"):
            raise ValueError("INVALID_OR_REPLAYED_EVENT_ID")
        services = _decode(source)
        fingerprint = hashlib.sha256(
            json.dumps(services, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        attention = any(s["signal"] != "REPORTED_UP_UNVERIFIED"
                        for s in services)
        should_queue = (
            (not row and attention)
            or (bool(row) and fingerprint != row[1]
                and (attention or bool(row[2])))
        )
        if should_queue:
            payload = {
                "version": 1, "eventId": event_id,
                "routeId": FOUNDER_ROUTE,
                "classification": "UNVERIFIED_OWNER_ADVISORY",
                "kind": "ATTENTION_REPORTED" if attention
                        else "RECOVERY_REPORTED_UNVERIFIED",
                "services": services,
            }
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            if len(encoded.encode()) > 8192:
                raise ValueError("OWNER_ADVISORY_TOO_LARGE")
            checksum = hashlib.sha256(encoded.encode()).hexdigest()
            conn.execute(
                "INSERT INTO founder_delivery_queue "
                "(event_id,route_id,payload_json,payload_sha256,next_due)"
                " VALUES (?,?,?,?,?)",
                (event_id, route_id, encoded, checksum, now_epoch),
            )
        conn.execute(
            "INSERT INTO founder_delivery_cursor "
            "(route_id,collector_id,last_sequence,last_fingerprint,last_attention) "
            "VALUES (?,?,?,?,?) ON CONFLICT(route_id,collector_id) DO UPDATE SET "
            "last_sequence=excluded.last_sequence,"
            "last_fingerprint=excluded.last_fingerprint,"
            "last_attention=excluded.last_attention",
            (route_id, collector_id, sequence, fingerprint, int(attention)),
        )
        conn.commit()
        return "QUEUED_REVIEW_ONLY" if should_queue else "SUPPRESSED"
    except (ValueError, KeyError, TypeError, sqlite3.Error, json.JSONDecodeError):
        if conn.in_transaction:
            conn.rollback()
        raise ValueError("STAGING_REJECTED_WITHOUT_PARTIAL_ADVANCE") from None


def claim_founder_delivery(conn, *, route_id, now_epoch):
    """Return one bounded lease for an OFFLINE simulated transport only.

    A future external transport must independently enforce the approved owner
    endpoint and never obtain privileged app or payment credentials. Returning
    a lease does not mean a notification was sent.
    """
    _route(route_id)
    _clock(now_epoch)
    if not _durable(conn):
        raise ValueError("UNTRUSTED_DELIVERY_STORE")
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "UPDATE founder_delivery_queue SET state='PAUSED',lease_hash=NULL,"
            "lease_until=NULL WHERE route_id=? AND state='LEASED' "
            "AND lease_until<=? AND attempts>=?",
            (route_id, now_epoch, MAX_ATTEMPTS),
        )
        row = conn.execute(
            "SELECT event_id,payload_json,payload_sha256,attempts "
            "FROM founder_delivery_queue WHERE route_id=? AND attempts<? "
            "AND ((state='PENDING' AND next_due<=?) "
            "OR (state='LEASED' AND lease_until<=?)) "
            "ORDER BY next_due,event_id LIMIT 1",
            (route_id, MAX_ATTEMPTS, now_epoch, now_epoch),
        ).fetchone()
        if row is None:
            conn.commit()
            return None
        event_id, payload_json, digest, attempts = row
        if hashlib.sha256(payload_json.encode()).hexdigest() != digest:
            raise ValueError("PERSISTED_DELIVERY_PAYLOAD_CHANGED")
        nonce = secrets.token_hex(24)
        lease_until = now_epoch + LEASE_SECONDS
        conn.execute(
            "UPDATE founder_delivery_queue SET state='LEASED',attempts=?,"
            "lease_hash=?,lease_until=? WHERE event_id=?",
            (attempts+1, hashlib.sha256(nonce.encode()).hexdigest(),
             lease_until, event_id),
        )
        conn.commit()
        return {
            "eventId": event_id, "routeId": FOUNDER_ROUTE,
            "attempt": attempts+1, "leaseNonce": nonce,
            "leaseUntil": lease_until, "payloadSha256": digest,
            "payload": json.loads(payload_json),
        }
    except (ValueError, TypeError, sqlite3.Error, json.JSONDecodeError):
        if conn.in_transaction:
            conn.rollback()
        raise ValueError("DELIVERY_LEASE_REJECTED") from None


def canonical_ack(ack):
    return json.dumps(
        {k: ack[k] for k in (
            "version", "eventId", "routeId", "leaseNonce",
            "payloadSha256", "acceptedAtEpoch"
        )}, sort_keys=True, separators=(",", ":"),
    ).encode()


def accept_signed_founder_ack(conn, *, route_id, lease, ack,
                              pinned_receiver_public_key, now_epoch):
    """Accept only a pinned Ed25519 owner-endpoint receipt for the active lease."""
    _route(route_id)
    _clock(now_epoch)
    if (not _durable(conn) or not isinstance(lease, dict)
            or not isinstance(ack, dict)
            or set(ack) != {"version", "eventId", "routeId", "leaseNonce",
                            "payloadSha256", "acceptedAtEpoch", "signature"}
            or type(ack["version"]) is not int or ack["version"] != 1
            or type(ack["acceptedAtEpoch"]) is not int
            or type(lease.get("leaseUntil")) is not int
            # No signed endpoint may claim it accepted a nonce before this
            # specific lease existed. Allow <=30s clock skew only.
            or ack["acceptedAtEpoch"] < lease["leaseUntil"] - LEASE_SECONDS - 30
            or not now_epoch-300 <= ack["acceptedAtEpoch"] <= now_epoch+30
            or type(pinned_receiver_public_key) is not bytes
            or len(pinned_receiver_public_key) != 32
            or any(ack.get(k) != lease.get(k) for k in (
                "eventId", "routeId", "leaseNonce", "payloadSha256"
            )) or lease.get("routeId") != FOUNDER_ROUTE
            or type(ack["signature"]) is not str
            or len(ack["signature"]) != 86):
        return False
    try:
        encoded = ack["signature"]
        sig = base64.urlsafe_b64decode(encoded + "==")
        if len(sig) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(pinned_receiver_public_key).verify(
            sig, canonical_ack(ack),
        )
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT state,lease_hash,lease_until,payload_sha256 "
            "FROM founder_delivery_queue WHERE event_id=? AND route_id=?",
            (ack["eventId"], FOUNDER_ROUTE),
        ).fetchone()
        if (not row or row[0] != "LEASED" or row[2] < now_epoch
                or row[3] != ack["payloadSha256"]
                or row[1] != hashlib.sha256(ack["leaseNonce"].encode()).hexdigest()):
            conn.rollback()
            return False
        conn.execute(
            "UPDATE founder_delivery_queue SET state='ACKED',ack_at=?,"
            "lease_hash=NULL,lease_until=NULL WHERE event_id=?",
            (now_epoch, ack["eventId"]),
        )
        conn.commit()
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError,
            sqlite3.Error, base64.binascii.Error):
        if conn.in_transaction:
            conn.rollback()
        return False


def retry_or_pause_founder_delivery(conn, *, route_id, lease, now_epoch):
    """Record a failed attempt with capped exponential backoff; no dispatch."""
    _route(route_id)
    _clock(now_epoch)
    if not _durable(conn) or not isinstance(lease, dict):
        return "REJECTED"
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT attempts,state,lease_hash,lease_until FROM founder_delivery_queue "
            "WHERE event_id=? AND route_id=?",
            (lease.get("eventId"), FOUNDER_ROUTE),
        ).fetchone()
        if (not row or row[1] != "LEASED"
                or row[3] < now_epoch
                or row[2] != hashlib.sha256(lease["leaseNonce"].encode()).hexdigest()):
            conn.rollback()
            return "REJECTED"
        paused = row[0] >= MAX_ATTEMPTS
        next_due = now_epoch + min(MAX_DELAY_SECONDS, 30 * 2**(row[0]-1))
        conn.execute(
            "UPDATE founder_delivery_queue SET state=?,next_due=?,"
            "lease_hash=NULL,lease_until=NULL WHERE event_id=?",
            ("PAUSED" if paused else "PENDING", next_due, lease["eventId"]),
        )
        conn.commit()
        return "PAUSED_MANUAL_REVIEW" if paused else "RETRY_SCHEDULED"
    except (KeyError, TypeError, ValueError, sqlite3.Error):
        if conn.in_transaction:
            conn.rollback()
        return "REJECTED"
