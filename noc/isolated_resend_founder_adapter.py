"""Resend founder-only email submission CONTRACT, disabled and offline.

This source contains NO HTTP/API client, email transport, API token, webhook,
or production activation. Its output can be passed to the Resend send-email API
only by a separate explicitly approved and authenticated caller.
A Resend email ID proves request acceptance at most, NOT delivery and NOT the
signed founder ACK required by the existing delivery protocol.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3

from .isolated_founder_delivery_protocol import FOUNDER_ROUTE, _durable

MAX_KEY_AGE_SECONDS = 23 * 3600  # Resend deduplicates keys for 24h.
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def prepare_isolated_resend_submission_store(conn: sqlite3.Connection) -> None:
    """Explicit schema in separate scratch/approved receiver DB only."""
    if not _durable(conn):
        raise ValueError("ISOLATED_DURABLE_DB_REQUIRED")
    tables = {
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    if "founder_delivery_queue" not in tables:
        raise ValueError("FOUNDER_QUEUE_REQUIRED")
    conn.execute("""CREATE TABLE IF NOT EXISTS resend_founder_submission (
        event_id TEXT PRIMARY KEY,
        route_id TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL,
        resend_email_id TEXT,
        response_recorded_at INTEGER
    )""")
    conn.commit()


def _verified_addresses(sender, founder, trusted_sender, trusted_founder):
    for value in (sender, founder, trusted_sender, trusted_founder):
        if type(value) is not str or not EMAIL_RE.fullmatch(value):
            raise ValueError("INVALID_EXPLICIT_ADDRESS")
    if (sender != trusted_sender or founder != trusted_founder
            or sender.rsplit("@", 1)[-1].lower() != "v79sl.com"
            or sender != sender.lower()):
        raise ValueError("FOUNDER_OR_SENDER_NOT_ALLOWLISTED")


def _render_request(lease, sender, founder):
    if (not isinstance(lease, dict) or lease.get("routeId") != FOUNDER_ROUTE
            or type(lease.get("eventId")) is not str
            or type(lease.get("payloadSha256")) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", lease["payloadSha256"])):
        raise ValueError("INVALID_FOUNDER_LEASE")
    event = lease.get("payload")
    if (not isinstance(event, dict)
            or set(event) != {"version", "eventId", "routeId",
                              "classification", "kind", "services"}
            or event.get("version") != 1
            or event.get("eventId") != lease["eventId"]
            or event.get("routeId") != FOUNDER_ROUTE
            or event.get("classification") != "UNVERIFIED_OWNER_ADVISORY"
            or event.get("kind") not in (
                "ATTENTION_REPORTED", "RECOVERY_REPORTED_UNVERIFIED"
            )
            or not isinstance(event.get("services"), list)
            or not 1 <= len(event["services"]) <= 20):
        raise ValueError("UNTRUSTED_ADVISORY_PAYLOAD")
    payload_json = json.dumps(event, sort_keys=True, separators=(",", ":"))
    if (len(payload_json.encode("utf-8")) > 8192
            or hashlib.sha256(payload_json.encode()).hexdigest()
               != lease["payloadSha256"]):
        raise ValueError("ADVISORY_PAYLOAD_DIGEST_MISMATCH")

    lines = []
    names = set()
    for s in event["services"]:
        if (not isinstance(s, dict) or set(s) != {"name", "signal"}
                or type(s["name"]) is not str
                or not 1 <= len(s["name"]) <= 80
                or any(ord(ch) < 32 for ch in s["name"])
                or s["name"] in names
                or s["signal"] not in (
                    "REPORTED_DOWN", "REVIEW_REPORTED",
                    "REPORTED_UP_UNVERIFIED"
                )):
            raise ValueError("UNTRUSTED_SERVICE_ROW")
        names.add(s["name"])
        lines.append(f"- {s['name']}: {s['signal']}")
    kind = event["kind"]
    subject = ("[V79 Sentinel] Unverified fault advisory"
               if kind == "ATTENTION_REPORTED"
               else "[V79 Sentinel] Unverified recovery advisory")
    text = (
        "INTERNAL PILOT - UNVERIFIED OBSERVATION, NOT A VERIFIED INCIDENT.\n"
        "Reported availability may be wrong or stale. Review independently.\n\n"
        + "\n".join(lines)
        + "\n\nNo automatic remediation has been performed.\n"
    )
    idem = "v79sentinel/" + hashlib.sha256(
        ("resend-founder-v1:" + lease["eventId"]).encode()
    ).hexdigest()
    return {
        "from": sender,
        "to": [founder],
        "subject": subject,
        "text": text,
        "idempotencyKey": idem,
    }


def reserve_isolated_resend_request(
    conn, *, lease, sender_address, founder_address,
    approved_sender, approved_founder, now_epoch,
):
    """Record immutable request intent; return offline Resend-shaped request.

    If an attempt might be older than Resend's 24-hour idempotency window,
    STOP instead of generating a new key or automatically resending.
    """
    _verified_addresses(
        sender_address, founder_address, approved_sender, approved_founder
    )
    if (not _durable(conn)
            or type(now_epoch) is not int
            or not 1 <= now_epoch <= 4_102_444_800
            or not isinstance(lease, dict)
            or type(lease.get("leaseUntil")) is not int
            or lease["leaseUntil"] < now_epoch):
        raise ValueError("NO_ACTIVE_FOUNDER_LEASE_OR_DB")
    request = _render_request(lease, sender_address, founder_address)
    digest = hashlib.sha256(
        json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT state,payload_sha256,lease_hash,lease_until "
            "FROM founder_delivery_queue WHERE event_id=? AND route_id=?",
            (lease["eventId"], FOUNDER_ROUTE),
        ).fetchone()
        if (not row or row[0] != "LEASED" or row[1] != lease["payloadSha256"]
                or row[3] < now_epoch
                or type(lease.get("leaseNonce")) is not str
                or hashlib.sha256(lease["leaseNonce"].encode()).hexdigest()
                   != row[2]):
            raise ValueError("UNTRUSTED_OR_EXPIRED_DELIVERY_LEASE")
        prior = conn.execute(
            "SELECT payload_sha256,request_sha256,idempotency_key,created_at "
            "FROM resend_founder_submission WHERE event_id=?",
            (lease["eventId"],),
        ).fetchone()
        if prior:
            if (prior[0] != lease["payloadSha256"]
                    or prior[1] != digest
                    or prior[2] != request["idempotencyKey"]
                    or now_epoch - prior[3] >= MAX_KEY_AGE_SECONDS
                    or now_epoch < prior[3]):
                raise ValueError("IDEMPOTENCY_CONFLICT_OR_EXPIRED")
        else:
            conn.execute(
                "INSERT INTO resend_founder_submission "
                "(event_id,route_id,payload_sha256,request_sha256,"
                "idempotency_key,created_at) VALUES (?,?,?,?,?,?)",
                (lease["eventId"], FOUNDER_ROUTE, lease["payloadSha256"],
                 digest, request["idempotencyKey"], now_epoch),
            )
        conn.commit()
        return request
    except (sqlite3.Error, ValueError, TypeError, KeyError):
        if conn.in_transaction:
            conn.rollback()
        raise ValueError("RESEND_REQUEST_RESERVATION_HOLD") from None


def record_resend_submission_response(
    conn, *, event_id, resend_email_id, now_epoch,
):
    """Record only provider acceptance metadata; NEVER mark founder ACK/delivery."""
    if (not _durable(conn)
            or type(event_id) is not str
            or type(resend_email_id) is not str
            or not UUID_RE.fullmatch(resend_email_id)
            or type(now_epoch) is not int or now_epoch < 1):
        return False
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT resend_email_id FROM resend_founder_submission "
            "WHERE event_id=?", (event_id,),
        ).fetchone()
        if not row or (row[0] is not None and row[0] != resend_email_id):
            conn.rollback()
            return False
        if row[0] is None:
            changed = conn.execute(
                "UPDATE resend_founder_submission SET resend_email_id=?,"
                "response_recorded_at=? WHERE event_id=? AND resend_email_id IS NULL",
                (resend_email_id, now_epoch, event_id),
            )
            if changed.rowcount != 1:
                conn.rollback()
                return False
        conn.commit()
        return True
    except sqlite3.Error:
        if conn.in_transaction:
            conn.rollback()
        return False
