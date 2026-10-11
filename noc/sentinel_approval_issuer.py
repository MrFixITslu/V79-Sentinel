"""DISCONNECTED staging prototype for supervised Ed25519 ticket approval.

Only a separately authenticated MFA-capable administrator may issue an approval
after an independent verified-evidence callback approves the exact event.
This module is NOT mounted on the live NOC or Tiquet service. No private keys in
source, output logs or ticket receiver. Real evidence authority remains unwired.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import errno
import json
import os
from pathlib import Path
import re
import stat
import time
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .security import accepted_totp_counter
from .store import timestamp

IDENT = re.compile(r"^[a-z][a-z0-9_.:-]{2,127}$", re.I)


def _uuid(text):
    try:
        return isinstance(text, str) and str(UUID(text)) == text.lower()
    except (TypeError, ValueError, AttributeError):
        return False


def _js_json(value):
    """JSON.stringify-compatible for this v1 event schema (no float values)."""
    def no_float(node):
        if isinstance(node, float):
            raise ValueError("Noncanonical floating-point approval evidence")
        if isinstance(node, dict):
            if not all(isinstance(k, str) for k in node):
                raise ValueError("Non-string approval evidence key")
            for v in node.values():
                no_float(v)
        if isinstance(node, list):
            for v in node:
                no_float(v)
    no_float(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf8")


def event_sha256(event):
    if not isinstance(event, dict):
        raise ValueError("Invalid event")
    bare = {k: v for k, v in event.items() if k != "approval"}
    return hashlib.sha256(_js_json(bare)).hexdigest()


def approval_claim_bytes(a):
    fields = ["v79-sentinel-ticket-approval-v1", a["key_id"], a["approval_id"],
        a["approver_user_id"], a["mfa_verified_at"], a["approved_at"],
        a["expires_at"], a["event_sha256"], a["event_id"], a["incident_id"],
        a["sentinel_customer_id"], a["tiquet_organization_id"],
        a["tiquet_client_id"], a["decision"]]
    return _js_json(fields)


def load_private_signer(path):
    """Read an owner-only, nonsymlink PEM file; reject group/world access."""
    p = Path(path)
    if p.parent.is_symlink():
        raise PermissionError("Symlink signer directory forbidden")
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENOENT, errno.EACCES):
            raise PermissionError("Unsafe or unavailable approval signing key") from None
        raise
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384):
            raise PermissionError("Approval signer requires owner-only regular 0600 file")
        with os.fdopen(fd,"rb",closefd=False) as stream:
            pem = stream.read(16385)
        if len(pem) > 16384:
            raise PermissionError("Oversized approval signing key")
    finally:
        os.close(fd)
    signer = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(signer, Ed25519PrivateKey):
        raise ValueError("Ed25519 private signer required")
    return signer


def _iso(ms):
    return (dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc)
        .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


def issue_supervised_approval(store, operator_id, otp, event, private_signer,
                              key_id, verify_evidence=None, confirmed=False,
                              now_ms=None):
    """Offline staging contract. Caller MUST authenticate+CSRF-check the session.

    Evidence verification must independently inspect the owned incident ledger
    and signed observation provenance; a caller-supplied classification alone
    is never sufficient. A fresh, unreplayed authenticator code is required.
    """
    if confirmed is not True:
        raise PermissionError("Human approval confirmation required")
    if not isinstance(private_signer, Ed25519PrivateKey):
        raise PermissionError("Independent private signer unavailable")
    if not isinstance(key_id, str) or not IDENT.fullmatch(key_id):
        raise ValueError("Invalid signing key ID")
    if not isinstance(event, dict) or event.get("source") != "v79-sentinel" or (
        event.get("classification") != "PRODUCTION_VERIFIED" or
        event.get("action") != "ticket.create"):
        raise PermissionError("Not an eligible production-verified creation event")
    tenant = event.get("tenant")
    if not isinstance(tenant, dict) or not all(isinstance(tenant.get(k), str)
         for k in ("sentinel_customer_id", "tiquet_organization_id", "tiquet_client_id")):
        raise ValueError("Missing exact customer mapping")
    if not all(_uuid(event.get(k)) for k in ("event_id", "source_incident_id")) or (
        not _uuid(tenant["sentinel_customer_id"])):
        raise ValueError("Invalid incident or customer identifiers")
    if not callable(verify_evidence) or verify_evidence(event) is not True:
        raise PermissionError("Independent verified-source evidence required")
    ms = int(time.time() * 1000 if now_ms is None else now_ms)
    proof = None
    with store.db() as db:
        operator = db.execute(
            "SELECT id,role,disabled,mfa_secret,mfa_last_counter FROM operators WHERE id=?",
            (operator_id,)).fetchone()
        if not operator or operator["disabled"] or operator["role"] != "admin" or (
            not operator["mfa_secret"]):
            raise PermissionError("MFA-enrolled administrator required")
        counter = accepted_totp_counter(
            operator["mfa_secret"], otp, now=ms / 1000,
            last=operator["mfa_last_counter"])
        if counter is None:
            raise PermissionError("Fresh non-replayed MFA verification required")
        approved_at = _iso(ms)
        proof = {
            "key_id": key_id,
            "approval_id": str(uuid4()),
            "approver_user_id": operator["id"],
            "mfa_verified_at": approved_at,
            "approved_at": approved_at,
            "expires_at": _iso(ms + 10 * 60_000),
            "event_id": event["event_id"],
            "incident_id": event["source_incident_id"],
            "sentinel_customer_id": tenant["sentinel_customer_id"],
            "tiquet_organization_id": tenant["tiquet_organization_id"],
            "tiquet_client_id": tenant["tiquet_client_id"],
            "decision": "approve_ticket_create",
            "event_sha256": event_sha256(event)
        }
        signature = private_signer.sign(approval_claim_bytes(proof))
        proof["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
        db.execute("""CREATE TABLE IF NOT EXISTS sentinel_approval_issuance(
          approval_id TEXT PRIMARY KEY, event_id TEXT NOT NULL,
          incident_id TEXT NOT NULL, approver_id TEXT NOT NULL REFERENCES operators(id),
          mfa_at TEXT NOT NULL, approved_at TEXT NOT NULL,
          evidence_sha256 TEXT NOT NULL, key_id TEXT NOT NULL, issued_at INTEGER NOT NULL
        )""")
        db.execute("UPDATE operators SET mfa_last_counter=? WHERE id=?",
                   (counter, operator_id))
        db.execute("""INSERT INTO sentinel_approval_issuance
          (approval_id,event_id,incident_id,approver_id,mfa_at,approved_at,
           evidence_sha256,key_id,issued_at) VALUES (?,?,?,?,?,?,?,?,?)""",
           (proof["approval_id"],proof["event_id"],proof["incident_id"],
            operator_id,proof["mfa_verified_at"],approved_at,
            proof["event_sha256"],key_id,timestamp()))
        store.audit(db,operator_id,"sentinel.ticket_approval.issued",proof["approval_id"])
    return proof
