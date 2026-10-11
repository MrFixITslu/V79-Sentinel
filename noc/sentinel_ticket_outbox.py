"""Offline-only durable Sentinel -> Tiquet outbox contract, staging.

This module NEVER starts a worker or network request. Explicitly wired
dispatch needs a separately approved transport and must be gated by the
live entitlement check and current human-reviewer check before each send.
"""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
from datetime import datetime, timezone
import json
import sqlite3
import time
from uuid import UUID, uuid4

from .sentinel_approval_issuer import event_sha256


def _uuid(value):
    try: return isinstance(value,str) and str(UUID(value)) == value.lower()
    except (ValueError, TypeError, AttributeError): return False


def _json(value):
    # Preserve issuer event insertion order: JS JSON.stringify(payload) includes
    # property order in the signed SHA-256 event digest.
    return json.dumps(value,sort_keys=False,ensure_ascii=False,separators=(",",":"))


def initialize(store):
    with store.db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS sentinel_dispatch_outbox (
         event_id TEXT PRIMARY KEY, source_incident_id TEXT NOT NULL,
         approval_id TEXT NOT NULL UNIQUE, customer_id TEXT NOT NULL,
         payload TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
         status TEXT NOT NULL CHECK(status IN ('pending','delivered','cancelled','expired')),
         approval_expires INTEGER NOT NULL,
         attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL,
         created INTEGER NOT NULL, delivered INTEGER,
         tiquet_job_id TEXT, UNIQUE(source_incident_id))""")
        db.execute("""CREATE TABLE IF NOT EXISTS sentinel_dispatch_attempts (
         id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES sentinel_dispatch_outbox(event_id),
         attempted INTEGER NOT NULL, result TEXT NOT NULL,
         CHECK(result IN ('retry','delivered','cancelled','expired')))""")


def queue_reviewed_ticket(store,event,approval,verify_approval=None,
                           verify_source=None,now=None):
    """Queue only when two independent verification functions pass.

    Missing trusted verification functions fail closed. No network action.
    """
    if not callable(verify_approval) or verify_approval(event,approval) is not True:
        raise PermissionError("Independent human-signature verification required")
    if not callable(verify_source) or verify_source(event) is not True:
        raise PermissionError("Independently verified owner evidence required")
    if not isinstance(event,dict) or event.get("action")!="ticket.create" or (
        event.get("classification")!="PRODUCTION_VERIFIED" or
        event.get("source")!="v79-sentinel"):
        raise PermissionError("Unverified ticket action")
    if not isinstance(approval,dict) or not _uuid(event.get("event_id")) or (
        not _uuid(event.get("source_incident_id")) or
        not _uuid(approval.get("approval_id")) or
        approval.get("event_id")!=event["event_id"] or
        approval.get("event_sha256")!=event_sha256(event)):
        raise ValueError("Approval does not bind the incident event")
    customer=event.get("tenant",{}).get("sentinel_customer_id")
    if not _uuid(customer) or approval.get("sentinel_customer_id")!=customer:
        raise PermissionError("Unverified owner customer mapping")
    body=_json({**event,"approval":approval})
    if len(body.encode("utf8"))>11500:raise ValueError("Event exceeds service limit")
    when=int(time.time() if now is None else now)
    try:
        expiry=datetime.fromisoformat(approval["expires_at"].replace("Z","+00:00"))
    except (KeyError,ValueError,TypeError,AttributeError):
        raise ValueError("Signed approval expiration required")
    if expiry.tzinfo is None:
        raise ValueError("Approval expiration must be timezone-aware")
    expiration=int(expiry.timestamp())
    if expiration<=when or expiration>when+15*60:
        raise PermissionError("Approved dispatch has expired or oversized lifetime")
    receipt=hashlib.sha256(body.encode("utf8")).hexdigest()
    with store.db() as db:
        old=db.execute("SELECT * FROM sentinel_dispatch_outbox WHERE event_id=?",
                        (event["event_id"],)).fetchone()
        if old:
            if old["payload_sha256"]!=receipt:
                raise ValueError("Conflicting event replay")
            return {"queued":False,"state":old["status"]}
        # Incident id uniqueness prevents two tickets for the same incident.
        if db.execute("SELECT 1 FROM sentinel_dispatch_outbox WHERE source_incident_id=?",
                      (event["source_incident_id"],)).fetchone():
            raise ValueError("Incident already assigned a different ticket event")
        db.execute("""INSERT INTO sentinel_dispatch_outbox
         (event_id,source_incident_id,approval_id,customer_id,payload,
          payload_sha256,status,approval_expires,next_attempt,created)
          VALUES(?,?,?,?,?,?,'pending',?,?,?)""",
          (event["event_id"],event["source_incident_id"],approval["approval_id"],
           customer,body,receipt,expiration,when,when))
        store.audit(db,approval["approver_user_id"],"sentinel.ticket.queued",event["event_id"])
    return {"queued":True,"state":"pending"}


def pending(store,now=None,limit=10):
    when=int(time.time() if now is None else now)
    if type(limit) is not int or not 1<=limit<=50:raise ValueError("Invalid delivery limit")
    with store.db() as db:
        db.execute("""UPDATE sentinel_dispatch_outbox SET status='expired'
           WHERE status='pending' AND approval_expires<=?""",(when,))
        return [dict(row) for row in db.execute(
            """SELECT event_id,source_incident_id,approval_id,customer_id,
               attempts,next_attempt,created,approval_expires FROM sentinel_dispatch_outbox
               WHERE status='pending' AND next_attempt<=? AND approval_expires>?
               ORDER BY created ASC,event_id ASC LIMIT ?""",(when,when,limit))]


def record_delivery(store,event_id,accepted=False,job_id=None,now=None):
    """Record an authenticated transport result; does not send anything.

    The caller must authenticate and validate Tiquet's signed acknowledgement
    before requesting accepted=True. A retry result never closes a ticket.
    """
    if not _uuid(event_id):raise ValueError("Invalid event")
    if accepted and not _uuid(job_id):raise ValueError("Authenticated Tiquet job ID required")
    when=int(time.time() if now is None else now)
    with store.db() as db:
        row=db.execute("SELECT status,attempts,approval_expires,next_attempt FROM sentinel_dispatch_outbox WHERE event_id=?",
                       (event_id,)).fetchone()
        if not row or row["status"]!="pending":
            raise ValueError("Unknown or already processed dispatch")
        if when<row["next_attempt"] and when<row["approval_expires"]:
            raise ValueError("Dispatch retry not yet due")
        if when>=row["approval_expires"]:
            db.execute("UPDATE sentinel_dispatch_outbox SET status='expired' WHERE event_id=?",(event_id,))
            db.execute("INSERT INTO sentinel_dispatch_attempts VALUES(?,?,?,?)",
                       (str(uuid4()),event_id,when,"expired"))
            return {"status":"expired","attempts":row["attempts"],"next_attempt":None}
        attempts=row["attempts"]+1
        result="delivered" if accepted else "retry"
        # Exponential retry is limited by the signed human approval expiration.
        delay=min(120,60*(2**min(attempts-1,2)))
        next_attempt=when+delay
        exhausted=(not accepted and (attempts>=8 or next_attempt>=row["approval_expires"]))
        state="delivered" if accepted else "expired" if exhausted else "pending"
        if exhausted: result="expired"
        db.execute("""UPDATE sentinel_dispatch_outbox SET attempts=?,next_attempt=?,
                      status=?,delivered=?,tiquet_job_id=? WHERE event_id=?""",
                   (attempts,next_attempt,state,
                    when if accepted else None,job_id if accepted else None,event_id))
        db.execute("INSERT INTO sentinel_dispatch_attempts VALUES(?,?,?,?)",
                   (str(uuid4()),event_id,when,result))
    return {"status":result,"attempts":attempts,
            "next_attempt":next_attempt if result=="retry" else None}


def cancel_pending(store,event_id,now=None):
    when=int(time.time() if now is None else now)
    with store.db() as db:
        changed=db.execute("UPDATE sentinel_dispatch_outbox SET status='cancelled' WHERE event_id=? AND status='pending'",
                           (event_id,)).rowcount
        if changed!=1:raise ValueError("Cannot cancel unknown/delivered dispatch")
        db.execute("INSERT INTO sentinel_dispatch_attempts VALUES(?,?,?,?)",
                   (str(uuid4()),event_id,when,"cancelled"))
