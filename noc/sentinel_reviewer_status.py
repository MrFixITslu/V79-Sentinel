"""Fail-closed current NOC reviewer authority for one signed incident approval.

The caller must independently authenticate its MACHINE identity in the HTTP
layer. No human cookie, recovery code or TOTP secret is returned here.
"""
from __future__ import annotations
from datetime import datetime,timezone
import sqlite3
import time
from uuid import UUID


def _uuid(x):
    try:return isinstance(x,str) and str(UUID(x))==x.lower()
    except (TypeError,ValueError,AttributeError):return False


def currently_authorized_reviewer(store,scope,mapping,now=None):
    when=int(time.time() if now is None else now)
    if not isinstance(scope,dict) or set(scope)!={
        "approverUserId","approvalId","approvedAt","organizationId",
        "sentinelCustomerId","action"} or not isinstance(mapping,dict):
        return False
    if not _uuid(scope["approverUserId"]) or not _uuid(scope["approvalId"]) or (
        scope["action"]!="ticket.create") or (
        scope["organizationId"]!=mapping.get("tiquet_organization_id")) or (
        scope["sentinelCustomerId"]!=mapping.get("sentinel_customer_id")):
        return False
    try:
        approved=datetime.fromisoformat(scope["approvedAt"].replace("Z","+00:00"))
        if approved.tzinfo is None:return False
        approved_time=approved.timestamp()
    except (TypeError,AttributeError,ValueError):
        return False
    if not 0<=when-approved_time<=10*60:return False
    try:
        with store.db() as db:
            row=db.execute("""SELECT o.disabled,o.role,o.mfa_secret,o.mfa_last_counter,
                    p.approved_at,p.issued_at,p.approver_id
                 FROM sentinel_approval_issuance p
                 JOIN operators o ON o.id=p.approver_id
                 WHERE p.approval_id=? AND p.approver_id=?""",
                 (scope["approvalId"],scope["approverUserId"])).fetchone()
            return bool(row and row["disabled"]==0 and row["role"]=="admin" and
                row["mfa_secret"] is not None and row["mfa_last_counter"]>=0 and
                row["approved_at"]==scope["approvedAt"] and
                0<=when-row["issued_at"]<=600)
    except sqlite3.OperationalError:
        # No approval ledger yet, or an incompatible schema: deny.
        return False
