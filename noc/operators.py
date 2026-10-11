"""Standalone Sentinel operator identities and opt-in TOTP, staging only.

All changes run inside a SQLite transaction. This module NEVER touches Hub.
No real operator accounts should be provisioned until a supervised MFA review.
"""
from __future__ import annotations
import re
import sqlite3
from .security import (ROLES, hash_password, valid_password, new_totp_secret,
                       accepted_totp_counter, provisioning_uri, new_recovery_codes,
                       hash_recovery_code)
from .store import new_id, timestamp

USERNAME=re.compile(r"^[a-z][a-z0-9_.-]{2,63}$")

def _reauth(db,operator_id,password):
    operator=db.execute("SELECT * FROM operators WHERE id=? AND disabled=0",
                        (operator_id,)).fetchone()
    if not operator or not valid_password(password,operator["password_hash"]):
        raise PermissionError("Operator password verification failed")
    return operator

def list_operators(store):
    with store.db() as db:
        return [dict(row) for row in db.execute(
            """SELECT id,username,role,disabled,
            CASE WHEN mfa_secret IS NULL THEN 0 ELSE 1 END AS mfa_enabled
            FROM operators ORDER BY username""")]

def create_operator(store,admin_id,admin_password,username,password,role):
    if not isinstance(username,str) or not USERNAME.fullmatch(username):
        raise ValueError("Username must be lowercase and contain 3-64 safe characters")
    if role not in ROLES:
        raise ValueError("Invalid operator role")
    password_hash=hash_password(password)
    with store.db() as db:
        admin=_reauth(db,admin_id,admin_password)
        if admin["role"]!="admin":
            raise PermissionError("Administrator role required")
        operator_id=new_id()
        db.execute("""INSERT INTO operators(id,username,password_hash,role)
                      VALUES(?,?,?,?)""",(operator_id,username,password_hash,role))
        store.audit(db,admin_id,"operator.created",operator_id)
        return {"id":operator_id,"username":username,"role":role}

def disable_operator(store,admin_id,admin_password,target_id):
    with store.db() as db:
        admin=_reauth(db,admin_id,admin_password)
        if admin["role"]!="admin":
            raise PermissionError("Administrator role required")
        if target_id==admin_id:
            raise ValueError("You cannot disable your own operator account")
        target=db.execute("SELECT id,role,disabled FROM operators WHERE id=?",
                          (target_id,)).fetchone()
        if not target or target["disabled"]:
            raise ValueError("Unknown or disabled operator")
        if target["role"]=="admin":
            count=db.execute("SELECT count(*) FROM operators WHERE role='admin' AND disabled=0").fetchone()[0]
            if count<=1: raise ValueError("Cannot disable the last active administrator")
        db.execute("UPDATE operators SET disabled=1 WHERE id=?",(target_id,))
        db.execute("DELETE FROM sessions WHERE operator_id=?",(target_id,))
        store.audit(db,admin_id,"operator.disabled",target_id)

def mfa_status(store,operator_id):
    with store.db() as db:
        row=db.execute("SELECT mfa_secret,disabled FROM operators WHERE id=?",
                       (operator_id,)).fetchone()
        if not row or row["disabled"]: raise PermissionError("Operator unavailable")
        return {"enabled":bool(row["mfa_secret"]),"method":"totp"}

def mfa_begin(store,operator_id,current_password):
    with store.db() as db:
        op=_reauth(db,operator_id,current_password)
        if op["mfa_secret"]:
            raise ValueError("MFA already enabled; cannot replace without supervised recovery")
        secret=new_totp_secret()
        db.execute("""UPDATE operators SET mfa_pending=?,mfa_pending_until=?,
                      mfa_pending_attempts=0 WHERE id=?""",
                   (secret,timestamp()+600,operator_id))
        store.audit(db,operator_id,"mfa.setup.started",operator_id)
        # Secret returned only to authenticated, same-origin, CSRF-protected user.
        return {"secret":secret,"uri":provisioning_uri(op["username"],secret),
                "expires_in_seconds":600}

def mfa_confirm(store,operator_id,code):
    denied=False
    recovery_codes=[]
    with store.db() as db:
        op=db.execute("SELECT * FROM operators WHERE id=? AND disabled=0",
                      (operator_id,)).fetchone()
        if not op or op["mfa_secret"]:
            raise PermissionError("MFA setup not available")
        if not op["mfa_pending"] or not op["mfa_pending_until"] or op["mfa_pending_until"]<timestamp():
            raise PermissionError("MFA setup expired")
        if op["mfa_pending_attempts"]>=5:
            raise PermissionError("Too many MFA attempts; restart enrollment")
        counter=accepted_totp_counter(op["mfa_pending"],code)
        if counter is None:
            attempts=op["mfa_pending_attempts"]+1
            if attempts>=5:
                db.execute("""UPDATE operators SET mfa_pending=NULL,mfa_pending_until=NULL,
                              mfa_pending_attempts=? WHERE id=?""",(attempts,operator_id))
                store.audit(db,operator_id,"mfa.setup.attempts_exhausted",operator_id)
            else:
                db.execute("UPDATE operators SET mfa_pending_attempts=? WHERE id=?",
                           (attempts,operator_id))
            denied=True
        else:
            db.execute("""UPDATE operators SET mfa_secret=mfa_pending,mfa_pending=NULL,
                          mfa_pending_until=NULL,mfa_pending_attempts=0,
                          mfa_last_counter=? WHERE id=?""",
                          (counter,operator_id))
            recovery_codes=new_recovery_codes()
            for recovery_code in recovery_codes:
                db.execute("""INSERT INTO mfa_recovery_codes
                          (code_hash,operator_id,created) VALUES(?,?,?)""",
                           (hash_recovery_code(recovery_code),operator_id,timestamp()))
            # Session must not outlive the privilege change.
            db.execute("DELETE FROM sessions WHERE operator_id=?",(operator_id,))
            store.audit(db,operator_id,"mfa.enabled",operator_id)
    if denied:
        raise PermissionError("Invalid MFA code; enrollment is limited to five attempts")
    # Cleartext codes leave the server exactly once; only hashes are persisted.
    return {"enabled":True,"must_sign_in_again":True,"recovery_codes":recovery_codes}
