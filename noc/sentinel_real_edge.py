"""Real Edge Agent signed measurement correlation, disconnected staging.

Agent signs a check observation WITHOUT an incident ID. NOC independently
authenticates the agent/check/target and creates its own incident after two
consecutive failed readings. This must never consume SIMULATED_ONLY events.
No listening endpoint or collector is enabled by importing this module.
"""
from __future__ import annotations

import hashlib
import json
import time
from uuid import uuid4
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VERSION="V79_SIGNED_EDGE_MEASUREMENT_V1"
WINDOW=15*60
MIN_FAILURE_GAP=20
CLAIMS=frozenset(("version","receipt_id","customer_id","site_id","agent_id",
 "check_id","sequence","observed_at","ok","target_ip","target_port","probe_kind"))


def canonical(claims):
    return json.dumps(claims,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode("utf8")


def verify_agent_measurement(envelope,public_keys,targets,now=None):
    """Trust model: keys and target/port pairs come from private owner configuration."""
    when=int(time.time() if now is None else now)
    if not isinstance(envelope,dict) or set(envelope)!={"claims","signature"}:
        raise PermissionError("Signed Edge observation envelope required")
    c=envelope["claims"]
    if not isinstance(c,dict) or set(c)!=CLAIMS or c.get("version")!=VERSION or (
        c.get("probe_kind")!="tcp") or type(c.get("ok")) is not bool or (
        type(c.get("sequence")) is not int or c["sequence"]<1) or (
        type(c.get("observed_at")) is not int or c["observed_at"]>when or
        when-c["observed_at"]>WINDOW):
        raise PermissionError("Untrusted Edge measurement claims")
    from uuid import UUID
    def uid(x):
        try:return isinstance(x,str) and str(UUID(x))==x.lower()
        except (ValueError,TypeError,AttributeError):return False
    if not all(uid(c.get(k)) for k in ("receipt_id","customer_id","site_id","agent_id","check_id")):
        raise PermissionError("Invalid owner identities")
    policy=targets.get(c["check_id"]) if isinstance(targets,dict) else None
    if not isinstance(policy,dict) or set(policy)!={"ip","port","customer_id","site_id","agent_id"} or (
        (c["target_ip"],c["target_port"],c["customer_id"],c["site_id"],c["agent_id"])!=
        (policy["ip"],policy["port"],policy["customer_id"],policy["site_id"],policy["agent_id"])):
        raise PermissionError("Agent attempted an unapproved target or site")
    key=public_keys.get(c["agent_id"]) if isinstance(public_keys,dict) else None
    if not isinstance(key,str) or not key.startswith("-----BEGIN PUBLIC KEY-----"):
        raise PermissionError("Unpinned signed observation origin")
    try:
        pub=serialization.load_pem_public_key(key.encode("ascii"))
        if not isinstance(pub,Ed25519PublicKey):raise PermissionError("Ed25519 signing required")
        signature=envelope["signature"]
        if not isinstance(signature,str) or len(signature)!=128:
            raise PermissionError("Bad Edge observation signature")
        pub.verify(bytes.fromhex(signature),canonical(c))
    except (ValueError,InvalidSignature,TypeError,UnicodeError):
        raise PermissionError("Invalid Edge observation signature") from None
    return c


def initialize(store):
    with store.db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS sentinel_real_measurements (
          receipt_id TEXT PRIMARY KEY,customer_id TEXT NOT NULL,site_id TEXT NOT NULL,
          agent_id TEXT NOT NULL,check_id TEXT NOT NULL,
          sequence INTEGER NOT NULL,seen INTEGER NOT NULL,ok INTEGER NOT NULL,
          envelope TEXT NOT NULL,UNIQUE(agent_id,sequence))""")
        db.execute("""CREATE TABLE IF NOT EXISTS sentinel_real_checks (
          check_id TEXT PRIMARY KEY,agent_id TEXT NOT NULL,last_sequence INTEGER NOT NULL,
          failures INTEGER NOT NULL,recoveries INTEGER NOT NULL,
          last_failed INTEGER,updated INTEGER NOT NULL)""")
        db.execute("""CREATE TABLE IF NOT EXISTS sentinel_real_incidents (
          id TEXT PRIMARY KEY,customer_id TEXT NOT NULL,site_id TEXT NOT NULL,
          agent_id TEXT NOT NULL,check_id TEXT NOT NULL,domain TEXT NOT NULL,
          opened INTEGER NOT NULL,state TEXT NOT NULL,
          resolved INTEGER,title TEXT NOT NULL,
          CHECK(state IN ('open','resolved')))""")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_real_one_active_check ON sentinel_real_incidents(check_id) WHERE state='open'")
        db.execute("CREATE INDEX IF NOT EXISTS idx_real_meas_check ON sentinel_real_measurements(check_id,seen)")


def ingest_signed_measurement(store,envelope,public_keys,targets,now=None):
    when=int(time.time() if now is None else now)
    c=verify_agent_measurement(envelope,public_keys,targets,now=when)
    with store.db() as db:
        db.execute("BEGIN IMMEDIATE")
        check=db.execute("""SELECT c.id,c.domain,c.site_id,c.customer_id,a.address,
             g.revoked,g.site_id agent_site,g.customer_id agent_customer
             FROM checks c JOIN assets a ON a.id=c.asset_id
             JOIN agents g ON g.id=?
             WHERE c.id=?""",(c["agent_id"],c["check_id"])).fetchone()
        if not check or check["revoked"]!=0 or any((
            check["site_id"]!=c["site_id"],
            check["customer_id"]!=c["customer_id"],
            check["agent_site"]!=c["site_id"],
            check["agent_customer"]!=c["customer_id"],
            check["address"]!=c["target_ip"])):
            raise PermissionError("Edge key not tied to active trusted inventory")
        prior=db.execute("SELECT * FROM sentinel_real_checks WHERE check_id=?",
                         (c["check_id"],)).fetchone()
        if prior and prior["agent_id"]!=c["agent_id"]:
            raise PermissionError("Unexpected observer change: reenrollment required")
        if c["sequence"]!=(prior["last_sequence"]+1 if prior else 1):
            raise ValueError("Missing or duplicate signed observation sequence")
        data=json.dumps(envelope,sort_keys=True,separators=(",",":"))
        db.execute("""INSERT INTO sentinel_real_measurements
           VALUES(?,?,?,?,?,?,?,?,?)""",
           (c["receipt_id"],c["customer_id"],c["site_id"],c["agent_id"],
            c["check_id"],c["sequence"],c["observed_at"],int(c["ok"]),data))
        failures=0 if c["ok"] else (prior["failures"]+1 if prior else 1)
        recoveries=(prior["recoveries"]+1 if prior else 1) if c["ok"] else 0
        last_failed=prior["last_failed"] if prior else None
        active=db.execute("SELECT id FROM sentinel_real_incidents WHERE check_id=? AND state='open'",
                          (c["check_id"],)).fetchone()
        incident_id=active["id"] if active else None
        if not c["ok"] and failures>=2 and last_failed is not None and (
            c["observed_at"]-last_failed>=MIN_FAILURE_GAP) and not active:
            planned=db.execute("""SELECT 1 FROM maintenance_windows
                WHERE site_id=? AND customer_id=? AND starts<=? AND ends>? LIMIT 1""",
                (c["site_id"],c["customer_id"],when,when)).fetchone()
            if not planned:
                incident_id=str(uuid4())
                db.execute("""INSERT INTO sentinel_real_incidents VALUES
                    (?,?,?,?,?,?,?,'open',NULL,?)""",
                  (incident_id,c["customer_id"],c["site_id"],c["agent_id"],
                   c["check_id"],check["domain"],last_failed,
                   "Verified signed Edge failure: "+check["domain"]))
        elif c["ok"] and recoveries>=2 and active:
            db.execute("UPDATE sentinel_real_incidents SET state='resolved',resolved=? WHERE id=?",
                       (c["observed_at"],incident_id))
        db.execute("""INSERT INTO sentinel_real_checks
            (check_id,agent_id,last_sequence,failures,recoveries,last_failed,updated)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(check_id) DO UPDATE SET
             last_sequence=excluded.last_sequence,failures=excluded.failures,
             recoveries=excluded.recoveries,last_failed=excluded.last_failed,
             updated=excluded.updated""",
          (c["check_id"],c["agent_id"],c["sequence"],failures,recoveries,
           c["observed_at"] if not c["ok"] else last_failed,when))
    return {"accepted":True,"incident_id":incident_id,
            "status":"resolved" if c["ok"] and recoveries>=2 and active else
                     "open" if incident_id else "observed"}


def independently_verified_incident(store,incident_id,public_keys,targets,now=None):
    when=int(time.time() if now is None else now)
    with store.db() as db:
        incident=db.execute("SELECT * FROM sentinel_real_incidents WHERE id=? AND state='open'",
                            (incident_id,)).fetchone()
        if not incident or when-incident["opened"]>WINDOW:return False
        rows=db.execute("""SELECT envelope,ok,seen FROM sentinel_real_measurements
             WHERE check_id=? AND agent_id=? AND seen>=? AND seen<=?
             ORDER BY sequence DESC LIMIT 50""",
             (incident["check_id"],incident["agent_id"],when-WINDOW,when)).fetchall()
        agent=db.execute("SELECT revoked FROM agents WHERE id=?",(incident["agent_id"],)).fetchone()
        if not agent or agent["revoked"]:return False
    receipts=[]
    for row in rows:
        try:c=verify_agent_measurement(json.loads(row["envelope"]),public_keys,targets,now=when)
        except (ValueError,TypeError,PermissionError):return False
        if c["customer_id"]!=incident["customer_id"] or c["site_id"]!=incident["site_id"] or (
            c["agent_id"]!=incident["agent_id"]) or c["check_id"]!=incident["check_id"] or (
            c["observed_at"]!=row["seen"]) or int(c["ok"])!=row["ok"]:
            return False
        if not c["ok"]:receipts.append(c)
    return any(
        a["sequence"]<b["sequence"] and
        b["observed_at"]-a["observed_at"]>=MIN_FAILURE_GAP
        for a in receipts for b in receipts)
