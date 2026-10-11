"""Disconnected first-party Edge TCP probe and Ed25519 observation producer.

Only an explicitly pinned target is probed when called. No scheduler,
enrollment keys or remote transmission are enabled by importing this module.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import time
import urllib.request
from uuid import uuid4
from ipaddress import ip_address

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .sentinel_real_edge import VERSION,canonical
from .sentinel_approval_issuer import load_private_signer


def _policy(policy):
    if not isinstance(policy,dict) or set(policy)!={
        "ip","port","customer_id","site_id","agent_id","check_id"}:
        raise ValueError("One explicitly approved check is required")
    try:
        addr=str(ip_address(policy["ip"]))
        from uuid import UUID
        ids=("customer_id","site_id","agent_id","check_id")
        if not all(str(UUID(policy[k]))==policy[k] for k in ids):
            raise ValueError()
    except (ValueError,TypeError,KeyError):
        raise ValueError("Invalid pinned Edge check identity")
    if not isinstance(policy["port"],int) or not 1<=policy["port"]<=65535:
        raise ValueError("Invalid pinned TCP port")
    return addr


def tcp_probe(policy,timeout=2):
    address=_policy(policy)
    if type(timeout) not in (float,int) or not .1<=timeout<=5:
        raise ValueError("Unbounded probe timeout")
    try:
        with socket.create_connection((address,policy["port"]),timeout=timeout):
            return True
    except (OSError,TimeoutError):
        return False


def sign_observation(policy,sequence,signer,ok,now=None):
    _policy(policy)
    if not isinstance(signer,Ed25519PrivateKey) or type(ok) is not bool or (
        type(sequence) is not int or sequence<1):
        raise ValueError("Dedicated Ed25519 signer and ordered reading required")
    when=int(time.time() if now is None else now)
    if when<1:raise ValueError("Invalid observation time")
    claims={"version":VERSION,"receipt_id":str(uuid4()),
        "customer_id":policy["customer_id"],"site_id":policy["site_id"],
        "agent_id":policy["agent_id"],"check_id":policy["check_id"],
        "sequence":sequence,"observed_at":when,"ok":ok,
        "target_ip":policy["ip"],"target_port":policy["port"],"probe_kind":"tcp"}
    return {"claims":claims,"signature":signer.sign(canonical(claims)).hex()}


def post_local_observation(envelope,enabled=False,endpoint="http://127.0.0.1:8788/api/v1/sentinel/edge/observation"):
    """Explicit local-only transport; never use unreviewed remote HTTP."""
    if enabled is not True:return {"status":"disabled"}
    if endpoint!="http://127.0.0.1:8788/api/v1/sentinel/edge/observation":
        raise PermissionError("Cannot publish a signed observation to an unapproved endpoint")
    body=json.dumps(envelope,separators=(",",":")).encode("utf8")
    if len(body)>4096:raise ValueError("Signed observation too large")
    request=urllib.request.Request(endpoint,data=body,method="POST",
        headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(request,timeout=4) as response:
        return json.loads(response.read(1024))


def queue_signed_reading(database_path,policy,signer,ok,now=None):
    """Persist one signed measurement until the trusted local intake acknowledges.

    If a prior observation is pending, return it unchanged and don't sample
    again. This prevents offline sequence gaps and changed-payload replays.
    """
    _policy(policy)
    p=Path(database_path)
    if p.is_symlink() or (p.exists() and p.stat().st_mode&0o077):
        raise PermissionError("Owner-only Edge queue required")
    if p.parent.is_symlink():raise PermissionError("Symlink Edge queue directory")
    p.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    with sqlite3.connect(p,timeout=5) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("""CREATE TABLE IF NOT EXISTS edge_pending (
            agent_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL,
            envelope TEXT NOT NULL, state TEXT NOT NULL
            CHECK(state IN ('pending','acked')))""")
        row=db.execute("SELECT * FROM edge_pending WHERE agent_id=?",(policy["agent_id"],)).fetchone()
        if row and row[3]=="pending":
            saved=json.loads(row[2])
            claims=saved["claims"]
            if (claims["check_id"],claims["target_ip"],claims["target_port"])!=(
                policy["check_id"],policy["ip"],policy["port"]):
                raise PermissionError("Cannot change target with an outstanding signed sample")
            return saved
        nxt=(row[1]+1 if row else 1)
        envelope=sign_observation(policy,nxt,signer,ok,now=now)
        body=json.dumps(envelope,sort_keys=True,separators=(",",":"))
        db.execute("""INSERT INTO edge_pending VALUES(?,?,?,'pending')
            ON CONFLICT(agent_id) DO UPDATE SET sequence=excluded.sequence,
            envelope=excluded.envelope,state='pending'""",
            (policy["agent_id"],nxt,body))
    p.chmod(0o600)
    return envelope


def acknowledge_signed_reading(database_path,agent_id,receipt_id,ack):
    """Caller supplies only trusted locally authenticated receiver response."""
    if not isinstance(ack,dict) or ack.get("accepted") is not True or (
        ack.get("status") not in ("observed","open","resolved")):
        raise ValueError("Receiver has not acknowledged the exact observation")
    with sqlite3.connect(database_path,timeout=5) as db:
        db.execute("BEGIN IMMEDIATE")
        row=db.execute("SELECT envelope,state FROM edge_pending WHERE agent_id=?",
                       (agent_id,)).fetchone()
        if not row or row[1]!="pending" or (
            json.loads(row[0])["claims"]["receipt_id"]!=receipt_id):
            raise ValueError("No matching pending signed observation")
        db.execute("UPDATE edge_pending SET state='acked' WHERE agent_id=?",(agent_id,))
    return True

def run_one_approved_probe(database_path,policy,signer_path,enabled=False):
    """Explicit, local-only, one-pass sampler; never schedules itself."""
    if enabled is not True:return {"status":"disabled"}
    signer=load_private_signer(signer_path)
    ok=tcp_probe(policy)
    envelope=queue_signed_reading(database_path,policy,signer,ok)
    result=post_local_observation(envelope,enabled=True)
    if result.get("accepted") is True:
        acknowledge_signed_reading(database_path,policy["agent_id"],
                                   envelope["claims"]["receipt_id"],result)
    return {"status":result.get("status","unacknowledged"),
            "sequence":envelope["claims"]["sequence"],
            "acknowledged":result.get("accepted") is True}
