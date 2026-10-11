"""Owner-authorized Dell-only local signed probe; never sends tickets."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
from uuid import uuid4

from cryptography.hazmat.primitives import serialization

from .sentinel_approval_issuer import load_private_signer
from .sentinel_agent_sampler import tcp_probe, queue_signed_reading, acknowledge_signed_reading
from .sentinel_real_edge import initialize, ingest_signed_measurement
from .store import NocStore

OWNER = "dda6ced3-5718-4a0b-b58b-fc0f8aa3f7da"
SITE = "568bc468-f5b0-4b6e-9cd7-fd2efd8aea7b"
HOST = "192.168.100.163"
PORT = 443
ASSET = "V79 Dell signed pilot"
CHECK = "Dell HTTPS TCP 443 signed"
AGENT = "Acer signed Dell edge probe"
HOME = Path.home() / ".config/v79-sentinel/dell-signed-pilot"
SECRET = HOME / "observer-ed25519.pem"
PUBLIC = HOME / "observer-ed25519.pub"
CONFIG = HOME / "pilot-config.json"
JOURNAL = HOME / "signed-queue.sqlite3"
DB = Path.home() / "V79-Sentinel/sentinel/data/noc-staging.sqlite3"


def key_info():
    if HOME.is_symlink() or stat.S_IMODE(HOME.stat().st_mode) != 0o700:
        raise PermissionError("Pilot key folder must be owner-only 0700")
    for p in (SECRET, PUBLIC):
        m = p.stat()
        if p.is_symlink() or m.st_uid != os.geteuid() or stat.S_IMODE(m.st_mode) != 0o600:
            raise PermissionError("Signing key files must be owned by current user and 0600")
    signer = load_private_signer(SECRET)
    public = signer.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    if public != PUBLIC.read_bytes():
        raise PermissionError("Public/private observer identity mismatch")
    return signer, hashlib.sha256(public).hexdigest()


def preflight():
    _, fingerprint = key_info()
    with sqlite3.connect("file:" + str(DB) + "?mode=ro", uri=True) as db:
        row = db.execute("SELECT customer_id FROM sites WHERE id=?", (SITE,)).fetchone()
        if not row or row[0] != OWNER:
            raise PermissionError("Site does not belong to V79 Digital")
        for table, name in (("assets", ASSET), ("agents", AGENT)):
            found = db.execute("SELECT COUNT(*) FROM " + table + " WHERE site_id=? AND name=?",
                               (SITE, name)).fetchone()[0]
            if found:
                raise PermissionError("Pilot asset/agent already exists: investigate before provisioning")
    return fingerprint


def install():
    if CONFIG.exists():
        raise FileExistsError("Pilot already configured; no key recreation or reprovisioning")
    fp = preflight()
    asset_id, check_id, agent_id = (str(uuid4()) for _ in range(3))
    cfg = {"customer_id": OWNER, "site_id": SITE, "asset_id": asset_id,
           "check_id": check_id, "agent_id": agent_id,
           "target_ip": HOST, "target_port": PORT, "public_fingerprint": fp}
    fd = os.open(CONFIG, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, separators=(",", ":"))
        f.flush()
        os.fsync(f.fileno())
    store = NocStore(DB)
    try:
        with store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO assets VALUES(?,?,?,?,?,?)",
                       (asset_id, OWNER, SITE, ASSET, HOST, "server"))
            db.execute("INSERT INTO checks(id,customer_id,site_id,asset_id,label,domain) "
                       "VALUES(?,?,?,?,?,?)",
                       (check_id, OWNER, SITE, asset_id, CHECK, "v79-dell-https"))
            token_digest = hashlib.sha256(secrets.token_bytes(48)).hexdigest()
            db.execute("INSERT INTO agents VALUES(?,?,?,?,?,0,NULL,0)",
                       (agent_id, OWNER, SITE, AGENT, token_digest))
            for kind, ident in (("asset.created", asset_id), ("check.created", check_id),
                                ("agent.enrolled", agent_id)):
                store.audit(db, "owner-signed-pilot", kind, ident)
        initialize(store)
    except BaseException:
        # Do not leave a config that authorizes an incomplete enrollment.
        CONFIG.unlink(missing_ok=True)
        raise
    print("DELL_SIGNED_PILOT_ENROLLED=YES")
    print("PILOT_AGENT=" + agent_id)
    print("PILOT_CHECK=" + check_id)
    print("TARGET=192.168.100.163:443")
    print("SIGNER_FINGERPRINT=" + fp[:16])
    print("TIQUET_DISPATCH=DISABLED")


def load_config():
    _, fp = key_info()
    if (CONFIG.is_symlink() or not stat.S_ISREG(CONFIG.stat().st_mode) or
        CONFIG.stat().st_uid != os.geteuid() or
        stat.S_IMODE(CONFIG.stat().st_mode) != 0o600):
        raise PermissionError("Pilot config must be a 0600 regular file")
    c = json.loads(CONFIG.read_text())
    if c.get("customer_id") != OWNER or c.get("site_id") != SITE or (
        c.get("target_ip") != HOST or c.get("target_port") != PORT or
        c.get("public_fingerprint") != fp):
        raise PermissionError("Pilot mapping or signing identity changed")
    with sqlite3.connect("file:" + str(DB) + "?mode=ro", uri=True) as db:
        row = db.execute("""SELECT a.revoked,ch.customer_id,ch.site_id,ast.address
              FROM agents a JOIN checks ch ON ch.id=?
              JOIN assets ast ON ast.id=ch.asset_id WHERE a.id=?""",
              (c["check_id"], c["agent_id"])).fetchone()
        if not row or tuple(row) != (0, OWNER, SITE, HOST):
            raise PermissionError("Pilot agent disabled or DB mapping changed")
    return c


def sample():
    c = load_config()
    policy = {"ip": HOST, "port": PORT, "customer_id": OWNER, "site_id": SITE,
              "agent_id": c["agent_id"], "check_id": c["check_id"]}
    signer, _ = key_info()
    healthy = tcp_probe(policy, timeout=2)
    envelope = queue_signed_reading(JOURNAL, policy, signer, healthy)
    store = NocStore(DB)
    trusted = {c["agent_id"]: PUBLIC.read_text()}
    mapping = {c["check_id"]: {k: v for k, v in policy.items() if k != "check_id"}}
    try:
        result = ingest_signed_measurement(store, envelope, trusted, mapping)
    except ValueError:
        # Recover a crash after DB commit but before sender acknowledgement,
        # only when the persisted signed envelope is byte-for-byte identical.
        old = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
        with store.db() as db:
            prior = db.execute("SELECT envelope FROM sentinel_real_measurements WHERE "
                               "receipt_id=? AND agent_id=?",
                               (envelope["claims"]["receipt_id"], c["agent_id"])).fetchone()
        if not prior or prior["envelope"] != old:
            raise
        result = {"accepted": True, "status": "observed"}
    if result.get("accepted") is not True:
        raise RuntimeError("Signed observation not accepted")
    acknowledge_signed_reading(JOURNAL, c["agent_id"],
        envelope["claims"]["receipt_id"],
        {"accepted": True, "status": result["status"]})
    print("SIGNED_DELL_HTTPS_PROBE=" + ("UP" if healthy else "DOWN"))
    print("SENTINEL_CORRELATION=" + result["status"])
    print("SIGNED_SEQUENCE=" + str(envelope["claims"]["sequence"]))
    print("LIVE_TICKET_DISPATCH=DISABLED")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    m = ap.add_mutually_exclusive_group(required=True)
    m.add_argument("--preflight", action="store_true")
    m.add_argument("--install", action="store_true")
    m.add_argument("--once", action="store_true")
    args = ap.parse_args()
    if args.preflight:
        print("PILOT_PREFLIGHT=PASS " + preflight()[:16])
    elif args.install:
        install()
    else:
        sample()
