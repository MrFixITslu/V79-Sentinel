"""Sentinel Edge simulator: outbound-only, SIMULATED telemetry with offline queue.

Not a real network probe or device discovery tool. Future remote transport MUST
use HTTPS; plain HTTP is only permitted to an explicitly loopback-bound lab.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import ipaddress
import json
from pathlib import Path
import sqlite3
from urllib import request, error
from urllib.parse import urlsplit
from .store import checked_string, timestamp

QUEUE_LIMIT=1000
MAX_BATCH=32

def allowed_endpoint(endpoint):
    url=urlsplit(endpoint)
    if url.username or url.password or url.fragment or url.query or url.path.rstrip("/") not in ("","/api/v1/agent/telemetry"):
        raise ValueError("Invalid telemetry endpoint")
    if url.scheme=="https" and url.hostname and url.port in (None,443):
        return endpoint.rstrip("/")
    if url.scheme=="http" and url.hostname:
        try: loopback=ipaddress.ip_address(url.hostname).is_loopback
        except ValueError: loopback=False
        if loopback and url.port in (8788,None):
            return endpoint.rstrip("/")
    raise ValueError("Agents require HTTPS except explicitly local loopback testing")

class OfflineQueue:
    def __init__(self,path):
        self.path=Path(path)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self.path.touch(mode=0o600,exist_ok=True)
        self.path.chmod(0o600)
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS pending (
                    sequence INTEGER PRIMARY KEY, payload TEXT NOT NULL, created INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS state (
                    id INTEGER PRIMARY KEY CHECK(id=1), next_seq INTEGER NOT NULL);
                INSERT OR IGNORE INTO state(id,next_seq) VALUES(1,1);
            """)

    @contextmanager
    def connection(self):
        db=sqlite3.connect(str(self.path),timeout=8)
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def enqueue(self,readings):
        if not isinstance(readings,list) or not 1<=len(readings)<=MAX_BATCH:
            raise ValueError("Only 1-32 explicitly configured simulated readings per batch")
        clean=[]
        seen=set()
        for r in readings:
            if not isinstance(r,dict) or set(r)-{"check_id","ok","latency","note"}:
                raise ValueError("Invalid reading")
            cid=checked_string(r.get("check_id"),"check ID",50)
            if cid in seen: raise ValueError("Repeated check ID in batch")
            seen.add(cid)
            if type(r.get("ok")) is not bool: raise ValueError("Status must be boolean")
            latency=r.get("latency")
            if latency is not None and (type(latency) not in (float,int) or not 0<=latency<=60000):
                raise ValueError("Invalid latency")
            note=r.get("note","SIMULATED")
            if not isinstance(note,str) or len(note)>160 or any(ord(ch)<32 for ch in note):
                raise ValueError("Invalid note")
            clean.append({"check_id":cid,"ok":r["ok"],"latency":latency,"note":note})
        with self.connection() as db:
            count=db.execute("SELECT count(*) FROM pending").fetchone()[0]
            if count>=QUEUE_LIMIT: raise RuntimeError("Offline queue full: stop collecting, preserve existing observations")
            seq=db.execute("SELECT next_seq FROM state WHERE id=1").fetchone()[0]
            payload=json.dumps({"sequence":seq,"readings":clean},separators=(",",":"))
            db.execute("INSERT INTO pending VALUES(?,?,?)",(seq,payload,timestamp()))
            db.execute("UPDATE state SET next_seq=? WHERE id=1",(seq+1,))
        return seq

    def pending(self):
        with self.connection() as db:
            return db.execute("SELECT sequence,payload FROM pending ORDER BY sequence").fetchall()

    def confirm(self,sequence):
        with self.connection() as db:
            db.execute("DELETE FROM pending WHERE sequence=?",(sequence,))

    def size(self):
        with self.connection() as db:
            return db.execute("SELECT count(*) FROM pending").fetchone()[0]

def post_event(endpoint,credential,payload,timeout=3):
    endpoint=allowed_endpoint(endpoint)
    full=endpoint if endpoint.endswith("/api/v1/agent/telemetry") else endpoint+"/api/v1/agent/telemetry"
    body=payload.encode()
    req=request.Request(full,body,method="POST",headers={
        "Content-Type":"application/json",
        "Authorization":"Bearer "+credential,
        "User-Agent":"V79-Sentinel-Edge-Simulator/0.1"})
    # A redirect must never forward an Edge credential to another host.
    # urllib's default opener automatically follows redirects.
    class NoRedirect(request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):
            return None
    opener=request.build_opener(NoRedirect())
    # TLS verification is performed by urllib's default certificate context.
    with opener.open(req,timeout=timeout) as response:
        if response.status!=200:raise RuntimeError("Unexpected ingestion status")
        result=json.load(response)
    if result.get("status") not in ("accepted","duplicate"):
        raise RuntimeError("Unexpected acknowledgement")
    return result

def heartbeat(endpoint,credential,timeout=3):
    """Authenticate an agent without inventing a device health observation."""
    endpoint=allowed_endpoint(endpoint)
    if not isinstance(credential,str) or not credential.startswith("sea_") or len(credential)>128:
        raise ValueError("Invalid agent credential")
    base=endpoint[:-len("/api/v1/agent/telemetry")] if endpoint.endswith(
        "/api/v1/agent/telemetry") else endpoint
    target=base+"/api/v1/agent/heartbeat"
    req=request.Request(target,b"",method="POST",headers={
        "Authorization":"Bearer "+credential,
        "User-Agent":"V79-Sentinel-Edge-Simulator/0.2"})
    class NoRedirect(request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):
            return None
    with request.build_opener(NoRedirect()).open(req,timeout=timeout) as response:
        if response.status!=200:raise RuntimeError("Unexpected heartbeat status")
        data=json.load(response)
    if data.get("status")!="online" or type(data.get("sequence")) is not int:
        raise RuntimeError("Unexpected heartbeat response")
    return data

def flush(queue,endpoint,credential,max_events=100):
    allowed_endpoint(endpoint)
    if not isinstance(credential,str) or not credential.startswith("sea_") or len(credential)>128:
        raise ValueError("Invalid agent credential")
    sent=0
    for seq,payload in queue.pending()[:max_events]:
        try: ack=post_event(endpoint,credential,payload)
        except error.HTTPError as exc:
            raise RuntimeError(f"Edge telemetry rejected by server (HTTP {exc.code}); queue retained") from None
        except (error.URLError,TimeoutError,OSError):
            break  # offline: preserve every queued observation
        if type(ack.get("sequence")) is not int or ack["sequence"]!=seq:
            raise RuntimeError("Sequence acknowledgement mismatch; queue retained")
        if ack["status"]=="accepted" and ack.get("accepted")!=len(json.loads(payload)["readings"]):
            raise RuntimeError("Observation count mismatch; queue retained")
        queue.confirm(seq)
        sent+=1
    return {"sent":sent,"remaining":queue.size()}

def read_private_config(file):
    f=Path(file)
    if f.stat().st_mode&0o077:
        raise PermissionError("Agent enrollment file must be owner-only")
    cfg=json.loads(f.read_text())
    if set(cfg)!={"endpoint","credential","check_ids"} or not isinstance(cfg["check_ids"],list):
        raise ValueError("Invalid simulator config")
    allowed_endpoint(cfg["endpoint"])
    for check in cfg["check_ids"]:checked_string(check,"check ID",50)
    return cfg

def main():
    p=argparse.ArgumentParser(description="SIMULATED Sentinel Edge Agent only")
    p.add_argument("--config",required=True,help="Owner-only private enrollment file")
    p.add_argument("--queue",required=True,help="Owner-only offline SQLite queue")
    modes=p.add_mutually_exclusive_group(required=True)
    modes.add_argument("--state",choices=("ok","fault"),help="Generate simulated observations")
    modes.add_argument("--heartbeat",action="store_true",help="Agent connectivity only, no device claims")
    p.add_argument("--offline",action="store_true",help="Queue without network transport")
    args=p.parse_args()
    cfg=read_private_config(args.config)
    q=OfflineQueue(args.queue)
    if args.heartbeat:
        if args.offline:
            print(json.dumps({"state":"offline_simulated","queued":q.size()}))
        else:
            print(json.dumps({"state":"agent_heartbeat",**heartbeat(cfg["endpoint"],cfg["credential"])}))
        return
    readings=[{"check_id":c,"ok":args.state=="ok","latency":18 if args.state=="ok" else None,
               "note":"SIMULATED "+args.state.upper()} for c in cfg["check_ids"]]
    seq=q.enqueue(readings)
    if args.offline:
        print(json.dumps({"queued_sequence":seq,"remaining":q.size(),"state":"offline_simulated"}))
    else:
        print(json.dumps({"queued_sequence":seq,**flush(q,cfg["endpoint"],cfg["credential"])}))

if __name__=="__main__":main()
