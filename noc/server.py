"""Provider-only NOC staging web/API service: localhost, zero Hub integrations."""
from __future__ import annotations
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import time
from urllib.parse import urlsplit
from .store import NocStore, checked_string, new_id, timestamp
from .security import hash_password, valid_password, accepted_totp_counter, hash_recovery_code
from .operators import (list_operators, create_operator, disable_operator,
                        mfa_status, mfa_begin, mfa_confirm)
from .owner_pilot_status import PILOT_ROOT, snapshot as owner_pilot_snapshot
from .sentinel_review_config import load_review_config
from .sentinel_real_ticket_review import build_real_ticket,review_real_and_queue
from .sentinel_real_edge import (initialize as initialize_real_edge,
                                 ingest_signed_measurement)
from .sentinel_approval_issuer import load_private_signer
from .sentinel_reviewer_status import currently_authorized_reviewer
from .sentinel_approver_machine_service import load_machine_secret,validate_machine_signature
from .sentinel_mission_bridge import snapshot as mission_control_snapshot
from .sentinel_mission_full import read_only_resource as mission_full_resource
from .sentinel_netpulse_interfaces import sample_host_interfaces
from .sentinel_network_lab import inventory as network_inventory, capabilities as network_capabilities, diagnostic as network_diagnostic

ROOT=Path(__file__).resolve().parent
DEFAULT_DB=ROOT.parent/"data"/"noc-staging.sqlite3"
MAX_BODY=32768
SESSION_SECONDS=8*3600
def csv_cell(value):
    """Prevent values supplied by customers/operators becoming spreadsheet formulas."""
    text="" if value is None else str(value)
    text=text.replace("\r"," ").replace("\n"," ").replace("\t"," ")
    if text.lstrip().startswith(("=","+","-","@")):
        return "'"+text
    return text

def incident_csv(store):
    """A bounded, operator-only mock incident export (maximum 5000 records)."""
    columns=("id","customer","site","title","severity","state","opened",
             "acknowledged","resolved","domain","related_checks")
    out=io.StringIO(newline="")
    writer=csv.writer(out,quoting=csv.QUOTE_ALL,lineterminator="\r\n")
    writer.writerow(("DATA_TYPE","SIMULATED_SENTINEL_INCIDENTS","NOT_SLA_VERIFIED"))
    writer.writerow(columns)
    for record in store.incident_report_rows():
        values=[]
        for key in columns:
            value=record[key]
            if key in ("opened","acknowledged","resolved") and value is not None:
                value=datetime.fromtimestamp(value,timezone.utc).isoformat(timespec="seconds")
            values.append(csv_cell(value))
        writer.writerow(values)
    return out.getvalue()

def bootstrap(store,username,password):
    username=checked_string(username,"operator username",80).lower()
    if not isinstance(password,str) or len(password)<18: raise ValueError("Password must be at least 18 characters")
    with store.db() as c:
        if c.execute("SELECT 1 FROM operators LIMIT 1").fetchone():
            raise ValueError("An operator exists: use the planned password-rotation workflow")
        c.execute("""INSERT INTO operators(id,username,password_hash,role)
                     VALUES(?,?,?,'admin')""",
                  (new_id(),username,hash_password(password)))
    return username

class NocAPI(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,bind,port,db,pilot_root=PILOT_ROOT):
        super().__init__((bind,port),NocHandler)
        self.store=NocStore(db)
        self.pilot_root=Path(pilot_root)
        self.attempts={}
        self.ticket_review_config=None
        self.review_attempts={}
        if os.environ.get("SENTINEL_REVIEW_ENABLED")=="1":
            location=os.environ.get("SENTINEL_REVIEW_CONFIG_PATH")
            if not location:
                raise RuntimeError("Approved Sentinel review configuration missing")
            self.ticket_review_config=load_review_config(location)
            initialize_real_edge(self.store)
        self.approver_machine_secret=None
        if os.environ.get("SENTINEL_APPROVER_SERVICE_ENABLED")=="1":
            if self.ticket_review_config is None:
                raise RuntimeError("Current approver service requires enabled, configured review")
            self.approver_machine_secret=load_machine_secret(
                os.environ.get("SENTINEL_APPROVER_SERVICE_SECRET_FILE",""))
        self.external_origin=os.environ.get('SENTINEL_NOC_EXTERNAL_ORIGIN','').rstrip('/')

class NocHandler(BaseHTTPRequestHandler):
    server: NocAPI
    def log_message(self,*args):
        # Avoid writing cookies, tokens, incident notes or telemetry into logs.
        pass

    def send(self,code,data,mime="application/json; charset=utf-8",headers=None,embed_within_noc=False):
        if isinstance(data,(dict,list)): payload=json.dumps(data,separators=(",",":")).encode()
        elif isinstance(data,str): payload=data.encode()
        else: payload=data
        self.send_response(code)
        for k,v in {
            "Content-Type":mime,"Content-Length":str(len(payload)),
            "Cache-Control":"no-store","X-Content-Type-Options":"nosniff",
            "X-Frame-Options":"SAMEORIGIN" if embed_within_noc else "DENY",
            "Referrer-Policy":"no-referrer",
            "Content-Security-Policy":("default-src 'self'; script-src 'self'; style-src 'self'; "
                                       "connect-src 'self'; img-src 'self'; object-src 'none'; "
                                       "frame-ancestors "+("'self'" if embed_within_noc else "'none'")+"; base-uri 'none'"),
            "Permissions-Policy":"camera=(), microphone=(), geolocation=()",
        }.items(): self.send_header(k,v)
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers()
        try: self.wfile.write(payload)
        except (BrokenPipeError,ConnectionResetError): pass

    def error(self,code,label):
        self.send(code,{"error":label})

    def body(self):
        length=self.headers.get("Content-Length","0")
        if not length.isdigit() or not 0<int(length)<=MAX_BODY:
            raise ValueError("Invalid request body size")
        if self.headers.get("Content-Type","").split(";")[0]!="application/json":
            raise ValueError("JSON content type required")
        obj=json.loads(self.rfile.read(int(length)))
        if not isinstance(obj,dict): raise ValueError("JSON object required")
        return obj

    def origin_ok(self):
        origin=self.headers.get("Origin","")
        local=f"http://127.0.0.1:{self.server.server_port}"
        return origin==local or bool(self.server.external_origin and origin==self.server.external_origin)

    def current(self):
        jar=cookies.SimpleCookie()
        try: jar.load(self.headers.get("Cookie",""))
        except cookies.CookieError: return None
        raw=jar.get("sentinel_noc")
        if not raw or len(raw.value)!=64: return None
        digest=hashlib.sha256(raw.value.encode()).hexdigest()
        with self.server.store.db() as c:
            entry=c.execute("""SELECT op.id,op.username,op.role,s.csrf,s.expires FROM sessions s
                               JOIN operators op ON op.id=s.operator_id
                               WHERE s.digest=? AND op.disabled=0""",(digest,)).fetchone()
            if not entry or entry["expires"]<=timestamp(): return None
            return dict(entry)

    def authorized(self,mutate=False):
        actor=self.current()
        if not actor:
            self.error(401,"Operator sign-in required")
            return None
        if mutate and (not self.origin_ok() or not secrets.compare_digest(
                self.headers.get("X-Sentinel-CSRF",""),actor["csrf"])):
            self.error(403,"Invalid mutation origin or CSRF token")
            return None
        return actor

    def do_GET(self):
        path=urlsplit(self.path).path
        try:
            if path=="/healthz":
                return self.send(200,"ok\n","text/plain; charset=utf-8")
            if path=="/readyz":
                with self.server.store.db() as c: c.execute("SELECT 1").fetchone()
                return self.send(200,{"ready":True,"collector":"simulated-only",
                                      "integrations":"disabled"})
            if path in ("/","/index.html","/app.js","/mission-native.js","/mission-native.css","/style.css","/enterprise-center.js","/enterprise-center.css","/netpulse-model.js"):
                file={" /":"", "/": "index.html","/index.html":"index.html",
                      "/app.js":"app.js","/mission-native.js":"mission-native.js",
                      "/mission-native.css":"mission-native.css","/style.css":"style.css",
                      "/enterprise-center.js":"enterprise-center.js","/enterprise-center.css":"enterprise-center.css",
                      "/netpulse-model.js":"netpulse-model.js"}.get(path)
                mime=("text/javascript" if path.endswith(".js") else
                      "text/css" if path.endswith(".css") else "text/html")+"; charset=utf-8"
                return self.send(200,(ROOT/"web"/file).read_bytes(),mime)
            if path.startswith("/mission-control"):
                actor=self.authorized()
                if not actor:return
                try:
                    data,mime,embedded=mission_full_resource(path)
                    return self.send(200,data,mime,embed_within_noc=embedded)
                except ValueError:
                    return self.error(404,"Mission Control resource not found")
                except (OSError,TimeoutError):
                    return self.error(503,"Mission Control monitoring service unavailable")
            if path in ("/api/v1/network/inventory","/api/v1/network/capabilities"):
                actor=self.authorized()
                if not actor:return
                try:return self.send(200,network_inventory() if path.endswith("/inventory") else network_capabilities())
                except (OSError,ValueError,subprocess.SubprocessError):return self.error(503,"Network observation source unavailable")
            if path=="/api/v1/netpulse/interfaces":
                actor=self.authorized()
                if not actor:return
                try:return self.send(200,sample_host_interfaces())
                except (OSError,ValueError):return self.error(503,"Local NIC counters unavailable")
            if path=="/api/v1/session":
                actor=self.authorized()
                if not actor:return
                return self.send(200,{"username":actor["username"],"role":actor["role"],"csrf":actor["csrf"]})
            if path=="/api/v1/operators":
                actor=self.authorized()
                if not actor:return
                if actor["role"]!="admin":return self.error(403,"Administrator role required")
                return self.send(200,{"operators":list_operators(self.server.store)})
            if path=="/api/v1/mfa/status":
                actor=self.authorized()
                if not actor:return
                return self.send(200,mfa_status(self.server.store,actor["id"]))
            if path=="/api/v1/sentinel/reviews":
                actor=self.authorized()
                if not actor:return
                if actor["role"]!="admin":return self.error(403,"Administrator required")
                config=self.server.ticket_review_config
                if config is None:
                    return self.send(200,{"enabled":False,"proposals":[],"dispatch":"disabled"})
                owner=config["mapping"]["sentinel_customer_id"]
                proposals=[]
                with self.server.store.db() as db:
                    ids=[row["id"] for row in db.execute(
                        "SELECT id FROM sentinel_real_incidents WHERE customer_id=? AND state='open' ORDER BY opened DESC LIMIT 30",
                        (owner,))]
                for incident_id in ids:
                    try:
                        event=build_real_ticket(self.server.store,incident_id,
                             config["mapping"],config["observer_public_keys"],
                             config["approved_targets"])
                        proposals.append({"incident_id":incident_id,
                          "title":event["incident"]["title"],
                          "site":event["impact"]["site_name"],
                          "detected_at":event["incident"]["detected_at"],
                          "severity":event["incident"]["severity"]})
                    except (PermissionError,ValueError,TypeError):
                        continue
                return self.send(200,{"enabled":True,
                    "proposals":proposals,"dispatch":"offline_review_only"})
            if path=="/api/v1/mission-control":
                actor=self.authorized()
                if not actor:return
                try:
                    return self.send(200,mission_control_snapshot())
                except (OSError,ValueError,TypeError,KeyError,TimeoutError):
                    return self.error(503,"Local Mission Control summary unavailable")
            if path=="/api/v1/dashboard":
                actor=self.authorized()
                if not actor:return
                return self.send(200,self.server.store.snapshot())
            if path=="/api/v1/owner-pilot":
                actor=self.authorized()
                if not actor:return
                if actor["role"]!="admin":
                    return self.error(403,"Provider administrator role required")
                try:
                    return self.send(200,owner_pilot_snapshot(self.server.pilot_root))
                except (OSError,PermissionError,ValueError,TypeError):
                    return self.error(503,"Owner pilot evidence temporarily unavailable")
            if path=="/api/v1/reports/incidents.csv":
                actor=self.authorized()
                if not actor:return
                return self.send(200,incident_csv(self.server.store),
                                 "text/csv; charset=utf-8",headers={
                                     "Content-Disposition":"attachment; filename=sentinel-simulated-incidents.csv"})
            return self.error(404,"Not found")
        except (OSError,sqlite3.Error):
            return self.error(503,"NOC service temporarily unavailable")

    def do_POST(self):
        path=urlsplit(self.path).path
        try:
            if path in ("/api/v1/agent/telemetry","/api/v1/agent/heartbeat"):
                header=self.headers.get("Authorization","")
                if not header.startswith("Bearer "):return self.error(401,"Agent credential required")
                if path=="/api/v1/agent/heartbeat":
                    return self.send(200,self.server.store.heartbeat(header[7:]))
                data=self.body()
                return self.send(200,self.server.store.ingest(header[7:],data))
            if path=="/api/v1/sentinel/service/approver/check":
                secret=self.server.approver_machine_secret
                if secret is None:return self.error(404,"Not found")
                if self.client_address[0] not in ("127.0.0.1","::1"):
                    return self.error(403,"Private service access only")
                size=self.headers.get("Content-Length","")
                if (not size.isdigit() or not 1<=int(size)<=4096 or
                    self.headers.get("Transfer-Encoding") or
                    self.headers.get("Content-Type","").split(";")[0]!="application/json"):
                    return self.error(400,"Invalid service request")
                raw=self.rfile.read(int(size))
                if not validate_machine_signature(self.headers,raw,secret):
                    return self.error(401,"Invalid service identity")
                query=json.loads(raw)
                allowed=currently_authorized_reviewer(self.server.store,query,
                    self.server.ticket_review_config["mapping"])
                return self.send(200,{"allowed":allowed,
                    "validForSeconds":5 if allowed else 0})
            if path=="/api/v1/sentinel/edge/observation":
                config=self.server.ticket_review_config
                if config is None:return self.error(404,"Not found")
                # First deployment mode is LOCAL LOOPBACK ONLY. External edge
                # transport must use a reviewed mTLS terminator/tunnel.
                if self.client_address[0] not in ("127.0.0.1","::1") or (
                    self.headers.get("Origin") or self.headers.get("Cookie") or
                    self.headers.get("Authorization")):
                    return self.error(403,"Signed service-only endpoint")
                signed=self.body()
                result=ingest_signed_measurement(
                    self.server.store,signed,config["observer_public_keys"],
                    config["approved_targets"])
                return self.send(200,result)
            if path=="/api/v1/network/diagnostic":
                actor=self.authorized(mutate=True)
                if not actor:return
                if actor["role"]!="admin":return self.error(403,"Administrator required for active diagnostics")
                try:return self.send(200,network_diagnostic(self.body()))
                except (OSError,ValueError,subprocess.SubprocessError):return self.error(400,"Diagnostic unavailable or invalid target; no broader network access attempted")
            if not self.origin_ok(): return self.error(403,"Invalid request origin")
            if path=="/api/v1/login":
                body=self.body()
                username=body.get("username","")
                password=body.get("password","")
                if not isinstance(username,str) or not isinstance(password,str) or len(password)>1024:
                    return self.error(400,"Invalid credentials")
                username=username.strip().lower()
                count,until=self.server.attempts.get(username,(0,0))
                if until>timestamp() and count>=8:return self.error(429,"Please try again later")
                with self.server.store.db() as c:
                    operator=c.execute("SELECT * FROM operators WHERE username=? AND disabled=0",(username,)).fetchone()
                    if not operator or not valid_password(password,operator["password_hash"]):
                        self.server.attempts[username]=(count+1 if until>timestamp() else 1,timestamp()+900)
                        return self.error(401,"Invalid credentials")
                    if operator["mfa_secret"]:
                        counter=accepted_totp_counter(operator["mfa_secret"],body.get("otp"),
                                                       last=operator["mfa_last_counter"])
                        recovery_hash=hash_recovery_code(body.get("recovery_code"))
                        if counter is not None:
                            # Last accepted counter persists, preventing OTP replay.
                            c.execute("UPDATE operators SET mfa_last_counter=? WHERE id=?",
                                      (counter,operator["id"]))
                        elif recovery_hash is not None:
                            # A recovery code is single-use; consume atomically with session issue.
                            used=c.execute("""UPDATE mfa_recovery_codes SET used_at=?
                                WHERE code_hash=? AND operator_id=? AND used_at IS NULL""",
                                (timestamp(),recovery_hash,operator["id"])).rowcount
                            if used!=1:
                                self.server.attempts[username]=(count+1 if until>timestamp() else 1,timestamp()+900)
                                return self.error(401,"MFA verification required or code invalid")
                        else:
                            self.server.attempts[username]=(count+1 if until>timestamp() else 1,timestamp()+900)
                            return self.error(401,"MFA verification required or code invalid")
                    self.server.attempts.pop(username,None)
                    token=secrets.token_hex(32)
                    csrf=secrets.token_urlsafe(24)
                    c.execute("DELETE FROM sessions WHERE expires<?",(timestamp(),))
                    c.execute("INSERT INTO sessions VALUES(?,?,?,?)",
                              (hashlib.sha256(token.encode()).hexdigest(),operator["id"],csrf,
                               timestamp()+SESSION_SECONDS))
                secure=("; Secure" if self.server.external_origin.startswith("https://") and
                        self.headers.get("Origin")==self.server.external_origin else "")
                cookie=f"sentinel_noc={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}{secure}"
                return self.send(200,{"signed_in":True},headers={"Set-Cookie":cookie})
            actor=self.authorized(mutate=True)
            if not actor:return
            if path=="/api/v1/logout":
                jar=cookies.SimpleCookie()
                jar.load(self.headers.get("Cookie",""))
                tok=jar.get("sentinel_noc")
                if tok:
                    with self.server.store.db() as c:
                        c.execute("DELETE FROM sessions WHERE digest=?",
                                  (hashlib.sha256(tok.value.encode()).hexdigest(),))
                return self.send(200,{"signed_out":True},headers={
                    "Set-Cookie":"sentinel_noc=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
            body=self.body()
            store=self.server.store
            if path=="/api/v1/mfa/start":
                return self.send(200,mfa_begin(store,actor["id"],body.get("password")))
            if path=="/api/v1/mfa/confirm":
                result=mfa_confirm(store,actor["id"],body.get("code"))
                return self.send(200,result,headers={
                    "Set-Cookie":"sentinel_noc=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
            if path=="/api/v1/sentinel/approve":
                if actor["role"]!="admin":return self.error(403,"Administrator required")
                config=self.server.ticket_review_config
                if config is None:return self.error(503,"Supervised review not configured")
                if set(body)!={"incident_id","otp","confirmed"} or (
                    body.get("confirmed") is not True):
                    return self.error(400,"Explicit incident approval required")
                now=timestamp()
                count,window=self.server.review_attempts.get(actor["id"],(0,now+900))
                if now>=window:count,window=0,now+900
                if count>=5:return self.error(429,"Review attempts temporarily limited")
                # Count every try, even before cryptographic validation.
                self.server.review_attempts[actor["id"]]=(count+1,window)
                try:
                    signer=load_private_signer(config["signing_key_path"])
                    result=review_real_and_queue(self.server.store,actor["id"],body.get("otp"),
                        body.get("incident_id"),config["mapping"],
                        config["observer_public_keys"],config["approved_targets"],signer,
                        config["signing_key_id"],confirmed=True)
                    self.server.review_attempts.pop(actor["id"],None)
                    return self.send(201,result)
                except (PermissionError,ValueError,TypeError,sqlite3.Error,OSError):
                    return self.error(403,"Review evidence, MFA or signer unavailable")
            if path=="/api/v1/incidents/ack":
                if actor["role"] not in ("admin","operator"):
                    return self.error(403,"Technician or administrator role required")
                store.acknowledge(body.get("incident_id"),actor["id"])
                return self.send(200,{"acknowledged":True})
            if actor["role"]!="admin":return self.error(403,"Administrator role required")
            if path=="/api/v1/operators":
                return self.send(201,create_operator(
                    store,actor["id"],body.get("current_password"),
                    body.get("username"),body.get("password"),body.get("role")))
            if path=="/api/v1/operators/disable":
                disable_operator(store,actor["id"],body.get("current_password"),
                                 body.get("operator_id"))
                return self.send(200,{"disabled":True})
            if path=="/api/v1/customers":
                return self.send(201,{"id":store.customer(body.get("name"))})
            if path=="/api/v1/sites":
                return self.send(201,{"id":store.site(body.get("customer_id"),body.get("name"))})
            if path=="/api/v1/assets":
                return self.send(201,{"id":store.asset(body.get("site_id"),body.get("name"),
                                                      body.get("address"),body.get("type","router"))})
            if path=="/api/v1/checks":
                return self.send(201,{"id":store.check(body.get("asset_id"),body.get("label"),
                                                      body.get("domain"))})
            if path=="/api/v1/maintenance":
                return self.send(201,store.maintenance(body.get("site_id"),
                                                      body.get("reason"),body.get("hours",1)))
            if path=="/api/v1/agents/enroll":
                return self.send(201,store.enroll(body.get("site_id"),body.get("name")))
            if path=="/api/v1/agents/revoke":
                store.revoke(body.get("agent_id"))
                return self.send(200,{"revoked":True})
            return self.error(404,"Not found")
        except PermissionError:
            return self.error(403,"Unauthorized site/agent operation")
        except (ValueError,TypeError,json.JSONDecodeError):
            return self.error(400,"Invalid or unsupported request")
        except sqlite3.IntegrityError:
            return self.error(409,"Record already exists")
        except (OSError,sqlite3.Error):
            return self.error(503,"NOC storage temporarily unavailable")

def main():
    p=argparse.ArgumentParser(description="Sentinel isolated operator NOC staging")
    p.add_argument("--db",default=str(DEFAULT_DB))
    p.add_argument("--port",type=int,default=8788)
    p.add_argument("--bind",default="127.0.0.1")
    p.add_argument("--bootstrap-operator",help="Only for a brand-new database")
    p.add_argument("--bootstrap-password-file",help="Read locally, never print password")
    args=p.parse_args()
    if not ipaddress.ip_address(args.bind).is_loopback:
        p.error("NOC staging must remain bound to loopback")
    store=NocStore(args.db)
    if args.bootstrap_operator:
        if not args.bootstrap_password_file:p.error("Operator bootstrap requires private password file")
        private=Path(args.bootstrap_password_file)
        if private.stat().st_mode & 0o077:p.error("Password file must not be group/world accessible")
        user=bootstrap(store,args.bootstrap_operator,private.read_text().strip())
        print("Created standalone operator: "+user)
        return
    with store.db() as c:
        if not c.execute("SELECT 1 FROM operators LIMIT 1").fetchone():
            p.error("Refusing to serve NOC without initialized operator credentials")
    server=NocAPI(args.bind,args.port,args.db)
    mode=("signed owner-incident review; no live ticket dispatch" if server.ticket_review_config
          else "simulated incident console; review disabled")
    print(f"NOC staging ready on http://{args.bind}:{args.port} ({mode})",flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt:pass
    finally: server.server_close()

if __name__=="__main__":
    main()
