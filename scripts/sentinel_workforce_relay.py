#!/usr/bin/env python3
"""Owner alert proposals only. No approval, execution, email or customer writes."""
import fcntl,hashlib,json,os,sqlite3,time
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
PUBLISHER="v79-sentinel-probe-v1"
FIELDS={"servicesObserved","up","down","degraded","unknown"}
def canonical(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
def request(url,token,body=None,worker=False):
 headers={"accept":"application/json","x-v79-workforce-token" if worker else "x-v79-gateway-internal":token}
 if body is not None:headers["content-type"]="application/json"
 req=Request(url,data=canonical(body) if body is not None else None,headers=headers,method="POST" if body is not None else "GET")
 with build_opener(NoRedirect()).open(req,timeout=6) as r:
  data=r.read(16385)
  if len(data)>16384:raise ValueError("Bounded response required")
  return r.status,json.loads(data)
def signal(envelope,pin,now):
 try:
  r=envelope["record"]
  Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin)).verify(bytes.fromhex(envelope["signature"]),canonical(r))
  if r["publisher"]!=PUBLISHER or r["target"]!="sentinel" or r["category"]!="service_health" or r["provenance"]!="sentinel_inprocess_probe":raise ValueError()
  observed=datetime.fromisoformat(r["observedAt"].replace("Z","+00:00")).timestamp();expires=datetime.fromisoformat(r["expiresAt"].replace("Z","+00:00")).timestamp()
  if not now-900<observed<=now+120 or not observed<expires<=observed+900 or expires<=now:return "STALE",{}
  m=r["measurements"]
  if not isinstance(m,dict) or set(m)!=FIELDS or not all(type(v) is int and 0<=v<=20 for v in m.values()) or not 1<=m["servicesObserved"]<=20 or m["servicesObserved"]!=sum(m[k] for k in ("up","down","degraded","unknown")):raise ValueError()
  state="UNKNOWN" if m["unknown"] else "PASS" if m["up"]==m["servicesObserved"] else "FAIL"
  if r["status"]!=state:raise ValueError()
  return state,m
 except Exception:return "UNKNOWN",{}
def transition(c,state,counts,now,post,identity):
 c.execute("CREATE TABLE IF NOT EXISTS cooldown(id INTEGER PRIMARY KEY,last REAL)")
 c.execute("BEGIN IMMEDIATE")
 row=c.execute("SELECT state,episode,body,job FROM status WHERE id=1").fetchone()
 previous,episode,body,job=row if row else ("STARTING",None,None,None)
 # Escalating a stale stream is a distinct alert from a known service issue.
 changed=state!=previous
 last_alert=c.execute("SELECT last FROM cooldown WHERE id=1").fetchone()
 if state!="PASS" and not episode and (not last_alert or now-last_alert[0]>=1800):
  episode=hashlib.sha256((identity+":"+str(now)).encode()).hexdigest()[:32]
  detail=("Sentinel signed aggregate requires owner review. Status "+state+". "+
    ("Observed "+str(counts["servicesObserved"])+"; up "+str(counts["up"])+"; down "+str(counts["down"])+"; degraded "+str(counts["degraded"])+". " if counts else "No current authenticated source observation is available. ")+
    "These are source-reported HTTPS reachability observations, not independent security certification. Review current evidence before action; repairs require separate approval.")
  body=json.dumps({"operation":"create_work_item","system":"sentinel","summary":"Sentinel monitoring alert: "+state,"payload":{"detail":detail},"idempotencyKey":"sentinel_"+episode},sort_keys=True)
  job=None
  c.execute("INSERT OR REPLACE INTO cooldown VALUES(1,?)",(now,))
 if state=="PASS":episode=body=job=None
 c.execute("INSERT OR REPLACE INTO status VALUES(1,?,?,?,?,?)",(state,episode,body,job,now));c.commit()
 if body and not job:
  result=post(json.loads(body))
  if result.get("job",{}).get("status") not in ("pending","approved","rejected","cancelled","succeeded"):raise ValueError("Owner proposal not confirmed")
  job=result["job"]["id"]
  with c:c.execute("UPDATE status SET job=? WHERE id=1 AND episode=?",(job,episode))
 return {"status":state,"observedCounts":counts,"proposalId":job,"ownerApprovalRequired":True,"automaticRepairs":False}
def main():
 import sys
 cfg=json.loads(Path(sys.argv[1]).read_text());root=Path(cfg["state"]);root.mkdir(mode=0o700,parents=True,exist_ok=True)
 with (root/"relay.lock").open("a") as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  c=sqlite3.connect(root/"relay.sqlite");os.chmod(root/"relay.sqlite",0o600);c.execute("PRAGMA synchronous=FULL")
  c.execute("CREATE TABLE IF NOT EXISTS status(id INTEGER PRIMARY KEY,state TEXT,episode TEXT,body TEXT,job TEXT,updated REAL)")
  try:
   _,payload=request("http://172.25.0.1:8765/internal/sentinel",Path(cfg["gatewayTokenFile"]).read_text().strip())
   state,counts=signal(payload.get("envelope"),cfg["publicKey"],time.time())
  except Exception:state,counts="UNKNOWN",{}
  def post(body):
   status,result=request("https://hub.v79sl.com/internal/workforce/propose",Path(cfg["workerTokenFile"]).read_text().strip(),body,True)
   if status!=201:raise ValueError("Proposal unavailable")
   return result
  result=transition(c,state,counts,time.time(),post,PUBLISHER);result["checkedAt"]=datetime.now().astimezone().isoformat()
  temp=root/"status.tmp";temp.write_text(json.dumps(result,sort_keys=True));os.chmod(temp,0o600);os.replace(temp,root/"status.json")
  print(json.dumps({"sourceStatus":state,"ownerProposal":bool(result["proposalId"]),"automaticRepairs":False}))
if __name__=="__main__":main()
