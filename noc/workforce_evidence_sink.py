"""Source-bound signed Sentinel aggregates; no raw status-page ingestion."""
import hashlib,json,os,sqlite3,stat,time,uuid
from pathlib import Path
from urllib.request import Request,build_opener,HTTPRedirectHandler
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PUBLISHER="v79-sentinel-probe-v1"
URL="http://172.25.0.1:8765/internal/evidence"
def canonical(value):return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None

def private(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or s.st_nlink!=1 or s.st_mode&0o077 or s.st_size>1024:raise ValueError("Private credential unavailable")
  return os.read(fd,1025)
 finally:os.close(fd)

def aggregate(receipt):
 if not isinstance(receipt,dict) or receipt.get("mode")!="IN_PROCESS_PROBE_CANDIDATE_ONLY":raise ValueError("In-process receipt required")
 r=receipt.get("report",{});rows=r.get("services")
 if r.get("mode")!="live" or r.get("error") is not None or type(r.get("cycle")) is not int or r["cycle"]<1 or not isinstance(rows,list) or not 1<=len(rows)<=20:raise ValueError("Live complete probe cycle required")
 counts={"servicesObserved":len(rows),"up":0,"down":0,"degraded":0,"unknown":0}
 for row in rows:
  key={"up":"up","down":"down","warning":"degraded"}.get(row.get("status"))
  if not key:raise ValueError("Unknown service reading")
  counts[key]+=1
 return counts

class EvidenceSink:
 def __init__(self,*,state,key,token,send=None):
  self.state=Path(state);self.key=key;self.token=token;self.send=send or self._send
  self.state.mkdir(mode=0o700,parents=True,exist_ok=True)
  s=self.state.lstat()
  if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o077 or self.state.resolve()!=self.state:raise ValueError("Protected sender directory required")
  self.path=self.state/"sender.sqlite"
  fd=os.open(self.path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);s=os.fstat(fd);os.close(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.geteuid() or s.st_mode&0o077:raise ValueError("Protected sender store required")
  with self.connect() as c:c.executescript("CREATE TABLE IF NOT EXISTS counter(id INTEGER PRIMARY KEY CHECK(id=1),value INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS outbox(sequence INTEGER PRIMARY KEY,id TEXT UNIQUE NOT NULL,expires REAL NOT NULL,body BLOB NOT NULL);")
 def connect(self):
  c=sqlite3.connect(self.path,timeout=3);c.execute("PRAGMA synchronous=FULL");return c
 def _send(self,envelope):
  req=Request(URL,data=canonical(envelope),method="POST",headers={"content-type":"application/json","x-v79-gateway-internal":self.token})
  with build_opener(NoRedirect()).open(req,timeout=3) as response:
   data=json.loads(response.read(1024))
   if response.status!=200 or data!={"accepted":True,"id":envelope["record"]["id"]}:raise ValueError("Receiver acknowledgement invalid")
 def __call__(self,receipt,now=None):
  from datetime import datetime,timezone
  clock=time.time() if now is None else now
  counts=aggregate(receipt);observed=receipt["report"]["last_check"]
  epoch=datetime.fromisoformat(observed.replace("Z","+00:00")).timestamp()
  if not clock-600<=epoch<=clock+120:raise ValueError("Stale probe cycle")
  with self.connect() as c:
   c.execute("BEGIN IMMEDIATE")
   row=c.execute("SELECT value FROM counter WHERE id=1").fetchone();sequence=(row[0] if row else 0)+1
   if not 1<=sequence<2**53:raise ValueError("Sequence exhausted")
   record={"version":1,"id":str(uuid.uuid4()),"publisher":PUBLISHER,"sequence":sequence,"target":"sentinel","category":"service_health","observedAt":observed,"expiresAt":datetime.fromtimestamp(epoch+900,timezone.utc).isoformat(),"provenance":"sentinel_inprocess_probe","status":"PASS" if counts["up"]==counts["servicesObserved"] else "FAIL","measurements":counts,"sourceRef":hashlib.sha256(canonical({"observedAt":observed,"counts":counts})).hexdigest()}
   envelope={"record":record,"signature":self.key.sign(canonical(record)).hex()}
   c.execute("DELETE FROM outbox WHERE expires<=?",(clock,))
   if c.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]>=32:raise ValueError("Signed outbox full")
   c.execute("INSERT OR REPLACE INTO counter VALUES(1,?)",(sequence,))
   c.execute("INSERT INTO outbox VALUES(?,?,?,?)",(sequence,record["id"],epoch+900,canonical(envelope)))
  # Retry the newest observation. An acknowledged newer sequence safely
  # supersedes an older unacknowledged report after a lost response.
  with self.connect() as c:pending=c.execute("SELECT sequence,body FROM outbox ORDER BY sequence DESC LIMIT 1").fetchone()
  self.send(json.loads(pending[1]))
  with self.connect() as c:c.execute("DELETE FROM outbox WHERE sequence<=?",(pending[0],))
  return {"accepted":True,"sequence":sequence}
def configured_sink():
 if os.environ.get("V79_SENTINEL_SIGNED_EVIDENCE")!="1":return None
 return EvidenceSink(state="/run/sentinel-evidence",key=Ed25519PrivateKey.from_private_bytes(private("/run/secrets/sentinel-signing.key")),token=private("/run/secrets/sentinel-ingest.token").decode().strip())
