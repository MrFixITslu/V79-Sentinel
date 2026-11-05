#!/usr/bin/env python3
"""Independent Acer sequence witness. Private key never leaves this host."""
import hashlib,json,os,sqlite3,subprocess,time,uuid
from pathlib import Path
from datetime import datetime,timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
def canonical(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()
def stamp(now):return datetime.fromtimestamp(now,timezone.utc).isoformat()
def evaluate(envelope,pin,previous,previous_hash,now):
 try:
  r=envelope["record"];digest=hashlib.sha256(canonical(envelope)).hexdigest()
  Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin)).verify(bytes.fromhex(envelope["signature"]),canonical(r))
  if r["publisher"]!="v79-sentinel-probe-v1" or r["target"]!="sentinel" or r["category"]!="service_health" or r["provenance"]!="sentinel_inprocess_probe" or type(r["sequence"]) is not int or not 1<=r["sequence"]<2**53:raise ValueError()
  seq=r["sequence"];observed=datetime.fromisoformat(r["observedAt"].replace("Z","+00:00")).timestamp();expires=datetime.fromisoformat(r["expiresAt"].replace("Z","+00:00")).timestamp()
  if seq<previous or (seq==previous and previous_hash and digest!=previous_hash):return "FAIL",{"sourceSequence":seq,"sourceAgeSeconds":max(0,now-observed),"rollbackDetected":True,"sourceValid":True},digest
  if not now-900<observed<=now+120 or not observed<expires<=observed+900 or expires<=now:raise ValueError()
  return "PASS",{"sourceSequence":seq,"sourceAgeSeconds":max(0,now-observed),"rollbackDetected":False,"sourceValid":True},digest
 except Exception:return "UNKNOWN",{"sourceSequence":previous,"sourceAgeSeconds":0,"rollbackDetected":False,"sourceValid":False},hashlib.sha256(b"unavailable-source").hexdigest()
def ssh(code,body=None):
 # No credential or arbitrary command comes from an evidence record.
 args=["ssh","-o","BatchMode=yes","-o","ConnectTimeout=6","firelion@192.168.100.163","python3 -c "+__import__("shlex").quote(code)]
 r=subprocess.run(args,input=body,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=18)
 if r.returncode or len(r.stdout)>16384:raise RuntimeError("Witness transport unavailable")
 return json.loads(r.stdout)
FETCH='import urllib.request,json;from pathlib import Path;t=Path("/home/firelion/.v79-evidence-gateway-runtime-20261105/secrets/gateway-ingest.token").read_text().strip();r=urllib.request.urlopen(urllib.request.Request("http://172.25.0.1:8765/internal/sentinel",headers={"x-v79-gateway-internal":t}),timeout=5);print(r.read(16384).decode())'
PUBLISH='import urllib.request,sys;from pathlib import Path;t=Path("/home/firelion/.v79-evidence-gateway-runtime-20261105/secrets/gateway-ingest.token").read_text().strip();b=sys.stdin.buffer.read(16385);assert len(b)<=16384;r=urllib.request.urlopen(urllib.request.Request("http://172.25.0.1:8765/internal/evidence",data=b,headers={"x-v79-gateway-internal":t,"content-type":"application/json"},method="POST"),timeout=5);print(r.read(1024).decode())'
def main():
 import fcntl,sys
 os.umask(0o077);root=Path(sys.argv[1]);cfg=json.loads((root/"config.json").read_text())
 with (root/"worker.lock").open("a") as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if not (root/"witness.sqlite").is_file():raise RuntimeError("Independent checkpoint missing; owner reenrolment required")
  c=sqlite3.connect(root/"witness.sqlite");c.execute("PRAGMA synchronous=FULL");c.execute("CREATE TABLE IF NOT EXISTS checkpoint(id INTEGER PRIMARY KEY,source_sequence INTEGER,source_hash TEXT,witness_sequence INTEGER)")
  row=c.execute("SELECT source_sequence,source_hash,witness_sequence FROM checkpoint WHERE id=1").fetchone() or (0,"",0)
  try:source=ssh(FETCH).get("envelope")
  except Exception:source=None
  now=time.time();status,m,digest=evaluate(source,cfg["sourcePublicKey"],row[0],row[1],now)
  # Anchor the highest accepted source sequence; never lower it after rollback.
  with c:c.execute("INSERT OR REPLACE INTO checkpoint VALUES(1,?,?,?)",(m["sourceSequence"] if status=="PASS" else row[0],digest if status=="PASS" else row[1],row[2]+1))
  record={"version":1,"id":str(uuid.uuid4()),"publisher":"v79-acer-sentinel-witness-v1","sequence":row[2]+1,"target":"sentinel","category":"sentinel_witness","observedAt":stamp(now),"expiresAt":stamp(now+180),"provenance":"independent_sequence_witness","status":status,"measurements":m,"sourceRef":digest}
  key=Ed25519PrivateKey.from_private_bytes((root/"witness.key").read_bytes());envelope={"record":record,"signature":key.sign(canonical(record)).hex()}
  result=ssh(PUBLISH,canonical(envelope));assert result=={"accepted":True,"id":record["id"]}
  receipt={"status":status,"sourceSequence":m["sourceSequence"],"sourceAgeSeconds":m["sourceAgeSeconds"],"rollbackDetected":m["rollbackDetected"],"publishedAt":record["observedAt"],"expiresAt":record["expiresAt"]}
  tmp=root/"status.tmp";tmp.write_text(json.dumps(receipt));os.replace(tmp,root/"status.json");print(json.dumps(receipt))
if __name__=="__main__":main()
