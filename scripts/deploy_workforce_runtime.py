#!/usr/bin/env python3
"""Guarded monitor/Gateway image-only activation with explicit signer mounts."""
import re,hashlib,copy,fcntl,http.client,json,os,socket,subprocess,sys,time
from pathlib import Path
ROOT=Path("/home/firelion/.v79-sentinel-runtime-20261105")
class UnixHTTP(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.connect("/var/run/docker.sock")
def api(method,path,body=None):
 c=UnixHTTP("localhost",timeout=30);data=json.dumps(body).encode() if body is not None else None
 c.request(method,"/v1.47"+path,data,{"Content-Type":"application/json"});r=c.getresponse();raw=r.read();status=r.status;c.close()
 if status>=300:raise RuntimeError("Docker operation rejected: "+str(status))
 return json.loads(raw) if raw else {}
def inspect(name):return api("GET","/containers/"+name+"/json")
def health(name):
 d=inspect(name);return d["State"]["Running"] and d["State"].get("Health",{}).get("Status")=="healthy"
def wait(name):
 for _ in range(30):
  if health(name):return
  time.sleep(2)
 raise RuntimeError("Candidate health unavailable")
def stable(d):return {k:(v["Image"],v["Id"]) for k,v in d.items()}
def main():
 os.umask(0o077);role=sys.argv[1];image=sys.argv[2]
 if role not in ("gateway","monitor") or not image.startswith("sha256:"):raise ValueError("Pinned image and role required")
 receipt=json.loads((ROOT/"offhost-recovery-verified.json").read_text())
 if receipt.get("restoreVerified") is not True or receipt.get("signerPublicKeyMatched") is not True or receipt.get("archiveSha256")!=hashlib.sha256((ROOT/"sentinel-checkpoint.tar.gz.gpg").read_bytes()).hexdigest():raise RuntimeError("Verified offhost checkpoint required")
 with (ROOT/"cutover.lock").open("a") as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  protected={n:inspect(n) for n in ["v79-hub","v79-tiquet-manager","v79-business-agent","v79-sentinel-dell-noc","v79-sentinel-dell-ingress",("v79-sentinel-dell-monitor" if role=="gateway" else "v79-evidence-gateway")]}
  if not all(x["State"]["Running"] and x["State"].get("Health",{}).get("Status")=="healthy" for x in protected.values()):raise RuntimeError("Protected baseline not healthy")
  pressure=float(Path("/proc/pressure/io").read_text().splitlines()[1].split()[1].split("=")[1])
  if pressure>10:raise RuntimeError("I/O pressure exceeds guard")
  name="v79-evidence-gateway" if role=="gateway" else "v79-sentinel-dell-monitor"
  old=inspect(name);expected=json.loads((ROOT/"baseline.json").read_text())[name]
  if old["Image"]!=expected or not health(name):raise RuntimeError("Live baseline changed")
  cfg=copy.deepcopy(old["Config"]);host=copy.deepcopy(old["HostConfig"]);cfg["Image"]=image
  extra=[]
  if role=="monitor":
   # The monitor inherits the NOC network namespace hostname; Docker refuses an explicit hostname with container networking.
   cfg["Hostname"]=""
   cfg["Env"]=[e for e in cfg["Env"] if not e.startswith("V79_SENTINEL_SIGNED_EVIDENCE=")]+["V79_SENTINEL_SIGNED_EVIDENCE=1"]
   extra=[{"Type":"bind","Source":str(ROOT/"signer/secrets/signing.key"),"Target":"/run/secrets/sentinel-signing.key","ReadOnly":True},{"Type":"bind","Source":str(ROOT/"signer/secrets/ingest.token"),"Target":"/run/secrets/sentinel-ingest.token","ReadOnly":True},{"Type":"bind","Source":str(ROOT/"signer/state"),"Target":"/run/sentinel-evidence","ReadOnly":False}]
   host["Mounts"]=[*host.get("Mounts",[]),*extra]
  body={**cfg,"HostConfig":host}
  if not host.get("NetworkMode","").startswith("container:"):
   body["NetworkingConfig"]={"EndpointsConfig":{n:{"Aliases":v.get("Aliases") or []} for n,v in old["NetworkSettings"]["Networks"].items()}}
  rollout=sys.argv[3] if len(sys.argv)>3 else "20261105"
  if not re.fullmatch(r"[a-z0-9-]{8,40}",rollout):raise ValueError("Invalid rollout identity")
  candidate=name+"-prepared-"+rollout;rollback=name+"-rollback-sentinel-"+rollout
  try:new=inspect(candidate)
  except RuntimeError:
   api("POST","/containers/create?name="+candidate,body);new=inspect(candidate)
  if new["Image"]!=image or new["State"]["Status"]!="created":raise RuntimeError("Unexpected prepared candidate")
  # Docker normalises unset OOM-disable to false; true is always refused.
  for k in set(host)|set(new["HostConfig"]):
   a,b=host.get(k),new["HostConfig"].get(k)
   if k=="Mounts":
    def norm(items):return [{**m,"ReadOnly":m.get("ReadOnly",False)} for m in (items or [])]
    a,b=norm(a),norm(b)
   if k=="OomKillDisable" and a in (None,False) and b in (None,False):continue
   if a!=b:raise RuntimeError("Candidate HostConfig differs: "+k)
  for k in ["Cmd","Entrypoint","User","WorkingDir","Healthcheck","Env","ExposedPorts","Labels","Volumes"]:
   if new["Config"].get(k)!=cfg.get(k):raise RuntimeError("Candidate config differs: "+k)
  expected_mounts={(m["Destination"],m["Source"],m["RW"]) for m in old["Mounts"]}
  expected_mounts|={(m["Target"],m["Source"],not m["ReadOnly"]) for m in extra}
  if {(m["Destination"],m["Source"],m["RW"]) for m in new["Mounts"]}!=expected_mounts:raise RuntimeError("Candidate mounts differ")
  (ROOT/(role+"-original-config.json")).write_text(json.dumps(old))
  renamed=False
  try:
   api("POST","/containers/"+name+"/stop?t=15");api("POST","/containers/"+name+"/rename?name="+rollback);renamed=True
   api("POST","/containers/"+candidate+"/rename?name="+name);api("POST","/containers/"+name+"/start");wait(name)
   after={n:inspect(n) for n in protected}
   if stable(protected)!=stable(after) or not all(health(n) for n in protected):raise RuntimeError("Protected service changed")
   result={"role":role,"image":image,"healthy":True,"protectedServicesPreserved":True,"rollback":rollback}
   (ROOT/(role+"-release.json")).write_text(json.dumps(result));print(json.dumps(result),flush=True)
  except Exception:
   if renamed:
    try:
     api("POST","/containers/"+name+"/stop?t=10");api("POST","/containers/"+name+"/rename?name="+name+"-failed-20261105")
    except Exception:pass
    api("POST","/containers/"+rollback+"/rename?name="+name);api("POST","/containers/"+name+"/start");wait(name)
   else:
    api("POST","/containers/"+name+"/start")
   raise
if __name__=="__main__":main()
