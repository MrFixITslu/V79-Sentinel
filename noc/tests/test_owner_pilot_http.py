"""NOC owner-only pilot endpoint: RBAC, stale evidence, no data mutation."""
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
import time

from noc.server import NocAPI,bootstrap
from noc.store import NocStore
from noc.owner_pilot_status import ALLOWED_TARGETS

ADMIN_PASSWORD="synthetic-supervised-admin-password-only"
VIEW_PASSWORD="synthetic-readonly-view-password-only"

class OwnerPilotHttpTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix="owner-pilot-http-")
  self.addCleanup(self.tmp.cleanup)
  root=Path(self.tmp.name)
  self.pilot=root/"owner-evidence"
  self.pilot.mkdir(mode=0o700)
  self.db=root/"noc.sqlite3"
  store=NocStore(self.db)
  bootstrap(store,"noc-admin",ADMIN_PASSWORD)
  with store.db() as db:
   from noc.security import hash_password
   from noc.store import new_id
   db.execute("INSERT INTO operators(id,username,password_hash,role) VALUES(?,?,?,'viewer')",
             (new_id(),"readonly",hash_password(VIEW_PASSWORD)))
  self.stamp=int(time.time())
  readings=[{"ip":ip,"port":port,"ok":True,"latency_ms":1.5}
            for ip,port in sorted(ALLOWED_TARGETS)]
  self.evidence=self.pilot/"last-observation.json"
  self.evidence.write_text(json.dumps({"scope":"V79_DIGITAL_OWN_NETWORK_PILOT",
       "collected_at":self.stamp,"queued_readings":0,"checks":readings}))
  self.evidence.chmod(0o600)
  self.srv=NocAPI("127.0.0.1",0,self.db,pilot_root=self.pilot)
  self.thread=threading.Thread(target=self.srv.serve_forever,daemon=True)
  self.thread.start()
  self.addCleanup(lambda:(self.srv.shutdown(),self.srv.server_close(),self.thread.join(timeout=5)))
 def request(self,method,path,body=None,cookie=None):
  c=http.client.HTTPConnection("127.0.0.1",self.srv.server_port,timeout=5)
  headers={}
  if cookie:headers["Cookie"]=cookie
  if body is not None:
   headers["Origin"]=f"http://127.0.0.1:{self.srv.server_port}"
   headers["Content-Type"]="application/json"
   body=json.dumps(body)
  c.request(method,path,body=body,headers=headers)
  r=c.getresponse()
  data=r.read()
  out=(r.status,dict(r.getheaders()),json.loads(data) if r.getheader("Content-Type","").startswith("application/json") else data)
  c.close()
  return out
 def login(self,username,password):
  status,headers,_=self.request("POST","/api/v1/login",{"username":username,"password":password})
  self.assertEqual(status,200)
  return headers["Set-Cookie"].split(";")[0]
 def test_unauthenticated_and_viewer_cannot_read_owner_network(self):
  self.assertEqual(self.request("GET","/api/v1/owner-pilot")[0],401)
  cookie=self.login("readonly",VIEW_PASSWORD)
  self.assertEqual(self.request("GET","/api/v1/dashboard",cookie=cookie)[0],200)
  self.assertEqual(self.request("GET","/api/v1/owner-pilot",cookie=cookie)[0],403)
 def test_admin_live_snapshot_keeps_synthetic_dashboard_independent(self):
  cookie=self.login("noc-admin",ADMIN_PASSWORD)
  status,headers,data=self.request("GET","/api/v1/owner-pilot",cookie=cookie)
  self.assertEqual(status,200)
  self.assertIn("no-store",headers["Cache-Control"])
  self.assertEqual(data["mode"],"V79_OWNER_NETWORK_LIVE_READ_ONLY")
  self.assertEqual(len(data["approved_checks"]),5)
  self.assertTrue(data["data_current"])
  self.assertEqual(data["integrations"],"disabled")
  status,_,separate=self.request("GET","/api/v1/dashboard",cookie=cookie)
  self.assertEqual(status,200)
  self.assertTrue(separate["simulated"])
  self.assertEqual(separate["customers"],[])
 def test_corrupted_evidence_returns_503_but_valid_admin_session_remains(self):
  cookie=self.login("noc-admin",ADMIN_PASSWORD)
  self.evidence.write_text('{"bad":"file"}')
  self.assertEqual(self.request("GET","/api/v1/owner-pilot",cookie=cookie)[0],503)
  self.assertEqual(self.request("GET","/api/v1/session",cookie=cookie)[0],200)
  self.assertEqual(self.request("GET","/api/v1/dashboard",cookie=cookie)[0],200)
 def test_missing_evidence_returns_explicit_unavailable_not_simulated_health(self):
  cookie=self.login("noc-admin",ADMIN_PASSWORD)
  self.evidence.unlink()
  code,_,result=self.request("GET","/api/v1/owner-pilot",cookie=cookie)
  self.assertEqual(code,200)
  self.assertFalse(result["available"])
  self.assertFalse(result["data_current"])
  self.assertEqual(result["connectivity_status"],"no_pilot_observations")

if __name__=="__main__":unittest.main()
