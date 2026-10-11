"""Verify V79 owner pilot readiness projection never confuses basic reachability with app readiness."""
from datetime import datetime,timezone,timedelta
import json
from pathlib import Path
import tempfile
import time
import unittest

from noc.owner_pilot_status import APP_ENDPOINTS,ALLOWED_TARGETS,snapshot

class ServiceReadinessProjectionTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix="noc-semantic-readiness-")
  self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name)/"owner-only"
  self.root.mkdir(mode=0o700)
  self.now=int(time.time())
  self.write("last-observation.json",{
    "scope":"V79_DIGITAL_OWN_NETWORK_PILOT","collected_at":self.now,
    "queued_readings":0,
    "checks":[{"ip":ip,"port":port,"ok":True,"latency_ms":2.0}
              for ip,port in sorted(ALLOWED_TARGETS)]})
  self.write("app-checks-latest.json",{
    "captured_at":datetime.fromtimestamp(self.now,timezone.utc).isoformat(),
    "results":[{"app":name,"status":200,"tls_verified":True,"category":"reachable"}
              for name in APP_ENDPOINTS]})
  self.good={"schema_version":1,
             "scope":"approved_V79_public_readiness_get_only",
             "captured_at":datetime.fromtimestamp(self.now,timezone.utc).isoformat(),
             "results":[{"app":name,"hostname":host,"path":path,
                         "status":401 if name=="POS" else 200,"tls_verified":True,
                         "reason":"authentication_required" if name=="POS" else "expected_response_verified",
                         "readiness":"protected" if name=="POS" else "ready"}
                        for name,(host,path) in APP_ENDPOINTS.items()]}
  self.write("service-readiness-latest.json",self.good)
 def write(self,name,body):
  p=self.root/name
  p.write_text(json.dumps(body))
  p.chmod(0o600)
 def test_distinguishes_200_homepage_from_semantic_ready(self):
  result=snapshot(self.root,now=self.now)
  self.assertTrue(result["service_readiness_current"])
  self.assertEqual(result["service_readiness_summary"],
       {"ready":7,"protected":1,"failed":0,"unverified":0})
  pos=next(x for x in result["applications"] if x["app"]=="POS")
  self.assertEqual(pos["http_status"],200)
  self.assertEqual(pos["service_http_status"],401)
  self.assertEqual(pos["service_readiness"],"protected")
 def test_stale_deep_readiness_does_not_fake_healthy(self):
  self.good["captured_at"]=(datetime.fromtimestamp(self.now,timezone.utc)-timedelta(hours=2)).isoformat()
  self.write("service-readiness-latest.json",self.good)
  result=snapshot(self.root,now=self.now)
  self.assertFalse(result["service_readiness_current"])
  self.assertEqual(result["service_readiness_summary"]["unverified"],8)
  self.assertTrue(all(x["service_readiness"]=="unverified" for x in result["applications"]))
 def test_missing_deep_evidence_all_unverified(self):
  (self.root/"service-readiness-latest.json").unlink()
  result=snapshot(self.root,now=self.now)
  self.assertFalse(result["service_readiness_current"])
  self.assertEqual(result["service_readiness_summary"]["ready"],0)
 def test_false_ready_claim_rejected(self):
  self.good["results"][0]["tls_verified"]=False
  self.write("service-readiness-latest.json",self.good)
  with self.assertRaises(PermissionError):snapshot(self.root,now=self.now)
 def test_cross_hostname_or_unknown_path_rejected(self):
  self.good["results"][1]["path"]="/admin"
  self.write("service-readiness-latest.json",self.good)
  with self.assertRaises(PermissionError):snapshot(self.root,now=self.now)
 def test_malformed_or_world_readable_evidence_rejected(self):
  p=self.root/"service-readiness-latest.json"
  p.chmod(0o644)
  with self.assertRaises(PermissionError):snapshot(self.root,now=self.now)
  p.chmod(0o600)
  self.good["results"]=self.good["results"][:-1]
  self.write(p.name,self.good)
  with self.assertRaises(ValueError):snapshot(self.root,now=self.now)

if __name__=="__main__":
 unittest.main()
