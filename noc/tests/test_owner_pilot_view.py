"""Owner-pilot view contract security tests with private fixture files."""
import json
from pathlib import Path
import tempfile
import time
import unittest
from datetime import datetime,timezone

from noc.owner_pilot_status import snapshot

class OwnerPilotViewTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix="owner-pilot-view-")
  self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name)/"private"
  self.root.mkdir(mode=0o700)
  self.now=int(time.time())
  self.pilot={"scope":"V79_DIGITAL_OWN_NETWORK_PILOT","collected_at":self.now,
    "queued_readings":0,"checks":[
      {"ip":ip,"port":port,"ok":True,"latency_ms":2} for ip,port in [
      ("192.168.100.1",53),("192.168.100.1",80),("192.168.100.163",22),
      ("192.168.100.163",80),("192.168.100.163",443)]]}
  self.save("last-observation.json",self.pilot)
  self.save("app-checks-latest.json",{"captured_at":datetime.now(timezone.utc).isoformat(),
          "results":[{"app":"Hub","status":200,"tls_verified":True,"category":"reachable"}]})
  self.save("certificate-health.json",{
    "checked_at":datetime.now(timezone.utc).isoformat(),"scope":"OWNER_LAN_PILOT_ONLY",
    "client_hours_remaining":20,"server_hours_remaining":20,"ca_hours_remaining":400})
 def save(self,name,data):
  file=self.root/name
  file.write_text(json.dumps(data))
  file.chmod(0o600)
 def test_fresh_pilot_and_certificate_human_readable(self):
  result=snapshot(self.root,now=self.now)
  self.assertTrue(result["data_current"])
  self.assertEqual(len(result["approved_checks"]),5)
  self.assertEqual(result["connectivity_status"],"all_approved_tcp_checks_connected")
  self.assertEqual(result["cert_status"],"valid_time_remaining")
  self.assertEqual(result["applications"][0]["app"],"Hub")
  self.assertTrue(result["no_customer_ticket_creation"])
 def test_stale_pilot_never_claims_healthy(self):
  self.pilot["collected_at"]=self.now-3600
  self.save("last-observation.json",self.pilot)
  result=snapshot(self.root,now=self.now)
  self.assertFalse(result["data_current"])
  self.assertEqual(result["connectivity_status"],"stale_do_not_assume_healthy")
 def test_unapproved_asset_refused(self):
  self.pilot["checks"][0]["ip"]="192.168.100.146"
  self.save("last-observation.json",self.pilot)
  with self.assertRaises(PermissionError):snapshot(self.root,now=self.now)
 def test_unknown_app_and_world_readable_file_refused(self):
  f=self.root/"app-checks-latest.json"
  f.chmod(0o644)
  with self.assertRaises(PermissionError):snapshot(self.root,now=self.now)
  f.chmod(0o600)
  self.save(f.name,{"captured_at":datetime.now(timezone.utc).isoformat(),
                    "results":[{"app":"Bad App","status":200}]})
  with self.assertRaises(PermissionError):snapshot(self.root,now=self.now)
 def test_symlink_evidence_refused(self):
  (self.root/"last-observation.json").unlink()
  (self.root/"last-observation.json").symlink_to(self.root/"certificate-health.json")
  with self.assertRaises(PermissionError):snapshot(self.root,now=self.now)

if __name__=="__main__":unittest.main()
