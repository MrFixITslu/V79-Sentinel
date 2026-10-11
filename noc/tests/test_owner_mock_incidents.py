"""Mock-only incident projection security and lifecycle-display tests."""
import copy
from datetime import datetime,timezone,timedelta
import json
from pathlib import Path
import tempfile
import time
import unittest

from noc.owner_mock_incidents import summary
from noc.owner_pilot_status import snapshot,ALLOWED_TARGETS,APP_ENDPOINTS

class MockPanelTests(unittest.TestCase):
 def setUp(self):
  self.now=int(time.time())
  self.t=tempfile.TemporaryDirectory(prefix="noc-mock-incidents-view-")
  self.addCleanup(self.t.cleanup)
  self.root=Path(self.t.name)/"owner"
  self.root.mkdir(mode=0o700)
  self.empty={"scope":"OWNER_ONLY_APPLICATION_INCIDENT_SIMULATION",
    "generated_at":datetime.fromtimestamp(self.now,timezone.utc).isoformat(),
    "incidents":[],"pending_mock_events":0,"live_integrations":"disabled"}
 def write(self,body):
  p=self.root/"app-incidents-mock-latest.json"
  p.write_text(json.dumps(body))
  p.chmod(0o600)
  return p
 def test_current_mock_evidence_does_not_create_real_incidents(self):
  self.write(self.empty)
  view=snapshot(self.root,now=self.now)
  self.assertTrue(view["mock_incidents_current"])
  self.assertEqual(view["mock_incidents_open"],0)
  self.assertEqual(view["mock_events_pending"],0)
  self.assertEqual(view["mock_integrations"],"disabled")
  self.assertTrue(view["no_customer_ticket_creation"])
 def test_open_and_recovered_are_unambiguously_mock(self):
  r=copy.deepcopy(self.empty)
  r["incidents"]=[
   {"app":"Hub","status":"open","opened_at":self.now-900,"resolved_at":None},
   {"app":"Website","status":"resolved","opened_at":self.now-1800,
     "resolved_at":self.now-500}]
  r["pending_mock_events"]=3
  view=summary(r,now=self.now)
  self.assertEqual(view["mock_incidents_open"],1)
  self.assertEqual(view["mock_events_pending"],3)
  self.assertEqual([i["classification"] for i in view["mock_incidents"]],["MOCK_ONLY","MOCK_ONLY"])
  self.assertEqual(view["mock_incidents"][1]["state"],"resolved")
 def test_missing_and_stale_evidence_never_claim_zero(self):
  absent=summary(None,now=self.now)
  self.assertIsNone(absent["mock_incidents_open"])
  self.assertIsNone(absent["mock_events_pending"])
  r=copy.deepcopy(self.empty)
  r["generated_at"]=datetime.fromtimestamp(self.now-4000,timezone.utc).isoformat()
  old=summary(r,now=self.now)
  self.assertEqual(old["mock_status"],"stale")
  self.assertFalse(old["mock_incidents_current"])
  self.assertIsNone(old["mock_incidents_open"])
 def test_wrong_scope_and_dispatch_state_rejected(self):
  for field,value in (("scope","LIVE_INCIDENTS"),("live_integrations","enabled")):
   bad=copy.deepcopy(self.empty)
   bad[field]=value
   with self.subTest(field=field),self.assertRaises(PermissionError):
    summary(bad,now=self.now)
 def test_untrusted_app_and_inconsistent_recovery_rejected(self):
  for app,status,opened,resolved in (
   ("Other","open",self.now-1,None),
   ("Hub","resolved",self.now-1,None),
   ("Hub","open",self.now-1,self.now),
   ("Hub","resolved",self.now-1,self.now+100),
  ):
   r=copy.deepcopy(self.empty)
   r["incidents"]=[{"app":app,"status":status,"opened_at":opened,"resolved_at":resolved}]
   with self.subTest(app=app,status=status),self.assertRaises(ValueError):
    summary(r,now=self.now)
 def test_symlink_and_loose_private_file_rejected(self):
  p=self.write(self.empty)
  p.chmod(0o644)
  with self.assertRaises(PermissionError):snapshot(self.root,now=self.now)
  p.chmod(0o600)
  p.unlink()
  p.symlink_to(self.root/"another")
  with self.assertRaises(PermissionError):snapshot(self.root,now=self.now)
 def test_outage_does_not_mutate_noc_customer_info(self):
  self.write(self.empty)
  r=snapshot(self.root,now=self.now)
  self.assertFalse(r["available"])
  self.assertTrue(r["mock_incidents_current"])
  self.assertEqual(r["integrations"],"disabled")
 if False: pass

if __name__=="__main__":unittest.main()
