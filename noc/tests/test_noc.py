"""Isolated NOC foundation tests. Never connect to a customer network."""
import tempfile
import unittest
from pathlib import Path
from noc.store import NocStore

class NocFoundationTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix="v79-noc-test-")
  self.store=NocStore(Path(self.tmp.name)/"state.sqlite3")
  self.c1=self.store.customer("Example Hotel")
  self.c2=self.store.customer("Example Office")
  self.site1=self.store.site(self.c1,"Main Branch")
  self.site2=self.store.site(self.c2,"Main Branch")
  self.a1=self.store.asset(self.site1,"Router","192.168.1.1")
  self.a2=self.store.asset(self.site2,"Router","192.168.1.1")
  self.ch1=self.store.check(self.a1,"WAN","isp")
  self.ch2=self.store.check(self.a2,"WAN","isp")
  self.agent1=self.store.enroll(self.site1,"Edge One")
  self.agent2=self.store.enroll(self.site2,"Edge Two")
 def tearDown(self): self.tmp.cleanup()
 def observation(self,token,seq,check,ok):
  return self.store.ingest(token,{"sequence":seq,"readings":[{"check_id":check,"ok":ok}]})
 def test_duplicate_private_ip_stays_separate(self):
  self.assertEqual(len(self.store.snapshot()["customers"]),2)
  self.assertEqual(len({a["address"] for a in self.store.snapshot()["assets"]}),1)
  self.assertEqual(len({a["site_id"] for a in self.store.snapshot()["assets"]}),2)
 def test_cross_tenant_observation_blocked(self):
  with self.assertRaises(PermissionError):
   self.observation(self.agent1["credential"],1,self.ch2,False)
  self.assertEqual(len(self.store.snapshot()["incidents"]),0)
  self.assertEqual(self.observation(self.agent1["credential"],1,self.ch1,False)["status"],"accepted")
 def test_two_failures_one_incident_and_recovery(self):
  tok=self.agent1["credential"]
  self.observation(tok,1,self.ch1,False)
  self.assertEqual(len(self.store.snapshot()["incidents"]),0)
  self.observation(tok,2,self.ch1,False)
  self.assertEqual(len(self.store.snapshot()["incidents"]),1)
  self.observation(tok,3,self.ch1,False)
  self.assertEqual(len(self.store.snapshot()["incidents"]),1)
  self.observation(tok,4,self.ch1,True)
  self.assertEqual(self.store.snapshot()["incidents"][0]["state"],"open")
  self.observation(tok,5,self.ch1,True)
  self.assertEqual(self.store.snapshot()["incidents"][0]["state"],"resolved")
  self.assertEqual(self.store.snapshot()["pending_mock_events"],2)
 def test_idempotent_sequence(self):
  t=self.agent1["credential"]
  self.observation(t,1,self.ch1,False)
  self.assertEqual(self.observation(t,1,self.ch1,False)["status"],"duplicate")
  self.assertEqual(self.observation(t,2,self.ch1,False)["status"],"accepted")
  self.assertEqual(len(self.store.snapshot()["incidents"]),1)
 def test_atomic_batch_denies_other_customer(self):
  t=self.agent1["credential"]
  with self.assertRaises(PermissionError):
   self.store.ingest(t,{"sequence":1,"readings":[
    {"check_id":self.ch1,"ok":False},{"check_id":self.ch2,"ok":False}]})
  with self.store.db() as c:
   self.assertEqual(c.execute("SELECT COUNT(*) FROM observations").fetchone()[0],0)
 def test_revoked_agent_denied(self):
  t=self.agent1["credential"]
  self.store.revoke(self.agent1["agent_id"])
  with self.assertRaises(PermissionError):
   self.observation(t,1,self.ch1,False)
 def test_invalid_telemetry_rejected(self):
  t=self.agent1["credential"]
  for r in [{"check_id":self.ch1,"ok":1},{"check_id":self.ch1,"ok":False,"latency":-1},
            {"check_id":self.ch1,"ok":True,"shell":"bash"}]:
   with self.assertRaises(ValueError):
    self.store.ingest(t,{"sequence":1,"readings":[r]})
 def test_acknowledgement(self):
  t=self.agent1["credential"]
  self.observation(t,1,self.ch1,False)
  self.observation(t,2,self.ch1,False)
  incident=self.store.snapshot()["incidents"][0]
  self.store.acknowledge(incident["id"],"operator-demo")
  self.assertEqual(self.store.snapshot()["incidents"][0]["state"],"acknowledged")

 def test_maintenance_suppresses_new_incident_but_records_telemetry(self):
  policy=self.store.maintenance(self.site1,"Planned lab maintenance",hours=2)
  self.assertTrue(policy["id"])
  tok=self.agent1["credential"]
  self.observation(tok,1,self.ch1,False)
  self.observation(tok,2,self.ch1,False)
  snap=self.store.snapshot()
  self.assertEqual(len(snap["incidents"]),0)
  self.assertEqual(snap["checks"][0]["state"],"alarm")
  self.assertEqual(len(snap["maintenance"]),1)
  with self.store.db() as c:
   self.assertEqual(c.execute("SELECT count(*) FROM observations").fetchone()[0],2)
  other=self.agent2["credential"]
  self.observation(other,1,self.ch2,False)
  self.observation(other,2,self.ch2,False)
  self.assertEqual(len(self.store.snapshot()["incidents"]),1)
  self.assertEqual(self.store.snapshot()["incidents"][0]["customer_id"],self.c2)

 def test_maintenance_expiry_allows_new_incident(self):
  self.store.maintenance(self.site1,"Planned lab maintenance",hours=1)
  tok=self.agent1["credential"]
  self.observation(tok,1,self.ch1,False)
  self.observation(tok,2,self.ch1,False)
  self.assertEqual(len(self.store.snapshot()["incidents"]),0)
  with self.store.db() as c:
   c.execute("UPDATE maintenance_windows SET starts=starts-7200, ends=ends-7200")
  self.observation(tok,3,self.ch1,False)
  self.assertEqual(len(self.store.snapshot()["incidents"]),1)

 def test_maintenance_does_not_close_previous_incident(self):
  tok=self.agent1["credential"]
  self.observation(tok,1,self.ch1,False)
  self.observation(tok,2,self.ch1,False)
  self.store.maintenance(self.site1,"Authorized maintenance",hours=1)
  self.assertEqual(self.store.snapshot()["incidents"][0]["state"],"open")
  self.observation(tok,3,self.ch1,True)
  self.observation(tok,4,self.ch1,True)
  self.assertEqual(self.store.snapshot()["incidents"][0]["state"],"resolved")

 def test_maintenance_validation(self):
  for hours in (0,337,1.5,"3",True):
   with self.assertRaises(ValueError):
    self.store.maintenance(self.site1,"Planned lab",hours=hours)
  with self.assertRaises(ValueError):
   self.store.maintenance("unknown-site","Planned lab",hours=2)
  self.store.maintenance(self.site1,"Planned lab",hours=2)
  with self.assertRaises(ValueError):
   self.store.maintenance(self.site1,"Overlapping lab maintenance",hours=1)

 def test_resolutionproof_history_and_mock_outbox(self):
  tok=self.agent1["credential"]
  self.observation(tok,1,self.ch1,False)
  self.observation(tok,2,self.ch1,False)
  incident=self.store.snapshot()["incidents"][0]
  self.store.acknowledge(incident["id"],"test-operator")
  self.observation(tok,3,self.ch1,True)
  self.observation(tok,4,self.ch1,True)
  snapshot=self.store.snapshot()
  self.assertEqual(snapshot["metrics"]["total_incidents"],1)
  self.assertEqual(snapshot["metrics"]["resolved_incidents"],1)
  self.assertGreaterEqual(snapshot["metrics"]["mean_recovery_seconds"],0)
  actions={h["action"] for h in snapshot["history"]}
  self.assertEqual(actions,{"incident.opened","incident.acknowledged","incident.resolved"})
  self.assertEqual(snapshot["pending_mock_events"],2)
  self.assertEqual(snapshot["future_integrations"],"disabled")

if __name__=="__main__":
 unittest.main()
