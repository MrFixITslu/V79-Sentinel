import importlib.util,json,os,sqlite3,sys,tempfile,time,unittest
from pathlib import Path
from datetime import datetime,timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from noc.workforce_evidence_sink import EvidenceSink,canonical
sys.path.insert(0,"/home/firelion/v79-evidence-gateway-20261105")
from evidence_gateway.store import EvidenceStore,Denied
spec=importlib.util.spec_from_file_location("relay",Path(__file__).resolve().parents[2]/"scripts/sentinel_workforce_relay.py")
relay=importlib.util.module_from_spec(spec);spec.loader.exec_module(relay)
class Integration(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.key=Ed25519PrivateKey.generate();self.pin=self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
  self.store=EvidenceStore(self.root/"gateway.sqlite",os.urandom(32),{"v79-sentinel-probe-v1":{"publicKey":self.pin,"targets":["sentinel"],"categories":["service_health"],"provenance":["sentinel_inprocess_probe"]}})
  self.sent=[];self.sink=EvidenceSink(state=str(self.root/"sender"),key=self.key,token="synthetic",send=self.send)
 def tearDown(self):self.tmp.cleanup()
 def send(self,x):self.sent.append(x);return self.store.ingest(x)
 def receipt(self,status="up"):
  return {"mode":"IN_PROCESS_PROBE_CANDIDATE_ONLY","report":{"mode":"live","error":None,"cycle":1,"last_check":datetime.now(timezone.utc).isoformat(),"services":[{"status":status,"message":"DO_NOT_FORWARD"}]}}
 def test_source_to_receiver_and_proposal(self):
  self.sink(self.receipt("down"));e=self.store.read("sentinel","service_health");self.assertEqual(e["status"],"FAIL")
  state,counts=relay.signal(self.sent[-1],self.pin,time.time());self.assertEqual(state,"FAIL")
  c=self.db();posted=[]
  result=relay.transition(c,state,counts,time.time(),lambda b:posted.append(b) or {"job":{"id":"synthetic","status":"pending"}},"test")
  self.assertEqual(len(posted),1);self.assertTrue(result["ownerApprovalRequired"]);self.assertEqual(posted[0]["operation"],"create_work_item")
 def db(self):
  c=sqlite3.connect(self.root/"relay.sqlite");c.execute("CREATE TABLE status(id INTEGER PRIMARY KEY,state TEXT,episode TEXT,body TEXT,job TEXT,updated REAL)")
  return c
 def test_restart_preserves_sender_counter(self):
  self.sink(self.receipt());second=EvidenceSink(state=str(self.root/"sender"),key=self.key,token="test",send=self.send);second(self.receipt())
  self.assertEqual([x["record"]["sequence"] for x in self.sent],[1,2])
 def test_receiver_restart_rejects_replay(self):
  self.sink(self.receipt());s=EvidenceStore(self.root/"gateway.sqlite",self.store.audit_key,self.store.publishers)
  with self.assertRaises(Denied):s.ingest(self.sent[0])
 def test_tampered_counts_rejected(self):
  self.sink(self.receipt());e=json.loads(json.dumps(self.sent[0]));e["record"]["measurements"]["up"]=0
  with self.assertRaises(Denied):self.store.ingest(e)
  self.assertEqual(relay.signal(e,self.pin,time.time())[0],"UNKNOWN")
 def test_foreign_publisher_scope_rejected(self):
  self.sink(self.receipt());e=self.sent[0];e["record"]["target"]="hub";e["signature"]=self.key.sign(canonical(e["record"])).hex()
  with self.assertRaises(Denied):self.store.ingest(e)
 def test_expired_source_stays_stale(self):
  self.sink(self.receipt());self.assertEqual(self.store.read("sentinel","service_health",now=time.time()+901)["status"],"STALE")
  self.assertEqual(relay.signal(self.sent[0],self.pin,time.time()+901)[0],"STALE")
 def test_unknown_and_contradictory_counts(self):
  self.sink(self.receipt());e=self.sent[0];e["record"]["measurements"]["down"]=1;e["signature"]=self.key.sign(canonical(e["record"])).hex()
  with self.assertRaises(Denied):self.store.ingest(e)
 def test_outage_keeps_signed_outbox(self):
  self.sink.send=lambda _:(_ for _ in ()).throw(OSError("offline"))
  with self.assertRaises(OSError):self.sink(self.receipt())
  with self.sink.connect() as c:self.assertEqual(c.execute("SELECT COUNT(*) FROM outbox").fetchone()[0],1)
  self.sink.send=self.send;self.sink(self.receipt());self.assertEqual(self.sent[0]["record"]["sequence"],2)
  with self.sink.connect() as c:self.assertEqual(c.execute("SELECT COUNT(*) FROM outbox").fetchone()[0],0)
 def test_sanitization(self):
  self.sink(self.receipt());self.assertNotIn("DO_NOT_FORWARD",json.dumps(self.sent));self.assertNotIn("services",self.sent[0]["record"]["measurements"])
 def test_wrong_source_and_bad_time(self):
  with self.assertRaises(ValueError):self.sink({"mode":"demo"})
  r=self.receipt();r["report"]["last_check"]="2000-01-01T00:00:00Z"
  with self.assertRaises(ValueError):self.sink(r)
 def test_duplicate_proposal_retry_is_idempotent(self):
  c=self.db();calls=[]
  def post(body):
   calls.append(body)
   if len(calls)==1:raise OSError("lost acknowledgement")
   return {"job":{"id":"same-job","status":"pending"}}
  with self.assertRaises(OSError):relay.transition(c,"FAIL",{"servicesObserved":1,"up":0,"down":1,"degraded":0,"unknown":0},1000,post,"test")
  relay.transition(c,"FAIL",{"servicesObserved":1,"up":0,"down":1,"degraded":0,"unknown":0},1060,post,"test")
  self.assertEqual(calls[0],calls[1])
 def test_flapping_has_bounded_alerts(self):
  c=self.db();calls=[];post=lambda b:calls.append(b) or {"job":{"id":"one","status":"pending"}}
  for n,state in enumerate(["FAIL","PASS","FAIL","PASS","FAIL"]):relay.transition(c,state,{},1000+n*60,post,"test")
  self.assertEqual(len(calls),1)
 def test_recovery_and_no_duplicate_task(self):
  c=self.db();calls=[];post=lambda b:calls.append(b) or {"job":{"id":"one","status":"pending"}}
  relay.transition(c,"FAIL",{},1000,post,"test");relay.transition(c,"UNKNOWN",{},1060,post,"test")
  relay.transition(c,"PASS",{},1120,post,"test")
  self.assertEqual(len(calls),1)
if __name__=="__main__":unittest.main()
