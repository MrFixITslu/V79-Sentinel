import importlib.util,sys,time,unittest,uuid
from pathlib import Path
from datetime import datetime,timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
p=Path(__file__).resolve().parents[2]/"scripts/sentinel_offhost_witness.py";spec=importlib.util.spec_from_file_location("witness",p);w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
class Witness(unittest.TestCase):
 def setUp(self):self.key=Ed25519PrivateKey.generate();self.pin=self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex();self.now=time.time()
 def envelope(self,seq=5,**changes):
  r={"publisher":"v79-sentinel-probe-v1","sequence":seq,"target":"sentinel","category":"service_health","provenance":"sentinel_inprocess_probe","observedAt":datetime.fromtimestamp(self.now,timezone.utc).isoformat(),"expiresAt":datetime.fromtimestamp(self.now+900,timezone.utc).isoformat(),"measurements":{"up":7},"id":str(uuid.uuid4())};r.update(changes);return {"record":r,"signature":self.key.sign(w.canonical(r)).hex()}
 def test_fresh_source_anchors_sequence(self):self.assertEqual(w.evaluate(self.envelope(),self.pin,4,"old",self.now)[0],"PASS")
 def test_rolled_back_source_is_detected(self):self.assertEqual(w.evaluate(self.envelope(seq=4),self.pin,5,"old",self.now)[0],"FAIL")
 def test_same_sequence_changed_content_is_detected(self):self.assertEqual(w.evaluate(self.envelope(),self.pin,5,"different",self.now)[0],"FAIL")
 def test_identical_unchanged_source_is_allowed_while_fresh(self):
  e=self.envelope();import hashlib;digest=hashlib.sha256(w.canonical(e)).hexdigest();self.assertEqual(w.evaluate(e,self.pin,5,digest,self.now)[0],"PASS")
 def test_expired_report_cannot_refresh_witness(self):self.assertEqual(w.evaluate(self.envelope(),self.pin,0,"",self.now+901)[0],"UNKNOWN")
 def test_forged_key_or_signature_is_unknown(self):
  e=self.envelope();e["signature"]="0"*128;self.assertEqual(w.evaluate(e,self.pin,0,"",self.now)[0],"UNKNOWN")
 def test_missing_and_foreign_sources_are_unknown(self):
  self.assertEqual(w.evaluate(None,self.pin,3,"old",self.now)[0],"UNKNOWN");self.assertEqual(w.evaluate(self.envelope(target="hub"),self.pin,3,"old",self.now)[0],"UNKNOWN")
 def test_missing_checkpoint_requires_reenrolment(self):
  import tempfile,json
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);(root/"config.json").write_text(json.dumps({"sourcePublicKey":self.pin}))
   with patch.object(sys,"argv",["witness",tmp]):
    with self.assertRaisesRegex(RuntimeError,"checkpoint missing"):w.main()
 def test_future_source_rejected(self):
  e=self.envelope(observedAt=datetime.fromtimestamp(self.now+121,timezone.utc).isoformat());self.assertEqual(w.evaluate(e,self.pin,0,"",self.now)[0],"UNKNOWN")
if __name__=="__main__":unittest.main()
