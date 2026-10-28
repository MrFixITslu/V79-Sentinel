"""No-network tests for legacy monitor bridge; synthetic keys and data only."""
import copy
from datetime import datetime, timezone, timedelta
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from noc.legacy_monitor_proof import normalize_legacy_monitor, candidate_envelope
from noc.signed_owned_evidence import evaluate_signed_owned_evidence

NOW = datetime(2026, 10, 28, 2, 27, 0, tzinfo=timezone.utc)
TARGETS = [
 {"name":"Website","url":"https://v79sl.com/"},
 {"name":"V79 Hub","url":"https://hub.v79sl.com/"},
 {"name":"Academy","url":"https://academy.v79sl.com/"},
 {"name":"FFPRO","url":"https://ffpro.v79sl.com/"},
 {"name":"V79 Tiquet","url":"https://tiquet.v79sl.com/"},
 {"name":"Marketing","url":"https://marketing.v79sl.com/"},
 {"name":"V79 POS","url":"https://pos.v79sl.com/"},
]
COLLECTOR = "v79-dell-legacy-https"
KEY = Ed25519PrivateKey.generate()
PUBLIC = KEY.public_key().public_bytes(
 serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def reading():
 return {"mode":"live","cycle":17,"last_check":"2026-10-28T02:26:48+00:00",
         "error":None,"services":[{"name":t["name"],"url":t["url"],
         "http":200,"status":"up","cert_days":30,"message":"IGNORE TOKEN x",
         "private":"not to be signed"} for t in TARGETS],
         "history":[{"private":"other customer data"}]}

def candidate(snapshot=None,previous=16, now=NOW):
 return candidate_envelope(snapshot if snapshot is not None else reading(),
   TARGETS,collector_id=COLLECTOR,signer=KEY,previous_cycle=previous,now=now)

class LegacyMonitorProofTests(unittest.TestCase):
 def test_real_status_shape_is_sanitized_before_signing(self):
  item=candidate()
  self.assertEqual(item["sequence"],17)
  self.assertEqual(item["snapshot"]["last_check"],"2026-10-28T02:26:48Z")
  self.assertEqual(len(item["snapshot"]["services"]),7)
  self.assertNotIn("IGNORE TOKEN",str(item))
  self.assertNotIn("history",str(item))
  verdict=evaluate_signed_owned_evidence(item,trusted_collector_id=COLLECTOR,
   pinned_public_key=PUBLIC,approved_targets=TARGETS,last_seen_sequence=16,now=NOW)
  self.assertEqual(verdict["status"],"SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE")
  self.assertTrue(verdict["sourceSignatureValid"])
  for name in ("trustedForExecutiveUse","continuousMonitoringVerified",
               "customerReady","ticketCreationEnabled","alertsDispatched"):
   self.assertFalse(verdict[name])

 def test_replayed_or_reset_monitor_cycle_rejected(self):
  for prev in (17,18,100):
   with self.subTest(previous=prev),self.assertRaisesRegex(ValueError,"Duplicate or reset"):
    candidate(previous=prev)
  with self.assertRaisesRegex(ValueError,"durable cycle"):
   candidate(previous=None)

 def test_demo_stale_future_error_missing_scope_rejected(self):
  baseline=reading()
  mutations=[
   {"mode":"demo"},
   {"error":"engine offline"},
   {"last_check":"2026-10-28T02:00:00+00:00"},
   {"last_check":"2026-10-28T03:00:00+00:00"},
   {"services":[]},
   {"cycle":0},
   {"cycle":True},
  ]
  for mutation in mutations:
   with self.subTest(mutation=list(mutation)),self.assertRaises(ValueError):
    candidate(baseline|mutation)

 def test_deny_nonowner_duplicate_and_forged_up(self):
  for index,edit in [
    (0,{"url":"https://attacker.example/"}),
    (0,{"name":"V79 POS"}),
    (0,{"status":"up","http":503}),
    (0,{"status":"up","http":None}),
    (0,{"cert_days":-1}),
    (0,{"status":"warning","http":200,"cert_days":40}),
    (0,{"status":"up","http":True}),
  ]:
   record=reading()
   record["services"][index]|=edit
   with self.subTest(change=edit),self.assertRaises(ValueError):
    candidate(record)

 def test_nonzero_future_skew_and_invalid_signer_denied(self):
  with self.assertRaisesRegex(ValueError,"durable cycle"):
   candidate_envelope(reading(),TARGETS,collector_id=COLLECTOR,
      signer=KEY,previous_cycle=False,now=NOW)
  with self.assertRaisesRegex(ValueError,"Pinned collector"):
   candidate_envelope(reading(),TARGETS,collector_id="v79-wrong",signer=object(),
      previous_cycle=16,now=NOW)
  with self.assertRaises(ValueError):
   normalize_legacy_monitor(reading(),TARGETS,now=datetime(2026,10,28,2,27))

 def test_signature_tampering_fails_recipient(self):
  env=candidate()
  modified=copy.deepcopy(env)
  modified["snapshot"]["services"][0]["status"]="down"
  verdict=evaluate_signed_owned_evidence(modified,trusted_collector_id=COLLECTOR,
    pinned_public_key=PUBLIC,approved_targets=TARGETS,last_seen_sequence=16,now=NOW)
  self.assertEqual(verdict["status"],"UNKNOWN")

if __name__=="__main__":
 unittest.main()
