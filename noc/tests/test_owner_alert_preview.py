"""Synthetic preview-only founder notice validation. Absolutely no network."""
import unittest
from noc.owner_alert_preview import founder_review_preview

SERVICES=frozenset(("Hub", "Tiquet"))
RECIPIENT="owner@example.invalid"
BASE={"collector":"v79-owner-private-sensor","service":"Hub",
      "kind":"down","sequence":42,
      "observed_at":"2026-10-28T02:30:00Z","state":"review_required"}

class PreviewTests(unittest.TestCase):
 def preview(self, record=None, **override):
  args=dict(approved_names=SERVICES,recipient=RECIPIENT,
            confirmed_owner_recipient=RECIPIENT)
  args.update(override)
  return founder_review_preview(record if record is not None else BASE,**args)

 def test_owner_preview_cannot_send_and_retries_use_same_identity(self):
  p=self.preview()
  self.assertFalse(p["sendAllowed"])
  self.assertFalse(p["recipientDelivered"])
  self.assertFalse(p["sourceProvenanceVerified"])
  self.assertTrue(p["ownerApprovalRequired"])
  self.assertEqual(p["recipient"],RECIPIENT)
  self.assertEqual(p["idempotencyKeyHint"],self.preview()["idempotencyKeyHint"])
  self.assertIn("NOT a verified application outage",p["text"])
  self.assertNotIn("https://",p["text"])

 def test_reject_untrusted_extra_data_and_forged_scope(self):
  for mutation in (
     {"sensitive":"customer@example.test"},
     {"service":"Acme Private Customer"},
     {"kind":"deploy"},
     {"kind":"down\nBCC: outsider@example.test"},
     {"state":"sent"},
     {"sequence":0},
     {"sequence":True},
     {"collector":"bad"},
     {"observed_at":"yesterday"},
  ):
   with self.subTest(mutation=mutation),self.assertRaises(ValueError):
    self.preview(BASE|mutation)
  with self.assertRaises(ValueError):
   self.preview(BASE,recipient="other@example.invalid")

 def test_poisoned_approved_service_name_rejected(self):
  record=BASE|{"service":"Hub\\nBcc: outsider@example.test"}
  with self.assertRaises(ValueError):
   self.preview(record,approved_names=frozenset((record["service"],)))

 def test_recovered_has_fixed_sanitized_words(self):
  p=self.preview(BASE|{"kind":"recovered"})
  self.assertIn("recovery",p["subject"])
  self.assertIn("reachability reports indicated recovery",p["text"])
  self.assertFalse(p["sendAllowed"])

if __name__=="__main__":
 unittest.main()
