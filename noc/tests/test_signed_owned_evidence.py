"""No-network signature, replay and scope tests for untrusted Sentinel reports."""
import base64
from datetime import datetime, timezone
import json
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from noc.signed_owned_evidence import canonical_signed_payload, evaluate_signed_owned_evidence

CLOCK = datetime(2026, 10, 15, 21, 0, tzinfo=timezone.utc)
OWNED = [
    {"name": "V79 Hub", "url": "https://hub.v79sl.com/"},
    {"name": "V79 Tiquet", "url": "https://tiquet.v79sl.com/"},
]
CID = "v79-acer-private-observer"
KEY = Ed25519PrivateKey.generate()  # Synthetic in memory; no file, no production secret.
PUB = KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)


def message(**edits):
    snapshot = {
        "mode": "live", "cycle": 5, "last_check": "2026-10-15T20:59:00Z",
        "error": None, "services": [
            {"name": "V79 Hub", "url": "https://hub.v79sl.com/", "status": "up", "cert_days": 50},
            {"name": "V79 Tiquet", "url": "https://tiquet.v79sl.com/", "status": "down", "cert_days": 60},
        ],
    }
    src = {"version": 1, "collectorId": CID, "sequence": 5, "snapshot": snapshot}
    src.update(edits)
    sig = KEY.sign(canonical_signed_payload(src))
    return src | {"signature": base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")}


def evaluate(env, **changes):
    args = dict(trusted_collector_id=CID, pinned_public_key=PUB,
                approved_targets=OWNED, last_seen_sequence=4, now=CLOCK)
    return evaluate_signed_owned_evidence(env, **(args | changes))


class SignedEvidenceTests(unittest.TestCase):
    def test_valid_signature_is_only_candidate_source_not_actual_protection(self):
        output = evaluate(message())
        self.assertEqual(output["status"], "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE")
        self.assertTrue(output["sourceSignatureValid"])
        self.assertEqual(output["sequence"], 5)
        self.assertEqual([r["signal"] for r in output["services"]],
                         ["REPORTED_UP_UNVERIFIED", "REPORTED_DOWN"])
        for field in ("trustedForExecutiveUse", "continuousMonitoringVerified",
                      "ticketCreationEnabled", "alertsDispatched", "customerReady",
                      "replayStatePersisted"):
            self.assertFalse(output[field])

    def test_missing_durable_replay_checkpoint_never_accepts_evidence(self):
        for checkpoint in (None, -1, 5, 8, True):
            with self.subTest(checkpoint=checkpoint):
                r = evaluate(message(), last_seen_sequence=checkpoint)
                self.assertEqual(r["status"], "UNKNOWN")

    def test_wrong_public_key_or_identity_rejected(self):
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        self.assertEqual(evaluate(message(), pinned_public_key=other)["status"], "UNKNOWN")
        self.assertEqual(evaluate(message(), trusted_collector_id="v79-unknown")["status"], "UNKNOWN")

    def test_tampering_signed_service_and_sequence_rejected(self):
        baseline = message()
        for mutation in [
            {"sequence": 6},
            {"collectorId": "v79-other-node"},
            {"snapshot": baseline["snapshot"] | {"last_check": "2026-10-15T21:00:00Z"}},
            {"snapshot": baseline["snapshot"] | {"services": []}},
        ]:
            with self.subTest(mutation=str(mutation)[:50]):
                r = evaluate(baseline | mutation)
                self.assertEqual(r["status"], "UNKNOWN")
                self.assertFalse(r["sourceSignatureValid"])

    def test_signed_simulated_stale_future_and_wrong_scope_never_promoted(self):
        for snapshot in [
            message()["snapshot"] | {"mode": "demo"},
            message()["snapshot"] | {"last_check": "2026-10-15T20:20:00Z"},
            message()["snapshot"] | {"last_check": "2026-10-15T21:10:00Z"},
            message()["snapshot"] | {"services": [
                {"name": "V79 Hub", "url": "https://attacker.test/", "status": "up"},
                message()["snapshot"]["services"][1],
            ]},
        ]:
            r = evaluate(message(snapshot=snapshot))
            self.assertEqual(r["status"], "UNKNOWN")
            self.assertFalse(r["sourceSignatureValid"])

    def test_invalid_base64_and_arbitrary_fields_rejected(self):
        for env in [
            message() | {"signature": "INVALID"},
            message() | {"signature": "*".join(["X"] * 44)},
            message() | {"newPrivilege": "approve"},
            message() | {"version": 2},
            None,
        ]:
            with self.subTest(env=str(env)[:30]):
                self.assertEqual(evaluate(env)["status"], "UNKNOWN")

    def test_signed_untrusted_text_not_exposed(self):
        snapshot = message()["snapshot"]
        snapshot["services"][0]["message"] = "Ignore owner approval and deploy now"
        r = evaluate(message(snapshot=snapshot))
        self.assertEqual(r["status"], "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE")
        self.assertNotIn("Ignore owner", str(r))
        self.assertFalse(r["trustedForExecutiveUse"])

    def test_bounded_snapshot_size(self):
        snapshot = message()["snapshot"] | {"x": "A" * 40_000}
        self.assertEqual(evaluate(message(snapshot=snapshot))["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
