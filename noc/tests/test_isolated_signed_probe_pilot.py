"""No-network end-to-end tests for the OFF-by-default Sentinel signing pilot.

Ephemeral synthetic keys and temporary SQLite only. No live Sentinel probes,
production volumes, customer tickets, Hub access or owner alerts.
"""
import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from noc.inprocess_probe_receipt import project_probe_cycle
from noc.isolated_signed_probe_pilot import sign_review_receipt
from noc.owned_replay_checkpoint import (
    evaluate_and_checkpoint_owned_evidence, prepare_owned_replay_store,
)

NOW = datetime(2026, 10, 28, 22, 30, tzinfo=timezone.utc)
TARGETS = [
    {"name": "Website", "url": "https://v79sl.com/"},
    {"name": "V79 Hub", "url": "https://hub.v79sl.com/"},
    {"name": "Academy", "url": "https://academy.v79sl.com/"},
    {"name": "FFPRO", "url": "https://ffpro.v79sl.com/"},
    {"name": "V79 Tiquet", "url": "https://tiquet.v79sl.com/"},
    {"name": "Marketing", "url": "https://marketing.v79sl.com/"},
    {"name": "V79 POS", "url": "https://pos.v79sl.com/"},
]
COLLECTOR = "v79-dell-sourcebound-pilot"
SECRET = "DO_NOT_EXPORT_FAKE_CUSTOMER_SECRET"


def source_receipt(sequence=11, *, observed=None, targets=TARGETS, readings=None):
    stamp = observed or NOW - timedelta(seconds=15)
    if readings is None:
        readings = [
            {**t, "status": "up", "http": 200, "cert_days": 90,
             "message": SECRET, "customer": SECRET, "ip": "10.1.1.1"}
            for t in targets
        ]
    return project_probe_cycle(
        targets=targets, readings=readings, cycle=sequence,
        observed_at=stamp.isoformat(), now=NOW,
    )


class IsolatedSignedProbePilotTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = str(Path(self.temp.name) / "sourcebound-test.sqlite3")
        self.conn = sqlite3.connect(self.db, timeout=3)
        self.addCleanup(lambda: self.conn.close())
        self.conn.execute("PRAGMA synchronous=FULL")
        prepare_owned_replay_store(self.conn)

    def sign(self, receipt=None, previous=10, **kw):
        return sign_review_receipt(
            source_receipt() if receipt is None else receipt,
            signer=self.key, collector_id=COLLECTOR,
            approved_targets=TARGETS, previous_cycle=previous,
            now=NOW, **kw,
        )

    def receive(self, envelope, conn=None):
        return evaluate_and_checkpoint_owned_evidence(
            envelope, conn=self.conn if conn is None else conn,
            trusted_collector_id=COLLECTOR,
            pinned_public_key=self.pub, approved_targets=TARGETS, now=NOW,
        )

    def test_source_projection_to_signature_to_durable_advisory(self):
        envelope = self.sign()
        self.assertEqual(envelope["sequence"], 11)
        self.assertEqual(len(envelope["snapshot"]["services"]), 7)
        self.assertNotIn(SECRET, str(envelope))
        self.assertNotIn("10.1.1.1", str(envelope))
        result = self.receive(envelope)
        self.assertEqual(result["status"], "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE")
        self.assertTrue(result["sourceSignatureValid"])
        self.assertTrue(result["replayStatePersisted"])
        for flag in ("trustedForExecutiveUse", "continuousMonitoringVerified",
                     "alertsDispatched", "ticketCreationEnabled", "customerReady"):
            self.assertFalse(result[flag])

    def test_durable_duplicate_replay_and_restart_resistance(self):
        envelope = self.sign()
        self.assertTrue(self.receive(envelope)["replayStatePersisted"])
        rejected = self.receive(envelope)
        self.assertEqual(rejected["status"], "UNKNOWN")
        self.assertEqual(rejected["reason"], "MISSING_OR_REPLAYED_SEQUENCE")
        self.conn.close()
        self.conn = sqlite3.connect(self.db)
        self.conn.execute("PRAGMA synchronous=FULL")
        self.assertEqual(self.receive(envelope)["status"], "UNKNOWN")
        next_receipt = source_receipt(sequence=12)
        later = self.sign(next_receipt, previous=11)
        self.assertTrue(self.receive(later)["replayStatePersisted"])

    def test_tampering_wrong_key_and_counterfeit_scope_fail_closed(self):
        original = self.sign()
        altered = copy.deepcopy(original)
        altered["snapshot"]["services"][0]["status"] = "down"
        self.assertEqual(self.receive(altered)["status"], "UNKNOWN")
        self.assertEqual(self.receive(original | {"collectorId": "v79-forged"})["status"], "UNKNOWN")
        foreign = source_receipt()
        foreign["report"]["services"][0]["url"] = "https://outside.example/"
        with self.assertRaises(ValueError):
            self.sign(foreign)
        self.assertIsNone(
            self.conn.execute("SELECT last_sequence FROM owned_observation_sequence").fetchone()
        )

    def test_invalid_receipt_flags_and_unsanitized_input_rejected(self):
        sample = source_receipt()
        cases = [
            {"mode": "live", "cycle": 11, "services": []},
            sample | {"sourceProvenanceVerified": True},
            sample | {"alertsDispatched": True},
            sample | {"extra": "arbitrary"},
            sample | {"report": sample["report"] | {"extra": SECRET}},
        ]
        for case in cases:
            with self.subTest(keys=sorted(case)), self.assertRaises(ValueError):
                self.sign(case)

    def test_stale_future_monitor_reset_and_invalid_key_rejected(self):
        for offset in (-12 * 60, 5 * 60):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.sign(source_receipt(observed=NOW + timedelta(seconds=offset)))
        for prior in (11, 12):
            with self.assertRaises(ValueError):
                self.sign(previous=prior)
        for prior in (None, True, -1):
            with self.assertRaises(ValueError):
                self.sign(previous=prior)
        with self.assertRaises(ValueError):
            sign_review_receipt(source_receipt(), signer=object(),
                collector_id=COLLECTOR, approved_targets=TARGETS,
                previous_cycle=10, now=NOW)

    def test_unavailable_replay_store_never_promotes(self):
        signed = self.sign()
        memory = sqlite3.connect(":memory:")
        self.addCleanup(memory.close)
        status = self.receive(signed, conn=memory)
        self.assertEqual(status["status"], "UNKNOWN")
        self.assertFalse(status["replayStatePersisted"])

    def test_no_network_signer_loading_or_production_actions(self):
        import inspect
        from noc import isolated_signed_probe_pilot
        source = inspect.getsource(isolated_signed_probe_pilot)
        for forbidden in ("urllib.request", "requests.", "socket.", "docker",
                          "SMTP", "send_email(", "sqlite3.connect(",
                          "os.environ", "load_pem_private_key", "http.server"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
