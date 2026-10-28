"""No-network atomic signed-advisory receiver and pending outbox tests."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from noc.inprocess_probe_receipt import project_probe_cycle
from noc.isolated_sender_counter import (
    prepare_isolated_sender_store, sign_with_atomic_sender_counter,
)
from noc.isolated_atomic_advisory_outbox import (
    prepare_isolated_advisory_outbox,
    evaluate_and_enqueue_isolated_advisory,
)

NOW = datetime(2026, 10, 28, 22, 30, tzinfo=timezone.utc)
CID = "v79-dell-atomic-outbox-pilot"
TARGETS = [
    {"name": "Website", "url": "https://v79sl.com/"},
    {"name": "V79 Hub", "url": "https://hub.v79sl.com/"},
    {"name": "Academy", "url": "https://academy.v79sl.com/"},
    {"name": "FFPRO", "url": "https://ffpro.v79sl.com/"},
    {"name": "V79 Tiquet", "url": "https://tiquet.v79sl.com/"},
    {"name": "Marketing", "url": "https://marketing.v79sl.com/"},
    {"name": "V79 POS", "url": "https://pos.v79sl.com/"},
]


def source_receipt(cycle=11):
    return project_probe_cycle(
        targets=TARGETS,
        readings=[
            {**t, "http": 200, "status": "up", "cert_days": 45,
             "message": "SECRET_NEVER_PERSIST",
             "account": "PRIVATE_NEVER_PERSIST",
             "ip": "10.99.99.99"}
            for t in TARGETS
        ],
        cycle=cycle, observed_at="2026-10-28T22:29:45+00:00", now=NOW,
    )


class IsolatedAtomicAdvisoryOutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        self.sender_path = str(Path(self.temp.name) / "sender.sqlite")
        self.receiver_path = str(Path(self.temp.name) / "receiver.sqlite")
        self.sender = sqlite3.connect(self.sender_path, timeout=3)
        self.receiver = sqlite3.connect(self.receiver_path, timeout=3)
        self.addCleanup(lambda: self.sender.close())
        self.addCleanup(lambda: self.receiver.close())
        self.sender.execute("PRAGMA synchronous=FULL")
        self.receiver.execute("PRAGMA synchronous=FULL")
        prepare_isolated_sender_store(self.sender)
        prepare_isolated_advisory_outbox(self.receiver)

    def sign(self, cycle=11):
        return sign_with_atomic_sender_counter(
            source_receipt(cycle), conn=self.sender, signer=self.key,
            collector_id=CID, approved_targets=TARGETS, now=NOW,
        )

    def receive(self, envelope, conn=None, **kw):
        return evaluate_and_enqueue_isolated_advisory(
            envelope, conn=self.receiver if conn is None else conn,
            trusted_collector_id=CID, pinned_public_key=self.pub,
            approved_targets=TARGETS, now=NOW, **kw,
        )

    def counts(self):
        return (
            self.receiver.execute("SELECT COUNT(*) FROM signed_advisory_outbox").fetchone()[0],
            self.receiver.execute("SELECT COUNT(*) FROM owned_observation_sequence").fetchone()[0],
        )

    def test_source_to_signed_to_atomic_pending_event_without_dispatch(self):
        signed = self.sign()
        result = self.receive(signed)
        self.assertEqual(result["status"], "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE")
        self.assertTrue(result["replayStatePersisted"])
        self.assertTrue(result["advisoryOutboxPersisted"])
        for flag in ("alertsDispatched", "trustedForExecutiveUse",
                     "continuousMonitoringVerified", "ticketCreationEnabled",
                     "customerReady"):
            self.assertFalse(result[flag])
        self.assertEqual(self.counts(), (1, 1))
        row = self.receiver.execute(
            "SELECT event_id,state,advisory_json FROM signed_advisory_outbox"
        ).fetchone()
        self.assertEqual(row[0], CID + ":11")
        self.assertEqual(row[1], "PENDING")
        data = json.loads(row[2])
        self.assertEqual(len(data["services"]), 7)
        self.assertFalse(data["alertsDispatched"])
        for forbidden in ("SECRET_NEVER_PERSIST", "PRIVATE_NEVER_PERSIST",
                          "10.99.99.99", "signature", "https://"):
            self.assertNotIn(forbidden, str(row))

    def test_replay_denied_and_restart_retains_both_records(self):
        signed = self.sign()
        self.assertTrue(self.receive(signed)["advisoryOutboxPersisted"])
        again = self.receive(signed)
        self.assertEqual(again["status"], "UNKNOWN")
        self.assertEqual(self.counts(), (1, 1))
        self.receiver.close()
        self.receiver = sqlite3.connect(self.receiver_path)
        self.receiver.execute("PRAGMA synchronous=FULL")
        self.assertEqual(self.receive(signed)["status"], "UNKNOWN")
        self.assertEqual(self.counts(), (1, 1))
        self.assertTrue(self.receive(self.sign(12))["advisoryOutboxPersisted"])
        self.assertEqual(self.counts(), (2, 1))

    def test_missing_outbox_rolls_back_replay_update(self):
        self.receiver.execute("DROP TABLE signed_advisory_outbox")
        self.receiver.commit()
        verdict = self.receive(self.sign())
        self.assertEqual(verdict["status"], "UNKNOWN")
        self.assertFalse(verdict["replayStatePersisted"])
        self.assertIsNone(self.receiver.execute(
            "SELECT last_sequence FROM owned_observation_sequence"
        ).fetchone())

    def test_untrusted_signature_and_collector_identity_never_advance(self):
        signed = self.sign()
        corrupted = signed | {"signature": "A" * 86}
        self.assertEqual(self.receive(corrupted)["status"], "UNKNOWN")
        self.assertEqual(self.receive(signed | {"collectorId": "v79-forged"})["status"], "UNKNOWN")
        self.assertEqual(self.counts(), (0, 0))
        self.assertTrue(self.receive(signed)["advisoryOutboxPersisted"])

    def test_unsafe_receiver_db_cannot_record_or_claim_delivery(self):
        mem = sqlite3.connect(":memory:")
        self.addCleanup(mem.close)
        mem.execute("PRAGMA synchronous=FULL")
        prepare_isolated_advisory_outbox(mem)
        result = self.receive(self.sign(), conn=mem)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertFalse(result["advisoryOutboxPersisted"])
        self.assertEqual(self.counts(), (0, 0))

    def test_concurrent_identical_received_once(self):
        signed = self.sign()
        def submit(_):
            with sqlite3.connect(self.receiver_path, timeout=4) as c:
                c.execute("PRAGMA synchronous=FULL")
                return self.receive(signed, conn=c)["status"]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit, range(2)))
        self.assertEqual(results.count("SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE"), 1)
        self.assertEqual(results.count("UNKNOWN"), 1)
        self.assertEqual(self.counts(), (1, 1))

    def test_source_has_no_network_dispatch_or_account_actions(self):
        import inspect
        from noc import isolated_atomic_advisory_outbox
        code = inspect.getsource(isolated_atomic_advisory_outbox)
        for forbidden in ("requests.", "urllib.request", "socket.", "SMTP(",
                          "send_email(", "HubClient", "docker", "os.environ",
                          "subprocess.", "ticket_create("):
            self.assertNotIn(forbidden, code)


if __name__ == "__main__":
    unittest.main()
