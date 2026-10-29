"""End-to-end local probe-loop callback -> signed review (synthetic only).

No network, Docker, private signer files, production databases or emails.
Patches probe_many to avoid contacting V79 websites. A fabricated callback
payload can still be constructed by an attacker: source provenance NOT proven.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sentinel
from noc.inprocess_probe_receipt import project_probe_cycle
from noc.isolated_sender_counter import prepare_isolated_sender_store
from noc.isolated_atomic_advisory_outbox import prepare_isolated_advisory_outbox
from noc.isolated_inprocess_review_bridge import IsolatedInProcessReviewBridge

STAMP = datetime.now(timezone.utc).replace(microsecond=0)
COLLECTOR = "v79-inprocess-isolated-review-only"
SECRET = "SYNTHETIC_SENSITIVE_SHOULD_NEVER_BE_IN_A_REVIEW_DB"
TARGETS = [
    {"name": "Website", "url": "https://v79sl.com/"},
    {"name": "V79 Hub", "url": "https://hub.v79sl.com/"},
    {"name": "Academy", "url": "https://academy.v79sl.com/"},
    {"name": "FFPRO", "url": "https://ffpro.v79sl.com/"},
    {"name": "V79 Tiquet", "url": "https://tiquet.v79sl.com/"},
    {"name": "Marketing", "url": "https://marketing.v79sl.com/"},
    {"name": "V79 POS", "url": "https://pos.v79sl.com/"},
]


def make_readings(*, fail=False):
    return [
        {**t, "status": "down" if fail and t["name"] == "V79 Tiquet" else "up",
         "http": 503 if fail and t["name"] == "V79 Tiquet" else 200,
         "cert_days": 45, "message": SECRET,
         "account": {"password": SECRET}, "ip": "192.0.2.5"}
        for t in TARGETS
    ]


class FakeStore:
    def __init__(self):
        self.saved = []
    def record(self, readings):
        self.saved.append(readings)
    def summary(self, targets):
        return {"history": [], "uptime24h": {}, "trend": []}


class EndProbeLoop(Exception):
    pass


class InProcessSignedReviewBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="v79-offline-callback-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sender = sqlite3.connect(self.root / "sender.sqlite3", timeout=3)
        self.receiver = sqlite3.connect(self.root / "receiver.sqlite3", timeout=3)
        self.addCleanup(self.sender.close)
        self.addCleanup(self.receiver.close)
        for conn in (self.sender, self.receiver):
            conn.execute("PRAGMA synchronous=FULL")
        prepare_isolated_sender_store(self.sender)
        prepare_isolated_advisory_outbox(self.receiver)
        self.key = Ed25519PrivateKey.generate()
        self.pin = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )

    def bridge(self, **changes):
        args = {
            "sender_store": self.sender, "receiver_store": self.receiver,
            "signer": self.key, "pinned_receiver_public_key": self.pin,
            "collector_id": COLLECTOR, "approved_targets": TARGETS,
        }
        args.update(changes)
        return IsolatedInProcessReviewBridge(**args)

    def receiver_rows(self):
        return self.receiver.execute(
            "SELECT event_id,state,advisory_json FROM signed_advisory_outbox"
            " ORDER BY sequence"
        ).fetchall()

    def sender_counter(self):
        row = self.sender.execute(
            "SELECT last_cycle FROM sourcebound_sender_sequence"
        ).fetchone()
        return None if row is None else row[0]

    def run_probe(self, *, sink=None, fail=False):
        fake = FakeStore()
        readings = make_readings(fail=fail)
        with patch.object(sentinel, "probe_many", return_value=readings) as probe, \
             patch.object(sentinel, "dell_status", return_value={}), \
             patch.object(sentinel, "now_iso", return_value=STAMP.isoformat()), \
             patch.object(sentinel.time, "monotonic", return_value=0), \
             patch.object(sentinel.time, "sleep", side_effect=EndProbeLoop), \
             patch.object(sentinel, "state", {"mode": "demo", "cycle": 0, "error": None}):
            with self.assertRaises(EndProbeLoop):
                sentinel.monitor_forever(TARGETS, fake, evidence_sink=sink)
            self.assertEqual(probe.call_count, 1)
            self.assertEqual(sentinel.state["mode"], "live")
            self.assertEqual(sentinel.state["cycle"], 1)
        return fake

    def test_real_probe_boundary_emits_single_signed_pending_not_alert(self):
        tap = self.bridge()
        collector = []
        def observe(value):
            collector.append(tap(value))
        store = self.run_probe(sink=observe, fail=True)
        self.assertEqual(len(store.saved), 1)
        self.assertEqual(self.sender_counter(), 1)
        rows = self.receiver_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], COLLECTOR + ":1")
        self.assertEqual(rows[0][1], "PENDING")
        self.assertNotIn(SECRET, str(rows))
        self.assertNotIn("192.0.2.5", str(rows))
        self.assertNotIn("password", str(rows))
        projection = json.loads(rows[0][2])
        self.assertEqual(len(projection["services"]), 7)
        self.assertFalse(projection["trustedForExecutiveUse"])
        self.assertFalse(projection["alertsDispatched"])
        self.assertEqual(len(collector), 1)
        self.assertEqual(collector[0]["status"],
                         "LOCAL_SIGNED_REVIEW_PROPOSAL_ONLY")
        for safety in (
            "sourceProvenanceVerified", "physicalProbeAttested",
            "trustedForExecutiveUse", "alertsDispatched",
            "ticketCreationEnabled", "productionApproved",
        ):
            self.assertFalse(collector[0][safety])
        self.assertEqual(self.receiver.execute(
            "SELECT last_sequence FROM owned_observation_sequence"
        ).fetchone(), (1,))

    def test_unregistered_default_live_sampler_does_not_sign(self):
        self.run_probe()  # Default evidence_sink=None
        self.assertEqual(self.sender_counter(), None)
        self.assertEqual(self.receiver_rows(), [])

    def test_reset_or_replay_never_advances_or_enqueues(self):
        tap = self.bridge()
        self.run_probe(sink=tap)
        self.assertEqual(len(self.receiver_rows()), 1)
        receipt = project_probe_cycle(
            targets=TARGETS, readings=make_readings(), cycle=1,
            observed_at=STAMP.isoformat(), now=STAMP,
        )
        with self.assertRaises(ValueError):
            tap(receipt)
        self.assertEqual(self.sender_counter(), 1)
        self.assertEqual(len(self.receiver_rows()), 1)

    def test_wrong_pinned_public_key_never_commits_receiver(self):
        tap = self.bridge(
            pinned_receiver_public_key=Ed25519PrivateKey.generate()
                .public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
        )
        # The hook MUST NOT interrupt a healthy monitoring cycle.
        self.run_probe(sink=tap)
        self.assertEqual(self.sender_counter(), 1)
        self.assertEqual(self.receiver_rows(), [])
        self.assertIsNone(self.receiver.execute(
            "SELECT last_sequence FROM owned_observation_sequence"
        ).fetchone())

    def test_receiver_write_failure_does_not_create_review_or_reset_sender(self):
        tap = self.bridge()
        self.receiver.executescript("""
          CREATE TRIGGER synthetic_denial
          BEFORE INSERT ON signed_advisory_outbox
          BEGIN SELECT RAISE(ABORT, 'test only'); END;
        """)
        self.run_probe(sink=tap)
        self.assertEqual(self.sender_counter(), 1)
        self.assertEqual(self.receiver_rows(), [])
        self.assertIsNone(self.receiver.execute(
            "SELECT last_sequence FROM owned_observation_sequence"
        ).fetchone())

    def test_refuse_same_file_or_memory_stores_and_unapproved_scope(self):
        other = sqlite3.connect(self.root / "sender.sqlite3")
        self.addCleanup(other.close)
        other.execute("PRAGMA synchronous=FULL")
        with self.assertRaises(ValueError):
            self.bridge(receiver_store=other)
        mem = sqlite3.connect(":memory:")
        self.addCleanup(mem.close)
        with self.assertRaises(ValueError):
            self.bridge(receiver_store=mem)
        with self.assertRaises(ValueError):
            self.bridge(approved_targets=TARGETS[:1] + TARGETS[:1])
        with self.assertRaises(ValueError):
            self.bridge(collector_id="bad collector id")

    def test_bad_external_receipt_not_equivalent_to_inprocess_probe(self):
        tap = self.bridge()
        for payload in (
            {"mode": "live", "cycle": 1, "services": make_readings()},
            {"mode": "IN_PROCESS_PROBE_CANDIDATE_ONLY", "report": {}},
            [],
            None,
        ):
            with self.subTest(kind=type(payload).__name__):
                with self.assertRaises(ValueError):
                    tap(payload)
        self.assertEqual(self.sender_counter(), None)
        self.assertEqual(self.receiver_rows(), [])

    def test_no_live_runtime_activation_or_network_transport(self):
        import inspect
        from noc import isolated_inprocess_review_bridge as module
        src = inspect.getsource(module)
        for forbidden in (
            "send_email(", "requests.", "urlopen(", "SMTP(", "docker ",
            "subprocess.", "os.environ", "ThreadingHTTPServer(",
            "Ed25519PrivateKey.generate(", "open(", "sqlite3.connect(",
        ):
            self.assertNotIn(forbidden, src)
        self.assertNotIn("IsolatedInProcessReviewBridge", inspect.getsource(sentinel.main))
        self.assertIn("sourceProvenanceVerified", src)


if __name__ == "__main__":
    unittest.main()
