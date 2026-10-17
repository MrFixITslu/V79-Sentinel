"""Isolated local disk, concurrency and replay regressions. No live monitoring."""
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from noc.signed_owned_evidence import canonical_signed_payload
from noc.owned_replay_checkpoint import (
    evaluate_and_checkpoint_owned_evidence, prepare_owned_replay_store,
)

NOW = datetime(2026, 10, 15, 21, tzinfo=timezone.utc)
COLLECTOR = "v79-private-observer"
APPROVED = [
    {"name": "Hub", "url": "https://hub.v79sl.com/"},
    {"name": "Tiquet", "url": "https://tiquet.v79sl.com/"},
]
KEY = Ed25519PrivateKey.generate()  # Test-only, never persisted.
PUB = KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)


def envelope(sequence=5, *, status="up", observed="2026-10-15T20:59:00Z"):
    payload = {
        "version": 1, "collectorId": COLLECTOR, "sequence": sequence,
        "snapshot": {
            "mode": "live", "cycle": sequence, "last_check": observed, "error": None,
            "services": [
                {"name": "Hub", "url": "https://hub.v79sl.com/", "status": status, "cert_days": 90},
                {"name": "Tiquet", "url": "https://tiquet.v79sl.com/", "status": "warning", "cert_days": 30},
            ],
        },
    }
    signed = KEY.sign(canonical_signed_payload(payload))
    return payload | {"signature": base64.urlsafe_b64encode(signed).rstrip(b"=").decode("ascii")}


class DurableReplayTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = str(Path(self.dir.name) / "owned-collector-replay.sqlite")
        self.conn = sqlite3.connect(self.path, timeout=3)
        self.addCleanup(self.conn.close)
        self.conn.execute("PRAGMA synchronous=FULL")
        prepare_owned_replay_store(self.conn)

    def check(self, report, conn=None, **kw):
        return evaluate_and_checkpoint_owned_evidence(
            report, conn=conn or self.conn, trusted_collector_id=COLLECTOR,
            pinned_public_key=PUB, approved_targets=APPROVED, now=NOW, **kw
        )

    def count(self):
        return self.conn.execute("SELECT last_sequence FROM owned_observation_sequence WHERE collector_id=?", (COLLECTOR,)).fetchone()

    def test_first_signature_commits_candidate_but_never_authorizes_action(self):
        result = self.check(envelope())
        self.assertEqual(result["status"], "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE")
        self.assertTrue(result["sourceSignatureValid"])
        self.assertTrue(result["replayStatePersisted"])
        self.assertEqual(self.count()[0], 5)
        for key in ("trustedForExecutiveUse", "continuousMonitoringVerified",
                    "ticketCreationEnabled", "alertsDispatched", "customerReady"):
            self.assertFalse(result[key], key)

    def test_exact_signed_replay_denied_and_does_not_advance_state(self):
        e = envelope()
        self.check(e)
        denied = self.check(e)
        self.assertEqual(denied["status"], "UNKNOWN")
        self.assertEqual(denied["reason"], "MISSING_OR_REPLAYED_SEQUENCE")
        self.assertEqual(self.count()[0], 5)

    def test_restart_uses_durable_checkpoint_and_rejects_older_report(self):
        self.check(envelope())
        self.conn.close()
        self.conn = sqlite3.connect(self.path, timeout=3)
        self.conn.execute("PRAGMA synchronous=FULL")
        self.assertEqual(self.check(envelope(sequence=4))["status"], "UNKNOWN")
        self.assertEqual(self.count()[0], 5)
        self.assertTrue(self.check(envelope(sequence=6))["replayStatePersisted"])
        self.assertEqual(self.count()[0], 6)

    def test_signature_tamper_and_stale_report_never_mutate_checkpoint(self):
        self.check(envelope())
        tampered = envelope(sequence=7)
        tampered["snapshot"]["services"][0]["status"] = "down"
        self.assertEqual(self.check(tampered)["status"], "UNKNOWN")
        stale = envelope(sequence=8, observed="2026-10-15T20:00:00Z")
        self.assertEqual(self.check(stale)["status"], "UNKNOWN")
        self.assertEqual(self.count()[0], 5)

    def test_missing_schema_memory_db_and_unsafe_sync_fail_closed(self):
        missing = sqlite3.connect(str(Path(self.dir.name) / "missing.sqlite"))
        self.addCleanup(missing.close)
        self.assertEqual(self.check(envelope(), conn=missing)["status"], "UNKNOWN")
        memory = sqlite3.connect(":memory:")
        self.addCleanup(memory.close)
        prepare_owned_replay_store(memory)
        self.assertEqual(self.check(envelope(), conn=memory)["status"], "UNKNOWN")
        weak = sqlite3.connect(str(Path(self.dir.name) / "weak.sqlite"))
        self.addCleanup(weak.close)
        weak.execute("PRAGMA synchronous=OFF")
        prepare_owned_replay_store(weak)
        self.assertEqual(self.check(envelope(), conn=weak)["status"], "UNKNOWN")

    def test_invalid_pinned_key_and_unsigned_payload_fail_without_storage(self):
        fake = envelope()
        fake["signature"] = "X" * 86
        self.assertEqual(self.check(fake)["status"], "UNKNOWN")
        self.assertIsNone(self.count())

    def test_concurrent_duplicate_acceptance_only_once(self):
        current = envelope()
        def worker(_):
            con = sqlite3.connect(self.path, timeout=4)
            try:
                con.execute("PRAGMA synchronous=FULL")
                return self.check(current, conn=con)
            finally:
                con.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(worker, [0,1]))
        self.assertEqual(sum(x["replayStatePersisted"] is True for x in results), 1)
        self.assertEqual(self.count()[0], 5)

    def test_invalid_transaction_context_denied_without_rolling_back_caller(self):
        self.conn.execute("BEGIN IMMEDIATE")
        result = self.check(envelope())
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertTrue(self.conn.in_transaction)
        self.conn.rollback()


if __name__ == "__main__":
    unittest.main()
