"""Private signer acceptance tests — synthetic keys and isolated disk only.

No production signer key, monitor, email, network socket, Docker access or
host configuration is touched. These tests NEVER attest physical probe origin.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from noc.owner_private_candidate import accept_owner_private_candidate
from noc.owned_alert_state import prepare_advisory_store

COLLECTOR = "v79-isolated-test-collector"
TARGETS = [
    {"name": "Hub", "url": "https://hub.v79sl.com/"},
    {"name": "CombatZone", "url": "https://combatzone.v79sl.com/"},
]
START = datetime(2026, 10, 28, 18, 0, tzinfo=timezone.utc)


class PrivateSignerSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sentinel-private-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key_dir = self.root / "signer"
        self.key_dir.mkdir(mode=0o700)
        self.key_dir.chmod(0o700)
        signer = Ed25519PrivateKey.generate()  # TEST ONLY: never persisted outside temp directory.
        raw = signer.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        self.key_file = self.key_dir / "signer.ed25519.raw"
        self.key_file.write_bytes(raw)
        self.key_file.chmod(0o600)
        public = signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.pin = hashlib.sha256(public).hexdigest()
        self.db_path = self.root / "review.sqlite"
        self.db = sqlite3.connect(self.db_path, timeout=3)
        self.addCleanup(self.db.close)
        self.db_path.chmod(0o600)
        self.db.execute("PRAGMA synchronous=FULL")
        prepare_advisory_store(self.db)

    def snapshot(self, cycle=1, *, states=("up", "up"), timestamp=None):
        stamp = timestamp or START + timedelta(minutes=5 * (cycle - 1))
        return {
            "mode": "live",
            "cycle": cycle,
            "last_check": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "error": None,
            "services": [
                {
                    **target,
                    "status": state,
                    "http": 200 if state == "up" else 503,
                    "cert_days": 30,
                    "message": "SENSITIVE_UNTRUSTED_CONTENT_MUST_NOT_PERSIST",
                }
                for target, state in zip(TARGETS, states)
            ],
        }

    def accept(self, cycle=1, *, snapshot=None, key_dir=None, pin=None,
               conn=None, collector_id=COLLECTOR):
        return accept_owner_private_candidate(
            snapshot if snapshot is not None else self.snapshot(cycle),
            TARGETS,
            conn=self.db if conn is None else conn,
            collector_id=collector_id,
            key_dir=self.key_dir if key_dir is None else key_dir,
            expected_public_fingerprint=self.pin if pin is None else pin,
            now=START + timedelta(minutes=5 * (cycle - 1), seconds=20),
        )

    def cursor(self):
        return self.db.execute(
            "SELECT sequence FROM advisory_cursor WHERE collector=?", (COLLECTOR,)
        ).fetchone()

    def assert_fail_closed(self, result):
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertFalse(result["replayCommitted"])
        self.assertEqual(result["outboxProposals"], 0)
        for flag in (
            "trustedForExecutiveUse", "continuousMonitoringVerified",
            "alertsDispatched", "ticketCreationEnabled",
            "sourceProvenanceVerified",
        ):
            self.assertFalse(result[flag])

    def test_one_valid_private_candidate_is_review_only_and_not_an_alert(self):
        result = self.accept()
        self.assertEqual(result["status"], "SIGNED_CANDIDATE_REVIEW_ONLY")
        self.assertTrue(result["replayCommitted"])
        self.assertEqual(result["acceptedSequence"], 1)
        self.assertTrue(result["sourceSignatureValid"])
        self.assertFalse(result["trustedForExecutiveUse"])
        self.assertFalse(result["continuousMonitoringVerified"])
        self.assertFalse(result["sourceProvenanceVerified"])
        self.assertFalse(result["alertsDispatched"])
        self.assertFalse(result["ticketCreationEnabled"])
        self.assertEqual(result["outboxProposals"], 0)
        self.assertEqual(self.cursor(), (1,))
        self.assertNotIn("SENSITIVE_UNTRUSTED_CONTENT", str(result))

    def test_repeated_sequence_and_reset_are_rejected(self):
        self.assertTrue(self.accept()["replayCommitted"])
        self.assert_fail_closed(self.accept())
        self.assertEqual(self.cursor(), (1,))

    def test_restart_reuses_durable_cursor_and_refuses_replay(self):
        self.assertTrue(self.accept()["replayCommitted"])
        reopened = sqlite3.connect(self.db_path, timeout=3)
        self.addCleanup(reopened.close)
        reopened.execute("PRAGMA synchronous=FULL")
        self.assert_fail_closed(self.accept(conn=reopened))
        next_result = self.accept(2, conn=reopened)
        self.assertEqual(next_result["status"], "SIGNED_CANDIDATE_REVIEW_ONLY")
        self.assertEqual(self.cursor(), (2,))

    def test_owner_private_review_outbox_never_sends_messages(self):
        self.accept(1, snapshot=self.snapshot(1, states=("down", "up")))
        event = self.accept(2, snapshot=self.snapshot(2, states=("down", "up")))
        self.assertEqual(event["outboxProposals"], 1)
        self.assertFalse(event["alertsDispatched"])
        rows = self.db.execute(
            "SELECT service,kind,sequence,state FROM advisory_outbox"
        ).fetchall()
        self.assertEqual(rows, [("Hub", "down", 2, "review_required")])

    def test_untrusted_simulated_and_false_success_report_refused(self):
        for edit in (
            {"mode": "demo"},
            {"error": "collector error"},
            {"services": []},
        ):
            with self.subTest(edit=edit):
                self.assert_fail_closed(self.accept(snapshot=self.snapshot() | edit))
                self.assertIsNone(self.cursor())
        bad = self.snapshot()
        bad["services"][0]["http"] = 503
        self.assert_fail_closed(self.accept(snapshot=bad))
        self.assertIsNone(self.cursor())

    def test_owner_scope_and_collector_identity_fails_closed(self):
        self.assert_fail_closed(self.accept(collector_id="random"))
        bad = self.snapshot()
        bad["services"][0]["url"] = "https://not-v79.example/"
        self.assert_fail_closed(self.accept(snapshot=bad))
        self.assertIsNone(self.cursor())

    def test_public_key_pin_is_explicit_and_cannot_be_substituted(self):
        for pin in (None, "", "0" * 64, "X" * 64, 123):
            with self.subTest(pin=pin):
                # Pass explicit pin, including None, rather than helper default.
                outcome = accept_owner_private_candidate(
                    self.snapshot(), TARGETS,
                    conn=self.db, collector_id=COLLECTOR,
                    key_dir=self.key_dir, expected_public_fingerprint=pin,
                    now=START + timedelta(seconds=20),
                )
                self.assert_fail_closed(outcome)
        self.assertIsNone(self.cursor())

    def test_world_readable_or_wrong_size_key_rejected(self):
        self.key_file.chmod(0o644)
        self.assert_fail_closed(self.accept())
        self.key_file.chmod(0o600)
        self.key_file.write_bytes(b"not-an-ed25519-private-key")
        self.assert_fail_closed(self.accept())
        self.assertIsNone(self.cursor())

    def test_group_or_world_accessible_signer_directory_rejected(self):
        self.key_dir.chmod(0o755)
        self.assert_fail_closed(self.accept())
        self.key_dir.chmod(0o770)
        self.assert_fail_closed(self.accept())
        self.assertIsNone(self.cursor())

    def test_symlink_key_and_final_directory_rejected(self):
        real_key = self.key_dir / "real-key"
        self.key_file.rename(real_key)
        self.key_file.symlink_to(real_key)
        self.assert_fail_closed(self.accept())
        self.key_file.unlink()
        real_key.rename(self.key_file)
        alias = self.root / "alias"
        alias.symlink_to(self.key_dir, target_is_directory=True)
        self.assert_fail_closed(self.accept(key_dir=alias))
        self.assertIsNone(self.cursor())

    def test_ancestor_symlink_path_is_rejected(self):
        # A final-component O_NOFOLLOW is insufficient: /alias/signer resolves
        # an untrusted ancestor symlink unless every path segment is verified.
        alias_parent = self.root / "alias-parent"
        alias_parent.symlink_to(self.root, target_is_directory=True)
        self.assert_fail_closed(self.accept(key_dir=alias_parent / "signer"))
        self.assertIsNone(self.cursor())

    def test_invalid_silent_store_and_public_ledger_rejected(self):
        memory = sqlite3.connect(":memory:")
        self.addCleanup(memory.close)
        self.assert_fail_closed(self.accept(conn=memory))
        self.db_path.chmod(0o644)
        self.assert_fail_closed(self.accept())
        self.db_path.chmod(0o600)
        self.db.execute("PRAGMA synchronous=OFF")
        self.assert_fail_closed(self.accept())
        self.assertIsNone(self.cursor())

    def test_root_signing_and_relative_signer_directory_denied(self):
        with patch("noc.owner_private_candidate.os.geteuid", return_value=0):
            self.assert_fail_closed(self.accept())
        self.assert_fail_closed(self.accept(key_dir=Path("relative/signer")))
        self.assertIsNone(self.cursor())

    def test_bad_timestamp_does_not_advance_durable_checkpoint(self):
        stale = self.snapshot(timestamp=START - timedelta(hours=4))
        self.assert_fail_closed(self.accept(snapshot=stale))
        future = self.snapshot(timestamp=START + timedelta(hours=4))
        self.assert_fail_closed(self.accept(snapshot=future))
        self.assertIsNone(self.cursor())


    def test_unsafe_off_or_memory_journal_refuses_real_private_checkpoint(self):
        # File-backed and FULL synchronous alone are not a durable replay store.
        for mode in ("OFF", "MEMORY"):
            with self.subTest(mode=mode):
                actual = self.db.execute(
                    "PRAGMA journal_mode=" + mode
                ).fetchone()[0].upper()
                self.assertEqual(actual, mode)
                self.assert_fail_closed(self.accept())
                self.assertIsNone(self.cursor())
                self.db.execute("PRAGMA journal_mode=DELETE")

    def test_outbox_insert_failure_rolls_back_sequence_and_phase(self):
        # One DOWN is only a candidate; second sustained DOWN proposes review.
        first = self.accept(1, snapshot=self.snapshot(1, states=("down", "up")))
        self.assertTrue(first["replayCommitted"])
        self.assertEqual(self.cursor(), (1,))
        before = self.db.execute(
            "SELECT prior_sequence,bad_count FROM advisory_checks "
            "WHERE collector=? AND service=?", (COLLECTOR, "Hub")
        ).fetchone()
        self.db.executescript("""
          CREATE TEMP TRIGGER reject_test_outbox_insert
          BEFORE INSERT ON advisory_outbox
          BEGIN SELECT RAISE(FAIL, 'synthetic-only-outbox-denial'); END;
        """)
        second = self.accept(2, snapshot=self.snapshot(2, states=("down", "up")))
        self.assert_fail_closed(second)
        self.assertEqual(self.cursor(), (1,))
        self.assertEqual(before, self.db.execute(
            "SELECT prior_sequence,bad_count FROM advisory_checks "
            "WHERE collector=? AND service=?", (COLLECTOR, "Hub")
        ).fetchone())
        self.assertEqual(
            self.db.execute("SELECT COUNT(*) FROM advisory_outbox").fetchone()[0], 0
        )
        self.db.execute("DROP TRIGGER reject_test_outbox_insert")
        recovered = self.accept(2, snapshot=self.snapshot(2, states=("down", "up")))
        self.assertTrue(recovered["replayCommitted"])
        self.assertEqual(recovered["outboxProposals"], 1)
        self.assertEqual(self.cursor(), (2,))

    def test_same_sequence_across_two_workers_never_accepts_twice(self):
        from concurrent.futures import ThreadPoolExecutor

        def worker(_index):
            conn = sqlite3.connect(self.db_path, timeout=5)
            try:
                conn.execute("PRAGMA synchronous=FULL")
                return accept_owner_private_candidate(
                    self.snapshot(1), TARGETS, conn=conn,
                    collector_id=COLLECTOR, key_dir=self.key_dir,
                    expected_public_fingerprint=self.pin,
                    now=START + timedelta(seconds=20),
                )
            finally:
                conn.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(worker, (0, 1)))
        self.assertEqual(sum(x["replayCommitted"] for x in results), 1)
        self.assertEqual(self.cursor(), (1,))
        for outcome in results:
            self.assertFalse(outcome["sourceProvenanceVerified"])
            self.assertFalse(outcome["alertsDispatched"])

    def test_well_formed_fake_live_snapshot_never_proves_real_probe(self):
        # The trusted source of the dict remains UNSOLVED: a forged 'live'
        # snapshot can be signed, but MUST stay strictly review-only.
        forged = self.snapshot()
        result = self.accept(snapshot=forged)
        self.assertEqual(result["status"], "SIGNED_CANDIDATE_REVIEW_ONLY")
        self.assertFalse(result["sourceProvenanceVerified"])
        self.assertFalse(result["continuousMonitoringVerified"])
        self.assertFalse(result["trustedForExecutiveUse"])
        self.assertFalse(result["alertsDispatched"])
        self.assertFalse(result["ticketCreationEnabled"])



if __name__ == "__main__":
    unittest.main()
