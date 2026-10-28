"""Synthetic, no-network sender-counter and key-metadata security tests."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from noc.inprocess_probe_receipt import project_probe_cycle
from noc.isolated_sender_counter import (
    prepare_isolated_sender_store, sign_with_atomic_sender_counter,
)
from noc.isolated_key_mount_policy import verify_isolated_key_mount
from noc.owned_replay_checkpoint import (
    prepare_owned_replay_store, evaluate_and_checkpoint_owned_evidence,
)
from cryptography.hazmat.primitives import serialization

NOW = datetime(2026, 10, 28, 22, 30, tzinfo=timezone.utc)
COLLECTOR = "v79-dell-isolated-sender"
TARGETS = [
    {"name": "Website", "url": "https://v79sl.com/"},
    {"name": "V79 Hub", "url": "https://hub.v79sl.com/"},
    {"name": "Academy", "url": "https://academy.v79sl.com/"},
    {"name": "FFPRO", "url": "https://ffpro.v79sl.com/"},
    {"name": "V79 Tiquet", "url": "https://tiquet.v79sl.com/"},
    {"name": "Marketing", "url": "https://marketing.v79sl.com/"},
    {"name": "V79 POS", "url": "https://pos.v79sl.com/"},
]


def receipt(cycle=11, stamp=None):
    readings = [{**t, "status": "up", "http": 200, "cert_days": 40,
                 "message": "SECRET_NOT_EXPORTED"} for t in TARGETS]
    return project_probe_cycle(
        targets=TARGETS, readings=readings, cycle=cycle,
        observed_at=stamp or "2026-10-28T22:29:45+00:00", now=NOW,
    )


class IsolatedSenderCounterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "sender.sqlite3")
        self.conn = sqlite3.connect(self.path, timeout=3)
        self.addCleanup(lambda: self.conn.close())
        self.conn.execute("PRAGMA synchronous=FULL")
        prepare_isolated_sender_store(self.conn)
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, cycle=11, conn=None, data=None):
        return sign_with_atomic_sender_counter(
            receipt(cycle) if data is None else data,
            conn=self.conn if conn is None else conn,
            signer=self.key, collector_id=COLLECTOR,
            approved_targets=TARGETS, now=NOW,
        )

    def last(self):
        row = self.conn.execute(
            "SELECT last_cycle FROM sourcebound_sender_sequence WHERE collector_id=?",
            (COLLECTOR,),
        ).fetchone()
        return None if row is None else row[0]

    def test_sender_commits_before_exposing_signed_advisory(self):
        env = self.sign()
        self.assertEqual(self.last(), 11)
        self.assertEqual(env["sequence"], 11)
        self.assertNotIn("SECRET_NOT_EXPORTED", str(env))
        with self.assertRaisesRegex(ValueError, "SENDER_SIGN_OR_CHECKPOINT_REJECTED"):
            self.sign(11)
        self.assertEqual(self.last(), 11)

    def test_sender_restart_and_reset_cannot_replay_cycle(self):
        self.sign(11)
        self.conn.close()
        self.conn = sqlite3.connect(self.path, timeout=3)
        self.conn.execute("PRAGMA synchronous=FULL")
        for seq in (1, 10, 11):
            with self.subTest(seq=seq), self.assertRaises(ValueError):
                self.sign(seq)
        self.assertEqual(self.sign(13)["sequence"], 13)
        self.assertEqual(self.last(), 13)

    def test_receiver_independent_replay_db_accepts_once(self):
        env = self.sign()
        receiver_path = str(Path(self.temp.name) / "receiver.sqlite3")
        with sqlite3.connect(receiver_path) as receiver:
            receiver.execute("PRAGMA synchronous=FULL")
            prepare_owned_replay_store(receiver)
            kwargs = dict(
                trusted_collector_id=COLLECTOR, pinned_public_key=self.public,
                approved_targets=TARGETS, conn=receiver, now=NOW,
            )
            first = evaluate_and_checkpoint_owned_evidence(env, **kwargs)
            self.assertTrue(first["replayStatePersisted"])
            self.assertFalse(first["trustedForExecutiveUse"])
            self.assertFalse(first["alertsDispatched"])
            self.assertEqual(
                evaluate_and_checkpoint_owned_evidence(env, **kwargs)["status"],
                "UNKNOWN",
            )

    def test_invalid_scope_never_advances_sender_state(self):
        bad = receipt()
        bad["report"]["services"][0]["url"] = "https://attacker.example/"
        with self.assertRaises(ValueError):
            self.sign(data=bad)
        self.assertIsNone(self.last())
        self.assertEqual(self.sign()["sequence"], 11)

    def test_memory_or_unsafe_db_or_missing_schema_fail_closed(self):
        memory = sqlite3.connect(":memory:")
        self.addCleanup(memory.close)
        prepare_isolated_sender_store(memory)
        with self.assertRaises(ValueError):
            self.sign(conn=memory)
        low = sqlite3.connect(str(Path(self.temp.name) / "unsafe.sqlite3"))
        self.addCleanup(low.close)
        low.execute("PRAGMA synchronous=NORMAL")
        prepare_isolated_sender_store(low)
        with self.assertRaises(ValueError):
            self.sign(conn=low)
        absent = sqlite3.connect(str(Path(self.temp.name) / "missing.sqlite3"))
        self.addCleanup(absent.close)
        absent.execute("PRAGMA synchronous=FULL")
        with self.assertRaises(ValueError):
            self.sign(conn=absent)
        self.assertIsNone(self.last())

    def test_parallel_duplicate_only_one_signature_returned(self):
        def contender(_):
            with sqlite3.connect(self.path, timeout=4) as conn:
                conn.execute("PRAGMA synchronous=FULL")
                try:
                    return self.sign(conn=conn)["sequence"]
                except ValueError:
                    return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(contender, range(2)))
        self.assertEqual(results.count(11), 1)
        self.assertEqual(results.count(None), 1)
        self.assertEqual(self.last(), 11)

    def test_active_transaction_rejected(self):
        self.conn.execute("BEGIN")
        with self.assertRaises(ValueError):
            self.sign()
        self.conn.rollback()
        self.assertIsNone(self.last())


class KeyMetadataOnlyTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.skipTest("production key identity requires a non-root UID")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.key = self.root / "private.key"
        self.key.write_bytes(b"SYNTHETIC_NOT_A_REAL_PRIVATE_KEY")
        self.key.chmod(0o400)
        self.opts = dict(key_path=str(self.key), approved_dir=str(self.root),
                         expected_uid=os.geteuid())

    def test_good_metadata_does_not_read_key(self):
        result = verify_isolated_key_mount(**self.opts)
        self.assertTrue(result["keyMetadataAccepted"])
        self.assertFalse(result["keyMaterialRead"])
        self.assertFalse(result["authorizedToDeploy"])

    def test_file_world_or_group_read_rejected(self):
        for mode in (0o444, 0o640, 0o666):
            self.key.chmod(mode)
            with self.subTest(mode=oct(mode)), self.assertRaises(ValueError):
                verify_isolated_key_mount(**self.opts)

    def test_symlink_file_parent_and_hardlink_rejected(self):
        link = self.root / "link.key"
        link.symlink_to(self.key)
        with self.assertRaises(ValueError):
            verify_isolated_key_mount(**(self.opts | {"key_path": str(link)}))
        link.unlink()
        hard = self.root / "hard.key"
        os.link(self.key, hard)
        with self.assertRaises(ValueError):
            verify_isolated_key_mount(**self.opts)
        hard.unlink()
        nested = self.root / "nested"
        nested.mkdir()
        nested.chmod(0o700)
        nested_link = self.root / "nested-link"
        nested_link.symlink_to(nested)
        with self.assertRaises(ValueError):
            verify_isolated_key_mount(
                key_path=str(nested_link / "private.key"),
                approved_dir=str(self.root), expected_uid=os.geteuid(),
            )

    def test_unsafe_root_or_nested_directory_rejected(self):
        self.root.chmod(0o777)
        with self.assertRaises(ValueError):
            verify_isolated_key_mount(**self.opts)
        self.root.chmod(0o700)
        nested = self.root / "nested"
        nested.mkdir()
        nested.chmod(0o777)
        inner = nested / "inner.key"
        inner.write_bytes(b"dummy")
        inner.chmod(0o400)
        with self.assertRaises(ValueError):
            verify_isolated_key_mount(
                key_path=str(inner), approved_dir=str(self.root),
                expected_uid=os.geteuid(),
            )

    def test_outside_mount_traversal_and_wrong_uid_denied(self):
        with self.assertRaises(ValueError):
            verify_isolated_key_mount(**(self.opts | {"key_path": "/tmp/outside"}))
        with self.assertRaises(ValueError):
            verify_isolated_key_mount(**(self.opts | {"key_path": str(self.root) + "/../else"}))
        with self.assertRaises(ValueError):
            verify_isolated_key_mount(**(self.opts | {"expected_uid": os.geteuid() + 1}))


if __name__ == "__main__":
    unittest.main()
