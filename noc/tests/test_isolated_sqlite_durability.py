"""No-network adversarial journal-mode tests for every isolated state boundary.

The existing FULL synchronous check was insufficient if file-backed SQLite
was opened with journal_mode=OFF or MEMORY. These cases must not sign, consume
replay sequence, accept events, lease delivery, or record provider submission.
"""
from pathlib import Path
import sqlite3
import tempfile
import unittest

from noc.isolated_sqlite_durability import is_durable_isolated_sqlite
from noc.isolated_sender_counter import sign_with_atomic_sender_counter
from noc.owned_replay_checkpoint import evaluate_and_checkpoint_owned_evidence
from noc.owned_alert_state import _safe_store
from noc.isolated_atomic_advisory_outbox import evaluate_and_enqueue_isolated_advisory
from noc.isolated_founder_delivery_protocol import (
    FOUNDER_ROUTE, claim_founder_delivery, prepare_founder_delivery_store,
)
from noc.isolated_resend_founder_adapter import (
    reserve_isolated_resend_request, record_resend_submission_response,
)

COLLECTOR = "v79-durable-mode-test"
NOW = 1793234780


class UnsafeJournalModesFailClosed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def connection(self, label, mode):
        path = Path(self.tmp.name) / (label + ".sqlite3")
        conn = sqlite3.connect(str(path))
        self.addCleanup(conn.close)
        conn.execute("PRAGMA synchronous=FULL")
        actual = conn.execute(f"PRAGMA journal_mode={mode}").fetchone()[0].lower()
        self.assertEqual(actual, mode.lower())
        return conn

    def test_file_backed_off_or_memory_journal_rejected_everywhere(self):
        for mode in ("OFF", "MEMORY"):
            with self.subTest(mode=mode):
                conn = self.connection("bad_" + mode, mode)
                self.assertFalse(is_durable_isolated_sqlite(conn))
                with self.assertRaisesRegex(
                    ValueError, "DURABLE_SENDER_STORE_UNAVAILABLE"
                ):
                    sign_with_atomic_sender_counter(
                        {}, conn=conn, signer=object(), collector_id=COLLECTOR,
                        approved_targets=[], now=None,
                    )
                replay = evaluate_and_checkpoint_owned_evidence(
                    {}, conn=conn, trusted_collector_id=COLLECTOR,
                    pinned_public_key=b"x"*32, approved_targets=[],
                )
                self.assertEqual(replay["status"], "UNKNOWN")
                self.assertEqual(
                    replay["reason"], "DURABLE_REPLAY_STORE_UNAVAILABLE"
                )
                self.assertFalse(replay["replayStatePersisted"])
                outbox = evaluate_and_enqueue_isolated_advisory(
                    {}, conn=conn, trusted_collector_id=COLLECTOR,
                    pinned_public_key=b"x"*32, approved_targets=[],
                )
                self.assertEqual(
                    outbox["reason"], "ATOMIC_ADVISORY_STORE_UNAVAILABLE"
                )
                self.assertFalse(outbox["advisoryOutboxPersisted"])
                with self.assertRaisesRegex(ValueError, "UNTRUSTED_DELIVERY_STORE"):
                    claim_founder_delivery(
                        conn, route_id=FOUNDER_ROUTE, now_epoch=NOW,
                    )
                with self.assertRaisesRegex(ValueError, "ISOLATED_DURABLE_DB_REQUIRED"):
                    prepare_founder_delivery_store(conn)
                with self.assertRaisesRegex(ValueError, "NO_ACTIVE_FOUNDER_LEASE_OR_DB"):
                    reserve_isolated_resend_request(
                        conn, lease={"leaseUntil": NOW+30},
                        sender_address="alerts@v79sl.com",
                        founder_address="owner@example.net",
                        approved_sender="alerts@v79sl.com",
                        approved_founder="owner@example.net",
                        now_epoch=NOW,
                    )
                self.assertFalse(record_resend_submission_response(
                    conn, event_id="synthetic",
                    resend_email_id="11111111-1111-4111-8111-111111111111",
                    now_epoch=NOW,
                ))
                self.assertEqual(conn.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
                ).fetchone()[0], 0)

    def test_full_sync_durable_file_journals_pass_configuration_gate(self):
        for mode in ("DELETE", "WAL", "TRUNCATE", "PERSIST"):
            with self.subTest(mode=mode):
                conn = self.connection("good_" + mode, mode)
                self.assertTrue(is_durable_isolated_sqlite(conn))

    def test_private_signed_advisory_ledger_unsafe_journals_rejected(self):
        # Private candidate has stricter file and parent ownership checks.
        # Keep those intact while rejecting OFF/MEMORY journal operation.
        for mode in ("DELETE", "WAL", "OFF", "MEMORY"):
            with self.subTest(mode=mode):
                conn = self.connection("private_" + mode, mode)
                path = Path(self.tmp.name) / ("private_" + mode + ".sqlite3")
                path.chmod(0o600)
                self.assertEqual(
                    _safe_store(conn), mode in ("DELETE", "WAL")
                )

    def test_normal_sync_and_memory_main_db_fail_closed(self):
        conn = self.connection("normal", "DELETE")
        conn.execute("PRAGMA synchronous=NORMAL")
        self.assertFalse(is_durable_isolated_sqlite(conn))
        memory = sqlite3.connect(":memory:")
        self.addCleanup(memory.close)
        memory.execute("PRAGMA synchronous=FULL")
        self.assertFalse(is_durable_isolated_sqlite(memory))

    def test_open_transaction_fails_closed_even_with_safe_journal(self):
        conn = self.connection("transaction", "WAL")
        conn.execute("BEGIN")
        self.assertFalse(is_durable_isolated_sqlite(conn))
        conn.rollback()

    def test_no_network_secrets_or_production_activation(self):
        import inspect
        from noc import isolated_sqlite_durability
        code = inspect.getsource(isolated_sqlite_durability)
        for forbidden in (
            "requests.", "urllib.request", "socket.", "os.environ",
            "send_email(", "sqlite3.connect(", "subprocess.", "docker",
        ):
            self.assertNotIn(forbidden, code)


if __name__ == "__main__":
    unittest.main()
