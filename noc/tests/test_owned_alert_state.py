"""Isolated negative and durability tests; no network, sender or real identities."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from noc.legacy_monitor_proof import candidate_envelope
from noc.owned_alert_state import (
    ingest_candidate, passive_heartbeat, prepare_advisory_store,
)

KEY = Ed25519PrivateKey.generate()
PUB = KEY.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
COLLECTOR = "v79-owner-private-sensor"
TARGETS = [
    {"name": "Hub", "url": "https://hub.v79sl.com/"},
    {"name": "Tiquet", "url": "https://tiquet.v79sl.com/"},
]
FIRST = datetime(2026, 10, 28, 2, 0, tzinfo=timezone.utc)


def signed(seq, *, status="up", other="up", when=None):
    dt = when or (FIRST + timedelta(minutes=5*(seq-1)))
    services=[]
    for target, code, state in zip(TARGETS, [200 if status=="up" else 503,
                                             200 if other=="up" else 503],
                                            [status, other]):
        services.append({**target, "http":code, "status":state, "cert_days":60,
                         "message":"PASSWORD_DO_NOT_COPY_TO_DATABASE"})
    snapshot={"mode":"live","cycle":seq, "last_check":dt.isoformat(),
              "error":None, "services":services, "history":["private"]}
    return candidate_envelope(snapshot, TARGETS, collector_id=COLLECTOR,
        signer=KEY, previous_cycle=seq-1, now=dt+timedelta(seconds=25))


class OwnedAdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/"advisory.sqlite"
        self.db=sqlite3.connect(self.path, timeout=3)
        self.addCleanup(self.db.close)
        self.path.chmod(0o600)
        self.db.execute("PRAGMA synchronous=FULL")
        prepare_advisory_store(self.db)

    def ingest(self, seq, status="up", other="up", when=None, *, env=None, conn=None):
        instant=when or (FIRST+timedelta(minutes=5*(seq-1)))
        return ingest_candidate(conn or self.db,
            env if env is not None else signed(seq,status=status,other=other,when=instant),
            trusted_collector_id=COLLECTOR,pinned_public_key=PUB,
            approved_targets=TARGETS,now=instant+timedelta(seconds=25))

    def outbox(self):
        return self.db.execute(
            "SELECT service,kind,sequence,state FROM advisory_outbox ORDER BY id"
        ).fetchall()

    def cursor(self):
        return self.db.execute(
            "SELECT sequence FROM advisory_cursor WHERE collector=?", (COLLECTOR,)
        ).fetchone()

    def test_no_alert_or_privileged_action_from_one_signed_reading(self):
        verdict=self.ingest(1,status="down")
        self.assertEqual(verdict["status"],"SIGNED_CANDIDATE_REVIEW_ONLY")
        self.assertTrue(verdict["replayCommitted"])
        self.assertEqual(verdict["outboxProposals"],0)
        self.assertEqual(self.outbox(),[])
        self.assertFalse(verdict["alertsDispatched"])
        self.assertFalse(verdict["ticketCreationEnabled"])
        self.assertFalse(verdict["trustedForExecutiveUse"])
        self.assertEqual(self.cursor(),(1,))

    def test_two_failures_open_once_and_two_recoveries_close_once(self):
        self.ingest(1,status="down")
        self.ingest(2,status="down")
        self.assertEqual(self.outbox(),[("Hub","down",2,"review_required")])
        self.ingest(3,status="down")
        self.assertEqual(len(self.outbox()),1)
        self.ingest(4,status="up")
        self.assertEqual(len(self.outbox()),1)
        self.ingest(5,status="up")
        self.assertEqual(self.outbox(),[
            ("Hub","down",2,"review_required"),
            ("Hub","recovered",5,"review_required")
        ])
        self.ingest(6,status="up")
        self.assertEqual(len(self.outbox()),2)

    def test_warning_never_satisfies_down_or_recovery(self):
        self.ingest(1,status="down")
        self.ingest(2,status="warning")
        self.ingest(3,status="down")
        self.assertEqual(len(self.outbox()),0)
        self.ingest(4,status="down")
        self.assertEqual(len(self.outbox()),1)
        self.ingest(5,status="up")
        self.ingest(6,status="warning")
        self.ingest(7,status="up")
        self.assertEqual(len(self.outbox()),1)
        self.ingest(8,status="up")
        self.assertEqual(len(self.outbox()),2)

    def test_skipped_sequence_does_not_qualify_as_consecutive_failure(self):
        self.ingest(1,status="down")
        self.ingest(3,status="down")
        self.assertEqual(len(self.outbox()),0)
        self.ingest(4,status="down")
        self.assertEqual(self.outbox(),[("Hub","down",4,"review_required")])

    def test_short_spacing_rejects_false_repeat(self):
        t1=FIRST
        t2=t1+timedelta(seconds=30)
        self.ingest(1,status="down",when=t1)
        self.ingest(2,status="down",when=t2)
        self.assertEqual(len(self.outbox()),0)
        self.ingest(3,status="down",when=t1+timedelta(minutes=5))
        self.assertEqual(len(self.outbox()),1)

    def test_replay_stale_and_signature_tamper_are_not_checkpointed(self):
        self.ingest(1,status="down")
        replay=self.ingest(1,status="down")
        self.assertEqual(replay["status"],"UNKNOWN")
        self.assertFalse(replay["replayCommitted"])
        forged=signed(2,status="down")
        forged["snapshot"]["services"][0]["status"]="up"
        result=self.ingest(2,env=forged)
        self.assertFalse(result["replayCommitted"])
        self.assertEqual(self.cursor(),(1,))
        self.assertEqual(self.outbox(),[])

    def test_atomic_outbox_failure_does_not_lose_replay_cursor(self):
        self.ingest(1,status="down")
        self.db.execute("""
          CREATE TRIGGER stop_outbox BEFORE INSERT ON advisory_outbox
          BEGIN SELECT RAISE(ABORT,'synthetic disk failure'); END
        """)
        self.db.commit()
        denied=self.ingest(2,status="down")
        self.assertEqual(denied["status"],"UNKNOWN")
        self.assertEqual(self.cursor(),(1,))
        self.assertEqual(self.outbox(),[])
        self.db.execute("DROP TRIGGER stop_outbox")
        self.db.commit()
        accepted=self.ingest(2,status="down")
        self.assertEqual(accepted["outboxProposals"],1)
        self.assertEqual(self.cursor(),(2,))

    def test_concurrent_same_signed_reading_commits_exactly_once(self):
        env=signed(1)
        def worker(_):
            con=sqlite3.connect(self.path, timeout=5)
            try:
                con.execute("PRAGMA synchronous=FULL")
                return self.ingest(1,env=env,conn=con)
            finally:
                con.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(worker,range(2)))
        self.assertEqual(sum(r["replayCommitted"] for r in results),1)
        self.assertEqual(self.cursor(),(1,))

    def test_private_permissions_and_memory_store_required(self):
        self.path.chmod(0o644)
        self.assertEqual(self.ingest(1)["status"],"UNKNOWN")
        self.path.chmod(0o600)
        memory=sqlite3.connect(":memory:")
        self.addCleanup(memory.close)
        with self.assertRaises(PermissionError):
            prepare_advisory_store(memory)
        self.assertEqual(self.ingest(1)["status"],"SIGNED_CANDIDATE_REVIEW_ONLY")

    def test_reset_after_process_restart_fails_closed(self):
        self.ingest(1)
        self.db.close()
        self.db=sqlite3.connect(self.path,timeout=4)
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA synchronous=FULL")
        self.assertEqual(self.ingest(1)["status"],"UNKNOWN")
        self.assertEqual(self.ingest(2)["status"],"SIGNED_CANDIDATE_REVIEW_ONLY")

    def test_review_queue_capacity_fails_closed_with_no_lost_cursor(self):
        from noc import owned_alert_state
        self.ingest(1,status="down")
        with patch.object(owned_alert_state, "MAX_REVIEW_EVENTS", 0):
            verdict=self.ingest(2,status="down")
        self.assertEqual(verdict["status"],"UNKNOWN")
        self.assertEqual(self.cursor(),(1,))
        self.assertEqual(self.outbox(),[])
        self.assertEqual(self.ingest(2,status="down")["outboxProposals"],1)

    def test_invalid_external_watchdog_time_is_unknown(self):
        self.assertEqual(passive_heartbeat("2026-10-28T02:00:00Z",now=0)["status"],"UNKNOWN")
        self.assertEqual(passive_heartbeat("not-an-iso-timestamp",now=FIRST)["status"],"UNKNOWN")

    def test_raw_messages_never_in_advisory_database(self):
        self.ingest(1,status="down")
        self.ingest(2,status="down")
        content=b"".join(row[0] or b"" for row in
            self.db.execute("SELECT CAST(service AS BLOB) FROM advisory_outbox"))
        self.assertNotIn(b"PASSWORD_DO_NOT_COPY_TO_DATABASE",content)
        self.assertTrue(all(row[3]=="review_required" for row in self.outbox()))

    def test_external_heartbeat_classification_never_proves_host(self):
        baseline="2026-10-28T02:00:00Z"
        t=FIRST+timedelta(minutes=5)
        self.assertEqual(passive_heartbeat(baseline,now=t)["status"],
                         "RECENT_SIGNED_REPORT_ONLY")
        self.assertEqual(passive_heartbeat(baseline,now=t+timedelta(minutes=15))["status"],
                         "UNKNOWN")
        self.assertEqual(passive_heartbeat(baseline,now=FIRST-timedelta(minutes=1))["status"],
                         "UNKNOWN")
        self.assertEqual(passive_heartbeat(None,now=t)["status"],"UNKNOWN")


if __name__=="__main__":
    unittest.main()
