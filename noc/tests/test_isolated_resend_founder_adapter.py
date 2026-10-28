"""Synthetic zero-network tests for optional Resend founder email adapter."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from noc.inprocess_probe_receipt import project_probe_cycle
from noc.isolated_sender_counter import (
    prepare_isolated_sender_store, sign_with_atomic_sender_counter,
)
from noc.isolated_atomic_advisory_outbox import (
    prepare_isolated_advisory_outbox, evaluate_and_enqueue_isolated_advisory,
)
from noc.isolated_founder_delivery_protocol import (
    FOUNDER_ROUTE, prepare_founder_delivery_store,
    stage_next_founder_advisory, claim_founder_delivery,
)
from noc.isolated_resend_founder_adapter import (
    prepare_isolated_resend_submission_store,
    reserve_isolated_resend_request, record_resend_submission_response,
)

NOW = datetime(2026, 10, 28, 22, 30, tzinfo=timezone.utc)
EPOCH = int(NOW.timestamp())
COLLECTOR = "v79-resend-isolated-test"
SENDER = "alerts@v79sl.com"  # FICTIONAL TEST FIXTURE - NOT AN AUTHORIZED SENDER
RECIPIENT = "owner@example.net"  # FICTIONAL TEST FIXTURE - NOT A LIVE RECIPIENT
EMAIL_ID = "f020fd61-2a6d-43f8-8702-dcb2cf79a441"
TARGETS = [
    {"name": "Website", "url": "https://v79sl.com/"},
    {"name": "V79 Hub", "url": "https://hub.v79sl.com/"},
    {"name": "V79 Tiquet", "url": "https://tiquet.v79sl.com/"},
]


class ResendFounderAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.sender = sqlite3.connect(str(Path(self.temp.name) / "sender.sqlite"))
        self.receiver_path = str(Path(self.temp.name) / "receiver.sqlite")
        self.receiver = sqlite3.connect(self.receiver_path)
        self.addCleanup(lambda: self.sender.close())
        self.addCleanup(lambda: self.receiver.close())
        for conn in (self.sender, self.receiver):
            conn.execute("PRAGMA synchronous=FULL")
        prepare_isolated_sender_store(self.sender)
        prepare_isolated_advisory_outbox(self.receiver)
        prepare_founder_delivery_store(self.receiver)
        prepare_isolated_resend_submission_store(self.receiver)
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )

    def make_fault(self, cycle=11):
        stamp = "2026-10-28T22:29:45+00:00"
        readings = [
            {**target, "status": "down" if target["name"] == "V79 Tiquet" else "up",
             "http": 503 if target["name"] == "V79 Tiquet" else 200,
             "cert_days": 70, "message": "FAKE_PRIVATE_ACCOUNT_TOKEN"}
            for target in TARGETS
        ]
        projection = project_probe_cycle(
            targets=TARGETS, readings=readings,
            cycle=cycle, observed_at=stamp, now=NOW,
        )
        signed = sign_with_atomic_sender_counter(
            projection, conn=self.sender, signer=self.private,
            collector_id=COLLECTOR, approved_targets=TARGETS, now=NOW,
        )
        verdict = evaluate_and_enqueue_isolated_advisory(
            signed, conn=self.receiver, trusted_collector_id=COLLECTOR,
            pinned_public_key=self.public, approved_targets=TARGETS, now=NOW,
        )
        self.assertTrue(verdict["advisoryOutboxPersisted"])
        self.assertEqual(
            stage_next_founder_advisory(
                self.receiver, route_id=FOUNDER_ROUTE,
                collector_id=COLLECTOR, now_epoch=EPOCH,
            ), "QUEUED_REVIEW_ONLY"
        )
        lease = claim_founder_delivery(
            self.receiver, route_id=FOUNDER_ROUTE, now_epoch=EPOCH,
        )
        self.assertIsNotNone(lease)
        return lease

    def prepare(self, lease, *, conn=None, clock=EPOCH, **changes):
        args = dict(
            lease=lease, sender_address=SENDER, founder_address=RECIPIENT,
            approved_sender=SENDER, approved_founder=RECIPIENT,
            now_epoch=clock,
        )
        args.update(changes)
        return reserve_isolated_resend_request(
            self.receiver if conn is None else conn, **args,
        )

    def test_signed_source_to_fixed_founder_resend_request(self):
        lease = self.make_fault()
        outgoing = self.prepare(lease)
        self.assertEqual(outgoing["from"], SENDER)
        self.assertEqual(outgoing["to"], [RECIPIENT])
        self.assertTrue(outgoing["idempotencyKey"].startswith("v79sentinel/"))
        self.assertIn("UNVERIFIED", outgoing["text"])
        self.assertNotIn("FAKE_PRIVATE_ACCOUNT_TOKEN", str(outgoing))
        self.assertEqual(set(outgoing), {
            "to", "from", "subject", "text", "idempotencyKey"
        })
        stored = self.receiver.execute(
            "SELECT request_sha256,resend_email_id "
            "FROM resend_founder_submission WHERE event_id=?",
            (lease["eventId"],),
        ).fetchone()
        self.assertEqual(len(stored[0]), 64)
        self.assertIsNone(stored[1])
        self.assertEqual(self.receiver.execute(
            "SELECT state FROM founder_delivery_queue"
        ).fetchone()[0], "LEASED")

    def test_identical_retry_preserves_message_and_key(self):
        first_lease = self.make_fault()
        one = self.prepare(first_lease)
        retry_lease = claim_founder_delivery(
            self.receiver, route_id=FOUNDER_ROUTE, now_epoch=EPOCH+61,
        )
        self.assertEqual(retry_lease["attempt"], 2)
        two = self.prepare(retry_lease, clock=EPOCH+61)
        self.assertEqual(one, two)
        self.assertEqual(self.receiver.execute(
            "SELECT COUNT(*) FROM resend_founder_submission"
        ).fetchone()[0], 1)

    def test_provider_acceptance_is_not_ack_or_delivery(self):
        lease = self.make_fault()
        self.prepare(lease)
        self.assertFalse(record_resend_submission_response(
            self.receiver, event_id=lease["eventId"],
            resend_email_id="not-a-uuid", now_epoch=EPOCH+1,
        ))
        self.assertTrue(record_resend_submission_response(
            self.receiver, event_id=lease["eventId"],
            resend_email_id=EMAIL_ID, now_epoch=EPOCH+1,
        ))
        self.assertTrue(record_resend_submission_response(
            self.receiver, event_id=lease["eventId"],
            resend_email_id=EMAIL_ID, now_epoch=EPOCH+2,
        ))
        self.assertFalse(record_resend_submission_response(
            self.receiver, event_id=lease["eventId"],
            resend_email_id="11111111-1111-4111-8111-111111111111",
            now_epoch=EPOCH+2,
        ))
        self.assertEqual(self.receiver.execute(
            "SELECT state,ack_at FROM founder_delivery_queue"
        ).fetchone(), ("LEASED", None))

    def test_recipient_or_sender_substitution_is_rejected(self):
        lease = self.make_fault()
        for override in [
            {"founder_address": "client@example.net"},
            {"sender_address": "evil@example.com"},
            {"approved_sender": "admin@v79sl.com"},
            {"approved_founder": "someoneelse@example.net"},
            {"sender_address": "ALERTS@v79sl.com"},
        ]:
            with self.subTest(override=override), self.assertRaises(ValueError):
                self.prepare(lease, **override)
        self.assertEqual(self.receiver.execute(
            "SELECT COUNT(*) FROM resend_founder_submission"
        ).fetchone()[0], 0)

    def test_tampered_payload_or_expired_lease_rejected(self):
        lease = self.make_fault()
        changed = dict(lease, payload=dict(lease["payload"]))
        changed["payload"]["kind"] = "RECOVERY_REPORTED_UNVERIFIED"
        with self.assertRaises(ValueError):
            self.prepare(changed)
        with self.assertRaises(ValueError):
            self.prepare(lease, clock=EPOCH+61)
        self.assertEqual(self.receiver.execute(
            "SELECT COUNT(*) FROM resend_founder_submission"
        ).fetchone()[0], 0)

    def test_provider_key_expiry_requires_manual_hold(self):
        original = self.make_fault()
        self.prepare(original)
        reissued = claim_founder_delivery(
            self.receiver, route_id=FOUNDER_ROUTE,
            now_epoch=EPOCH+23*3600,
        )
        self.assertIsNotNone(reissued)
        with self.assertRaisesRegex(ValueError, "RESEND_REQUEST_RESERVATION_HOLD"):
            self.prepare(reissued, clock=EPOCH+23*3600)

    def test_missing_schema_and_unsafe_db_fail_closed(self):
        lease = self.make_fault()
        self.receiver.execute("DROP TABLE resend_founder_submission")
        self.receiver.commit()
        with self.assertRaises(ValueError):
            self.prepare(lease)
        self.assertEqual(self.receiver.execute(
            "SELECT state FROM founder_delivery_queue"
        ).fetchone()[0], "LEASED")
        memory = sqlite3.connect(":memory:")
        self.addCleanup(memory.close)
        with self.assertRaises(ValueError):
            prepare_isolated_resend_submission_store(memory)

    def test_offline_only_no_live_auth_or_network(self):
        import inspect
        from noc import isolated_resend_founder_adapter
        source = inspect.getsource(isolated_resend_founder_adapter)
        for forbidden in (
            "requests.", "urllib.request", "socket.", "SMTP(",
            "send_email(", "os.environ", "subprocess.", "load_pem_private_key(",
            "Authorization", "Bearer ", "resend.api_key",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
