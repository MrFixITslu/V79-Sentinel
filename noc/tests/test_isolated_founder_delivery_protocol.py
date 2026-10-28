"""Synthetic no-network founder-only delivery, retry, dedup and signed-ack tests."""
import base64
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
    prepare_isolated_advisory_outbox, evaluate_and_enqueue_isolated_advisory,
)
from noc.isolated_founder_delivery_protocol import (
    FOUNDER_ROUTE, canonical_ack, prepare_founder_delivery_store,
    stage_next_founder_advisory, claim_founder_delivery,
    accept_signed_founder_ack, retry_or_pause_founder_delivery,
)

NOW = datetime(2026, 10, 28, 22, 30, tzinfo=timezone.utc)
EPOCH = int(NOW.timestamp())
COLLECTOR = "v79-founder-source-pilot"
TARGETS = [
    {"name": "Website", "url": "https://v79sl.com/"},
    {"name": "V79 Hub", "url": "https://hub.v79sl.com/"},
    {"name": "Academy", "url": "https://academy.v79sl.com/"},
    {"name": "FFPRO", "url": "https://ffpro.v79sl.com/"},
    {"name": "V79 Tiquet", "url": "https://tiquet.v79sl.com/"},
    {"name": "Marketing", "url": "https://marketing.v79sl.com/"},
    {"name": "V79 POS", "url": "https://pos.v79sl.com/"},
]


class IsolatedFounderDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.sender = sqlite3.connect(str(Path(self.temp.name) / "sender.sqlite"), timeout=3)
        self.receiver_path = str(Path(self.temp.name) / "receiver.sqlite")
        self.receiver = sqlite3.connect(self.receiver_path, timeout=3)
        self.addCleanup(lambda: self.sender.close())
        self.addCleanup(lambda: self.receiver.close())
        self.sender.execute("PRAGMA synchronous=FULL")
        self.receiver.execute("PRAGMA synchronous=FULL")
        prepare_isolated_sender_store(self.sender)
        prepare_isolated_advisory_outbox(self.receiver)
        prepare_founder_delivery_store(self.receiver)
        self.source_key = Ed25519PrivateKey.generate()
        self.receiver_key = Ed25519PrivateKey.generate()
        self.source_pub = self.source_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        self.receiver_pub = self.receiver_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )

    def add(self, cycle, status="up"):
        readings = [
            {**t, "status": status if t["name"] == "V79 Tiquet" else "up",
             "http": 503 if status == "down" and t["name"] == "V79 Tiquet" else 200,
             "cert_days": 45, "message": "SECRET_NEVER_DELIVER"}
            for t in TARGETS
        ]
        projected = project_probe_cycle(
            targets=TARGETS, readings=readings, cycle=cycle,
            observed_at="2026-10-28T22:29:45+00:00", now=NOW,
        )
        signed = sign_with_atomic_sender_counter(
            projected, conn=self.sender, signer=self.source_key,
            collector_id=COLLECTOR, approved_targets=TARGETS, now=NOW,
        )
        accepted = evaluate_and_enqueue_isolated_advisory(
            signed, conn=self.receiver, trusted_collector_id=COLLECTOR,
            pinned_public_key=self.source_pub, approved_targets=TARGETS, now=NOW,
        )
        self.assertTrue(accepted["advisoryOutboxPersisted"])
        return stage_next_founder_advisory(
            self.receiver, route_id=FOUNDER_ROUTE, collector_id=COLLECTOR,
            now_epoch=EPOCH,
        )

    def ack(self, lease, *, private=None, **edits):
        payload = {
            "version": 1, "eventId": lease["eventId"],
            "routeId": lease["routeId"], "leaseNonce": lease["leaseNonce"],
            "payloadSha256": lease["payloadSha256"],
            "acceptedAtEpoch": EPOCH + 1,
        }
        payload.update(edits)
        key = private or self.receiver_key
        payload["signature"] = base64.urlsafe_b64encode(
            key.sign(canonical_ack(payload))
        ).rstrip(b"=").decode()
        return payload

    def count(self):
        return self.receiver.execute(
            "SELECT COUNT(*) FROM founder_delivery_queue"
        ).fetchone()[0]

    def test_baseline_fault_duplicate_and_recovery_only_two_events(self):
        self.assertEqual(self.add(11, "up"), "SUPPRESSED")
        self.assertEqual(self.add(12, "down"), "QUEUED_REVIEW_ONLY")
        self.assertEqual(self.add(13, "down"), "SUPPRESSED")
        self.assertEqual(self.add(14, "up"), "QUEUED_REVIEW_ONLY")
        self.assertEqual(self.count(), 2)
        payloads = [json.loads(row[0]) for row in self.receiver.execute(
            "SELECT payload_json FROM founder_delivery_queue ORDER BY event_id"
        )]
        self.assertEqual(
            [p["kind"] for p in payloads],
            ["ATTENTION_REPORTED", "RECOVERY_REPORTED_UNVERIFIED"],
        )
        for payload in payloads:
            self.assertEqual(payload["routeId"], FOUNDER_ROUTE)
            self.assertEqual(payload["classification"], "UNVERIFIED_OWNER_ADVISORY")
            self.assertNotIn("SECRET_NEVER_DELIVER", str(payload))
            self.assertNotIn("https://", str(payload))

    def test_signature_bound_ack_is_required_and_once_only(self):
        self.add(11, "down")
        lease = claim_founder_delivery(self.receiver, route_id=FOUNDER_ROUTE,
                                       now_epoch=EPOCH)
        self.assertEqual(lease["attempt"], 1)
        self.assertEqual(lease["payload"]["classification"], "UNVERIFIED_OWNER_ADVISORY")
        self.assertFalse(accept_signed_founder_ack(
            self.receiver, route_id=FOUNDER_ROUTE, lease=lease,
            ack=self.ack(lease, private=Ed25519PrivateKey.generate()),
            pinned_receiver_public_key=self.receiver_pub, now_epoch=EPOCH+1,
        ))
        self.assertFalse(accept_signed_founder_ack(
            self.receiver, route_id=FOUNDER_ROUTE, lease=lease,
            ack=self.ack(lease, routeId="v79-customer-random"),
            pinned_receiver_public_key=self.receiver_pub, now_epoch=EPOCH+1,
        ))
        accepted = self.ack(lease)
        self.assertTrue(accept_signed_founder_ack(
            self.receiver, route_id=FOUNDER_ROUTE, lease=lease,
            ack=accepted, pinned_receiver_public_key=self.receiver_pub,
            now_epoch=EPOCH+1,
        ))
        self.assertFalse(accept_signed_founder_ack(
            self.receiver, route_id=FOUNDER_ROUTE, lease=lease,
            ack=accepted, pinned_receiver_public_key=self.receiver_pub,
            now_epoch=EPOCH+1,
        ))
        self.assertIsNone(claim_founder_delivery(
            self.receiver, route_id=FOUNDER_ROUTE, now_epoch=EPOCH+2))
        row = self.receiver.execute(
            "SELECT state,ack_at FROM founder_delivery_queue"
        ).fetchone()
        self.assertEqual(row, ("ACKED", EPOCH+1))

    def test_no_other_recipient_route_is_permitted(self):
        self.add(11, "down")
        for operation in (
            lambda: claim_founder_delivery(self.receiver,
                                            route_id="any-email@example.com",
                                            now_epoch=EPOCH),
            lambda: stage_next_founder_advisory(
                self.receiver, route_id="v79-customer", collector_id=COLLECTOR,
                now_epoch=EPOCH),
        ):
            with self.assertRaises(ValueError):
                operation()
        self.assertEqual(self.count(), 1)

    def test_backoff_then_manual_hold_after_five_failures(self):
        self.add(11, "down")
        clock = EPOCH
        for attempt in range(1, 6):
            lease = claim_founder_delivery(self.receiver, route_id=FOUNDER_ROUTE,
                                           now_epoch=clock)
            self.assertEqual(lease["attempt"], attempt)
            state = retry_or_pause_founder_delivery(
                self.receiver, route_id=FOUNDER_ROUTE,
                lease=lease, now_epoch=clock,
            )
            self.assertEqual(state, "PAUSED_MANUAL_REVIEW" if attempt == 5
                             else "RETRY_SCHEDULED")
            clock += 30 * 2**(attempt-1)
        self.assertIsNone(claim_founder_delivery(
            self.receiver, route_id=FOUNDER_ROUTE, now_epoch=clock+10000))
        self.assertEqual(self.receiver.execute(
            "SELECT state,attempts FROM founder_delivery_queue"
        ).fetchone(), ("PAUSED", 5))

    def test_expired_lease_reissued_and_old_ack_rejected(self):
        self.add(11, "down")
        first = claim_founder_delivery(self.receiver, route_id=FOUNDER_ROUTE,
                                       now_epoch=EPOCH)
        self.assertIsNone(claim_founder_delivery(
            self.receiver, route_id=FOUNDER_ROUTE, now_epoch=EPOCH+59))
        second = claim_founder_delivery(self.receiver, route_id=FOUNDER_ROUTE,
                                        now_epoch=EPOCH+61)
        self.assertEqual(second["attempt"], 2)
        self.assertNotEqual(first["leaseNonce"], second["leaseNonce"])
        self.assertFalse(accept_signed_founder_ack(
            self.receiver, route_id=FOUNDER_ROUTE, lease=first,
            ack=self.ack(first), pinned_receiver_public_key=self.receiver_pub,
            now_epoch=EPOCH+61,
        ))
        self.assertTrue(accept_signed_founder_ack(
            self.receiver, route_id=FOUNDER_ROUTE, lease=second,
            ack=self.ack(second, acceptedAtEpoch=EPOCH+62),
            pinned_receiver_public_key=self.receiver_pub,
            now_epoch=EPOCH+62,
        ))

    def test_missing_outbox_and_unsafe_store_do_not_create_delivery(self):
        fresh = sqlite3.connect(":memory:")
        self.addCleanup(fresh.close)
        fresh.execute("PRAGMA synchronous=FULL")
        with self.assertRaises(ValueError):
            prepare_founder_delivery_store(fresh)
        with self.assertRaises(ValueError):
            claim_founder_delivery(fresh, route_id=FOUNDER_ROUTE,
                                   now_epoch=EPOCH)
        self.assertEqual(self.count(), 0)

    def test_parallel_lease_only_one_worker_claims(self):
        self.add(11, "down")
        def claim(_):
            with sqlite3.connect(self.receiver_path, timeout=4) as conn:
                conn.execute("PRAGMA synchronous=FULL")
                return claim_founder_delivery(
                    conn, route_id=FOUNDER_ROUTE, now_epoch=EPOCH,
                )
        with ThreadPoolExecutor(max_workers=2) as pool:
            items = list(pool.map(claim, range(2)))
        self.assertEqual(sum(x is not None for x in items), 1)
        self.assertEqual(self.receiver.execute(
            "SELECT attempts FROM founder_delivery_queue"
        ).fetchone()[0], 1)

    def test_missing_or_wrong_signed_ack_cannot_claim_delivery(self):
        self.add(11, "down")
        lease = claim_founder_delivery(self.receiver, route_id=FOUNDER_ROUTE,
                                       now_epoch=EPOCH)
        for change in (
            {"leaseNonce": "f" * 48},
            {"payloadSha256": "0" * 64},
            {"acceptedAtEpoch": EPOCH-301},
        ):
            with self.subTest(change=change):
                self.assertFalse(accept_signed_founder_ack(
                    self.receiver, route_id=FOUNDER_ROUTE, lease=lease,
                    ack=self.ack(lease, **change),
                    pinned_receiver_public_key=self.receiver_pub,
                    now_epoch=EPOCH+1,
                ))
        self.assertEqual(self.receiver.execute(
            "SELECT state FROM founder_delivery_queue"
        ).fetchone()[0], "LEASED")

    def test_no_network_dispatch_or_runtime_activation(self):
        import inspect
        from noc import isolated_founder_delivery_protocol
        source = inspect.getsource(isolated_founder_delivery_protocol)
        for forbidden in (
            "urllib.request", "requests.", "socket.", "SMTP(", "send_email(",
            "subprocess.", "os.environ", "load_pem_private_key(", "http.server",
            "HubClient", "WiPay", "docker run",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
