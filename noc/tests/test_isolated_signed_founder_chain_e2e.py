"""Whole signed-review-to-founder-request chain: SYNTHETIC, OFFLINE, NEVER SEND.

Every probe is a fabricated seven-target fixture, not evidence of a real
network request. Keys are random ephemeral test objects; databases are fresh
temporary files. An acknowledged simulated endpoint is NOT founder email
delivery. Nothing here registers an actual collector, key, service or sender.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
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
    accept_signed_founder_ack, canonical_ack,
)
from noc.isolated_resend_founder_adapter import (
    prepare_isolated_resend_submission_store,
    reserve_isolated_resend_request, record_resend_submission_response,
)

NOW = datetime(2026, 10, 29, 10, 0, tzinfo=timezone.utc)
EPOCH = int(NOW.timestamp())
COLLECTOR = "v79-offline-complete-chain-test"
SENDER = "alerts@v79sl.com"  # FICTIONAL; no access or authorization to send
RECIPIENT = "synthetic-founder@example.net"  # FICTIONAL; never delivered
TEST_PROVIDER_ID = "f020fd61-2a6d-43f8-8702-dcb2cf79a441"
TARGETS = [
    {"name": "Website", "url": "https://v79sl.com/"},
    {"name": "V79 Hub", "url": "https://hub.v79sl.com/"},
    {"name": "Academy", "url": "https://academy.v79sl.com/"},
    {"name": "FFPRO", "url": "https://ffpro.v79sl.com/"},
    {"name": "V79 Tiquet", "url": "https://tiquet.v79sl.com/"},
    {"name": "Marketing", "url": "https://marketing.v79sl.com/"},
    {"name": "V79 POS", "url": "https://pos.v79sl.com/"},
]


class FullChainOfflineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sentinel-offline-chain-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.sender_path, self.receiver_path = root / "source.sqlite", root / "owner.sqlite"
        self.sender = sqlite3.connect(self.sender_path, timeout=3)
        self.receiver = sqlite3.connect(self.receiver_path, timeout=3)
        self.addCleanup(self.sender.close)
        self.addCleanup(self.receiver.close)
        for db in (self.sender, self.receiver):
            db.execute("PRAGMA synchronous=FULL")
        prepare_isolated_sender_store(self.sender)
        prepare_isolated_advisory_outbox(self.receiver)
        prepare_founder_delivery_store(self.receiver)
        prepare_isolated_resend_submission_store(self.receiver)
        self.signer = Ed25519PrivateKey.generate()
        self.signer_public = self.signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        self.ack_key = Ed25519PrivateKey.generate()
        self.ack_public = self.ack_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )

    def fixture(self, cycle, *, fault=False):
        # Deliberately fabricated: the same payload could be invented by a
        # compromised signer. The pipeline must NEVER upgrade its provenance.
        measured = NOW - timedelta(seconds=140 - 10 * (cycle - 41))
        readings = [
            {
                **target,
                "status": "down" if fault and target["name"] == "V79 Tiquet" else "up",
                "http": 503 if fault and target["name"] == "V79 Tiquet" else 200,
                "cert_days": 45,
                "message": "DO_NOT_LEAK_SYNTHETIC_ACCOUNT_DATA",
            }
            for target in TARGETS
        ]
        return project_probe_cycle(
            targets=TARGETS, readings=readings, cycle=cycle,
            observed_at=measured.isoformat(), now=NOW,
        )

    def sign(self, cycle, *, fault=False):
        return sign_with_atomic_sender_counter(
            self.fixture(cycle, fault=fault), conn=self.sender, signer=self.signer,
            collector_id=COLLECTOR, approved_targets=TARGETS, now=NOW,
        )

    def receive(self, envelope):
        return evaluate_and_enqueue_isolated_advisory(
            envelope, conn=self.receiver, trusted_collector_id=COLLECTOR,
            pinned_public_key=self.signer_public,
            approved_targets=TARGETS, now=NOW,
        )

    def stage(self):
        return stage_next_founder_advisory(
            self.receiver, route_id=FOUNDER_ROUTE, collector_id=COLLECTOR,
            now_epoch=EPOCH,
        )

    def reserve(self, lease, *, epoch=EPOCH):
        return reserve_isolated_resend_request(
            self.receiver, lease=lease, sender_address=SENDER,
            founder_address=RECIPIENT, approved_sender=SENDER,
            approved_founder=RECIPIENT, now_epoch=epoch,
        )

    def ack(self, lease, *, signer=None, accepted_epoch=EPOCH + 1):
        content = {
            "version": 1, "eventId": lease["eventId"],
            "routeId": lease["routeId"], "leaseNonce": lease["leaseNonce"],
            "payloadSha256": lease["payloadSha256"],
            "acceptedAtEpoch": accepted_epoch,
        }
        key = signer or self.ack_key
        content["signature"] = base64.urlsafe_b64encode(
            key.sign(canonical_ack(content))
        ).rstrip(b"=").decode()
        return content

    def count(self, name):
        return self.receiver.execute(
            "SELECT COUNT(*) FROM " + name
        ).fetchone()[0]

    def test_full_baseline_fault_duplicate_recovery_resend_and_signed_ack(self):
        outputs = []
        for cycle, fault in ((41, False), (42, True), (43, True), (44, False)):
            signed = self.sign(cycle, fault=fault)
            outcome = self.receive(signed)
            self.assertTrue(outcome["advisoryOutboxPersisted"])
            self.assertFalse(outcome["trustedForExecutiveUse"])
            self.assertFalse(outcome["continuousMonitoringVerified"])
            self.assertFalse(outcome["alertsDispatched"])
            outputs.append(self.stage())
        self.assertEqual(outputs, [
            "SUPPRESSED", "QUEUED_REVIEW_ONLY", "SUPPRESSED",
            "QUEUED_REVIEW_ONLY",
        ])
        self.assertEqual(self.count("signed_advisory_outbox"), 4)
        self.assertEqual(self.count("founder_delivery_queue"), 2)

        first = claim_founder_delivery(
            self.receiver, route_id=FOUNDER_ROUTE, now_epoch=EPOCH,
        )
        self.assertEqual(first["eventId"], f"{COLLECTOR}:42")
        request = self.reserve(first)
        self.assertEqual(request["to"], [RECIPIENT])
        self.assertIn("UNVERIFIED", request["text"])
        self.assertNotIn("DO_NOT_LEAK_SYNTHETIC_ACCOUNT_DATA", str(request))
        self.assertEqual(
            set(request), {"from", "to", "subject", "text", "idempotencyKey"},
        )
        self.assertTrue(record_resend_submission_response(
            self.receiver, event_id=first["eventId"],
            resend_email_id=TEST_PROVIDER_ID, now_epoch=EPOCH + 1,
        ))
        self.assertEqual(
            self.receiver.execute(
                "SELECT state,ack_at FROM founder_delivery_queue WHERE event_id=?",
                (first["eventId"],),
            ).fetchone(), ("LEASED", None),
        )  # Provider acceptance is NOT founder inbox delivery/ACK.

        second_lease = claim_founder_delivery(
            self.receiver, route_id=FOUNDER_ROUTE, now_epoch=EPOCH + 61,
        )
        self.assertEqual(second_lease["eventId"], first["eventId"])
        self.assertNotEqual(second_lease["leaseNonce"], first["leaseNonce"])
        self.assertEqual(self.reserve(second_lease, epoch=EPOCH + 61), request)
        self.assertFalse(accept_signed_founder_ack(
            self.receiver, route_id=FOUNDER_ROUTE, lease=first,
            ack=self.ack(first), pinned_receiver_public_key=self.ack_public,
            now_epoch=EPOCH + 1,
        ))  # Old timed-out lease cannot be acknowledged.
        self.assertFalse(accept_signed_founder_ack(
            self.receiver, route_id=FOUNDER_ROUTE, lease=second_lease,
            ack=self.ack(second_lease, signer=Ed25519PrivateKey.generate(),
                         accepted_epoch=EPOCH + 62),
            pinned_receiver_public_key=self.ack_public, now_epoch=EPOCH + 62,
        ))
        self.assertTrue(accept_signed_founder_ack(
            self.receiver, route_id=FOUNDER_ROUTE, lease=second_lease,
            ack=self.ack(second_lease, accepted_epoch=EPOCH + 62),
            pinned_receiver_public_key=self.ack_public, now_epoch=EPOCH + 62,
        ))  # Ephemeral simulated endpoint signature, NOT a real mailbox receipt.
        self.assertFalse(accept_signed_founder_ack(
            self.receiver, route_id=FOUNDER_ROUTE, lease=second_lease,
            ack=self.ack(second_lease, accepted_epoch=EPOCH + 62),
            pinned_receiver_public_key=self.ack_public, now_epoch=EPOCH + 62,
        ))

        recovered = claim_founder_delivery(
            self.receiver, route_id=FOUNDER_ROUTE, now_epoch=EPOCH + 63,
        )
        self.assertEqual(recovered["eventId"], f"{COLLECTOR}:44")
        recovery_request = self.reserve(recovered, epoch=EPOCH + 63)
        self.assertIn("recovery", recovery_request["subject"].lower())
        self.assertNotEqual(request["idempotencyKey"],
                            recovery_request["idempotencyKey"])
        self.assertTrue(all(
            value["state"] in ("ACKED", "LEASED") for value in (
                dict(event_id=e, state=s) for e, s in self.receiver.execute(
                    "SELECT event_id,state FROM founder_delivery_queue"
                )
            )
        ))
        self.assertEqual(self.count("resend_founder_submission"), 2)

    def test_signed_ack_before_renewed_lease_origin_is_not_delivery(self):
        envelope = self.sign(41, fault=True)
        self.assertTrue(self.receive(envelope)["advisoryOutboxPersisted"])
        self.assertEqual(self.stage(), "QUEUED_REVIEW_ONLY")
        first = claim_founder_delivery(
            self.receiver, route_id=FOUNDER_ROUTE, now_epoch=EPOCH,
        )
        self.assertIsNotNone(first)
        renewed = claim_founder_delivery(
            self.receiver, route_id=FOUNDER_ROUTE, now_epoch=EPOCH + 61,
        )
        self.assertIsNotNone(renewed)
        # Signed by the RIGHT test receiver but timestamp predates this
        # second lease issuance by 60s. Must not turn into founder ACK.
        self.assertFalse(accept_signed_founder_ack(
            self.receiver, route_id=FOUNDER_ROUTE, lease=renewed,
            ack=self.ack(renewed, accepted_epoch=EPOCH + 1),
            pinned_receiver_public_key=self.ack_public,
            now_epoch=EPOCH + 62,
        ))
        self.assertEqual(self.receiver.execute(
            "SELECT state FROM founder_delivery_queue"
        ).fetchone(), ("LEASED",))
        self.assertTrue(accept_signed_founder_ack(
            self.receiver, route_id=FOUNDER_ROUTE, lease=renewed,
            ack=self.ack(renewed, accepted_epoch=EPOCH + 62),
            pinned_receiver_public_key=self.ack_public,
            now_epoch=EPOCH + 62,
        ))

    def test_modified_envelope_and_replay_never_create_owner_notifications(self):
        good = self.sign(41, fault=True)
        corrupted = dict(good, signature="A" * 86)
        self.assertEqual(self.receive(corrupted)["status"], "UNKNOWN")
        self.assertEqual(self.count("signed_advisory_outbox"), 0)
        self.assertTrue(self.receive(good)["advisoryOutboxPersisted"])
        self.assertEqual(self.stage(), "QUEUED_REVIEW_ONLY")
        self.assertEqual(self.receive(good)["status"], "UNKNOWN")
        self.assertEqual(self.count("founder_delivery_queue"), 1)
        self.assertEqual(self.stage(), "NO_EVENT")
        self.assertEqual(self.count("resend_founder_submission"), 0)

    def test_failed_receiver_write_leaves_no_checkpoint_or_mail_intent(self):
        envelope = self.sign(41, fault=True)
        self.receiver.executescript("""
            CREATE TEMP TRIGGER deny_synthetic_advisory
            BEFORE INSERT ON signed_advisory_outbox
            BEGIN SELECT RAISE(ABORT, 'synthetic fault'); END;
        """)
        result = self.receive(envelope)
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertFalse(result["replayStatePersisted"])
        self.assertEqual(self.count("owned_observation_sequence"), 0)
        self.assertEqual(self.count("signed_advisory_outbox"), 0)
        self.assertEqual(self.count("founder_delivery_queue"), 0)
        self.assertEqual(self.count("resend_founder_submission"), 0)
        self.receiver.execute("DROP TRIGGER deny_synthetic_advisory")
        self.assertTrue(self.receive(envelope)["advisoryOutboxPersisted"])
        self.assertEqual(self.stage(), "QUEUED_REVIEW_ONLY")
        self.assertEqual(self.count("founder_delivery_queue"), 1)

    def test_untrusted_source_cannot_auto_promote_a_protected_report(self):
        synthetic = self.fixture(41, fault=True)
        signed = self.sign(41, fault=True)
        accepted = self.receive(signed)
        self.assertEqual(accepted["status"],
                         "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE")
        for origin in (synthetic, accepted):
            for field in ("trustedForExecutiveUse", "alertsDispatched"):
                self.assertFalse(origin[field])
        self.assertFalse(synthetic["sourceProvenanceVerified"])
        self.assertFalse(synthetic["durableReplayVerified"])
        self.assertFalse(accepted["continuousMonitoringVerified"])

    def test_forged_key_rejected_without_receiver_checkpoint(self):
        forged = sign_with_atomic_sender_counter(
            self.fixture(41, fault=True), conn=self.sender,
            signer=Ed25519PrivateKey.generate(), collector_id=COLLECTOR,
            approved_targets=TARGETS, now=NOW,
        )
        self.assertEqual(self.receive(forged)["status"], "UNKNOWN")
        self.assertEqual(self.count("signed_advisory_outbox"), 0)
        self.assertEqual(self.count("owned_observation_sequence"), 0)
        self.assertEqual(self.stage(), "NO_EVENT")


if __name__ == "__main__":
    unittest.main()
