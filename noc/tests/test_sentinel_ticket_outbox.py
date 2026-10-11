"""Synthetic isolated SQLite tests for supervised Sentinel dispatch bookkeeping."""
from pathlib import Path
import json
import hashlib
from datetime import datetime,timezone
from tempfile import TemporaryDirectory
import sqlite3
import unittest
from uuid import uuid4

from noc.store import NocStore
from noc.sentinel_approval_issuer import event_sha256
from noc.sentinel_ticket_outbox import (
    initialize, queue_reviewed_ticket, pending, record_delivery, cancel_pending)


class DispatchTests(unittest.TestCase):
    def setUp(self):
        temp=TemporaryDirectory(prefix="v79-sentinel-dispatch-")
        self.addCleanup(temp.cleanup)
        self.store=NocStore(Path(temp.name)/"isolated.sqlite3")
        initialize(self.store)
        self.event={
            "source":"v79-sentinel", "classification":"PRODUCTION_VERIFIED",
            "action":"ticket.create", "event_id":str(uuid4()),
            "source_incident_id":str(uuid4()),
            "tenant":{"sentinel_customer_id":str(uuid4()),
                "tiquet_organization_id":str(uuid4()), "tiquet_client_id":str(uuid4())}}
        self.approval={
            "approval_id":str(uuid4()), "event_id":self.event["event_id"],
            "event_sha256":event_sha256(self.event),
            "sentinel_customer_id":self.event["tenant"]["sentinel_customer_id"],
            "approver_user_id":str(uuid4()),
            "expires_at":datetime.fromtimestamp(1600,timezone.utc).isoformat()}

    def queue(self,**kwargs):
        return queue_reviewed_ticket(self.store,
            kwargs.get("event",self.event),kwargs.get("approval",self.approval),
            verify_approval=kwargs.get("verify_approval",lambda *_:True),
            verify_source=kwargs.get("verify_source",lambda *_:True),now=1000)

    def count(self,table):
        with self.store.db() as db:
            return db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def test_unverified_source_or_human_never_queues(self):
        with self.assertRaises(PermissionError): self.queue(verify_approval=None)
        with self.assertRaises(PermissionError): self.queue(verify_source=None)
        with self.assertRaises(PermissionError): self.queue(verify_approval=lambda *_:False)
        with self.assertRaises(PermissionError): self.queue(verify_source=lambda *_:False)
        with self.assertRaises(PermissionError):
            self.queue(event={**self.event,"classification":"SIMULATED_ONLY"})
        with self.assertRaises(ValueError):
            self.queue(approval={**self.approval,"event_sha256":"0"*64})
        self.assertEqual(self.count("sentinel_dispatch_outbox"),0)

    def test_durable_idempotence_retry_and_signed_ack_bookkeeping(self):
        self.assertEqual(self.queue(),{"queued":True,"state":"pending"})
        self.assertEqual(self.queue(),{"queued":False,"state":"pending"})
        self.assertEqual(len(pending(self.store,now=1000)),1)
        self.assertEqual(len(pending(self.store,now=999)),0)
        first=record_delivery(self.store,self.event["event_id"],now=1000)
        self.assertEqual(first,{"status":"retry","attempts":1,"next_attempt":1060})
        self.assertEqual(pending(self.store,now=1000),[])
        self.assertEqual(len(pending(self.store,now=1060)),1)
        second=record_delivery(self.store,self.event["event_id"],now=1060)
        self.assertEqual(second["next_attempt"],1180)
        job=str(uuid4())
        third=record_delivery(self.store,self.event["event_id"],accepted=True,job_id=job,now=1180)
        self.assertEqual(third["status"],"delivered")
        self.assertEqual(pending(self.store,now=2000),[])
        self.assertEqual(self.count("sentinel_dispatch_attempts"),3)
        self.assertEqual(self.count("sentinel_dispatch_outbox"),1)
        with self.assertRaises(ValueError):
            record_delivery(self.store,self.event["event_id"],accepted=True,job_id=job,now=1190)
        self.assertEqual(self.count("sentinel_dispatch_attempts"),3)

    def test_exact_event_replay_conflicts_and_one_incident_one_ticket(self):
        self.queue()
        with self.assertRaises(ValueError):
            self.queue(event={**self.event,"impact":{"name":"tampered"}})
        newer={**self.event,"event_id":str(uuid4())}
        newer_approval={**self.approval,"approval_id":str(uuid4()),
            "event_id":newer["event_id"],"event_sha256":event_sha256(newer)}
        with self.assertRaises(ValueError):
            self.queue(event=newer,approval=newer_approval)
        self.assertEqual(self.count("sentinel_dispatch_outbox"),1)

    def test_stored_json_keeps_original_approved_event_property_order(self):
        self.queue()
        with self.store.db() as db:
            body=db.execute("SELECT payload FROM sentinel_dispatch_outbox").fetchone()[0]
        parsed=json.loads(body)
        event={k:v for k,v in parsed.items() if k!="approval"}
        serialized=json.dumps(event,ensure_ascii=False,separators=(",",":"))
        self.assertEqual(hashlib.sha256(serialized.encode()).hexdigest(),
                         parsed["approval"]["event_sha256"])
        self.assertEqual(list(event),list(self.event))
        self.assertEqual(parsed["approval"]["approval_id"],self.approval["approval_id"])

    def test_cancelled_cannot_be_replayed_or_delivered(self):
        self.queue()
        cancel_pending(self.store,self.event["event_id"],now=1010)
        self.assertEqual(self.queue(),{"queued":False,"state":"cancelled"})
        self.assertEqual(pending(self.store,now=3000),[])
        with self.assertRaises(ValueError):
            record_delivery(self.store,self.event["event_id"],accepted=True,job_id=str(uuid4()),now=1050)
        with self.assertRaises(ValueError):
            cancel_pending(self.store,self.event["event_id"],now=1100)
        self.assertEqual(self.count("sentinel_dispatch_attempts"),1)

    def test_expired_or_too_long_human_approval_is_never_dispatched(self):
        with self.assertRaises(PermissionError):
            self.queue(approval={**self.approval,"expires_at":datetime.fromtimestamp(1000,timezone.utc).isoformat()})
        with self.assertRaises(PermissionError):
            self.queue(approval={**self.approval,"expires_at":datetime.fromtimestamp(3000,timezone.utc).isoformat()})
        with self.assertRaises(ValueError):
            self.queue(approval={**self.approval,"expires_at":"not-a-date"})
        self.queue()
        self.assertEqual(len(pending(self.store,now=1599)),1)
        self.assertEqual(pending(self.store,now=1600),[])
        with self.store.db() as db:
            status=db.execute("SELECT status FROM sentinel_dispatch_outbox").fetchone()[0]
        self.assertEqual(status,"expired")
        with self.assertRaises(ValueError):
            record_delivery(self.store,self.event["event_id"],accepted=True,job_id=str(uuid4()),now=1600)

    def test_retry_expires_before_signature_expiry_without_infinite_attempts(self):
        self.queue()
        self.assertEqual(record_delivery(self.store,self.event["event_id"],now=1000)["status"],"retry")
        self.assertEqual(record_delivery(self.store,self.event["event_id"],now=1060)["status"],"retry")
        self.assertEqual(record_delivery(self.store,self.event["event_id"],now=1180)["status"],"retry")
        self.assertEqual(record_delivery(self.store,self.event["event_id"],now=1300)["status"],"retry")
        self.assertEqual(record_delivery(self.store,self.event["event_id"],now=1420)["status"],"retry")
        self.assertEqual(record_delivery(self.store,self.event["event_id"],now=1540)["status"],"expired")
        self.assertEqual(pending(self.store,now=1550),[])
        self.assertEqual(self.count("sentinel_dispatch_attempts"),6)

    def test_malformed_delivery_receipts_and_invalid_limits_fail(self):
        self.queue()
        with self.assertRaises(ValueError):
            record_delivery(self.store,self.event["event_id"],accepted=True,job_id="made-up")
        with self.assertRaises(ValueError):
            record_delivery(self.store,"nonsense",now=1000)
        for limit in (0,51,1.5,"10"):
            with self.assertRaises(ValueError):
                pending(self.store,now=1000,limit=limit)
        self.assertEqual(self.count("sentinel_dispatch_attempts"),0)


if __name__=="__main__":
    unittest.main()
