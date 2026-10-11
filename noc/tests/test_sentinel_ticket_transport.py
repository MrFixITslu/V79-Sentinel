"""Sentinel sender contract tests: synthetic SQLite + in-memory transport only."""
import hashlib
import hmac
import json
import time
import unittest
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from noc.tests import test_sentinel_real_edge as source_test_fixture
from noc.security import new_totp_secret,totp
from noc.sentinel_real_ticket_review import review_real_and_queue,build_real_ticket
from noc.sentinel_ticket_transport import dispatch_once,PATH,DESTINATION


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture=source_test_fixture.RealSignedCollectorTests("test_agent_does_not_provide_incident_id_server_correlates_failures")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.t=self.fixture
        self.t.ingest(self.t.observation(1,self.t.now-45))
        incident=self.t.ingest(self.t.observation(2,self.t.now-5))
        self.incident=incident["incident_id"]
        assert self.incident is not None
        self.mapping={"sentinel_customer_id":self.t.customer,
            "tiquet_organization_id":str(uuid4()),
            "tiquet_client_id":str(uuid4())}
        self.signer=Ed25519PrivateKey.generate()
        self.secret="synthetic-sentinel-to-tiquet-secret-unique-and-test-only-1234567890"
        self.account=str(uuid4())
        actor=str(uuid4());mfa=new_totp_secret()
        with self.t.store.db() as db:
            db.execute("""INSERT INTO operators
                (id,username,password_hash,role,disabled,mfa_secret,mfa_last_counter)
                VALUES(?,?,?,'admin',0,?,-1)""",
                (actor,"synthetic-dispatcher","isolated-test-only",mfa))
        receipt=review_real_and_queue(self.t.store,actor,totp(mfa,self.t.now//30),
            self.incident,self.mapping,self.t.keys,self.t.targets,self.signer,
            "test-only-dispatch-approver",confirmed=True,now=self.t.now)
        self.event_id=receipt["event_id"]

    def kwargs(self,**changes):
        allowed={
            "enabled":True,
            "service_secret":self.secret,
            "approval_public_key":self.signer.public_key(),
            "verify_source":lambda event:event==build_real_ticket(
                self.t.store,self.incident,self.mapping,self.t.keys,self.t.targets,now=self.t.now),
            "authorize_machine":lambda scope:{"allowed":True,"accountId":self.account},
            "authorize_reviewer":lambda scope:True,
            "transport":self.success,
            "now":self.t.now,
        }
        allowed.update(changes)
        return allowed

    def success(self,url,body,headers):
        self.assertEqual(url,DESTINATION)
        self.assertEqual(headers["X-V79-Service-Id"],"v79-sentinel")
        self.assertEqual(headers["X-V79-Sentinel-Customer"],self.t.customer)
        canonical="POST\n"+PATH+"\n"+headers["X-V79-Timestamp"]+"\n"+hashlib.sha256(body).hexdigest()
        signature=hmac.new(self.secret.encode(),canonical.encode(),hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-V79-Signature"],signature)
        event=json.loads(body)
        self.assertEqual(event["event_id"],self.event_id)
        return {"status":201,"content_type":"application/json",
             "body":json.dumps({"accepted":True,"state":"created",
               "jobId":str(uuid4()),"correlationKey":event["correlation_key"]}).encode()}

    def test_explicit_signed_approval_and_current_reevaluations_allow_one_delivery(self):
        result=dispatch_once(self.t.store,self.event_id,**self.kwargs())
        self.assertEqual(result["status"],"delivered")
        with self.t.store.db() as db:
            row=db.execute("SELECT status,attempts,tiquet_job_id FROM sentinel_dispatch_outbox").fetchone()
        self.assertEqual(row["status"],"delivered")
        self.assertEqual(row["attempts"],1)
        self.assertTrue(row["tiquet_job_id"])
        with self.assertRaises(PermissionError):
            dispatch_once(self.t.store,self.event_id,**self.kwargs())

    def test_default_off_deny_reviewer_revocation_and_machine_revocation(self):
        self.assertEqual(dispatch_once(self.t.store,self.event_id,**self.kwargs(enabled=False)),
                         {"status":"disabled"})
        for key,change in [
            ("authorize_reviewer",lambda _:False),
            ("authorize_machine",lambda _:False),
            ("verify_source",lambda _:False),
            ("approval_public_key",None),
            ("service_secret","weak"),
            ("transport",None)
        ]:
            with self.subTest(key=key):
                with self.assertRaises(PermissionError):
                    dispatch_once(self.t.store,self.event_id,**self.kwargs(**{key:change}))
        with self.t.store.db() as db:
            self.assertEqual(db.execute("SELECT attempts FROM sentinel_dispatch_outbox").fetchone()[0],0)

    def test_replayed_tiquet_receipt_records_existing_job_after_lost_ack(self):
        job=str(uuid4())
        def replayed(url,body,headers):
            self.assertEqual(url,DESTINATION)
            event=json.loads(body)
            return {"status":200,"content_type":"application/json",
                "body":json.dumps({"accepted":True,"state":"duplicate",
                  "jobId":job,"correlationKey":event["correlation_key"]}).encode()}
        result=dispatch_once(self.t.store,self.event_id,
            **self.kwargs(transport=replayed))
        self.assertEqual(result["status"],"delivered")
        with self.t.store.db() as db:
            row=db.execute("SELECT status,tiquet_job_id,attempts FROM sentinel_dispatch_outbox").fetchone()
        self.assertEqual((row["status"],row["tiquet_job_id"],row["attempts"]),
                         ("delivered",job,1))

    def test_tampered_acknowledgement_does_not_confirm_ticket(self):
        rejected=lambda url,body,headers:{"status":201,"content_type":"application/json",
            "body":json.dumps({"accepted":True,"state":"created",
              "jobId":str(uuid4()),"correlationKey":"foreign-incident"}).encode()}
        result=dispatch_once(self.t.store,self.event_id,
            **self.kwargs(transport=rejected))
        self.assertEqual(result["status"],"retry")
        self.assertEqual(result["next_attempt"],self.t.now+60)
        with self.t.store.db() as db:
            row=db.execute("SELECT status,tiquet_job_id FROM sentinel_dispatch_outbox").fetchone()
        self.assertEqual(row["status"],"pending")
        self.assertIsNone(row["tiquet_job_id"])


if __name__=="__main__":
    unittest.main()
