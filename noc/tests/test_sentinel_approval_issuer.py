"""Synthetic-only tests for disconnected owner ticket-approval signing."""
from __future__ import annotations

import base64
from pathlib import Path
import tempfile
import time
import unittest
from uuid import uuid4
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from noc.store import NocStore
from noc.security import hash_password, new_totp_secret, totp
from noc.sentinel_approval_issuer import (
    issue_supervised_approval, approval_claim_bytes, event_sha256,
    load_private_signer)


class IssuerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="v79-owner-approval-test-")
        self.addCleanup(self.temp.cleanup)
        self.store=NocStore(Path(self.temp.name)/"isolated-noc.sqlite3")
        self.operator_id=str(uuid4())
        self.secret=new_totp_secret()
        self.signer=Ed25519PrivateKey.generate()
        self.evidence_checked=[]
        with self.store.db() as db:
            db.execute("""INSERT INTO operators
               (id,username,password_hash,role,disabled,mfa_secret,mfa_last_counter)
               VALUES (?,?,?,?,?,?,?)""",
               (self.operator_id,"owner-reviewer",hash_password("synthetic-private-only-pass"),"admin",0,self.secret,-1))
        event_id=str(uuid4());incident_id=str(uuid4())
        self.event={
            "schema_version":1,"source":"v79-sentinel",
            "classification":"PRODUCTION_VERIFIED",
            "event_id":event_id,"idempotency_key":"sentinel:event:"+event_id,
            "source_incident_id":incident_id,"correlation_key":"sentinel:incident:"+incident_id,
            "tenant":{"sentinel_customer_id":str(uuid4()),
                "tiquet_organization_id":"hub-org-one","tiquet_client_id":"client-one"},
            "impact":{"site_id":str(uuid4()),"site_name":"Synthetic staging site","failure_domain":"application_readiness"},
            "incident":{"title":"Synthetic verified incident","severity":"warning",
                "detected_at":"2026-10-10T14:20:00.000Z","observed_state":"open"},
            "action":"ticket.create"}
        self.now=int(time.time() * 1000)
        self.otp=totp(self.secret,int(self.now//30000))

    def evidence_ok(self,event):
        self.evidence_checked.append(event["event_id"])
        return True

    def issue(self,**kwargs):
        return issue_supervised_approval(
            self.store,self.operator_id,kwargs.pop("otp",self.otp),
            kwargs.pop("event",self.event),
            kwargs.pop("signer",self.signer),
            kwargs.pop("key_id","owner-pilot-key"),
            verify_evidence=kwargs.pop("verify_evidence",self.evidence_ok),
            confirmed=kwargs.pop("confirmed",True),
            now_ms=kwargs.pop("now_ms",self.now))

    def test_valid_mfa_approval_is_signed_and_audited_atomically(self):
        signed=self.issue()
        signature=base64.urlsafe_b64decode(signed["signature"]+"==")
        self.signer.public_key().verify(signature,approval_claim_bytes(signed))
        self.assertEqual(signed["event_sha256"],event_sha256(self.event))
        self.assertEqual(signed["approver_user_id"],self.operator_id)
        with self.store.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sentinel_approval_issuance").fetchone()[0],1)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM audit WHERE action='sentinel.ticket_approval.issued'").fetchone()[0],1)
        with self.assertRaises(PermissionError):
            self.issue()
        with self.store.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sentinel_approval_issuance").fetchone()[0],1)

    def test_no_evidence_or_explicit_human_confirmation_means_no_signature(self):
        with self.assertRaises(PermissionError):
            self.issue(verify_evidence=None)
        with self.assertRaises(PermissionError):
            self.issue(verify_evidence=lambda event:False)
        with self.assertRaises(PermissionError):
            self.issue(confirmed=False)
        with self.store.db() as db:
            self.assertFalse(db.execute(
                "SELECT name FROM sqlite_master WHERE name='sentinel_approval_issuance'").fetchone())

    def test_simulated_event_and_wrong_operator_role_rejected(self):
        with self.assertRaises(PermissionError):
            self.issue(event={**self.event,"classification":"SIMULATED_ONLY"})
        with self.store.db() as db:
            db.execute("UPDATE operators SET role='viewer' WHERE id=?",(self.operator_id,))
        with self.assertRaises(PermissionError):
            self.issue()
        with self.store.db() as db:
            db.execute("UPDATE operators SET role='admin',disabled=1 WHERE id=?",(self.operator_id,))
        with self.assertRaises(PermissionError):
            self.issue()

    def test_signer_file_requires_owner_only_0600_and_no_symlink(self):
        pem=self.signer.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
        key_path=Path(self.temp.name)/"owner-signing-key.pem"
        key_path.write_bytes(pem)
        os.chmod(key_path,0o644)
        with self.assertRaises(PermissionError):load_private_signer(key_path)
        os.chmod(key_path,0o600)
        loaded=load_private_signer(key_path)
        self.assertIsInstance(loaded,Ed25519PrivateKey)
        link=Path(self.temp.name)/"linked.pem"
        link.symlink_to(key_path)
        with self.assertRaises(PermissionError):load_private_signer(link)


if __name__=="__main__":
    unittest.main()
