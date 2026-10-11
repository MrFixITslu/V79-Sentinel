"""Isolated current-approver revalidation: historical signatures are not enough."""
from datetime import datetime,timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from uuid import uuid4

from noc.store import NocStore
from noc.sentinel_reviewer_status import currently_authorized_reviewer


class ReviewerStatusTests(unittest.TestCase):
    def setUp(self):
        t=TemporaryDirectory(prefix="v79-approver-status-")
        self.addCleanup(t.cleanup)
        self.store=NocStore(Path(t.name)/"isolated.sqlite3")
        self.now=int(time.time())
        self.operator=str(uuid4())
        self.approval=str(uuid4())
        self.customer=str(uuid4())
        self.organization=str(uuid4())
        self.approved=datetime.fromtimestamp(self.now,timezone.utc).isoformat(
            timespec="milliseconds").replace("+00:00","Z")
        self.mapping={"sentinel_customer_id":self.customer,
            "tiquet_organization_id":self.organization}
        self.scope={"approverUserId":self.operator,"approvalId":self.approval,
            "approvedAt":self.approved,"sentinelCustomerId":self.customer,
            "organizationId":self.organization,"action":"ticket.create"}

    def issue(self):
        with self.store.db() as db:
            db.execute("""INSERT INTO operators
                 (id,username,password_hash,role,disabled,mfa_secret,mfa_last_counter)
                 VALUES(?,?,?,'admin',0,?,10)""",
                 (self.operator,"synthetic-current-approver","test-only","synthetic-mfa-present"))
            db.execute("""CREATE TABLE sentinel_approval_issuance (
                approval_id TEXT PRIMARY KEY,event_id TEXT,incident_id TEXT,
                approver_id TEXT,mfa_at TEXT,approved_at TEXT,
                evidence_sha256 TEXT,key_id TEXT,issued_at INTEGER)""")
            db.execute("""INSERT INTO sentinel_approval_issuance
                 VALUES(?,?,?,?,?,?,?,?,?)""",
                 (self.approval,str(uuid4()),str(uuid4()),self.operator,
                  self.approved,self.approved,"test-evidence","test-key",self.now))

    def allowed(self,scope=None,mapping=None,now=None):
        return currently_authorized_reviewer(self.store,
            scope or self.scope,mapping or self.mapping,
            now=self.now if now is None else now)

    def test_without_exact_signed_issuance_record_always_denies(self):
        self.assertFalse(self.allowed())
        self.issue()
        self.assertTrue(self.allowed())
        self.assertFalse(self.allowed(scope={**self.scope,"approvalId":str(uuid4())}))
        self.assertFalse(self.allowed(scope={**self.scope,"organizationId":str(uuid4())}))
        self.assertFalse(self.allowed(scope={**self.scope,"sentinelCustomerId":str(uuid4())}))
        self.assertFalse(self.allowed(scope={**self.scope,"action":"ticket.close"}))

    def test_immediate_operator_revocation_role_change_and_mfa_removal(self):
        self.issue()
        with self.store.db() as db:
            db.execute("UPDATE operators SET disabled=1 WHERE id=?",(self.operator,))
        self.assertFalse(self.allowed())
        with self.store.db() as db:
            db.execute("UPDATE operators SET disabled=0,role='viewer' WHERE id=?",(self.operator,))
        self.assertFalse(self.allowed())
        with self.store.db() as db:
            db.execute("UPDATE operators SET role='admin',mfa_secret=NULL WHERE id=?",(self.operator,))
        self.assertFalse(self.allowed())

    def test_expired_approval_and_malformed_scope_denied(self):
        self.issue()
        self.assertFalse(self.allowed(now=self.now+601))
        self.assertFalse(self.allowed(scope={**self.scope,"approvedAt":"not-a-time"}))
        self.assertFalse(self.allowed(scope={**self.scope,"approverUserId":"nobody"}))


if __name__=="__main__":
    unittest.main()
