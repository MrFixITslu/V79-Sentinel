"""Cross-runtime Sentinel NOC approval -> actual V79Tiquet receiver contract.

No network, live credentials, production PostgreSQL, or real customer writes.
All identities, Ed25519 keys, and NOC state are ephemeral synthetic fixtures.
"""
import json
from pathlib import Path
import subprocess
import unittest
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

from noc.security import new_totp_secret,totp
from noc.tests import test_sentinel_real_edge as edge
from noc.sentinel_real_ticket_review import review_real_and_queue


NODE_CHECK = r"""
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {parseApprovalPublicKeys,verifyHumanTicketApproval}
  from './server/sentinelHumanApproval.js';
import {validateSentinelEvent} from './server/sentinelIngress.js';

const fixture=JSON.parse(fs.readFileSync(0,'utf8'));
const event=fixture.event;
const customer=event.tenant.sentinel_customer_id;
const org=event.tenant.tiquet_organization_id;
const client=event.tenant.tiquet_client_id;
const link={sentinelCustomerId:customer,tiquetOrganizationId:org,
  tiquetClientId:client};
const now=Date.parse(event.approval.approved_at)+1000;
const keys=parseApprovalPublicKeys([{keyId:event.approval.key_id,
  publicKeyPem:fixture.publicKeyPem,enabled:true}]);
assert.equal(validateSentinelEvent(event,link),event);
const approved=verifyHumanTicketApproval(event,keys,now);
assert.equal(approved.approvalId,event.approval.approval_id);
assert.equal(approved.approverUserId,event.approval.approver_user_id);
assert.equal(approved.eventSha256,event.approval.event_sha256);
assert.throws(()=>verifyHumanTicketApproval(
  {...event,incident:{...event.incident,title:'ALTERED'}},keys,now));
assert.throws(()=>verifyHumanTicketApproval(
  {...event,tenant:{...event.tenant,tiquet_client_id:
    'ffffffff-ffff-4fff-8fff-ffffffffffff'}},keys,now));
assert.throws(()=>verifyHumanTicketApproval(event,[],now));
assert.throws(()=>verifyHumanTicketApproval(
  event,keys,Date.parse(event.approval.expires_at)+1));
console.log('PYTHON_OUTBOX_TO_NODE_VALIDATION=PASS');
console.log('INDEPENDENT_ED25519_APPROVAL=PASS');
console.log('TAMPERING_CROSS_TENANT_EXPIRED_REVOKED_KEY_DENIAL=PASS');
"""


class CrossRuntimeSignedApproval(unittest.TestCase):
    def test_real_edge_evidence_approved_queue_verifies_in_tiquet_node(self):
        fixture=edge.RealSignedCollectorTests(
            "test_agent_does_not_provide_incident_id_server_correlates_failures")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.ingest(fixture.observation(1,fixture.now-45))
        receipt=fixture.ingest(fixture.observation(2,fixture.now-5))
        incident=receipt["incident_id"]
        self.assertIsNotNone(incident)
        owner=str(uuid4());client=str(uuid4())
        mapping={"sentinel_customer_id":fixture.customer,
            "tiquet_organization_id":owner,"tiquet_client_id":client}
        signer=Ed25519PrivateKey.generate()
        secret=new_totp_secret()
        approver=str(uuid4())
        with fixture.store.db() as db:
            db.execute("""INSERT INTO operators
             (id,username,password_hash,role,disabled,mfa_secret,mfa_last_counter)
             VALUES(?,?,?,'admin',0,?,-1)""",
             (approver,"synthetic-js-compat-admin","test-only",secret))
        result=review_real_and_queue(fixture.store,approver,
            totp(secret,fixture.now//30),incident,mapping,
            fixture.keys,fixture.targets,signer,
            "test-js-cross-approval",confirmed=True,now=fixture.now)
        self.assertTrue(result["queued"])
        with fixture.store.db() as db:
            record=db.execute(
                "SELECT payload FROM sentinel_dispatch_outbox WHERE event_id=?",
                (result["event_id"],)).fetchone()
        self.assertIsNotNone(record)
        fixture_json={"event":json.loads(record[0]),"publicKeyPem":
            signer.public_key().public_bytes(
                Encoding.PEM,PublicFormat.SubjectPublicKeyInfo).decode()}
        tiquet=Path(__file__).resolve().parents[3]/"tiquet-sentinel-service-staging"
        self.assertTrue((tiquet/"server/sentinelHumanApproval.js").exists())
        process=subprocess.run(
            ["node","--input-type=module","-e",NODE_CHECK],
            input=json.dumps(fixture_json,separators=(",",":")),
            text=True,capture_output=True,timeout=18,cwd=tiquet,check=False)
        self.assertEqual(process.returncode,0,
            "Node verification failed: "+process.stderr[-2000:])
        self.assertIn("INDEPENDENT_ED25519_APPROVAL=PASS",process.stdout)
        self.assertIn("PYTHON_OUTBOX_TO_NODE_VALIDATION=PASS",process.stdout)


if __name__=="__main__":
    unittest.main()
