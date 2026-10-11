"""Isolated real HTTP signed Tiquet -> NOC human-approver revalidation.

Uses disposable NOC SQLite and an ephemeral localhost-only HTTP listener.
No production machine secret or external network access.
"""
import hashlib
import hmac
import json
import os
from datetime import datetime,timezone
from http.client import HTTPConnection
from pathlib import Path
import subprocess
import threading
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from noc.server import NocAPI
from noc.sentinel_approver_machine_service import PATH,load_machine_secret

NODE_CLIENT = r"""
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createSentinelNocApproverChecker}
  from './server/sentinelNocApproverChecker.js';
const data=JSON.parse(fs.readFileSync(0,'utf8'));
const checker=createSentinelNocApproverChecker({
  nocUrl:data.origin,secret:data.secret,allowLoopbackTesting:true});
const result=await checker(data.scope);
assert.equal(result,data.expected);
console.log('SIGNED_NODE_NOC_APPROVER_STATUS=PASS');
"""

class SignedNocServiceBridge(unittest.TestCase):
    def setUp(self):
        tmp=TemporaryDirectory(prefix="v79-owner-approval-bridge-")
        self.addCleanup(tmp.cleanup)
        self.temp=Path(tmp.name)
        env=patch.dict(os.environ,{
            "SENTINEL_REVIEW_ENABLED":"0","SENTINEL_APPROVER_SERVICE_ENABLED":"0"})
        env.start();self.addCleanup(env.stop)
        self.server=NocAPI("127.0.0.1",0,self.temp/"noc.sqlite3")
        self.addCleanup(self.server.server_close)
        self.now=int(time.time())
        self.secret=b"synthetic-private-machine-secret-not-for-production-123456789"
        self.customer=str(uuid4())
        self.organization=str(uuid4())
        self.operator=str(uuid4())
        self.approval=str(uuid4())
        self.approved=datetime.fromtimestamp(self.now,timezone.utc).isoformat(
            timespec="milliseconds").replace("+00:00","Z")
        self.scope={
            "approverUserId":self.operator,"approvalId":self.approval,
            "approvedAt":self.approved,"organizationId":self.organization,
            "sentinelCustomerId":self.customer,"action":"ticket.create"
        }
        self.server.approver_machine_secret=self.secret
        self.server.ticket_review_config={"mapping":{
            "sentinel_customer_id":self.customer,
            "tiquet_organization_id":self.organization}}
        with self.server.store.db() as db:
            db.execute("""INSERT INTO operators
              (id,username,password_hash,role,disabled,mfa_secret,mfa_last_counter)
              VALUES(?,?,?,'admin',0,?,3)""",
              (self.operator,"synthetic-bridge-operator","test-only-hash","test-mfa"))
            db.execute("""CREATE TABLE sentinel_approval_issuance(
              approval_id TEXT PRIMARY KEY,event_id TEXT,incident_id TEXT,
              approver_id TEXT,mfa_at TEXT,approved_at TEXT,
              evidence_sha256 TEXT,key_id TEXT,issued_at INTEGER)""")
            db.execute("""INSERT INTO sentinel_approval_issuance VALUES(?,?,?,?,?,?,?,?,?)""",
              (self.approval,str(uuid4()),str(uuid4()),self.operator,
               self.approved,self.approved,"synthetic-only","test-key",self.now))
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.server.shutdown)

    def post(self,headers=None,body=None):
        body=json.dumps(self.scope,separators=(",",":")).encode() if body is None else body
        stamp=str(self.now)
        canonical="POST\n"+PATH+"\n"+stamp+"\n"+hashlib.sha256(body).hexdigest()
        signature=hmac.new(self.secret,canonical.encode(),hashlib.sha256).hexdigest()
        h={"Content-Type":"application/json","X-V79-Service-Id":"v79-tiquet",
           "X-V79-Timestamp":stamp,"X-V79-Signature":signature,
           **(headers or {})}
        client=HTTPConnection("127.0.0.1",self.server.server_port,timeout=4)
        try:
            client.request("POST",PATH,body=body,headers=h)
            response=client.getresponse()
            raw=response.read()
            return response.status,json.loads(raw)
        finally:client.close()

    def test_local_signed_http_approver_and_immediate_revocation(self):
        status,result=self.post()
        self.assertEqual(status,200)
        self.assertEqual(result,{"allowed":True,"validForSeconds":5})
        for h in ({"X-V79-Signature":"0"*64},
                  {"Origin":"https://evil.example"},
                  {"Cookie":"session=must-not-use"},
                  {"X-V79-Service-Id":"browser"}):
            status,_=self.post(headers=h)
            self.assertEqual(status,401)
        with self.server.store.db() as db:
            db.execute("UPDATE operators SET disabled=1 WHERE id=?",(self.operator,))
        status,revoked=self.post()
        self.assertEqual(status,200)
        self.assertEqual(revoked,{"allowed":False,"validForSeconds":0})
        self.server.approver_machine_secret=None
        status,_=self.post()
        self.assertEqual(status,404)

    def test_actual_node_machine_checker_against_private_noc_http(self):
        tiquet=Path(__file__).resolve().parents[3]/"tiquet-sentinel-service-staging"
        if not (tiquet/"server/sentinelNocApproverChecker.js").exists():
            self.skipTest("NOT RUN: separate reviewed V79Tiquet staging checkout required")
        fixture={"origin":f"http://127.0.0.1:{self.server.server_port}/",
            "secret":self.secret.decode(),"scope":self.scope,"expected":True}
        def run_check(expected):
            fixture["expected"]=expected
            result=subprocess.run(
                ["node","--input-type=module","-e",NODE_CLIENT],
                input=json.dumps(fixture),text=True,capture_output=True,
                timeout=12,cwd=tiquet,env={**os.environ,"NODE_ENV":"test"},check=False)
            self.assertEqual(result.returncode,0,result.stderr[-2000:])
            self.assertIn("SIGNED_NODE_NOC_APPROVER_STATUS=PASS",result.stdout)
        run_check(True)
        with self.server.store.db() as db:
            db.execute("UPDATE operators SET role='viewer' WHERE id=?",(self.operator,))
        run_check(False)

    def test_file_secret_permissions_fail_closed(self):
        target=self.temp/"machine-secret"
        target.write_bytes(self.secret)
        target.chmod(0o644)
        with self.assertRaises(PermissionError):load_machine_secret(str(target))
        target.chmod(0o600)
        self.assertEqual(load_machine_secret(str(target)),self.secret)


if __name__=="__main__":
    unittest.main()
