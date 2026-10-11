"""Real HTTP checks for disabled-by-default Sentinel review, isolated ephemeral DB."""
from contextlib import contextmanager
from http.client import HTTPConnection
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import os
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from noc.server import NocAPI,bootstrap


class TicketReviewHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory(prefix="v79-review-http-")
        self.addCleanup(self.temp.cleanup)
        self.env=patch.dict(os.environ,{"SENTINEL_REVIEW_ENABLED":"0"})
        self.env.start();self.addCleanup(self.env.stop)
        self.server=NocAPI("127.0.0.1",0,Path(self.temp.name)/"test.sqlite3")
        self.addCleanup(self.server.server_close)
        bootstrap(self.server.store,"synthetic-admin","synthetic-test-only-password-18974")
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.server.shutdown)
        self.origin="http://127.0.0.1:"+str(self.server.server_port)

    def request(self,method,path,payload=None,headers=None):
        connection=HTTPConnection("127.0.0.1",self.server.server_port,timeout=4)
        body=json.dumps(payload).encode() if payload is not None else None
        hdr={"Origin":self.origin,**(headers or {})}
        if payload is not None:hdr["Content-Type"]="application/json"
        connection.request(method,path,body=body,headers=hdr)
        response=connection.getresponse()
        value=response.read().decode()
        result=(response.status,json.loads(value) if value.strip().startswith(("{","[")) else value,
                dict(response.getheaders()))
        connection.close()
        return result

    def login(self):
        status,body,headers=self.request("POST","/api/v1/login",{
            "username":"synthetic-admin","password":"synthetic-test-only-password-18974"})
        self.assertEqual(status,200)
        cookie=headers.get("Set-Cookie","").split(";",1)[0]
        self.assertTrue(cookie.startswith("sentinel_noc="))
        status,session,_=self.request("GET","/api/v1/session",headers={"Cookie":cookie})
        self.assertEqual(status,200)
        return cookie,session["csrf"]

    def test_review_requires_operator_session_and_admin_csrf(self):
        status,_,_=self.request("GET","/api/v1/sentinel/reviews")
        self.assertEqual(status,401)
        status,_,_=self.request("POST","/api/v1/sentinel/approve",{
            "incident_id":str(uuid4()),"otp":"123456","confirmed":True})
        self.assertEqual(status,401)
        status,_,_=self.request("POST","/api/v1/sentinel/edge/observation",{})
        self.assertEqual(status,404) # unsigned receiver disabled by default
        cookie,csrf=self.login()
        status,detail,_=self.request("GET","/api/v1/sentinel/reviews",
                                    headers={"Cookie":cookie})
        self.assertEqual(status,200)
        self.assertEqual(detail,{"enabled":False,"proposals":[],"dispatch":"disabled"})
        status,_,_=self.request("POST","/api/v1/sentinel/approve",{
            "incident_id":str(uuid4()),"otp":"123456","confirmed":True},
            headers={"Cookie":cookie})
        self.assertEqual(status,403) # CSRF protection enforced first
        status,_,_=self.request("POST","/api/v1/sentinel/approve",{
            "incident_id":str(uuid4()),"otp":"123456","confirmed":True},
            headers={"Cookie":cookie,"X-Sentinel-CSRF":csrf})
        self.assertEqual(status,503) # disabled even with valid owner login/CSRF
        with self.server.store.db() as db:
            self.assertFalse(db.execute(
                "SELECT name FROM sqlite_master WHERE name='sentinel_dispatch_outbox'").fetchone())

    def test_verified_signed_incident_gets_one_mfa_http_approval_without_dispatch(self):
        import time
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from noc.security import new_totp_secret,totp
        from noc.sentinel_real_edge import (initialize,ingest_signed_measurement,
             canonical,VERSION)
        cookie,csrf=self.login()
        store=self.server.store
        customer=store.customer("Synthetic Owner Network")
        site=store.site(customer,"Synthetic Site")
        asset=store.asset(site,"Synthetic Gateway","192.0.2.11")
        check=store.check(asset,"Synthetic Edge TCP","network")
        agent=store.enroll(site,"Synthetic Signed Observer")["agent_id"]
        now=int(time.time())
        initialize(store)
        source_key=Ed25519PrivateKey.generate()
        source_public=source_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        targets={check:{"ip":"192.0.2.11","port":443,"customer_id":customer,
                        "site_id":site,"agent_id":agent}}
        incident=None
        for seq,observed in ((1,now-45),(2,now-5)):
            claims={"version":VERSION,"receipt_id":str(uuid4()),
                "customer_id":customer,"site_id":site,"agent_id":agent,
                "check_id":check,"sequence":seq,"observed_at":observed,
                "ok":False,"target_ip":"192.0.2.11",
                "target_port":443,"probe_kind":"tcp"}
            signed={"claims":claims,"signature":source_key.sign(canonical(claims)).hex()}
            outcome=ingest_signed_measurement(store,signed,{agent:source_public},targets,now=now)
            incident=outcome["incident_id"] or incident
        self.assertIsNotNone(incident)
        signer=Ed25519PrivateKey.generate()
        path=Path(self.temp.name)/"approval-key.pem"
        path.write_bytes(signer.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
        path.chmod(0o600)
        secret=new_totp_secret()
        with store.db() as db:
            actor_id=db.execute("SELECT id FROM operators WHERE username='synthetic-admin'").fetchone()[0]
            db.execute("UPDATE operators SET mfa_secret=?,mfa_last_counter=-1 WHERE id=?",(secret,actor_id))
        self.server.ticket_review_config={
            "mapping":{"sentinel_customer_id":customer,
                "tiquet_organization_id":str(uuid4()),"tiquet_client_id":str(uuid4())},
            "observer_public_keys":{agent:source_public},
            "approved_targets":targets,
            "signing_key_path":str(path),"signing_key_id":"synthetic-approval-key"}
        claims={"version":VERSION,"receipt_id":str(uuid4()),
            "customer_id":customer,"site_id":site,"agent_id":agent,
            "check_id":check,"sequence":3,"observed_at":now-1,
            "ok":False,"target_ip":"192.0.2.11","target_port":443,"probe_kind":"tcp"}
        signed={"claims":claims,"signature":source_key.sign(canonical(claims)).hex()}
        status,_,_=self.request("POST","/api/v1/sentinel/edge/observation",signed,
                            headers={"Origin":""})
        self.assertEqual(status,200)
        forged={**signed,"signature":"0"*128}
        status,_,_=self.request("POST","/api/v1/sentinel/edge/observation",forged,
                            headers={"Origin":""})
        self.assertEqual(status,403)
        status,_,_=self.request("POST","/api/v1/sentinel/edge/observation",signed,
                            headers={"Origin":self.origin})
        self.assertEqual(status,403) # no browser-origin access
        status,details,_=self.request("GET","/api/v1/sentinel/reviews",
                                     headers={"Cookie":cookie})
        self.assertEqual(status,200)
        self.assertTrue(details["enabled"])
        self.assertEqual(len(details["proposals"]),1)
        self.assertEqual(details["proposals"][0]["incident_id"],incident)
        approval={"incident_id":incident,
                  "otp":totp(secret,now//30),"confirmed":True}
        status,result,_=self.request("POST","/api/v1/sentinel/approve",approval,
            headers={"Cookie":cookie,"X-Sentinel-CSRF":csrf})
        self.assertEqual(status,201)
        self.assertTrue(result["queued"])
        self.assertEqual(result["state"],"pending")
        with store.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sentinel_dispatch_outbox").fetchone()[0],1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sentinel_dispatch_attempts").fetchone()[0],0)
        status,_,_=self.request("POST","/api/v1/sentinel/approve",approval,
            headers={"Cookie":cookie,"X-Sentinel-CSRF":csrf})
        self.assertEqual(status,403) # TOTP replay blocked

    def test_review_still_local_and_no_deployment_flag_enabled(self):
        status,body,_=self.request("GET","/healthz")
        self.assertEqual(status,200)
        self.assertFalse(bool(os.getenv("SENTINEL_REVIEW_ENABLED")=="1"))
        self.assertIsNone(self.server.ticket_review_config)


if __name__=="__main__":
    unittest.main()
