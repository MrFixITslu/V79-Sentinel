"""Isolated provider-role and TOTP tests. No real operator accounts are changed."""
import http.client
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path

from noc.operators import create_operator, disable_operator, list_operators, mfa_begin, mfa_confirm
from noc.security import totp, accepted_totp_counter, new_totp_secret, provisioning_uri
from noc.store import NocStore
from noc.server import NocAPI, bootstrap

ADMIN_PASSWORD="synthetic-only-long-admin-password"
TECH_PASSWORD="synthetic-only-long-tech-password"
VIEW_PASSWORD="synthetic-only-long-view-password"

class MigrationTests(unittest.TestCase):
    def test_existing_admin_and_sessions_preserved_by_additive_migration(self):
        with tempfile.TemporaryDirectory(prefix="sentinel-legacy-migration-") as directory:
            path=Path(directory)/"legacy.sqlite3"
            with sqlite3.connect(path) as db:
                db.executescript("""
                  CREATE TABLE operators (
                    id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,role TEXT NOT NULL);
                  CREATE TABLE sessions (
                    digest TEXT PRIMARY KEY,operator_id TEXT NOT NULL,
                    csrf TEXT NOT NULL,expires INTEGER NOT NULL);
                """)
                db.execute("INSERT INTO operators VALUES(?,?,?,?)",
                           ("existing-admin","noc-admin","existing-password-hash","admin"))
                db.execute("INSERT INTO sessions VALUES(?,?,?,?)",
                           ("x"*64,"existing-admin","existing-csrf",int(time.time())+3600))
            store=NocStore(path)
            with store.db() as db:
                record=db.execute("SELECT * FROM operators WHERE id='existing-admin'").fetchone()
                self.assertEqual(record["username"],"noc-admin")
                self.assertEqual(record["password_hash"],"existing-password-hash")
                self.assertEqual(record["role"],"admin")
                self.assertEqual(record["disabled"],0)
                self.assertIsNone(record["mfa_secret"])
                self.assertEqual(db.execute("SELECT count(*) FROM sessions").fetchone()[0],1)
            # Running initialization a second time does not change the existing record.
            store=NocStore(path)
            with store.db() as db:
                self.assertEqual(db.execute("SELECT count(*) FROM operators").fetchone()[0],1)

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="sentinel-security-test-")
        self.addCleanup(self.temp.cleanup)
        self.store=NocStore(Path(self.temp.name)/"isolated.sqlite3")
        bootstrap(self.store,"noc-admin",ADMIN_PASSWORD)
        with self.store.db() as db:
            self.admin_id=db.execute("SELECT id FROM operators WHERE username='noc-admin'").fetchone()[0]

    def test_totp_vector_replay_and_provisioning(self):
        # RFC 6238 SHA-1 reference vector 59s, 8 digits 94287082 -> six 287082.
        import base64
        # Public RFC 6238 SHA-1 fixture, not a credential
        secret = base64.b32encode(b"12345678901234567890").decode("ascii")
        self.assertEqual(totp(secret,1),"287082")
        self.assertEqual(accepted_totp_counter(secret,"287082",now=59),1)
        self.assertIsNone(accepted_totp_counter(secret,"287082",now=59,last=1))
        self.assertIsNone(accepted_totp_counter(secret,"287O82",now=59))
        self.assertIn("otpauth://totp/",provisioning_uri("noc-admin",new_totp_secret()))

    def test_role_creation_requires_admin_password_and_known_role(self):
        with self.assertRaises(PermissionError):
            create_operator(self.store,self.admin_id,"incorrect",
                            "technician1",TECH_PASSWORD,"operator")
        with self.assertRaises(ValueError):
            create_operator(self.store,self.admin_id,ADMIN_PASSWORD,
                            "technician1",TECH_PASSWORD,"superuser")
        with self.assertRaises(ValueError):
            create_operator(self.store,self.admin_id,ADMIN_PASSWORD,
                            "bad username",TECH_PASSWORD,"operator")
        op=create_operator(self.store,self.admin_id,ADMIN_PASSWORD,
                           "technician1",TECH_PASSWORD,"operator")
        self.assertEqual(op["role"],"operator")
        records=list_operators(self.store)
        self.assertEqual(len(records),2)
        self.assertTrue(all("password_hash" not in x and "mfa_secret" not in x for x in records))

    def test_disable_operator_revokes_all_sessions(self):
        created=create_operator(self.store,self.admin_id,ADMIN_PASSWORD,
                                "technician1",TECH_PASSWORD,"operator")
        with self.store.db() as db:
            db.execute("INSERT INTO sessions VALUES(?,?,?,?)",
                       ("x"*64,created["id"],"test-csrf",int(time.time())+3600))
        with self.assertRaises(PermissionError):
            disable_operator(self.store,self.admin_id,"bad",created["id"])
        with self.assertRaises(ValueError):
            disable_operator(self.store,self.admin_id,ADMIN_PASSWORD,self.admin_id)
        disable_operator(self.store,self.admin_id,ADMIN_PASSWORD,created["id"])
        with self.store.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM sessions WHERE operator_id=?",
                                        (created["id"],)).fetchone()[0],0)
        with self.assertRaises(ValueError):
            disable_operator(self.store,self.admin_id,ADMIN_PASSWORD,created["id"])

    def test_enrollment_expiry_and_session_invalidation(self):
        with self.assertRaises(PermissionError):
            mfa_begin(self.store,self.admin_id,"incorrect")
        info=mfa_begin(self.store,self.admin_id,ADMIN_PASSWORD)
        self.assertIn("otpauth://totp/",info["uri"])
        with self.store.db() as db:
            db.execute("INSERT INTO sessions VALUES(?,?,?,?)",
                       ("z"*64,self.admin_id,"test",int(time.time())+1800))
        with self.assertRaises(PermissionError):
            mfa_confirm(self.store,self.admin_id,"00000x")
        counter=int(time.time()//30)
        result=mfa_confirm(self.store,self.admin_id,totp(info["secret"],counter))
        self.assertTrue(result["must_sign_in_again"])
        with self.store.db() as db:
            row=db.execute("SELECT mfa_secret,mfa_pending,mfa_last_counter FROM operators WHERE id=?",
                           (self.admin_id,)).fetchone()
            self.assertEqual(row["mfa_secret"],info["secret"])
            self.assertIsNone(row["mfa_pending"])
            self.assertEqual(row["mfa_last_counter"],counter)
            self.assertEqual(db.execute("SELECT count(*) FROM sessions WHERE operator_id=?",
                                        (self.admin_id,)).fetchone()[0],0)
        with self.assertRaises(ValueError):mfa_begin(self.store,self.admin_id,ADMIN_PASSWORD)

    def test_mfa_confirm_attempt_limit_invalidates_pending_secret(self):
        info=mfa_begin(self.store,self.admin_id,ADMIN_PASSWORD)
        for _ in range(5):
            with self.assertRaises(PermissionError):
                mfa_confirm(self.store,self.admin_id,"badcode")
        with self.store.db() as db:
            row=db.execute("""SELECT mfa_pending,mfa_pending_until,mfa_pending_attempts
                              FROM operators WHERE id=?""",(self.admin_id,)).fetchone()
            self.assertIsNone(row["mfa_pending"])
            self.assertIsNone(row["mfa_pending_until"])
            self.assertEqual(row["mfa_pending_attempts"],5)
        with self.assertRaises(PermissionError):
            mfa_confirm(self.store,self.admin_id,totp(info["secret"],int(time.time()//30)))
        new_info=mfa_begin(self.store,self.admin_id,ADMIN_PASSWORD)
        self.assertNotEqual(new_info["secret"],info["secret"])

    def test_expired_enrollment_denied(self):
        info=mfa_begin(self.store,self.admin_id,ADMIN_PASSWORD)
        with self.store.db() as db:
            db.execute("UPDATE operators SET mfa_pending_until=? WHERE id=?",
                       (int(time.time())-30,self.admin_id))
        with self.assertRaises(PermissionError):
            mfa_confirm(self.store,self.admin_id,totp(info["secret"],int(time.time()//30)))

class RoleHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="sentinel-roles-http-")
        self.addCleanup(self.temp.cleanup)
        self.db=Path(self.temp.name)/"http.sqlite3"
        self.store=NocStore(self.db)
        bootstrap(self.store,"noc-admin",ADMIN_PASSWORD)
        with self.store.db() as c:
            self.admin=c.execute("SELECT id FROM operators WHERE username='noc-admin'").fetchone()[0]
        create_operator(self.store,self.admin,ADMIN_PASSWORD,"tech1",TECH_PASSWORD,"operator")
        create_operator(self.store,self.admin,ADMIN_PASSWORD,"view1",VIEW_PASSWORD,"viewer")
        customer=self.store.customer("DEMO Security Customer")
        site=self.store.site(customer,"DEMO Office")
        asset=self.store.asset(site,"Router","192.168.100.1")
        check=self.store.check(asset,"WAN","demo-failure")
        agent=self.store.enroll(site,"Demo Collector")
        for seq in (1,2):
            self.store.ingest(agent["credential"],{"sequence":seq,"readings":[{"check_id":check,"ok":False}]})
        self.incident_id=self.store.snapshot()["incidents"][0]["id"]
        self.server=NocAPI("127.0.0.1",0,self.db)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(lambda:(self.server.shutdown(),self.server.server_close(),
                                self.thread.join(timeout=5)))
        self.origin=f"http://127.0.0.1:{self.server.server_port}"

    def request(self,method,path,body=None,headers=None):
        connection=http.client.HTTPConnection("127.0.0.1",self.server.server_port,timeout=6)
        hs=dict(headers or {})
        data=None
        if body is not None:
            data=json.dumps(body)
            hs["Content-Type"]="application/json"
        connection.request(method,path,body=data,headers=hs)
        response=connection.getresponse()
        value=response.read()
        typ=response.getheader("content-type","")
        result=(response.status,dict(response.getheaders()),json.loads(value)
                if typ.startswith("application/json") else value)
        connection.close()
        return result

    def sign_in(self,username,password,otp=None):
        credentials={"username":username,"password":password}
        if otp is not None:credentials["otp"]=otp
        code,headers,_=self.request("POST","/api/v1/login",credentials,
                                    {"Origin":self.origin})
        self.assertEqual(code,200)
        cookie=headers["Set-Cookie"].split(";")[0]
        status,_,session=self.request("GET","/api/v1/session",headers={"Cookie":cookie})
        self.assertEqual(status,200)
        return {"Cookie":cookie,"Origin":self.origin,"X-Sentinel-CSRF":session["csrf"]}

    def test_operator_can_acknowledge_but_not_manage_inventory(self):
        auth=self.sign_in("tech1",TECH_PASSWORD)
        code,_,_=self.request("POST","/api/v1/incidents/ack",
                              {"incident_id":self.incident_id},auth)
        self.assertEqual(code,200)
        self.assertEqual(self.store.snapshot()["incidents"][0]["state"],"acknowledged")
        code,_,_=self.request("POST","/api/v1/customers",{"name":"Forbidden"},auth)
        self.assertEqual(code,403)
        code,_,_=self.request("GET","/api/v1/operators",headers=auth)
        self.assertEqual(code,403)

    def test_viewer_cannot_acknowledge_or_manage(self):
        auth=self.sign_in("view1",VIEW_PASSWORD)
        code,_,data=self.request("GET","/api/v1/dashboard",headers=auth)
        self.assertEqual(code,200)
        self.assertEqual(len(data["incidents"]),1)
        code,_,_=self.request("POST","/api/v1/incidents/ack",
                              {"incident_id":self.incident_id},auth)
        self.assertEqual(code,403)
        code,_,_=self.request("POST","/api/v1/agents/enroll",
                              {"site_id":"bad","name":"Forbidden"},auth)
        self.assertEqual(code,403)

    def test_admin_user_management_requires_password_and_csrf(self):
        auth=self.sign_in("noc-admin",ADMIN_PASSWORD)
        body={"username":"newtech","password":TECH_PASSWORD,
              "role":"operator","current_password":ADMIN_PASSWORD}
        hs=dict(auth)
        hs.pop("X-Sentinel-CSRF")
        code,_,_=self.request("POST","/api/v1/operators",body,hs)
        self.assertEqual(code,403)
        body["current_password"]="incorrect"
        code,_,_=self.request("POST","/api/v1/operators",body,auth)
        self.assertEqual(code,403)
        body["current_password"]=ADMIN_PASSWORD
        code,_,created=self.request("POST","/api/v1/operators",body,auth)
        self.assertEqual(code,201)
        code,_,items=self.request("GET","/api/v1/operators",headers=auth)
        self.assertEqual(code,200)
        self.assertEqual(len(items["operators"]),4)
        self.assertNotIn("password_hash",repr(items))
        code,_,_=self.request("POST","/api/v1/operators/disable",
                              {"operator_id":created["id"],"current_password":ADMIN_PASSWORD},auth)
        self.assertEqual(code,200)
        code,_,_=self.request("POST","/api/v1/login",
                              {"username":"newtech","password":TECH_PASSWORD},
                              {"Origin":self.origin})
        self.assertEqual(code,401)

    def test_one_time_recovery_codes_allow_access_and_cannot_be_reused(self):
        auth=self.sign_in("noc-admin",ADMIN_PASSWORD)
        status,_,pending=self.request("POST","/api/v1/mfa/start",
                                      {"password":ADMIN_PASSWORD},auth)
        self.assertEqual(status,200)
        token=totp(pending["secret"],int(time.time()//30))
        status,_,confirmation=self.request("POST","/api/v1/mfa/confirm",
                                           {"code":token},auth)
        self.assertEqual(status,200)
        codes=confirmation["recovery_codes"]
        self.assertEqual(len(codes),8)
        self.assertEqual(len(set(codes)),8)
        with self.store.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM mfa_recovery_codes").fetchone()[0],8)
            db_text=str(db.execute("SELECT group_concat(code_hash) FROM mfa_recovery_codes").fetchone()[0])
            for code in codes:self.assertNotIn(code,db_text)
        origin={"Origin":self.origin}
        status,headers,_=self.request("POST","/api/v1/login",
              {"username":"noc-admin","password":ADMIN_PASSWORD,
               "recovery_code":codes[0]},origin)
        self.assertEqual(status,200)
        self.assertIn("sentinel_noc",headers.get("Set-Cookie",""))
        status,_,_=self.request("POST","/api/v1/login",
              {"username":"noc-admin","password":ADMIN_PASSWORD,
               "recovery_code":codes[0]},origin)
        self.assertEqual(status,401)
        status,_,_=self.request("POST","/api/v1/login",
              {"username":"noc-admin","password":ADMIN_PASSWORD,
               "recovery_code":codes[1]},origin)
        self.assertEqual(status,200)
        with self.store.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM mfa_recovery_codes WHERE used_at IS NOT NULL").fetchone()[0],2)

    def test_admin_opt_in_totp_requires_second_factor_and_replay_is_rejected(self):
        auth=self.sign_in("noc-admin",ADMIN_PASSWORD)
        code,_,pending=self.request("POST","/api/v1/mfa/start",
                                    {"password":ADMIN_PASSWORD},auth)
        self.assertEqual(code,200)
        secret=pending["secret"]
        counter=int(time.time()//30)
        code,_,complete=self.request("POST","/api/v1/mfa/confirm",
                                     {"code":totp(secret,counter)},auth)
        self.assertEqual(code,200)
        self.assertTrue(complete["must_sign_in_again"])
        code,_,_=self.request("GET","/api/v1/dashboard",headers=auth)
        self.assertEqual(code,401)
        code,_,_=self.request("POST","/api/v1/login",
                              {"username":"noc-admin","password":ADMIN_PASSWORD},
                              {"Origin":self.origin})
        self.assertEqual(code,401)
        auth2=self.sign_in("noc-admin",ADMIN_PASSWORD,totp(secret,counter+1))
        self.assertTrue(auth2["Cookie"])
        code,_,_=self.request("POST","/api/v1/login",
                              {"username":"noc-admin","password":ADMIN_PASSWORD,
                               "otp":totp(secret,counter+1)},{"Origin":self.origin})
        self.assertEqual(code,401)

if __name__=="__main__":unittest.main()
