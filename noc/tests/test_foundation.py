"""Red-team tests for Sentinel NOC isolated multi-site foundation."""
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from noc.store import NocStore
from noc.server import NocAPI, bootstrap

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="sentinel-noc-tests-")
        self.addCleanup(self.temp.cleanup)
        self.store=NocStore(Path(self.temp.name)/"test.db")
        self.a=self.store.customer("DEMO Customer One")
        self.b=self.store.customer("DEMO Customer Two")
        self.site_a=self.store.site(self.a,"Main Office")
        self.site_b=self.store.site(self.b,"Main Office")
        # Both customers use the exact same private IP address.
        self.asset_a=self.store.asset(self.site_a,"Router","192.168.1.1")
        self.asset_b=self.store.asset(self.site_b,"Router","192.168.1.1")
        self.check_a=self.store.check(self.asset_a,"WAN ping","shared-wan")
        self.check_b=self.store.check(self.asset_b,"WAN ping","shared-wan")
        self.agent_a=self.store.enroll(self.site_a,"Edge A")
        self.agent_b=self.store.enroll(self.site_b,"Edge B")

    def send(self,agent,check,seq,ok,note="synthetic"):
        return self.store.ingest(agent["credential"],{
            "sequence":seq,"readings":[{"check_id":check,"ok":ok,"latency":22,"note":note}]
        })

    def test_duplicate_customer_private_ip_does_not_merge_incidents(self):
        self.send(self.agent_a,self.check_a,1,False)
        self.send(self.agent_a,self.check_a,2,False)
        self.send(self.agent_b,self.check_b,1,False)
        self.send(self.agent_b,self.check_b,2,False)
        incidents=self.store.snapshot()["incidents"]
        self.assertEqual(len(incidents),2)
        self.assertEqual({i["customer_id"] for i in incidents},{self.a,self.b})
        self.assertEqual({i["site_id"] for i in incidents},{self.site_a,self.site_b})

    def test_cross_customer_injection_fails_atomically(self):
        baseline=self.store.snapshot()
        with self.assertRaises(PermissionError):
            self.store.ingest(self.agent_a["credential"],{"sequence":1,"readings":[
                {"check_id":self.check_a,"ok":False},
                {"check_id":self.check_b,"ok":False}
            ]})
        self.assertEqual(self.store.snapshot()["incidents"],baseline["incidents"])
        self.assertEqual(self.store.snapshot()["agents"][0]["last_seq"],0)
        self.assertEqual(self.store.snapshot()["agents"][1]["last_seq"],0)

    def test_incident_hysteresis_and_recovery(self):
        self.send(self.agent_a,self.check_a,1,False)
        self.assertEqual(len(self.store.snapshot()["incidents"]),0)
        self.send(self.agent_a,self.check_a,2,False)
        self.assertEqual(self.store.snapshot()["incidents"][0]["state"],"open")
        self.send(self.agent_a,self.check_a,3,True)
        self.assertEqual(self.store.snapshot()["incidents"][0]["state"],"open")
        self.send(self.agent_a,self.check_a,4,True)
        self.assertEqual(self.store.snapshot()["incidents"][0]["state"],"resolved")

    def test_repeated_packet_cannot_duplicate_incident(self):
        self.send(self.agent_a,self.check_a,1,False)
        self.send(self.agent_a,self.check_a,2,False)
        before=self.store.snapshot()
        result=self.send(self.agent_a,self.check_a,2,False)
        self.assertEqual(result["status"],"duplicate")
        self.assertEqual(self.store.snapshot()["incidents"],before["incidents"])
        with self.store.db() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM observations").fetchone()[0],2)

    def test_revoked_agent_cannot_ingest(self):
        self.store.revoke(self.agent_a["agent_id"])
        with self.assertRaises(PermissionError):
            self.send(self.agent_a,self.check_a,1,False)

    def test_invalid_payloads_are_rejected(self):
        for payload in [
            {"sequence":True,"readings":[{"check_id":self.check_a,"ok":True}]},
            {"sequence":1,"readings":[{"check_id":self.check_a,"ok":1}]},
            {"sequence":1,"readings":[{"check_id":self.check_a,"ok":True,"latency":-1}]},
            {"sequence":1,"readings":[{"check_id":self.check_a,"ok":True,"tenant_id":self.b}]},
            {"sequence":1,"readings":[{"check_id":self.check_a,"ok":True},
                                      {"check_id":self.check_a,"ok":True}]},
            {"sequence":1,"readings":[]}
        ]:
            with self.subTest(payload=payload),self.assertRaises(ValueError):
                self.store.ingest(self.agent_a["credential"],payload)

    def test_credential_is_never_in_dashboard(self):
        payload=json.dumps(self.store.snapshot())
        self.assertNotIn(self.agent_a["credential"],payload)
        self.assertNotIn(self.agent_b["credential"],payload)

    def test_no_active_outbound_ticketing(self):
        self.send(self.agent_a,self.check_a,1,False)
        self.send(self.agent_a,self.check_a,2,False)
        self.assertEqual(self.store.snapshot()["pending_mock_events"],1)
        with self.store.db() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM integration_outbox WHERE delivered=1").fetchone()[0],0)


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="sentinel-noc-http-")
        self.addCleanup(self.temp.cleanup)
        self.db=Path(self.temp.name)/"http.db"
        store=NocStore(self.db)
        bootstrap(store,"noc-admin","my-long-isolated-test-password")
        self.srv=NocAPI("127.0.0.1",0,self.db)
        self.thread=threading.Thread(target=self.srv.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(lambda:(self.srv.shutdown(),self.srv.server_close(),self.thread.join(timeout=5)))
        self.base=f"127.0.0.1:{self.srv.server_port}"

    def call(self,method,path,body=None,headers=None):
        conn=http.client.HTTPConnection("127.0.0.1",self.srv.server_port,timeout=4)
        headers=dict(headers or {})
        if body is not None:
            headers["Content-Type"]="application/json"
            body=json.dumps(body)
        conn.request(method,path,body,headers=headers)
        response=conn.getresponse()
        data=response.read()
        result=response.status,dict(response.getheaders()),(
            json.loads(data) if response.getheader("content-type","").startswith("application/json") else data)
        conn.close()
        return result

    def test_login_auth_cookie_csrf_and_customer_data_access(self):
        code,_,_=self.call("GET","/api/v1/dashboard")
        self.assertEqual(code,401)
        origin={"Origin":f"http://{self.base}"}
        code,headers,_=self.call("POST","/api/v1/login",{
            "username":"noc-admin","password":"my-long-isolated-test-password"},origin)
        self.assertEqual(code,200)
        cookie=headers["Set-Cookie"].split(";")[0]
        self.assertIn("HttpOnly",headers["Set-Cookie"])
        self.assertIn("SameSite=Strict",headers["Set-Cookie"])
        code,_,session=self.call("GET","/api/v1/session",headers={"Cookie":cookie})
        self.assertEqual(code,200)
        self.assertNotIn("password",session)
        h={"Origin":origin["Origin"],"Cookie":cookie,"X-Sentinel-CSRF":session["csrf"]}
        code,_,_=self.call("POST","/api/v1/customers",{"name":"DEMO Test"},{
            "Origin":origin["Origin"],"Cookie":cookie})
        self.assertEqual(code,403)
        code,_,created=self.call("POST","/api/v1/customers",{"name":"DEMO Test"},h)
        self.assertEqual(code,201)
        code,_,dashboard=self.call("GET","/api/v1/dashboard",headers={"Cookie":cookie})
        self.assertEqual(code,200)
        self.assertEqual(len(dashboard["customers"]),1)
        self.assertTrue(dashboard["simulated"])
        code,_,_=self.call("POST","/api/v1/logout",{},h)
        self.assertEqual(code,200)
        code,_,_=self.call("GET","/api/v1/dashboard",headers={"Cookie":cookie})
        self.assertEqual(code,401)

    def test_incident_csv_report_is_private_bounded_and_formula_safe(self):
        store=NocStore(self.db)
        cid=store.customer("=SUM(1,1) Demo Customer")
        site=store.site(cid,"+DEMO Branch")
        asset=store.asset(site,"Router","192.168.1.1")
        check=store.check(asset,"WAN","test-wan")
        agent=store.enroll(site,"Edge")
        for seq in (1,2):
            store.ingest(agent["credential"],{
                "sequence":seq,"readings":[{"check_id":check,"ok":False}]})
        code,_,_=self.call("GET","/api/v1/reports/incidents.csv")
        self.assertEqual(code,401)
        origin={"Origin":f"http://{self.base}"}
        code,headers,_=self.call("POST","/api/v1/login",{
            "username":"noc-admin","password":"my-long-isolated-test-password"},origin)
        self.assertEqual(code,200)
        cookie=headers["Set-Cookie"].split(";")[0]
        code,headers,data=self.call("GET","/api/v1/reports/incidents.csv",
                                      headers={"Cookie":cookie})
        self.assertEqual(code,200)
        self.assertIn("text/csv",headers["Content-Type"])
        self.assertIn("attachment",headers["Content-Disposition"])
        report=data.decode("utf-8")
        self.assertIn("SIMULATED_SENTINEL_INCIDENTS",report)
        self.assertIn("'=SUM(1,1) Demo Customer",report)
        self.assertIn("'+DEMO Branch",report)
        self.assertNotIn(agent["credential"],report)
        self.assertEqual(len(report.splitlines()),3)

    def test_maintenance_requires_authenticated_operator_and_csrf(self):
        store=NocStore(self.db)
        customer=store.customer("DEMO Maintenance")
        site=store.site(customer,"Branch")
        origin={"Origin":f"http://{self.base}"}
        code,_,_=self.call("POST","/api/v1/maintenance",
                            {"site_id":site,"reason":"Approved staging test","hours":2},origin)
        self.assertEqual(code,401)
        code,headers,_=self.call("POST","/api/v1/login",{
            "username":"noc-admin","password":"my-long-isolated-test-password"},origin)
        self.assertEqual(code,200)
        cookie=headers["Set-Cookie"].split(";")[0]
        code,_,session=self.call("GET","/api/v1/session",headers={"Cookie":cookie})
        self.assertEqual(code,200)
        code,_,_=self.call("POST","/api/v1/maintenance",
                            {"site_id":site,"reason":"Approved staging test","hours":2},
                            {"Origin":origin["Origin"],"Cookie":cookie})
        self.assertEqual(code,403)
        auth={"Origin":origin["Origin"],"Cookie":cookie,"X-Sentinel-CSRF":session["csrf"]}
        code,_,created=self.call("POST","/api/v1/maintenance",
                                  {"site_id":site,"reason":"Approved staging test","hours":2},auth)
        self.assertEqual(code,201)
        self.assertTrue(created["id"])
        code,_,dashboard=self.call("GET","/api/v1/dashboard",headers={"Cookie":cookie})
        self.assertEqual(code,200)
        self.assertEqual(len(dashboard["maintenance"]),1)
        self.assertEqual(dashboard["maintenance"][0]["site_id"],site)

    def test_agent_heartbeat_without_device_observation(self):
        store=NocStore(self.db)
        customer=store.customer("DEMO Heartbeat Business")
        site=store.site(customer,"Lab Branch")
        agent=store.enroll(site,"Simulated Collector")
        auth={"Authorization":"Bearer "+agent["credential"]}
        code,_,reply=self.call("POST","/api/v1/agent/heartbeat",headers=auth)
        self.assertEqual(code,200)
        self.assertEqual(reply,{"status":"online","sequence":0})
        self.assertEqual(store.snapshot()["agents"][0]["connection"],"online")
        with store.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM observations").fetchone()[0],0)
        store.revoke(agent["agent_id"])
        code,_,_=self.call("POST","/api/v1/agent/heartbeat",headers=auth)
        self.assertEqual(code,403)

    def test_origin_rejection_and_agent_restriction(self):
        code,_,_=self.call("POST","/api/v1/login",{"username":"noc-admin","password":"something"})
        self.assertEqual(code,403)
        code,_,_=self.call("POST","/api/v1/agent/telemetry",{
            "sequence":1,"readings":[{"check_id":"anything","ok":True}]},
            {"Authorization":"Bearer not-an-agent-token"})
        self.assertEqual(code,403)

    def test_refuses_non_loopback_public_binding(self):
        import subprocess,sys
        # Argument validation occurs before any socket bind or customer probe.
        # Do not launch the actual service on a public interface.
        result=subprocess.run([sys.executable,"-m","noc.server","--bind","0.0.0.0",
                               "--db",str(self.db),"--port","0"],capture_output=True,text=True,timeout=5)
        self.assertNotEqual(result.returncode,0)
        self.assertIn("loopback",result.stderr)

if __name__=="__main__":
    unittest.main()
