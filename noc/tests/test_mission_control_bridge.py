"""Mission Control -> NOC unification stays behind NOC login, read-only."""
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from noc.server import NocAPI,bootstrap
from noc.sentinel_mission_bridge import snapshot

class MissionBridgeTests(unittest.TestCase):
    def test_bounded_sanitized_summary_no_urls_secrets_or_browser_screenshots(self):
        class Response:
            status=200
            def __init__(self,body): self.body=json.dumps(body).encode()
            def __enter__(self):return self
            def __exit__(self,*args): pass
            def read(self,size):return self.body[:size]
        values={
            "/api/status":{"mode":"live","last_check":"2026-10-10T19:00:00Z",
                "services":[{"name":"Website","url":"https://private.example/path",
                    "status":"up","http":200,"ms":150,"private_token":"TOP_SECRET"},
                    {"name":"<img src=x onerror=alert(1)>","status":"strange","http":9999,"ms":-1}]},
            "/api/qa/latest":{"runId":"synthetic-test","state":"complete","at":"2026-10-10T18:00:00Z",
                "results":[{"name":"Website","viewport":"mobile","status":"pass",
                   "screenshot":"SECRET_IMAGE","body":"SECRET_DOC"},
                   {"name":"Hub","viewport":"desktop","status":"auth-gated"}]},
        }
        def fetch(url,timeout):return Response(values[url.removeprefix("http://127.0.0.1:8787")])
        with patch("noc.sentinel_mission_bridge.urlopen",side_effect=fetch):
            result=snapshot()
        self.assertEqual(result["services"][0]["latencyMs"],150)
        self.assertEqual(result["services"][1]["state"],"unknown")
        self.assertEqual(result["services"][1]["http"],None)
        self.assertEqual(result["qa"]["counts"]["pass"],1)
        self.assertEqual(result["qa"]["counts"]["auth-gated"],1)
        serialized=json.dumps(result)
        self.assertNotIn("TOP_SECRET",serialized)
        self.assertNotIn("SECRET_IMAGE",serialized)
        self.assertNotIn("private.example",serialized)
        self.assertNotIn("SECRET_DOC",serialized)

    def test_no_unapproved_upstream_endpoint(self):
        from noc.sentinel_mission_bridge import _read_local
        with self.assertRaises(ValueError):_read_local("http://evil.test/admin")
        with self.assertRaises(ValueError):_read_local("/api/qa/screenshot/anything")

class MissionHttpTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix="sentinel-mission-http-")
        self.addCleanup(temp.cleanup)
        self.db=Path(temp.name)/"noc.sqlite"
        bootstrap_store=__import__("noc.store",fromlist=["NocStore"]).NocStore(self.db)
        bootstrap(bootstrap_store,"mission-admin","synthetic-long-private-operator-password")
        self.server=NocAPI("127.0.0.1",0,self.db)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(lambda:(self.server.shutdown(),self.server.server_close(),
            self.thread.join(timeout=5)))

    def request(self,method,path,body=None,cookie=""):
        con=http.client.HTTPConnection("127.0.0.1",self.server.server_port,timeout=4)
        hdr={"Cookie":cookie} if cookie else {}
        if body is not None:
            hdr["Content-Type"]="application/json"
            hdr["Origin"]=f"http://127.0.0.1:{self.server.server_port}"
            body=json.dumps(body)
        con.request(method,path,body=body,headers=hdr)
        res=con.getresponse();raw=res.read();code=res.status
        headers=dict(res.getheaders());con.close()
        return code,headers,json.loads(raw) if headers.get("Content-Type","").startswith("application/json") else raw

    def login(self):
        code,h,_=self.request("POST","/api/v1/login",
            {"username":"mission-admin","password":"synthetic-long-private-operator-password"})
        self.assertEqual(code,200)
        return h["Set-Cookie"].split(";")[0]

    def test_unauthenticated_mission_summary_does_not_call_internal_monitor(self):
        with patch("noc.server.mission_control_snapshot") as fn:
            self.assertEqual(self.request("GET","/api/v1/mission-control")[0],401)
            fn.assert_not_called()

    def test_authenticated_summary_and_independent_failure(self):
        cookie=self.login()
        with patch("noc.server.mission_control_snapshot",return_value={
            "source":"local-mission-control","services":[{"name":"Website","state":"up"}],
            "qa":{"results":[],"counts":{"pass":0}}
        }):
            code,h,result=self.request("GET","/api/v1/mission-control",cookie=cookie)
        self.assertEqual(code,200)
        self.assertEqual(result["source"],"local-mission-control")
        self.assertEqual(h["Cache-Control"],"no-store")
        with patch("noc.server.mission_control_snapshot",side_effect=OSError("offline")):
            self.assertEqual(self.request("GET","/api/v1/mission-control",cookie=cookie)[0],503)
        self.assertEqual(self.request("GET","/api/v1/session",cookie=cookie)[0],200)
        self.assertEqual(self.request("GET","/api/v1/dashboard",cookie=cookie)[0],200)

if __name__=="__main__":unittest.main()
