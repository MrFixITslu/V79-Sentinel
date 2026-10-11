"""Local-only ingress contract: never proxy NOC admin routes."""
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from threading import Thread
import json
import unittest
from unittest.mock import patch

from noc.sentinel_private_gateway import Handler,PATH


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        self.addCleanup(self.server.server_close)
        thread=Thread(target=self.server.serve_forever,daemon=True)
        thread.start()
        self.addCleanup(self.server.shutdown)

    def request(self,method,path,body=None,headers=None):
        client=HTTPConnection("127.0.0.1",self.server.server_port,timeout=3)
        try:
            client.request(method,path,body=body,headers=headers or {})
            response=client.getresponse()
            return response.status,response.read(),dict(response.getheaders())
        finally:
            client.close()

    def test_all_admin_paths_and_http_methods_denied(self):
        for path in ("/","/healthz","/api/v1/session","/api/v1/dashboard",
                     "/api/v1/sentinel/reviews","/api/v1/sentinel/approve",
                     PATH+"/evil",PATH+"?debug=1"):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET",path)[0],404)
                self.assertEqual(self.request("POST",path,b"{}",
                    {"Content-Type":"application/json"})[0],404)
        self.assertEqual(self.request("OPTIONS",PATH)[0],404)

    def test_denies_unsigned_browser_cookie_and_bad_machine_identity(self):
        self.assertEqual(self.request("POST",PATH,b"{}",{
            "Content-Type":"application/json"})[0],400)
        signed={"Content-Type":"application/json","X-V79-Service-Id":"v79-tiquet",
            "X-V79-Timestamp":"1791650000","X-V79-Signature":"0"*64}
        for extra in ({"Cookie":"session=forbidden"},
                      {"Authorization":"Bearer forbidden"},
                      {"Origin":"https://untrusted.example"}):
            with self.subTest(extra=extra):
                self.assertEqual(self.request("POST",PATH,b"{}",{
                    **signed,**extra})[0],403)
        self.assertIn(self.request("POST",PATH,b"{}",signed)[0],(401,403,404,503))

    def test_no_browser_cors_or_reflective_headers(self):
        status,_,headers=self.request("GET","/")
        self.assertEqual(status,404)
        self.assertEqual(headers["Cache-Control"],"no-store")
        self.assertEqual(headers["X-Content-Type-Options"],"nosniff")
        self.assertNotIn("Access-Control-Allow-Origin",headers)


if __name__=="__main__":
    unittest.main()
