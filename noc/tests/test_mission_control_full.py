"""Full original Mission Control inside authenticated NOC: read-only boundaries."""
import unittest
from unittest.mock import patch
from noc.tests.test_mission_control_bridge import MissionHttpTests
from noc.sentinel_mission_full import read_only_resource,SCREENSHOT

class FullMissionControlTests(MissionHttpTests):
    def test_full_dashboard_requires_authenticated_noc_session(self):
        for path in ("/mission-control/","/mission-control/app.js",
                     "/mission-control/style.css","/mission-control/api/status",
                     "/mission-control/api/qa/latest","/mission-control/api/qa/auth-readiness",
                     "/mission-control/api/report.csv",
                     "/mission-control/api/qa/screenshot/20261009T221455Z/website-desktop.png"):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET",path)[0],401)

    def test_full_dashboard_uses_safe_same_origin_frame_and_routes(self):
        cookie=self.login()
        code,headers,html=self.request("GET","/mission-control/",cookie=cookie)
        self.assertEqual(code,200)
        self.assertEqual(headers["X-Frame-Options"],"SAMEORIGIN")
        self.assertIn("frame-ancestors 'self'",headers["Content-Security-Policy"])
        self.assertIn(b'href="/mission-control/style.css"',html)
        self.assertIn(b'src="/mission-control/app.js"',html)
        self.assertIn(b'id="trendChart"',html)
        self.assertIn(b'id="qaRows"',html)
        self.assertIn(b'id="events"',html)
        self.assertIn(b'id="insight"',html)
        self.assertIn(b'id="labState"',html)
        self.assertIn(b'id="qaAuthSummary"',html)
        code,h,js=self.request("GET","/mission-control/app.js",cookie=cookie)
        self.assertEqual(code,200)
        self.assertEqual(h["X-Frame-Options"],"DENY")
        for uri in ("/mission-control/api/status","/mission-control/api/qa/latest",
                    "/mission-control/api/qa/auth-readiness",
                    "/mission-control/api/qa/screenshot/"):
            self.assertIn(uri.encode(),js)
        self.assertNotIn(b"fetch('/api/status'",js)
        for p in ("/mission-control/style.css","/mission-control/api/status",
                  "/mission-control/api/qa/latest","/mission-control/api/qa/auth-readiness",
                  "/mission-control/api/report.csv"):
            with self.subTest(allowed=p):
                code,_,_=self.request("GET",p,cookie=cookie)
                self.assertEqual(code,200)

    def test_original_noc_remains_not_frameable(self):
        code,headers,_=self.request("GET","/",cookie=self.login())
        self.assertEqual(code,200)
        self.assertEqual(headers["X-Frame-Options"],"DENY")
        self.assertIn("frame-ancestors 'none'",headers["Content-Security-Policy"])

    def test_no_arbitrary_upstream_or_traversal(self):
        for path in ("/mission-control/api/foo",
                     "/mission-control/../../api/status",
                     "/mission-control/api/qa/screenshot/..%2fadmin/x.png",
                     "/mission-control/api/qa/screenshot/validid/../../secret.png",
                     "/mission-control/api/qa/screenshot/validid/someprivate.txt",
                     "/mission-control/api/qa/screenshot/validid/intruder.svg"):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET",path,cookie=self.login())[0],404)
        self.assertFalse(SCREENSHOT.fullmatch("/mission-control/api/qa/screenshot/run/../../file.png"))

    def test_only_original_static_and_upstream_data_from_fixed_local_address(self):
        body,mime,frame=read_only_resource("/mission-control/")
        self.assertTrue(frame)
        self.assertTrue(mime.startswith("text/html"))
        for field in (b'id="trendChart"',b'id="qaRows"',b'id="serviceRows"',
                      b'id="metricLatency"',b'id="labSSH"'):
            self.assertIn(field,body)
        with self.assertRaises(ValueError):
            read_only_resource("/mission-control/api/open/evil.example")
        with self.assertRaises(ValueError):
            read_only_resource("/mission-control/foo.php")

if __name__=="__main__": unittest.main()
