"""Internal Docker packaging must preserve the Acer safety contract.

These tests inspect only source/deployment configuration. They do not install
Sentinel, access production devices, create operators or expose services.
"""
from pathlib import Path
import hashlib
from unittest import TestCase
from unittest.mock import patch

from noc.sentinel_mission_full import SOURCE
from noc.sentinel_netpulse_interfaces import sample_host_interfaces

ROOT = Path(__file__).resolve().parents[2]
DOCKER = ROOT / "deploy" / "docker"


class PrivateDockerPackagingTests(TestCase):
    def test_mission_assets_are_repo_relative_and_exist(self):
        self.assertEqual(SOURCE.resolve(), (ROOT / "web").resolve())
        for item in ("index.html", "app.js", "style.css"):
            self.assertTrue((SOURCE / item).is_file(), item)

    def test_live_g221_native_ui_assets_unchanged(self):
        # SHA-256 recorded from the ACTIVE clean G2.21 Acer checkout.
        # This is a release migration parity gate, not a permanent UI design lock.
        expected = {
            "noc/web/index.html":
                "95b890208d2416a8ba7de8f4ae8071ea97daf224798030970e045dbe7e2a34e3",
            "noc/web/enterprise-center.js":
                "efc2a2d7fc6929e0ef6bf10d89a8fc37340d99759bdbc24617c64da2e8da42e9",
            "noc/web/mission-native.js":
                "9d8d79170f8a9c432f0425ec99868f77775f481ad86a9abdd3c70816d4eb488f",
        }
        for relative, sha in expected.items():
            with self.subTest(relative):
                self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), sha)

    def test_three_services_share_loopback_and_proxy_network(self):
        compose = (DOCKER / "compose.yaml").read_text()
        self.assertIn('network_mode: "service:noc"', compose)
        self.assertIn("networks: [proxy_network]", compose)
        self.assertIn("external: true", compose)
        self.assertIn('127.0.0.1:${SENTINEL_HOST_PORT:', compose)
        self.assertIn('"127.0.0.1"', compose)
        self.assertIn("8787", compose)
        self.assertIn("8788", compose)
        self.assertNotIn("3000:", compose)
        self.assertIn('SENTINEL_REVIEW_ENABLED: "0"', compose)
        self.assertIn('SENTINEL_APPROVER_SERVICE_ENABLED: "0"', compose)
        self.assertNotIn("docker.sock", compose)
        self.assertNotIn("privileged: true", compose)

    def test_nginx_proxies_only_noc_not_unprotected_monitor(self):
        nginx = (DOCKER / "nginx-private.conf").read_text()
        self.assertIn("listen 8080;", nginx)
        self.assertIn("proxy_pass http://127.0.0.1:8788;", nginx)
        self.assertNotIn("proxy_pass http://127.0.0.1:8787", nginx)

    def test_docker_file_nonroot_and_no_scanner_permissions(self):
        dockerfile = (DOCKER / "Dockerfile.noc").read_text()
        self.assertIn("USER 10001:10001", dockerfile)
        self.assertNotIn("sudo", dockerfile)
        self.assertNotIn("docker.sock", dockerfile)

    def test_docker_netpulse_counter_scope_is_explicit(self):
        fake = ("Inter-| Receive | Transmit\n"
                "face|bytes packets errs drop fifo frame compressed multicast|"
                "bytes packets errs drop fifo colls carrier compressed\n"
                "eth0: 250 0 0 0 0 0 0 0 500 0 0 0 0 0 0 0\n")
        with patch.dict("os.environ", {"SENTINEL_MONITORING_CONTEXT": "docker"}), \
             patch("noc.sentinel_netpulse_interfaces.Path.read_text", return_value=fake):
            report = sample_host_interfaces()
        self.assertEqual(report["source"], "container-netns:/proc/net/dev")
        self.assertIn("not represent host", report["scope"])
        self.assertEqual(report["interfaces"][0]["name"], "eth0")

    def test_existing_acer_netpulse_scope_is_unchanged(self):
        fake = ("Inter-| Receive | Transmit\n"
                "face|bytes packets errs drop fifo frame compressed multicast|"
                "bytes packets errs drop fifo colls carrier compressed\n"
                "wlp3s0: 10 0 0 0 0 0 0 0 20 0 0 0 0 0 0 0\n")
        with patch.dict("os.environ", {"SENTINEL_MONITORING_CONTEXT": ""}), \
             patch("noc.sentinel_netpulse_interfaces.Path.read_text", return_value=fake):
            report = sample_host_interfaces()
        self.assertEqual(report["source"], "acer-host:/proc/net/dev")


class PilotCookieOriginTests(TestCase):
    def test_private_localhost_login_cookie_not_secure_over_http(self):
        # A Secure cookie must not break private HTTP loopback staging.
        import http.client
        import tempfile
        from noc.server import NocAPI, bootstrap
        from noc.store import NocStore
        from threading import Thread
        with tempfile.TemporaryDirectory(prefix="sentinel-cookie-") as tmp:
            db = Path(tmp) / "noc.sqlite3"
            bootstrap(NocStore(db), "synthetic-admin", "synthetic-long-private-password")
            server = NocAPI("127.0.0.1", 0, db)
            server.external_origin = f"http://127.0.0.1:{server.server_port}"
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                import json
                con = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                con.request("POST", "/api/v1/login",
                            body=json.dumps({"username": "synthetic-admin",
                                             "password": "synthetic-long-private-password"}),
                            headers={"Content-Type": "application/json",
                                     "Origin": server.external_origin})
                res = con.getresponse()
                res.read()
                cookie = res.getheader("Set-Cookie", "")
                self.assertEqual(res.status, 200)
                self.assertIn("HttpOnly", cookie)
                self.assertNotIn("; Secure", cookie)
                con.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_https_operator_origin_retains_secure_cookie(self):
        import http.client
        import tempfile
        import json
        from threading import Thread
        from noc.server import NocAPI, bootstrap
        from noc.store import NocStore
        with tempfile.TemporaryDirectory(prefix="sentinel-cookie-https-") as tmp:
            db = Path(tmp) / "noc.sqlite3"
            bootstrap(NocStore(db), "synthetic-admin", "synthetic-long-private-password")
            server = NocAPI("127.0.0.1", 0, db)
            server.external_origin = "https://sentinel.example.invalid"
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                con = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                con.request("POST", "/api/v1/login",
                            body=json.dumps({"username": "synthetic-admin",
                                             "password": "synthetic-long-private-password"}),
                            headers={"Content-Type": "application/json",
                                     "Origin": server.external_origin})
                res = con.getresponse()
                res.read()
                cookie = res.getheader("Set-Cookie", "")
                self.assertEqual(res.status, 200)
                self.assertIn("; Secure", cookie)
                con.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
