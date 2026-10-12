"""Internal Docker packaging must preserve the Acer safety contract.

These tests inspect only source/deployment configuration. They do not install
Sentinel, access production devices, create operators or expose services.
"""
from pathlib import Path
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
