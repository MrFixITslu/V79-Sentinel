"""No-network DNS-rebinding regression tests for V79 Sentinel HTTPS HEAD probes."""
from __future__ import annotations

import socket
import ssl
import unittest
from unittest.mock import Mock, call, patch

import monitor_core as monitor

HOST = "hub.v79sl.com"
PUBLIC_A = "1.1.1.1"
PUBLIC_B = "8.8.8.8"
URL = "https://hub.v79sl.com/"


class PinnedPublicProbeTests(unittest.TestCase):
    def connection(self, addresses=(PUBLIC_A,)):
        self.tls = Mock()
        self.tls.wrap_socket.return_value = Mock()
        return monitor.PinnedPublicHTTPSConnection(
            HOST, list(addresses), timeout=8, context=self.tls)

    def test_tcp_socket_uses_checked_numeric_ip_but_tls_sni_original_hostname(self):
        conn = self.connection()
        raw = Mock()
        with patch.object(monitor.socket, "create_connection",
                          return_value=raw) as tcp:
            conn.connect()
        tcp.assert_called_once_with((PUBLIC_A, 443), 8, None)
        self.tls.wrap_socket.assert_called_once_with(
            raw, server_hostname=HOST)
        self.assertIs(conn.sock, self.tls.wrap_socket.return_value)

    def test_cannot_re_resolve_host_after_allowlist(self):
        with patch.object(monitor.socket, "getaddrinfo") as resolver, \
             patch.object(monitor.socket, "create_connection",
                          return_value=Mock()) as tcp:
            conn = self.connection()
            conn.connect()
            self.assertEqual(resolver.call_count, 0)
            self.assertEqual(tcp.call_args.args[0][0], PUBLIC_A)
            self.assertNotIn(HOST, str(tcp.call_args))

    def test_rejects_private_loopback_reserved_unspecified_and_empty(self):
        for ip in (
            "10.0.0.1", "172.16.0.2", "192.168.1.1", "127.0.0.1",
            "169.254.169.254", "::1", "fc00::1", "0.0.0.0",
        ):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                self.connection((PUBLIC_A, ip))
        with self.assertRaises(ValueError):
            self.connection(())
        with self.assertRaises(ValueError):
            self.connection((PUBLIC_A,) * 21)

    def test_refuses_http_proxy_tunnel(self):
        conn = self.connection()
        conn.set_tunnel("proxy.example", 443)
        with patch.object(monitor.socket, "create_connection") as tcp:
            with self.assertRaisesRegex(ValueError, "tunnels"):
                conn.connect()
            tcp.assert_not_called()

    def test_first_ip_tcp_failure_retries_only_next_prevalidated_public_ip(self):
        raw = Mock()
        conn = self.connection((PUBLIC_A, PUBLIC_B))
        with patch.object(monitor.socket, "create_connection",
                          side_effect=[OSError("synthetic TCP failure"), raw]) as tcp:
            conn.connect()
        self.assertEqual(
            tcp.call_args_list,
            [call((PUBLIC_A, 443), 8, None), call((PUBLIC_B, 443), 8, None)]
        )
        self.tls.wrap_socket.assert_called_once_with(
            raw, server_hostname=HOST)

    def test_tls_failure_closes_failed_socket_and_fails_closed(self):
        conn = self.connection()
        raw = Mock()
        self.tls.wrap_socket.side_effect = ssl.SSLError(
            "synthetic certificate mismatch")
        with patch.object(monitor.socket, "create_connection",
                          return_value=raw):
            with self.assertRaises(ssl.SSLError):
                conn.connect()
        raw.close.assert_called_once()
        self.assertIsNone(conn.sock)

    def test_dns_lookup_rejects_mixed_public_and_private_ips(self):
        public = (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                  (PUBLIC_A, 443))
        private = (socket.AF_INET, socket.SOCK_STREAM, 6, "",
                   ("127.0.0.1", 443))
        with patch.object(monitor.socket, "getaddrinfo",
                          return_value=[public, private]):
            with self.assertRaises(ValueError):
                monitor._safe_addresses(HOST)
        with patch.object(monitor.socket, "getaddrinfo",
                          return_value=[public]):
            self.assertEqual(monitor._safe_addresses(HOST), [PUBLIC_A])

    def test_probe_uses_pinned_connection_and_still_enforces_tls_defaults(self):
        target = {"name": "V79 Hub", "url": URL}
        session = Mock()
        session.sock.getpeercert.return_value = {"notAfter": "Dec 31 23:59:59 2027 GMT"}
        session.getresponse.return_value.status = 200
        with patch.object(monitor, "_safe_addresses",
                          return_value=[PUBLIC_A]) as lookup, \
             patch.object(monitor, "PinnedPublicHTTPSConnection",
                          return_value=session) as pinned, \
             patch.object(monitor.ssl, "create_default_context",
                          return_value=Mock()) as context:
            result = monitor.probe(target)
        lookup.assert_called_once_with(HOST)
        pinned.assert_called_once_with(
            HOST, [PUBLIC_A], timeout=monitor.TIMEOUT_SECONDS,
            context=context.return_value)
        self.assertEqual(result["status"], "up")
        self.assertEqual(result["http"], 200)
        self.assertEqual(result["ip_count"], 1)
        self.assertTrue(session.close.called)

    def test_tcp_and_tls_failure_remain_down_not_false_healthy(self):
        target = {"name": "V79 Hub", "url": URL}
        with patch.object(monitor, "_safe_addresses",
                          return_value=[PUBLIC_A]), \
             patch.object(monitor, "PinnedPublicHTTPSConnection") as pinned:
            pinned.return_value.connect.side_effect = ssl.SSLError(
                "synthetic TLS failure")
            report = monitor.probe(target)
        self.assertEqual(report["status"], "down")
        self.assertIsNone(report["http"])
        self.assertIn("SSLError", report["message"])


if __name__ == "__main__":
    unittest.main()
