#!/usr/bin/env python3
"""Unit tests for V79 Sentinel core: read-only target validation and local history."""
import pathlib
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from monitor_core import Telemetry, _safe_addresses, validate_services

class ValidationTests(unittest.TestCase):
    def test_accepts_known_v79(self):
        self.assertEqual(len(validate_services([
            {"name":"Site","url":"https://v79sl.com/"},
            {"name":"Hub","url":"https://hub.v79sl.com/"}])),2)

    def test_rejects_other_domains(self):
        for url in ["https://evil.tld/","https://v79sl.com.evil.tld/",
                    "http://v79sl.com/","https://127.0.0.1/",
                    "https://192.168.100.163/","https://v79sl.com:8443/",
                    "https://alice:password@v79sl.com/",
                    "https://v79sl.com/#anchor"]:
            with self.subTest(url=url),self.assertRaises(ValueError):
                validate_services([{"name":"Test","url":url}])

    def test_rejects_empty_duplicate(self):
        with self.assertRaises(ValueError):validate_services([])
        with self.assertRaises(ValueError):
            validate_services([{"name":"A","url":"https://v79sl.com/"}]*2)

    def test_denies_private_dns(self):
        fake=[(2,1,6,"",("192.168.100.163",443))]
        with patch("monitor_core.socket.getaddrinfo",return_value=fake):
            with self.assertRaises(ValueError):
                _safe_addresses("v79sl.com")

class TelemetryTests(unittest.TestCase):
    def test_transition_and_uptime(self):
        with tempfile.TemporaryDirectory() as td:
            store=Telemetry(pathlib.Path(td)/"history.sqlite")
            target={"name":"Site","url":"https://v79sl.com/"}
            good={"name":"Site","url":target["url"],"status":"up","http":200,
                  "ms":83,"dns_ms":7,"cert_days":45,"message":"ok"}
            bad={**good,"status":"down","http":503,"message":"upstream"}
            store.record([good])
            store.record([good])
            store.record([bad])
            report=store.summary([target])
            self.assertEqual(report["uptime24h"]["Site"]["observed"],3)
            self.assertEqual(report["uptime24h"]["Site"]["percent"],66.7)
            self.assertEqual(len(report["history"]),2)
            self.assertIn("up → down",report["history"][0]["message"])
            self.assertEqual(len(report["trend"]),1)
            with sqlite3.connect(str(store.path)) as con:
                self.assertEqual(con.execute("SELECT COUNT(*) FROM observations").fetchone()[0],3)

if __name__=="__main__":
    unittest.main(verbosity=2)
