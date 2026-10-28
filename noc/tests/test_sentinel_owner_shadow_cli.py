"""No-network tests of bounded STDIN-only shadow command."""
from contextlib import redirect_stdout
from datetime import datetime, timezone
import importlib.util
import io
import json
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "sentinel_owner_shadow.py"
spec = importlib.util.spec_from_file_location("shadow_cli", SCRIPT)
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


class ShadowCliTests(TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 28, 18, tzinfo=timezone.utc)
        self.sample = {
            "mode": "live", "cycle": 4,
            "last_check": "2026-10-28T17:59:20Z", "error": None,
            "services": [
                {**x, "http": 200, "status": "up", "cert_days": 50,
                 "message": "ACCESS_TOKEN_NEVER_SHOW"} for x in cli.TARGETS
            ],
            "history": [{"private": "CUSTOMER_PII_NEVER_SHOW"}],
        }

    def test_real_synthetic_seven_scope_passes_and_never_exposes_raw_report(self):
        raw = json.dumps(self.sample).encode()
        with patch("noc.owner_shadow_rehearsal.datetime") as clock:
            clock.now.return_value = self.now
            # Rehearsal receives local now from patched clock and uses
            # the true timezone type supplied to now() in implementation.
            output = cli.one_snapshot(raw)
        self.assertEqual(output["result"], "SIGNED_PAYLOAD_VERIFIED_IN_MEMORY")
        self.assertEqual(output["scopeCount"], 7)
        self.assertEqual(output["reportedUpUnverified"], 7)
        self.assertFalse(output["persistentSigner"])
        self.assertNotIn("CUSTOMER_PII", str(output))
        self.assertNotIn("ACCESS_TOKEN", str(output))

    def test_malformed_oversized_scope_and_stale_are_denied(self):
        for sample in (b"", b"X"*(cli.MAX_INPUT_BYTES+1),
                       b"[]", b"{bad", b'{"cycle": NaN}'):
            with self.subTest(length=len(sample)), self.assertRaises((ValueError, TypeError)):
                cli.one_snapshot(sample)
        with patch("noc.owner_shadow_rehearsal.datetime") as clock:
            clock.now.return_value = self.now
            with self.assertRaises(ValueError):
                cli.one_snapshot(json.dumps(self.sample|{"services":[]}).encode())
            with self.assertRaises(ValueError):
                cli.one_snapshot(json.dumps(self.sample|{"mode":"demo"}).encode())
            with self.assertRaises(ValueError):
                cli.one_snapshot(json.dumps(self.sample|{"last_check":"2026-10-28T17:00:00Z"}).encode())

    def test_parser_rejects_unapproved_domains(self):
        bad = dict(self.sample)
        rows = [dict(x) for x in bad["services"]]
        rows[0]["url"] = "https://unknown.example.invalid/"
        bad["services"] = rows
        with patch("noc.owner_shadow_rehearsal.datetime") as clock:
            clock.now.return_value = self.now
            with self.assertRaises(ValueError):
                cli.one_snapshot(json.dumps(bad).encode())


if __name__ == "__main__":
    main()
