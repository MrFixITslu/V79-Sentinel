"""Fail-closed local Mission Control bridge regression with synthetic data only."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from unittest import TestCase
from unittest.mock import patch

from noc import sentinel_mission_bridge as bridge

NOW = datetime(2026, 10, 29, 2, 0, tzinfo=timezone.utc)


def source_sample():
    return {
        "mode": "live", "cycle": 49, "error": None,
        "last_check": (NOW - timedelta(seconds=45)).isoformat(),
        "services": [
            {"name": name, "status": "up", "http": 200, "ms": 190}
            for name in ("Website", "V79 Hub", "Academy", "FFPRO",
                         "V79 Tiquet", "Marketing", "V79 POS")
        ],
    }


def observe(sample=None, *, qa=None):
    status = source_sample() if sample is None else sample
    quality = {"state": "unverified", "results": [], "runId": None}
    if qa is not None:
        quality = qa

    def fetch(path):
        return status if path == "/api/status" else quality

    with patch.object(bridge, "_read_local", side_effect=fetch):
        return bridge.snapshot(now=NOW)


class BridgeStaleAndUnverifiedTests(TestCase):
    def test_fresh_live_is_explicitly_unsigned_and_never_an_alert(self):
        result = observe()
        self.assertEqual(result["monitorMode"], "live")
        self.assertTrue(result["monitorSampleFresh"])
        self.assertEqual(len(result["services"]), 7)
        self.assertTrue(all(s["state"] == "up" for s in result["services"]))
        for flag in ("sourceSignatureValid", "sourceProvenanceVerified",
                     "trustedForExecutiveUse", "automaticSecurityAlertsEnabled"):
            self.assertFalse(result[flag])
        self.assertEqual(result["qa"]["policy"],
                         "Public-page browser QA only; account workflows are not verified.")

    def test_stale_errors_demo_and_incomplete_input_hide_all_green(self):
        modifications = (
            lambda v: v.update(last_check=(NOW-timedelta(hours=2)).isoformat()),
            lambda v: v.update(error="collector stopped"),
            lambda v: v.update(mode="demo"),
            lambda v: v.update(cycle=0),
            lambda v: v.update(services=v["services"][:-1]),
            lambda v: v.update(services=[]),
            lambda v: v.update(last_check=(NOW+timedelta(minutes=2)).isoformat()),
            lambda v: v.update(last_check="bad-time"),
            lambda v: v["services"][0].update(http=503),
            lambda v: v["services"][0].update(name="Unknown Customer"),
            lambda v: v["services"][0].update(name="V79 Hub"),
        )
        for mutate in modifications:
            sample = source_sample()
            mutate(sample)
            with self.subTest(sample=sample.get("mode"), age=sample.get("last_check"),
                              count=len(sample["services"])):
                r = observe(sample)
                self.assertEqual(r["monitorMode"], "stale-or-unverified")
                self.assertFalse(r["monitorSampleFresh"])
                self.assertTrue(all(row["state"] == "unknown" for row in r["services"]))
                self.assertTrue(all(row["http"] is None for row in r["services"]))
                self.assertFalse(r["trustedForExecutiveUse"])

    def test_local_qa_endpoint_failure_does_not_mislabel_live_monitor(self):
        sample = source_sample()
        def request(path):
            if path == "/api/status":
                return sample
            raise OSError("synthetic QA unavailable")
        with patch.object(bridge, "_read_local", side_effect=request):
            result = bridge.snapshot(now=NOW)
        self.assertEqual(result["monitorMode"], "live")
        self.assertEqual(result["qa"]["state"], "unavailable")
        self.assertEqual(result["qa"]["counts"]["pass"], 0)

    def test_missing_monitor_source_must_not_return_a_green_dashboard(self):
        with patch.object(bridge, "_read_local", side_effect=OSError("synthetic monitor down")):
            with self.assertRaises(OSError):
                bridge.snapshot(now=NOW)

    def test_read_only_no_network_sender_or_ticket_actions_added(self):
        import inspect
        source = inspect.getsource(bridge)
        for forbidden in ("send_email(", "create_ticket(", "requests.post(",
                          "os.environ", "subprocess.", "docker ", "SMTP("):
            self.assertNotIn(forbidden, source)
        self.assertIn("sourceProvenanceVerified\":False", source)
