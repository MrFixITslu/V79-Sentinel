"""No-network tests for an opt-in, source-only in-process candidate tap."""
from datetime import datetime, timedelta, timezone
import copy
import unittest
from unittest.mock import Mock, patch

import sentinel
from noc.inprocess_probe_receipt import project_probe_cycle

NOW = datetime.now(timezone.utc).replace(microsecond=0)
STAMP = NOW.isoformat().replace("+00:00", "Z")
TARGETS = [
    {"name": "V79 Hub", "url": "https://hub.v79sl.com/"},
    {"name": "CombatZone", "url": "https://combatzone.v79sl.com/"},
]
SECRET = "NEVER_EXPORT_UNTRUSTED_UPSTREAM_MESSAGE"


def readings():
    return [
        {**target, "status": "up", "http": 200, "cert_days": 60,
         "message": SECRET, "ip": "10.0.0.4", "customer": {"secret": SECRET}}
        for target in TARGETS
    ]


class StopAfterOneCycle(Exception):
    pass


class FakeStore:
    def __init__(self, *, fail=False):
        self.fail = fail
        self.observations = []

    def record(self, data):
        if self.fail:
            raise ValueError("synthetic database error")
        self.observations.append(data)

    def summary(self, _targets):
        return {"history": [], "uptime24h": {}, "trend": []}


class InProcessProbeBoundaryTests(unittest.TestCase):
    def run_one_cycle(self, *, sink=None, data=None, store=None):
        store = FakeStore() if store is None else store
        data = readings() if data is None else data
        initial = {"mode": "demo", "cycle": 0, "error": None}
        with patch.object(sentinel, "probe_many", return_value=data) as probe, \
             patch.object(sentinel, "dell_status", return_value={}), \
             patch.object(sentinel, "now_iso", return_value=STAMP), \
             patch.object(sentinel.time, "sleep", side_effect=StopAfterOneCycle), \
             patch.object(sentinel, "state", initial), \
             patch.object(sentinel.time, "monotonic", return_value=0):
            with self.assertRaises(StopAfterOneCycle):
                sentinel.monitor_forever(TARGETS, store, evidence_sink=sink)
            self.assertEqual(probe.call_count, 1)
            return store, copy.deepcopy(initial)

    def test_projection_strips_raw_messages_and_never_claims_security(self):
        value = project_probe_cycle(
            targets=TARGETS, readings=readings(),
            cycle=1, observed_at=STAMP, now=NOW,
        )
        self.assertEqual(value["mode"], "IN_PROCESS_PROBE_CANDIDATE_ONLY")
        self.assertEqual(value["report"]["cycle"], 1)
        self.assertEqual(len(value["report"]["services"]), 2)
        self.assertNotIn(SECRET, str(value))
        self.assertNotIn("10.0.0.4", str(value))
        for name in ("sourceProvenanceVerified", "sourceSignatureValid",
                     "durableReplayVerified", "externalObserverRunning",
                     "trustedForExecutiveUse", "hostUpProven",
                     "alertsDispatched", "ticketCreationEnabled"):
            self.assertIs(value[name], False)

    def test_monitor_loop_without_opt_in_has_no_evidence_sink(self):
        store, snapshot = self.run_one_cycle()
        self.assertEqual(len(store.observations), 1)
        self.assertEqual(snapshot["mode"], "live")
        self.assertEqual(snapshot["cycle"], 1)

    def test_one_completed_probe_cycle_one_sanitized_candidate(self):
        collected = []
        store, snapshot = self.run_one_cycle(sink=collected.append)
        self.assertEqual(len(store.observations), 1)
        self.assertEqual(snapshot["cycle"], 1)
        self.assertEqual(len(collected), 1)
        self.assertNotIn(SECRET, str(collected[0]))
        self.assertEqual(collected[0]["report"]["cycle"], snapshot["cycle"])

    def test_evidence_sink_exception_cannot_interrupt_health_sampling(self):
        callback = Mock(side_effect=RuntimeError(SECRET))
        store, snapshot = self.run_one_cycle(sink=callback)
        self.assertEqual(callback.call_count, 1)
        self.assertEqual(snapshot["mode"], "live")
        self.assertEqual(snapshot["error"], None)
        self.assertEqual(len(store.observations), 1)

    def test_bad_readings_are_not_passed_to_review_sink(self):
        bad = readings()
        bad[0]["http"] = 503  # Falsely claims UP.
        collected = []
        _store, snapshot = self.run_one_cycle(data=bad, sink=collected.append)
        self.assertEqual(collected, [])
        self.assertEqual(snapshot["cycle"], 1)

    def test_failed_main_telemetry_write_does_not_emit_candidate(self):
        collected = []
        store, snapshot = self.run_one_cycle(
            store=FakeStore(fail=True), sink=collected.append
        )
        self.assertEqual(store.observations, [])
        self.assertEqual(collected, [])
        self.assertEqual(snapshot["cycle"], 0)
        self.assertEqual(snapshot["error"], "Monitoring engine error: ValueError")

    def test_rejects_demo_like_incomplete_duplicate_or_wrong_domain(self):
        for invalid in (
            [],
            readings()[:1],
            readings()[:1] + readings()[:1],
            [{**readings()[0], "url": "https://attacker.invalid/"},
             readings()[1]],
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                project_probe_cycle(
                    targets=TARGETS, readings=invalid,
                    cycle=1, observed_at=STAMP, now=NOW
                )

    def test_rejects_stale_future_and_non_integer_cycle(self):
        for bad in (0, -1, True, "1", None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                project_probe_cycle(targets=TARGETS, readings=readings(),
                                    cycle=bad, observed_at=STAMP, now=NOW)
        for stamp in (
            (NOW - timedelta(minutes=12)).isoformat(),
            (NOW + timedelta(minutes=4)).isoformat(),
        ):
            with self.subTest(stamp=stamp), self.assertRaises(ValueError):
                project_probe_cycle(targets=TARGETS, readings=readings(),
                                    cycle=1, observed_at=stamp, now=NOW)

    def test_review_projection_has_no_signature_key_or_network_api(self):
        import inspect
        from noc import inprocess_probe_receipt as source
        text = inspect.getsource(source)
        for forbidden in (
            "send_email(", "SMTP(", "requests.get(",
            "Ed25519PrivateKey(", "sqlite3.connect(",
            "urllib.request.urlopen(", "ThreadingHTTPServer(",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
