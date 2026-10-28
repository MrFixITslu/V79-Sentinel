"""Pure watchdog tests. No network, scheduled checks or credentials."""
from datetime import datetime, timezone, timedelta
import unittest

from noc.offhost_watchdog_policy import offhost_watchdog_decision

NOW = datetime(2026, 10, 28, 16, 0, tzinfo=timezone.utc)
READY = {
    "sourceSignatureValid": True,
    "replayStatePersisted": True,
    "acceptedSequence": 5,
    "receivedAtUtc": "2026-10-28T15:55:00Z",
}


class OffhostWatchdogPolicyTests(unittest.TestCase):
    def verdict(self, value):
        return offhost_watchdog_decision(value, now=NOW)

    def assert_never_redefines_host_health(self, verdict):
        self.assertFalse(verdict["serviceHealthVerified"])
        self.assertFalse(verdict["hostUpProven"])
        self.assertFalse(verdict["hostDownProven"])
        self.assertFalse(verdict["ownerNotificationDispatched"])
        self.assertFalse(verdict["externalObserverRunning"])
        self.assertFalse(verdict["safeToAutoRecover"])

    def test_recent_authenticated_and_checkpointed_candidate_still_is_not_host_up(self):
        decision = self.verdict(READY)
        self.assertEqual(decision["state"], "RECENT_SIGNED_CANDIDATE_RECEIVED")
        self.assert_never_redefines_host_health(decision)

    def test_stale_or_future_receipt_is_monitoring_blind_not_host_down(self):
        for stamp in ("2026-10-28T15:30:00Z", "2026-10-28T16:10:00Z"):
            with self.subTest(stamp=stamp):
                decision = self.verdict({**READY, "receivedAtUtc": stamp})
                self.assertEqual(decision["state"], "MONITORING_BLIND")
                self.assert_never_redefines_host_health(decision)

    def test_missing_unsigned_uncheckpointed_and_invalid_sequence_are_unknown(self):
        for value in (
            None, {}, {**READY, "sourceSignatureValid": False},
            {**READY, "replayStatePersisted": False},
            {**READY, "acceptedSequence": True},
            {**READY, "acceptedSequence": 0},
            {**READY, "receivedAtUtc": "not-a-timestamp"},
            {**READY, "unexpected": "customer-content"},
        ):
            with self.subTest(value=value):
                decision = self.verdict(value)
                self.assertEqual(decision["state"], "UNKNOWN")
                self.assert_never_redefines_host_health(decision)

    def test_invalid_external_clock_does_not_fake_freshness(self):
        v = offhost_watchdog_decision(READY, now=datetime(2026, 10, 28, 16, 0))
        self.assertEqual(v["state"], "UNKNOWN")
        self.assert_never_redefines_host_health(v)
        v = offhost_watchdog_decision(READY, now=0)
        self.assertEqual(v["state"], "UNKNOWN")

if __name__ == "__main__":
    unittest.main()
