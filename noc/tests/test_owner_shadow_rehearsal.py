"""Synthetic no-network source-to-signature rehearsal regressions."""
from datetime import datetime, timezone
import unittest

from noc.owner_shadow_rehearsal import rehearse_legacy_snapshot

NOW = datetime(2026, 10, 28, 14, 0, tzinfo=timezone.utc)
TARGETS = [
    {"name": "V79 Hub", "url": "https://hub.v79sl.com/"},
    {"name": "V79 Tiquet", "url": "https://tiquet.v79sl.com/"},
]


def sample(**overrides):
    base = {
        "mode": "live", "cycle": 32,
        "last_check": "2026-10-28T13:59:00+00:00", "error": None,
        "services": [
            {"name": "V79 Hub", "url": "https://hub.v79sl.com/",
             "status": "up", "http": 200, "cert_days": 45,
             "message": "PRIVATE_PASS_DO_NOT_LOG"},
            {"name": "V79 Tiquet", "url": "https://tiquet.v79sl.com/",
             "status": "warning", "http": 405, "cert_days": 65},
        ],
        "history": [{"private": "PRIVATE_HISTORY_DO_NOT_LOG"}],
    }
    base.update(overrides)
    return base


class ShadowRehearsalTests(unittest.TestCase):
    def test_ephemeral_report_is_verified_but_not_a_deployed_sensor(self):
        response = rehearse_legacy_snapshot(sample(), TARGETS, now=NOW)
        self.assertEqual(response["result"], "SIGNED_PAYLOAD_VERIFIED_IN_MEMORY")
        self.assertEqual(response["scopeCount"], 2)
        self.assertEqual(response["reportedUpUnverified"], 1)
        self.assertEqual(response["reportedReview"], 1)
        self.assertEqual(response["reportedDown"], 0)
        self.assertNotIn("PRIVATE_", str(response))
        for name in ("trustedSourceIdentity", "persistentSigner",
                     "durableReplayStore", "externalHeartbeat",
                     "ownerMailDispatched", "productionChanges"):
            self.assertFalse(response[name])

    def test_demo_stale_future_error_unapproved_and_false_up_refused(self):
        baseline = sample()
        changed_rows = [dict(row) for row in baseline["services"]]
        changed_rows[0]["http"] = 503
        bad_cases = [
            {"mode": "demo"},
            {"error": "not available"},
            {"last_check": "2026-10-28T13:00:00Z"},
            {"last_check": "2026-10-28T14:20:00Z"},
            {"services": []},
            {"services": changed_rows},
            {"cycle": True},
        ]
        for mutation in bad_cases:
            with self.subTest(changed=list(mutation)), self.assertRaises(ValueError):
                rehearse_legacy_snapshot(sample(**mutation), TARGETS, now=NOW)

    def test_invalid_approved_scope_and_naive_clock_are_denied(self):
        with self.assertRaises(ValueError):
            rehearse_legacy_snapshot(sample(), TARGETS[:1], now=NOW)
        with self.assertRaises(ValueError):
            rehearse_legacy_snapshot(sample(), TARGETS,
                                    now=datetime(2026, 10, 28, 14, 0))


if __name__ == "__main__":
    unittest.main()
