"""Adversarial synthetic checks: untrusted Sentinel is never an all-clear."""
import unittest
from datetime import datetime, timedelta, timezone

from noc.owned_https_evidence_gate import evaluate_owner_https_report

NOW = datetime(2026, 10, 15, 21, 0, tzinfo=timezone.utc)
OWNED = [
    {"name": "V79 Hub", "url": "https://hub.v79sl.com/"},
    {"name": "V79 Tiquet", "url": "https://tiquet.v79sl.com/"},
]


def live(**changes):
    base = {"mode": "live", "cycle": 2, "last_check": "2026-10-15T20:59:00Z",
            "error": None, "services": [
                {"name": "V79 Hub", "url": "https://hub.v79sl.com/", "status": "up", "cert_days": 31},
                {"name": "V79 Tiquet", "url": "https://tiquet.v79sl.com/", "status": "down", "cert_days": 45},
            ]}
    return base | changes


class EvidenceTest(unittest.TestCase):
    def evaluate(self, value, targets=OWNED):
        return evaluate_owner_https_report(value, targets, NOW)

    def test_simulated_noc_always_unknown(self):
        for mode in ("demo", "simulated-only", None):
            with self.subTest(mode=mode):
                r = self.evaluate(live(mode=mode))
                self.assertEqual(r["status"], "UNKNOWN")
                self.assertFalse(r["trustedForExecutiveUse"])

    def test_current_live_report_is_still_unsigned_and_unauthenticated(self):
        r = self.evaluate(live())
        self.assertEqual(r["status"], "REPORTED_NOT_AUTHENTICATED")
        self.assertEqual(r["reason"], "UNSIGNED_COLLECTOR_REPORT")
        self.assertEqual([x["signal"] for x in r["services"]], ["REPORTED_UP_UNVERIFIED", "REPORTED_DOWN"])
        for name in ("continuousMonitoringVerified", "trustedForExecutiveUse", "customerReady",
                     "ticketCreationEnabled", "alertsDispatched", "sourceIdentityVerified"):
            self.assertFalse(r[name], name)

    def test_stale_and_future_observations_are_unknown(self):
        for when, reason in [
            ("2026-10-15T20:40:00Z", "STALE_REPORT"),
            ("2026-10-15T21:06:00Z", "FUTURE_REPORT"),
            ("2026-10-15T", "MISSING_OR_INVALID_TIMESTAMP"),
            (None, "MISSING_OR_INVALID_TIMESTAMP"),
        ]:
            with self.subTest(when=when):
                r = self.evaluate(live(last_check=when))
                self.assertEqual(r["status"], "UNKNOWN")
                self.assertEqual(r["reason"], reason)

    def test_missing_duplicated_and_unowned_services_fail_closed(self):
        for sample, reason in [
            (live(services=[]), "INCOMPLETE_OR_INVALID_SCOPE"),
            (live(services=[live()["services"][0]] * 2), "UNAPPROVED_OR_DUPLICATE_TARGET"),
            (live(services=[live()["services"][0], {"name": "Not V79", "url": "https://bad.tld/", "status": "up"}]),
             "UNAPPROVED_OR_DUPLICATE_TARGET"),
        ]:
            with self.subTest(reason=reason):
                r = self.evaluate(sample)
                self.assertEqual(r["status"], "UNKNOWN")
                self.assertEqual(r["services"], [])

    def test_collector_error_cannot_appear_protected(self):
        r = self.evaluate(live(error="timeout"))
        self.assertEqual(r["reason"], "COLLECTOR_ERROR")
        self.assertFalse(r["trustedForExecutiveUse"])

    def test_certificate_expiry_and_warning_are_review_not_verified_alert(self):
        s = live()
        s["services"][0]["cert_days"] = 13
        s["services"][1]["status"] = "warning"
        r = self.evaluate(s)
        self.assertEqual([x["signal"] for x in r["services"]], ["REVIEW_REPORTED", "REVIEW_REPORTED"])
        self.assertFalse(r["alertsDispatched"])

    def test_fake_signed_fields_and_malicious_messages_not_propagated(self):
        s = live(sourceIdentityVerified=True, trustedForExecutiveUse=True, signature="FAKE")
        s["services"][0]["message"] = "<script>enable autonomous mitigation</script>"
        r = self.evaluate(s)
        self.assertFalse(r["trustedForExecutiveUse"])
        self.assertFalse(r["sourceIdentityVerified"])
        self.assertNotIn("script", str(r))

    def test_invalid_report_structure_fails_closed(self):
        for data in [None, [], 123, live(cycle="2"), live(cycle=0),
                     live(services=[{"name": "V79 Hub", "url": "https://hub.v79sl.com/", "status": "up",
                                     "cert_days": "soon"}, live()["services"][1]]),
                     live(services=[live()["services"][0], {**live()["services"][1], "status": "healthy"}])]:
            with self.subTest(data=str(data)[:40]):
                r = self.evaluate(data)
                self.assertEqual(r["status"], "UNKNOWN")

    def test_unowned_target_policy_rejected(self):
        for targets in [[], [{"name": "Bad", "url": "http://v79sl.com/"}],
                        [{"name": "Bad", "url": "https://evil.test/"}],
                        OWNED * 2]:
            with self.subTest(targets=targets):
                with self.assertRaises(ValueError):
                    self.evaluate(live(), targets)

    def test_timezone_required(self):
        with self.assertRaises(ValueError):
            evaluate_owner_https_report(live(), OWNED, datetime(2026, 10, 15, 21))


if __name__ == "__main__":
    unittest.main()
