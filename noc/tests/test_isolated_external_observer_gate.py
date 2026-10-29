"""Synthetic no-network tests of external website status and signed-advisory reconciliation."""
from copy import deepcopy
import unittest

from noc.isolated_external_observer_gate import (
    compare_external_to_signed_advisory, evaluate_external_website_reports,
)

NOW = 1793234729
CONTACT = "1c1676c5c30325c1529be9ae08982bc4"
URLS = {
    "V79 Hub": "https://hub.v79sl.com/",
    "V79 Tiquet": "https://tiquet.v79sl.com/",
    "Vision79 Website": "https://v79sl.com/",
}
MAPPING = {
    "V79 Hub": "V79 Hub",
    "V79 Tiquet": "V79 Tiquet",
    "Vision79 Website": "Website",
}


def external(name, *, aggregate="up", location_status=None):
    loc = location_status or ["up", "up", "up"]
    return {
        "name": name,
        "target": URLS[name],
        "type": "website",
        "monitor_status": "active",
        "uptime_status": aggregate,
        "check_frequency": 1,
        "alert_after_minutes": 3,
        "triggering_locations": 2,
        "contact_lists": [CONTACT],
        "last_check": NOW - 6,
        "locations": {
            city: {"uptime_status": stat, "last_check": NOW - 10 - i}
            for i, (city, stat) in enumerate(zip(
                ("new_york", "london", "sao_paulo"), loc
            ))
        },
        "resolve_address": "PRIVATE_NOT_A_PROBE_INPUT",
    }


def signed_advisory(statuses=None):
    statuses = statuses or {
        "V79 Hub": "REPORTED_UP_UNVERIFIED",
        "V79 Tiquet": "REPORTED_UP_UNVERIFIED",
        "Website": "REPORTED_UP_UNVERIFIED",
    }
    return {
        "status": "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE",
        "sourceSignatureValid": True,
        "trustedForExecutiveUse": False,
        "services": [
            {"name": name, "signal": signal}
            for name, signal in statuses.items()
        ],
    }


def evaluate(monitors):
    return evaluate_external_website_reports(
        monitors, approved_name_urls=URLS,
        approved_contact_list=CONTACT, now_epoch=NOW,
    )


class ExternalObserverGateTests(unittest.TestCase):
    def setUp(self):
        self.rows = [external(name) for name in URLS]

    def test_all_up_is_external_claim_not_source_attestation(self):
        result = evaluate(self.rows)
        self.assertEqual(result["status"], "EXTERNAL_REPORTED_NOT_ATTESTED")
        self.assertEqual(len(result["services"]), 3)
        self.assertFalse(result["sourceIdentityCryptographicallyVerified"])
        self.assertFalse(result["trustedForExecutiveUse"])
        self.assertFalse(result["resendNotificationAllowed"])
        self.assertFalse(result["alertsDispatched"])
        self.assertNotIn("PRIVATE_NOT_A_PROBE_INPUT", str(result))
        comparison = compare_external_to_signed_advisory(
            result, signed_advisory(),
            external_to_internal_name=MAPPING,
        )
        self.assertEqual(comparison["status"], "CROSS_SOURCE_REVIEW_ONLY")
        self.assertEqual(
            {x["assessment"] for x in comparison["services"]},
            {"UP_REPORTED_BY_BOTH_UNVERIFIED"},
        )
        self.assertFalse(comparison["trustedForExecutiveUse"])

    def test_multi_region_downtime_matches_internal_only_as_review(self):
        rows = deepcopy(self.rows)
        rows[1] = external("V79 Tiquet", aggregate="down",
                           location_status=["down", "down", "up"])
        result = evaluate(rows)
        self.assertEqual(result["services"][1]["signal"], "REPORTED_DOWN")
        internal = signed_advisory({
            "V79 Hub": "REPORTED_UP_UNVERIFIED",
            "V79 Tiquet": "REPORTED_DOWN",
            "Website": "REPORTED_UP_UNVERIFIED",
        })
        comparison = compare_external_to_signed_advisory(
            result, internal, external_to_internal_name=MAPPING,
        )
        self.assertEqual(
            comparison["services"][1]["assessment"], "DOWN_REPORTED_BY_BOTH"
        )
        self.assertFalse(comparison["resendNotificationAllowed"])
        self.assertEqual(comparison["status"], "CROSS_SOURCE_REVIEW_ONLY")

    def test_disagreement_and_partial_failure_require_review(self):
        result = evaluate(self.rows)
        internal = signed_advisory({
            "V79 Hub": "REPORTED_DOWN",
            "V79 Tiquet": "REPORTED_UP_UNVERIFIED",
            "Website": "REPORTED_UP_UNVERIFIED",
        })
        comparison = compare_external_to_signed_advisory(
            result, internal, external_to_internal_name=MAPPING,
        )
        self.assertEqual(
            comparison["services"][0]["assessment"],
            "DISAGREEMENT_OR_WARNING_REQUIRES_REVIEW",
        )
        partial = deepcopy(self.rows)
        partial[0] = external("V79 Hub", aggregate="up",
                              location_status=["down", "up", "up"])
        self.assertEqual(
            evaluate(partial)["services"][0]["signal"], "REVIEW_REPORTED"
        )

    def test_stale_missing_or_bad_location_fail_closed(self):
        for mutation in (
            lambda rows: rows[0].update(last_check=NOW-500),
            lambda rows: rows[1]["locations"]["new_york"].update(last_check=NOW-600),
            lambda rows: rows[2]["locations"].pop("london"),
            lambda rows: rows[0].update(monitor_status="paused"),
            lambda rows: rows[0].update(contact_lists=[]),
            lambda rows: rows[0].update(alert_after_minutes=99),
            lambda rows: rows[0].update(triggering_locations=1),
            lambda rows: rows[0].update(target="https://outside.example/"),
        ):
            rows = deepcopy(self.rows)
            mutation(rows)
            with self.subTest(mutation=str(mutation)):
                result = evaluate(rows)
                self.assertEqual(result["status"], "UNKNOWN")
                self.assertEqual(result["services"], [])

    def test_duplicate_unowned_or_missing_monitor_fail_closed(self):
        self.assertEqual(evaluate(self.rows[:2])["status"], "UNKNOWN")
        duplicate = [self.rows[0], self.rows[0], self.rows[2]]
        self.assertEqual(evaluate(duplicate)["status"], "UNKNOWN")
        unknown = deepcopy(self.rows)
        unknown[0]["name"] = "Customer Site"
        self.assertEqual(evaluate(unknown)["status"], "UNKNOWN")
        with self.assertRaises(ValueError):
            evaluate_external_website_reports(
                self.rows, approved_name_urls={"Evil": "https://bad.example/"},
                approved_contact_list=CONTACT, now_epoch=NOW,
            )

    def test_forged_external_json_can_never_become_trusted(self):
        input_data = evaluate(self.rows)
        fake = dict(input_data, sourceIdentityCryptographicallyVerified=True)
        self.assertEqual(
            compare_external_to_signed_advisory(
                fake, signed_advisory(), external_to_internal_name=MAPPING
            )["status"], "UNKNOWN"
        )
        fake_internal = dict(signed_advisory(), sourceSignatureValid=False)
        self.assertEqual(
            compare_external_to_signed_advisory(
                input_data, fake_internal, external_to_internal_name=MAPPING
            )["status"], "UNKNOWN"
        )

    def test_no_network_no_account_actions_no_alerts(self):
        import inspect
        from noc import isolated_external_observer_gate
        source = inspect.getsource(isolated_external_observer_gate)
        for forbidden in ("requests.", "urllib.request", "socket.",
                          "SMTP(", "send_email(", "os.environ",
                          "subprocess.", "docker ", "HubClient"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
