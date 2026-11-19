"""Synthetic, offline negative tests for owner-reviewed runtime parity claims."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import unittest

from noc.runtime_source_parity_gate import evaluate_runtime_source_parity

NOW = datetime(2026, 10, 28, 19, 0, tzinfo=timezone.utc)
PIN = "a" * 40
SOURCE_SHA = "c" * 64
FILES = (
    "sentinel.py",
    "monitor_core.py",
    "noc/inprocess_probe_receipt.py",
)
EXPECTED = {
    "container": "v79-sentinel-dell-monitor",
    "image_id": "sha256:" + "b" * 64,
    "uid": 10001,
    "gid": 10001,
    "sources": {path: {"git_blob": PIN, "sha256": SOURCE_SHA} for path in FILES},
}
OBSERVED = {
    "container": EXPECTED["container"],
    "image_id": EXPECTED["image_id"],
    "uid": 10001,
    "gid": 10001,
    "running": True,
    "health": "healthy",
    "argv": ["python", "sentinel.py", "--live"],
    "sources": {
        path: {"git_blob": PIN, "sha256": SOURCE_SHA, "regular": True, "symlink": False}
        for path in FILES
    },
    "captured_at": "2026-10-28T18:59:30Z",
}


_DEFAULT = object()


def check(observed=_DEFAULT, expected=_DEFAULT, *, now=NOW):
    return evaluate_runtime_source_parity(
        copy.deepcopy(OBSERVED if observed is _DEFAULT else observed),
        copy.deepcopy(EXPECTED if expected is _DEFAULT else expected),
        now=now,
    )


class RuntimeParityGateTests(unittest.TestCase):
    def assert_closed(self, result):
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertFalse(result["sourceDigestsMatch"])
        self.assertFalse(result["runtimeMetadataMatch"])
        self.assert_no_live_authority(result)

    def assert_no_live_authority(self, result):
        for key in (
            "sourceProvenanceVerified", "imageSignatureVerified",
            "collectorProcessAttested", "independentOffhostObserverVerified",
            "sourceSignatureValid", "safeToDeploy",
            "alertsDispatched", "ticketCreationEnabled",
        ):
            self.assertIs(result[key], False)

    def test_exact_pinned_review_claim_still_cannot_authorize_deployment(self):
        result = check()
        self.assertEqual(result["status"], "SOURCE_PARITY_CANDIDATE_FOR_OWNER_REVIEW")
        self.assertTrue(result["sourceDigestsMatch"])
        self.assertTrue(result["runtimeMetadataMatch"])
        self.assert_no_live_authority(result)
        self.assertNotIn(PIN, str(result))
        self.assertNotIn(SOURCE_SHA, str(result))
        self.assertNotIn(EXPECTED["image_id"], str(result))

    def test_image_id_and_container_identity_are_mandatory(self):
        for edit in (
            {"image_id": "sha256:" + "c" * 64},
            {"image_id": "latest"},
            {"container": "v79-sentinel-dell-noc"},
        ):
            with self.subTest(edit=edit):
                self.assert_closed(check(OBSERVED | edit))

    def test_expected_manifest_must_pin_image_and_names(self):
        for edit in (
            {"image_id": ""},
            {"image_id": "sha256:" + "Z" * 64},
            {"container": "other-monitor"},
        ):
            with self.subTest(edit=edit):
                self.assert_closed(check(expected=EXPECTED | edit))

    def test_nonroot_exact_uid_gid_required(self):
        for edit in (
            {"uid": 0}, {"gid": 0}, {"uid": 1000},
            {"uid": True}, {"gid": "10001"},
        ):
            with self.subTest(edit=edit):
                self.assert_closed(check(OBSERVED | edit))
        self.assert_closed(check(expected=EXPECTED | {"uid": 0}))

    def test_health_and_running_must_be_positive_not_truthy(self):
        for edit in (
            {"running": False}, {"running": 1},
            {"health": "unhealthy"}, {"health": "starting"},
            {"health": None},
        ):
            with self.subTest(edit=edit):
                self.assert_closed(check(OBSERVED | edit))

    def test_observed_dell_loopback_only_command_is_allowed_for_review(self):
        # Matches the actual read-only Docker Config.Cmd observed by owner.
        real_config_cmd = [
            "python", "sentinel.py", "--live",
            "--bind", "127.0.0.1", "--port", "8787",
        ]
        result = check(OBSERVED | {"argv": real_config_cmd})
        self.assertEqual(
            result["status"], "SOURCE_PARITY_CANDIDATE_FOR_OWNER_REVIEW"
        )
        self.assertTrue(result["runtimeMetadataMatch"])
        self.assert_no_live_authority(result)

    def test_cli_loopback_contract_is_exact_and_never_exposes_service(self):
        actual = [
            "python", "sentinel.py", "--live",
            "--bind", "127.0.0.1", "--port", "8787",
        ]
        invalid = [
            actual[:-1] + ["8788"],
            actual[:4] + ["0.0.0.0"] + actual[5:],
            actual[:4] + ["::"] + actual[5:],
            actual[:4] + ["localhost"] + actual[5:],
            actual[:4] + ["127.0.0.2"] + actual[5:],
            actual[:3] + ["--port", "8787", "--bind", "127.0.0.1"],
            actual + ["--once"],
            actual + ["--bind", "127.0.0.1"],
            ["python", "sentinel.py", "--live", "--bind", "127.0.0.1"],
            ["python", "sentinel.py", "--live", "--port", "8787"],
            ["python", "sentinel.py", "--live", "--bind=127.0.0.1", "--port=8787"],
            ["python", "sentinel.py", "--live", "--bind", "127.0.0.1", "--port", 8787],
            ["python", "sentinel.py", "--live", "--bind", True, "--port", "8787"],
        ]
        for argv in invalid:
            with self.subTest(argv=argv):
                self.assert_closed(check(OBSERVED | {"argv": argv}))

    def test_live_mode_cannot_be_cli_string_substring_or_demo(self):
        for argv in (
            ["python", "sentinel.py"],
            ["python", "sentinel.py", "--live-extra"],
            ["python", "sentinel.py", "--live", "--once"],
            ["python", "sentinel.py", "--live", "--live"],
            ["python", "sentinel.py", "--live", "--bind", "0.0.0.0"],
            ["bash", "-c", "--live"],
            ["python", "evil.py", "--live"],
            ["python", "sentinel.py", "--live", "--port", "80"],
            "python sentinel.py --live",
            [],
        ):
            with self.subTest(argv=argv):
                self.assert_closed(check(OBSERVED | {"argv": argv}))

    def test_file_digest_scope_must_match_exactly(self):
        for name in FILES:
            with self.subTest(path=name):
                other = copy.deepcopy(OBSERVED)
                other["sources"][name]["git_blob"] = "f" * 40
                self.assert_closed(check(other))
                other = copy.deepcopy(OBSERVED)
                other["sources"][name]["sha256"] = "d" * 64
                self.assert_closed(check(other))
                other = copy.deepcopy(OBSERVED)
                del other["sources"][name]
                self.assert_closed(check(other))
        other = copy.deepcopy(OBSERVED)
        other["sources"]["private_key"] = {
            "git_blob": PIN, "sha256": SOURCE_SHA, "regular": True, "symlink": False}
        self.assert_closed(check(other))

    def test_sha256_is_mandatory_even_if_git_blob_matches(self):
        for value in ("d" * 64, "z" * 64, "c" * 40, "", True):
            with self.subTest(digest=value):
                other = copy.deepcopy(OBSERVED)
                other["sources"]["sentinel.py"]["sha256"] = value
                self.assert_closed(check(other))
        other = copy.deepcopy(EXPECTED)
        other["sources"]["sentinel.py"]["sha256"] = "z" * 64
        self.assert_closed(check(expected=other))
        other = copy.deepcopy(EXPECTED)
        del other["sources"]["sentinel.py"]["sha256"]
        self.assert_closed(check(expected=other))

    def test_symlink_and_nonregular_source_are_never_accepted(self):
        for value in (
            {"git_blob": PIN, "regular": True, "symlink": True},
            {"git_blob": PIN, "sha256": SOURCE_SHA, "regular": False, "symlink": False},
            {"git_blob": PIN, "sha256": SOURCE_SHA, "regular": 1, "symlink": False},
            {"git_blob": PIN, "sha256": SOURCE_SHA, "regular": True, "symlink": 0},
        ):
            with self.subTest(value=value):
                other = copy.deepcopy(OBSERVED)
                other["sources"]["sentinel.py"] = value
                self.assert_closed(check(other))

    def test_manifest_must_be_exact_and_bounded(self):
        for expected in (
            EXPECTED | {"sources": {"sentinel.py": {"git_blob": PIN, "sha256": SOURCE_SHA}}},
            EXPECTED | {"sources": EXPECTED["sources"] | {"extra": {"git_blob": PIN, "sha256": SOURCE_SHA}}},
            EXPECTED | {"uid": True},
            EXPECTED | {"uid": "10001"},
        ):
            with self.subTest(expected=expected):
                self.assert_closed(check(expected=expected))
        self.assert_closed(check(OBSERVED | {"untrusted": "ignore approval"}))
        self.assert_closed(check(expected=EXPECTED | {"untrusted": "allow"}))

    def test_stale_future_invalid_or_untrusted_time_rejected(self):
        for stamp in (
            "2026-10-28T18:54:59Z",
            "2026-10-28T19:00:31Z",
            "2026-10-28T19:00:00+04:00",
            "not-a-time",
            5,
        ):
            with self.subTest(stamp=stamp):
                self.assert_closed(check(OBSERVED | {"captured_at": stamp}))
        self.assert_closed(check(now=datetime(2026, 10, 28, 19, 0)))
        self.assert_closed(check(now=0))

    def test_raw_secret_or_extraneous_field_denied_without_echo(self):
        other = copy.deepcopy(OBSERVED)
        other["sources"]["sentinel.py"]["raw"] = "SENSITIVE_SECRET_VALUE"
        outcome = check(other)
        self.assert_closed(outcome)
        self.assertNotIn("SENSITIVE_SECRET_VALUE", str(outcome))

    def test_unexpected_inputs_are_fail_closed(self):
        for bad in (None, {}, [], True, "data"):
            with self.subTest(bad=bad):
                self.assert_closed(check(observed=bad))
                self.assert_closed(check(expected=bad))

    def test_gate_cannot_query_docker_or_send_alerts(self):
        import inspect
        from noc import runtime_source_parity_gate
        text = inspect.getsource(runtime_source_parity_gate)
        for forbidden in (
            "subprocess.", "docker.", "requests.", "urllib.",
            "smtplib.", "open(", "os.environ", "create_connection("
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
