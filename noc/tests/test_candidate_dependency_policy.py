"""Offline policy tests; no wheel installation and no live service access."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from scripts.check_sentinel_candidate_lock import (
    EXPECTED, check_lock, validate_lines,
)


def approved_lines():
    return [
        f"{name}=={version} --hash=sha256:{sha}"
        for name, (version, sha) in EXPECTED.items()
    ]


class CandidateDependencyGateTests(unittest.TestCase):
    def assert_denied(self, lines, reason):
        allowed, actual = validate_lines(lines)
        self.assertFalse(allowed)
        self.assertEqual(actual, reason)

    def test_exact_approved_three_wheels_can_pass_policy_only(self):
        allow, reason = validate_lines(approved_lines())
        self.assertTrue(allow)
        self.assertEqual(reason, "CANDIDATE_LOCK_POLICY_MATCH")

    def test_previous_vulnerable_cryptography_version_must_fail(self):
        original = approved_lines()
        original[0] = (
            "cryptography==45.0.7 "
            "--hash=sha256:b6a0e535baec27b528cb07a119f321ac024592388c5681a5ced167ae98e9fff3"
        )
        self.assert_denied(original, "VERSION_OR_SHA256_NOT_APPROVED")

    def test_new_version_with_old_hash_is_rejected(self):
        entries = approved_lines()
        entries[0] = (
            "cryptography==50.0.2 "
            "--hash=sha256:b6a0e535baec27b528cb07a119f321ac024592388c5681a5ced167ae98e9fff3"
        )
        self.assert_denied(entries, "VERSION_OR_SHA256_NOT_APPROVED")

    def test_tampered_whitelisted_package_hash_is_rejected(self):
        entries = approved_lines()
        entries[1] = "cffi==2.0.0 --hash=sha256:" + "0" * 64
        self.assert_denied(entries, "VERSION_OR_SHA256_NOT_APPROVED")

    def test_duplicate_or_extra_dependency_denied(self):
        for bad in (
            approved_lines() + [approved_lines()[0]],
            approved_lines() + ["requests==2.99.0 --hash=sha256:" + "a" * 64],
        ):
            self.assert_denied(bad, "EXTRA_OR_DUPLICATE_DEPENDENCY")

    def test_incomplete_lock_denied(self):
        self.assert_denied(approved_lines()[:2], "MISSING_OR_EXTRA_DEPENDENCY")

    def test_options_requirements_and_invalid_syntax_are_denied(self):
        for bad in (
            approved_lines() + ["--extra-index-url https://example.com"],
            approved_lines() + ["cryptography>=50.0.2"],
            approved_lines() + ["-e git+https://example.com"],
            approved_lines() + ["import os"],
        ):
            self.assert_denied(bad, "UNAPPROVED_LOCK_SYNTAX")

    def test_whitespace_comments_and_order_bounded(self):
        entries = ["# Source-only audit", "", *reversed(approved_lines())]
        self.assertTrue(validate_lines(entries)[0])
        self.assert_denied(approved_lines() + [""] * 30, "INVALID_LOCK")

    def test_wrong_types_denied(self):
        for bad in (None, True, {}, "test"):
            self.assert_denied(bad, "INVALID_LOCK")

    def test_symlink_and_missing_file_denied_without_following(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real.lock"
            real.write_text("\n".join(approved_lines()), encoding="utf-8")
            alias = root / "alias.lock"
            alias.symlink_to(real)
            self.assertEqual(check_lock(alias), (False, "LOCK_FILE_UNSAFE"))
            self.assertEqual(check_lock(root / "nope.lock"), (False, "LOCK_FILE_UNSAFE"))
            self.assertEqual(check_lock(real), (True, "CANDIDATE_LOCK_POLICY_MATCH"))


if __name__ == "__main__":
    unittest.main()
