"""Fail-closed dependency lock policy for an isolated Sentinel candidate only.

For a Python 3.12 Linux/amd64 GitHub CI candidate. The expected wheel hashes
were independently read from GitHub Actions wheel audit run 40764352876.

This module does NOT install packages, access credentials, network, Docker,
or approve a production release. A passing lock is not a vulnerability scan.
"""
from __future__ import annotations

from pathlib import Path
import re

# Explicitly owner-reviewed pins. Hashes intentionally in source for auditing.
EXPECTED = {
    "cryptography": (
        "50.0.2",
        "9dab55f57c74c3cad24c323bacbbd04be4705ba6eb0d92e920b1fc4837ed5079",
    ),
    "cffi": (
        "2.0.0",
        "3e17ed538242334bf70832644a32a7aae3d83b57567f9fd60a26257e992b79ba",
    ),
    "pycparser": (
        "2.23",
        "e5c6e8d3fbad53479cab09ac03729e0a9faf2bee3db8208a550daf5af81a5934",
    ),
}
LINE = re.compile(
    r"^(?P<name>[a-z]+)==(?P<version>[0-9]+(?:\.[0-9]+){1,3}) "
    r"--hash=sha256:(?P<sha>[0-9a-f]{64})$"
)


def validate_lines(lines):
    """Return (accepted, reason). Never include attacker-supplied input."""
    if not isinstance(lines, list) or len(lines) > 30:
        return False, "INVALID_LOCK"
    parsed = {}
    for line in lines:
        if not isinstance(line, str):
            return False, "INVALID_LOCK"
        if not line or line.startswith("#"):
            continue
        match = LINE.fullmatch(line)
        if match is None:
            return False, "UNAPPROVED_LOCK_SYNTAX"
        name, version, digest = (
            match.group("name"), match.group("version"), match.group("sha")
        )
        if name in parsed or name not in EXPECTED:
            return False, "EXTRA_OR_DUPLICATE_DEPENDENCY"
        parsed[name] = (version, digest)
    if set(parsed) != set(EXPECTED):
        return False, "MISSING_OR_EXTRA_DEPENDENCY"
    if parsed != EXPECTED:
        return False, "VERSION_OR_SHA256_NOT_APPROVED"
    return True, "CANDIDATE_LOCK_POLICY_MATCH"


def check_lock(path):
    """Check only an ordinary, small lock file, with no symlink traversal."""
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        return False, "LOCK_FILE_UNSAFE"
    try:
        if candidate.stat().st_size > 4096:
            return False, "LOCK_FILE_TOO_LARGE"
        lines = candidate.read_text(encoding="utf-8").splitlines()
        return validate_lines(lines)
    except (OSError, UnicodeError, ValueError):
        return False, "LOCK_FILE_UNREADABLE"


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("CANDIDATE_DEPENDENCY_LOCK=FAIL_INVALID_ARGS")
        raise SystemExit(2)
    passed, reason = check_lock(sys.argv[1])
    print(
        "CANDIDATE_DEPENDENCY_LOCK=" + ("PASS" if passed else "FAIL")
        + " REASON=" + reason
    )
    raise SystemExit(0 if passed else 1)
