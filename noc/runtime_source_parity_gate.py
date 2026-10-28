"""Fail-closed SOURCE-ONLY candidate gate for Dell Sentinel runtime identity.

Inputs are externally supplied *claims*, not an authenticated probe of the host.
No Docker access, socket, file read, key, network call, side effects or prints.
A match is an operator-review candidate, NEVER authorization to deploy/sign/send.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re

IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
BLOB_ID = re.compile(r"^[0-9a-f]{40}$")
SOURCE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_SOURCES = frozenset({
    "sentinel.py", "monitor_core.py", "noc/inprocess_probe_receipt.py",
})
MAX_AGE_SECONDS = 300
MAX_FUTURE_SKEW = 30
ALLOWED_HEALTH = frozenset({"healthy"})


def _utc_stamp(text):
    if not isinstance(text, str) or len(text) > 40 or not text.endswith("Z"):
        return None
    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if stamp.tzinfo is None or stamp.utcoffset().total_seconds() != 0:
            return None
        return stamp
    except (ValueError, TypeError, OverflowError):
        return None


def evaluate_runtime_source_parity(observed, expected, *, now=None):
    """Compare exact image and file digests, nonroot runtime and fresh state.

    The expected digest manifest MUST be established/pinned by the owner out of
    band. A caller can forge the observed snapshot; passing is not cryptographic
    process attestation. Never treat the output as permission to release.
    """
    result = {
        "status": "UNKNOWN",
        "reason": "READ_ONLY_RUNTIME_EVIDENCE_UNVERIFIED",
        "mode": "SOURCE_ONLY_REVIEW",
        "sourceDigestsMatch": False,
        "runtimeMetadataMatch": False,
        "sourceProvenanceVerified": False,
        "imageSignatureVerified": False,
        "collectorProcessAttested": False,
        "independentOffhostObserverVerified": False,
        "sourceSignatureValid": False,
        "safeToDeploy": False,
        "alertsDispatched": False,
        "ticketCreationEnabled": False,
    }
    try:
        if (not isinstance(observed, dict) or
                set(observed) != {
                    "container", "image_id", "uid", "gid", "running",
                    "health", "argv", "sources", "captured_at",
                } or not isinstance(expected, dict) or
                set(expected) != {
                    "container", "image_id", "uid", "gid", "sources",
                }):
            return result
        if (type(expected["container"]) is not str or
                expected["container"] != "v79-sentinel-dell-monitor" or
                observed["container"] != expected["container"] or
                type(expected["image_id"]) is not str or
                not IMAGE_ID.fullmatch(expected["image_id"]) or
                observed["image_id"] != expected["image_id"]):
            return result
        if (type(expected["uid"]) is not int or
                type(expected["gid"]) is not int or
                not (1 <= expected["uid"] <= 2**31 - 1) or
                not (1 <= expected["gid"] <= 2**31 - 1) or
                type(observed["uid"]) is not int or
                type(observed["gid"]) is not int or
                observed["uid"] != expected["uid"] or
                observed["gid"] != expected["gid"] or
                observed["running"] is not True or
                observed["health"] not in ALLOWED_HEALTH or
                type(observed["health"]) is not str):
            return result
        argv = observed["argv"]
        # The actual Dell Docker Config.Cmd includes the explicit safe bind
        # and port: python sentinel.py --live --bind 127.0.0.1 --port 8787.
        # Accept that exact fixed contract as well as the original three-part
        # invocation (which uses the same loopback/8787 defaults). Reject
        # wildcard listeners, other ports, reordering, duplicates and flags.
        # Config.Cmd describes container configuration, NOT a separately
        # authenticated /proc executable identity.
        if (type(argv) is not list or
                not all(type(arg) is str for arg in argv) or
                len(argv) not in (3, 7) or
                argv[0] not in (
                    "python", "python3", "/usr/local/bin/python",
                    "/usr/local/bin/python3",
                ) or
                argv[1] not in ("sentinel.py", "/app/sentinel.py") or
                argv[2] != "--live" or
                (len(argv) == 7 and argv[3:] != [
                    "--bind", "127.0.0.1", "--port", "8787"
                ])):
            return result
        stamp = _utc_stamp(observed["captured_at"])
        clock = datetime.now(timezone.utc) if now is None else now
        if (stamp is None or not isinstance(clock, datetime) or
                clock.tzinfo is None):
            return result
        age = (clock.astimezone(timezone.utc) - stamp).total_seconds()
        if not -MAX_FUTURE_SKEW <= age <= MAX_AGE_SECONDS:
            return result
        sources = observed["sources"]
        pins = expected["sources"]
        if (type(pins) is not dict or set(pins) != REQUIRED_SOURCES or
                type(sources) is not dict or set(sources) != REQUIRED_SOURCES):
            return result
        for name in REQUIRED_SOURCES:
            pin, item = pins[name], sources[name]
            if (type(pin) is not dict or
                    set(pin) != {"git_blob", "sha256"} or
                    type(pin["git_blob"]) is not str or
                    not BLOB_ID.fullmatch(pin["git_blob"]) or
                    type(pin["sha256"]) is not str or
                    not SOURCE_SHA256.fullmatch(pin["sha256"]) or
                    type(item) is not dict or
                    set(item) != {"git_blob", "sha256", "regular", "symlink"} or
                    item["regular"] is not True or
                    item["symlink"] is not False or
                    type(item["git_blob"]) is not str or
                    type(item["sha256"]) is not str or
                    item["git_blob"] != pin["git_blob"] or
                    item["sha256"] != pin["sha256"]):
                return result
        # Never return untrusted paths, source bytes, IPs, user messages or IDs.
        return {
            **result,
            "status": "SOURCE_PARITY_CANDIDATE_FOR_OWNER_REVIEW",
            "reason": "METADATA_AND_DIGEST_CLAIMS_MATCH_NOT_ATTESTED",
            "sourceDigestsMatch": True,
            "runtimeMetadataMatch": True,
        }
    except (KeyError, ValueError, TypeError, OverflowError):
        return result
