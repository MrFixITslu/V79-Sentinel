#!/usr/bin/env python3
"""Consume ONE local monitor JSON snapshot from stdin; no service mutations.

Owner-run offline shadow only. The input source is NOT authenticated and a
fresh 'live' label alone is not evidence the HTTPS probes actually happened.
No network, keys persisted, sqlite, email, stdout of raw input, or customer data.
"""
from __future__ import annotations

import json
import sys

from noc.owner_shadow_rehearsal import rehearse_legacy_snapshot

TARGETS = (
    {"name": "Website", "url": "https://v79sl.com/"},
    {"name": "V79 Hub", "url": "https://hub.v79sl.com/"},
    {"name": "Academy", "url": "https://academy.v79sl.com/"},
    {"name": "FFPRO", "url": "https://ffpro.v79sl.com/"},
    {"name": "V79 Tiquet", "url": "https://tiquet.v79sl.com/"},
    {"name": "Marketing", "url": "https://marketing.v79sl.com/"},
    {"name": "V79 POS", "url": "https://pos.v79sl.com/"},
)
MAX_INPUT_BYTES = 32_768


def one_snapshot(raw):
    if not isinstance(raw, bytes) or not 2 <= len(raw) <= MAX_INPUT_BYTES:
        raise ValueError("Input size unsupported")
    parsed = json.loads(raw.decode("utf-8", "strict"),
                        parse_constant=lambda _token: (_ for _ in ()).throw(ValueError()))
    if not isinstance(parsed, dict):
        raise ValueError("Unexpected input")
    return rehearse_legacy_snapshot(parsed, list(TARGETS))


def main():
    if len(sys.argv) != 1:
        print("SENTINEL_LOCAL_SHADOW=HOLD_ARGUMENTS", file=sys.stderr)
        return 2
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        result = one_snapshot(raw)
        if result.get("result") != "SIGNED_PAYLOAD_VERIFIED_IN_MEMORY":
            raise ValueError("Unverified result")
        print("SENTINEL_LOCAL_SHADOW=PASS_EPHEMERAL_SIGNATURE_ONLY")
        print("REPORTED_TARGETS=" + str(result["scopeCount"]))
        print("REPORTED_UP_UNVERIFIED=" + str(result["reportedUpUnverified"]))
        print("REPORTED_WARNING=" + str(result["reportedReview"]))
        print("REPORTED_DOWN=" + str(result["reportedDown"]))
        print("REPORTED_AGE_SECONDS=" + str(result["freshAgeSeconds"]))
        print("SOURCE_PROVENANCE=NOT_ATTESTED")
        print("DURABLE_SIGNING_REPLAY=NOT_ACTIVE")
        print("OWNER_ALERT_DELIVERY=NOT_ACTIVE")
        print("PRODUCTION_CHANGES=NONE")
        return 0
    except (ValueError, UnicodeError, TypeError, OverflowError):
        print("SENTINEL_LOCAL_SHADOW=HOLD_UNTRUSTED_OR_STALE_INPUT")
        print("PRODUCTION_CHANGES=NONE")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
