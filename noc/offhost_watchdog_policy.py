"""Pure watchdog classification for an independently hosted Sentinel observer.

No socket, timer, state file, key, email, or incident dispatch. This module
does NOT run on Dell in a production outage-detector configuration. A missing
signed heartbeat is 'monitoring blind', not proof that Dell is down.
"""
from __future__ import annotations

from datetime import datetime, timezone

MAX_AGE_SECONDS = 900


def offhost_watchdog_decision(receipt, *, now=None):
    """Classify verified-candidate receipt freshness; never assert host UP/DOWN.

    The caller must independently verify sender identity, signature, durable
    anti-replay state and off-host receipt origin. These booleans are only
    preconditions, not a cryptographic verification performed here.
    """
    result = {
        "mode": "INDEPENDENT_WATCHDOG_POLICY_ONLY",
        "state": "UNKNOWN",
        "reason": "RECEIPT_OR_VERIFICATION_MISSING",
        "serviceHealthVerified": False,
        "hostUpProven": False,
        "hostDownProven": False,
        "ownerNotificationDispatched": False,
        "externalObserverRunning": False,
        "safeToAutoRecover": False,
    }
    if not isinstance(receipt, dict) or set(receipt) != {
        "sourceSignatureValid", "replayStatePersisted",
        "acceptedSequence", "receivedAtUtc",
    }:
        return result
    if (receipt["sourceSignatureValid"] is not True or
            receipt["replayStatePersisted"] is not True or
            type(receipt["acceptedSequence"]) is not int or
            receipt["acceptedSequence"] < 1):
        return result
    stamp = receipt["receivedAtUtc"]
    if not isinstance(stamp, str) or not 15 <= len(stamp) <= 40 or (
            not stamp.endswith("Z")):
        return result
    try:
        observed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        clock = datetime.now(timezone.utc) if now is None else now
        if not isinstance(clock, datetime) or clock.tzinfo is None or (
                observed.tzinfo is None or
                observed.utcoffset().total_seconds() != 0):
            return result
        seconds = (clock.astimezone(timezone.utc) - observed).total_seconds()
        if not 0 <= seconds <= MAX_AGE_SECONDS:
            return {
                **result, "state": "MONITORING_BLIND",
                "reason": "VERIFIED_RECEIPT_NOT_RECENT_OR_CLOCK_UNTRUSTED",
            }
        return {
            **result, "state": "RECENT_SIGNED_CANDIDATE_RECEIVED",
            "reason": "EXTERNAL_RECEIPT_FRESH_BUT_PROBE_AND_HOST_UNVERIFIED",
        }
    except (ValueError, TypeError, OverflowError):
        return result
