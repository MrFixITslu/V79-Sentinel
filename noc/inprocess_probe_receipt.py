"""Source-only candidate projection at the existing Sentinel HTTPS probe boundary.

The only intended caller is sentinel.monitor_forever, *after* probe_many()
returns real loop readings. Never take input from /api/status, browser JSON,
stdin, a user-selected file, a ticket or an email. This adapter does not probe,
sign, send, persist, publish or attest producer process identity.

Even in-process measurements remain untrusted remotely until the deployed
process binary, signer custody and independent receiver are verified.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .legacy_monitor_proof import normalize_legacy_monitor


def project_probe_cycle(*, targets, readings, cycle, observed_at, now=None):
    """Return only a bounded REVIEW-ONLY candidate; never promote to UP."""
    if type(cycle) is not int or not 1 <= cycle <= 2**63 - 1:
        raise ValueError("MONITOR_CYCLE_REQUIRED")
    if not isinstance(observed_at, str):
        raise ValueError("UTC_MEASUREMENT_TIME_REQUIRED")
    clock = datetime.now(timezone.utc) if now is None else now
    # The normalizer enforces exact allowlist, matching service count, codes,
    # UTC timestamp, freshness, warning semantics and removes raw messages.
    report = normalize_legacy_monitor({
        "mode": "live",
        "cycle": cycle,
        "last_check": observed_at,
        "error": None,
        "services": readings,
    }, targets, now=clock)
    return {
        "mode": "IN_PROCESS_PROBE_CANDIDATE_ONLY",
        "report": report,
        "sourceProvenanceVerified": False,
        "sourceSignatureValid": False,
        "durableReplayVerified": False,
        "externalObserverRunning": False,
        "trustedForExecutiveUse": False,
        "hostUpProven": False,
        "alertsDispatched": False,
        "ticketCreationEnabled": False,
    }
