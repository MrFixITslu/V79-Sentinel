"""Fail-closed, *untrusted* advisory view of V79-owned HTTPS monitor reports.

Does not probe networks, query devices, sign evidence, generate tickets, or claim
that a historical "live" field authenticates its source. This is a pre-integration
contract, not a working protective collector.
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit

MAX_SERVICES = 20
MAX_AGE_SECONDS = 600
MAX_FUTURE_SECONDS = 120


def _time(raw):
    if not isinstance(raw, str) or len(raw) > 35 or not raw.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _approved(targets):
    if not isinstance(targets, list) or not (1 <= len(targets) <= MAX_SERVICES):
        raise ValueError("Missing/broad owned-target allowlist")
    names, urls = set(), set()
    for item in targets:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("url"), str):
            raise ValueError("Invalid approved target")
        name, address = item["name"], item["url"]
        parts = urlsplit(address)
        host = (parts.hostname or "").lower()
        if not (1 <= len(name) <= 80) or name in names or address in urls:
            raise ValueError("Duplicate or invalid allowlisted service")
        if parts.scheme != "https" or parts.username or parts.password or parts.fragment or parts.port not in (None, 443):
            raise ValueError("Target is not approved HTTPS")
        if host != "v79sl.com" and not host.endswith(".v79sl.com"):
            raise ValueError("Non-owned target")
        names.add(name)
        urls.add(address)
    return {item["name"]: item["url"] for item in targets}


def evaluate_owner_https_report(snapshot, targets, now=None):
    """Return advisory-only, never authenticated monitor or signed COO evidence."""
    clock = now or datetime.now(timezone.utc)
    if not isinstance(clock, datetime) or clock.tzinfo is None:
        raise ValueError("Aware datetime required")
    clock = clock.astimezone(timezone.utc)
    allowed = _approved(targets)
    base = {
        "mode": "untrusted-read-only",
        "trustedForExecutiveUse": False,
        "continuousMonitoringVerified": False,
        "customerReady": False,
        "ticketCreationEnabled": False,
        "alertsDispatched": False,
        "sourceIdentityVerified": False,
        "observedAt": None,
        "ageSeconds": None,
        "status": "UNKNOWN",
        "reason": "NO_VERIFIED_MEASUREMENT",
        "services": [],
    }
    if not isinstance(snapshot, dict) or snapshot.get("mode") != "live" or type(snapshot.get("cycle")) is not int or snapshot["cycle"] < 1:
        return base | {"reason": "NO_REAL_COLLECTOR_REPORT"}
    measured = _time(snapshot.get("last_check"))
    if measured is None:
        return base | {"reason": "MISSING_OR_INVALID_TIMESTAMP"}
    delta = (clock - measured).total_seconds()
    if delta < -MAX_FUTURE_SECONDS:
        return base | {"reason": "FUTURE_REPORT"}
    if delta > MAX_AGE_SECONDS:
        return base | {"reason": "STALE_REPORT", "observedAt": measured.isoformat(), "ageSeconds": round(delta)}
    if snapshot.get("error"):
        return base | {"reason": "COLLECTOR_ERROR"}
    items = snapshot.get("services")
    if not isinstance(items, list) or len(items) != len(allowed) or len(items) > MAX_SERVICES:
        return base | {"reason": "INCOMPLETE_OR_INVALID_SCOPE"}
    seen, results = set(), []
    for item in items:
        if not isinstance(item, dict):
            return base | {"reason": "MALFORMED_REPORT"}
        name, address, status = item.get("name"), item.get("url"), item.get("status")
        if not isinstance(name, str) or not isinstance(address, str) or name not in allowed or allowed[name] != address or name in seen:
            return base | {"reason": "UNAPPROVED_OR_DUPLICATE_TARGET"}
        if status not in ("up", "warning", "down") or not isinstance(status, str):
            return base | {"reason": "INVALID_STATUS"}
        seen.add(name)
        cert_days = item.get("cert_days")
        if cert_days is not None and (type(cert_days) is not int or cert_days < -1000 or cert_days > 5000):
            return base | {"reason": "MALFORMED_REPORT"}
        # A reported 2xx/3xx is still not an attested collector measurement.
        if status == "down":
            signal = "REPORTED_DOWN"
        elif status == "warning" or (cert_days is not None and cert_days < 14):
            signal = "REVIEW_REPORTED"
        else:
            signal = "REPORTED_UP_UNVERIFIED"
        results.append({"name": name, "signal": signal})
    results.sort(key=lambda x: x["name"])
    return base | {
        "status": "REPORTED_NOT_AUTHENTICATED",
        "reason": "UNSIGNED_COLLECTOR_REPORT",
        "observedAt": measured.isoformat(),
        "ageSeconds": max(0, round(delta)),
        "services": results,
    }
