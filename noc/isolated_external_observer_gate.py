"""Source-only external website observation cross-check (NO ALERT DISPATCH).

Processes explicitly supplied Hetrix-shaped metadata. NEVER fetches URLs,
credentials or network data. JSON shaped like a provider response can be
forged; only an independently reviewed authenticated connector may supply it.
Even mutually agreeing observations are reachability claims, NOT proof of
the monitor's source identity, application health or security protection.
"""
from __future__ import annotations

from urllib.parse import urlsplit

MAX_EXTERNAL_SERVICES = 20
MAX_AGE_SECONDS = 300
MAX_FUTURE_SECONDS = 30
REQUIRED_LOCATIONS = frozenset(("new_york", "london", "sao_paulo"))
VALID_SIGNALS = frozenset((
    "REPORTED_UP_UNVERIFIED", "REPORTED_DOWN", "REVIEW_REPORTED",
))


def _unknown(reason):
    return {
        "status": "UNKNOWN", "reason": reason,
        "source": "EXTERNAL_PROVIDER_METADATA",
        "sourceIdentityCryptographicallyVerified": False,
        "trustedForExecutiveUse": False,
        "continuousProtectionVerified": False,
        "alertsDispatched": False,
        "resendNotificationAllowed": False,
        "services": [],
    }


def _owned_targets(expected):
    if (not isinstance(expected, dict)
            or not 1 <= len(expected) <= MAX_EXTERNAL_SERVICES):
        raise ValueError("EXPLICIT_OWNED_MONITOR_MAP_REQUIRED")
    urls = set()
    for name, uri in expected.items():
        if (type(name) is not str or not 1 <= len(name) <= 80
                or type(uri) is not str or uri in urls):
            raise ValueError("INVALID_EXTERNAL_ALLOWLIST")
        parts = urlsplit(uri)
        host = (parts.hostname or "").lower()
        if (parts.scheme != "https" or parts.username or parts.password
                or parts.fragment or parts.port not in (None, 443)
                or (host != "v79sl.com" and not host.endswith(".v79sl.com"))):
            raise ValueError("UNOWNED_OR_UNSAFE_EXTERNAL_TARGET")
        urls.add(uri)


def _recent(stamp, now):
    return (type(stamp) is int
            and now - MAX_AGE_SECONDS <= stamp <= now + MAX_FUTURE_SECONDS)


def evaluate_external_website_reports(
    monitors, *, approved_name_urls, approved_contact_list, now_epoch
):
    """Fail closed on disabled/stale/missing/wrongly routed external monitoring.

    Returns only redacted provider-reported state, not attested measurements.
    The caller must verify connector origin, token scope and local clock;
    a dictionary is never sufficient authentication.
    """
    _owned_targets(approved_name_urls)
    if (type(approved_contact_list) is not str
            or len(approved_contact_list) != 32
            or not approved_contact_list.isalnum()
            or type(now_epoch) is not int or now_epoch <= 0
            or not isinstance(monitors, list)
            or len(monitors) != len(approved_name_urls)):
        return _unknown("MISSING_PROVIDER_METADATA_OR_POLICY")

    names = set()
    results = []
    for m in monitors:
        if not isinstance(m, dict):
            return _unknown("INVALID_PROVIDER_MONITOR")
        name = m.get("name")
        if (type(name) is not str or name not in approved_name_urls
                or name in names or m.get("target") != approved_name_urls[name]
                or m.get("type") != "website"
                or m.get("monitor_status") != "active"
                or m.get("check_frequency") != 1
                or m.get("alert_after_minutes") != 3
                or m.get("triggering_locations") != 2
                or not isinstance(m.get("contact_lists"), list)
                or approved_contact_list not in m["contact_lists"]):
            return _unknown("UNAPPROVED_OR_INACTIVE_EXTERNAL_TARGET")
        names.add(name)
        if not _recent(m.get("last_check"), now_epoch):
            return _unknown("STALE_PROVIDER_REPORT")
        locs = m.get("locations")
        if not isinstance(locs, dict) or set(locs) != REQUIRED_LOCATIONS:
            return _unknown("MISSING_EXTERNAL_GEOGRAPHIES")
        up = down = 0
        for loc in locs.values():
            if (not isinstance(loc, dict)
                    or not _recent(loc.get("last_check"), now_epoch)
                    or loc.get("uptime_status") not in ("up", "down")):
                return _unknown("STALE_OR_INVALID_LOCATION_OBSERVATION")
            up += loc["uptime_status"] == "up"
            down += loc["uptime_status"] == "down"
        provider_status = m.get("uptime_status")
        if provider_status == "down" and down >= 2:
            signal = "REPORTED_DOWN"
        elif provider_status == "up" and up == 3:
            signal = "REPORTED_UP_UNVERIFIED"
        elif provider_status in ("up", "down"):
            signal = "REVIEW_REPORTED"
        else:
            return _unknown("INVALID_EXTERNAL_AGGREGATE_STATE")
        results.append({"name": name, "signal": signal})
    if names != set(approved_name_urls):
        return _unknown("INCOMPLETE_EXTERNAL_SCOPE")
    return {
        **_unknown("PROVIDER_STATUS_NOT_INDEPENDENTLY_ATTESTED"),
        "status": "EXTERNAL_REPORTED_NOT_ATTESTED",
        "services": sorted(results, key=lambda x: x["name"]),
    }


def compare_external_to_signed_advisory(
    external, internal, *, external_to_internal_name
):
    """Compare only explicitly mapped names. No trust promotion or dispatch."""
    blank = _unknown("EXTERNAL_OR_INTERNAL_SOURCE_NOT_ACCEPTED")
    if (not isinstance(external, dict)
            or external.get("status") != "EXTERNAL_REPORTED_NOT_ATTESTED"
            or external.get("sourceIdentityCryptographicallyVerified") is not False
            or not isinstance(internal, dict)
            or internal.get("status") != "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE"
            or internal.get("sourceSignatureValid") is not True
            or internal.get("trustedForExecutiveUse") is not False
            or not isinstance(external_to_internal_name, dict)
            or not isinstance(external.get("services"), list)
            or not isinstance(internal.get("services"), list)):
        return blank
    rows = {}
    for row in internal["services"]:
        if (not isinstance(row, dict) or type(row.get("name")) is not str
                or row.get("signal") not in VALID_SIGNALS
                or row["name"] in rows):
            return blank
        rows[row["name"]] = row["signal"]
    findings = []
    seen = set()
    for row in external["services"]:
        if not isinstance(row, dict) or type(row.get("name")) is not str:
            return blank
        external_name = row["name"]
        if (external_name in seen or external_name not in external_to_internal_name
                or row.get("signal") not in VALID_SIGNALS):
            return blank
        seen.add(external_name)
        internal_name = external_to_internal_name[external_name]
        if internal_name not in rows:
            return blank
        source_signal = rows[internal_name]
        reported_signal = row["signal"]
        if source_signal == reported_signal == "REPORTED_DOWN":
            assessment = "DOWN_REPORTED_BY_BOTH"
        elif source_signal == reported_signal == "REPORTED_UP_UNVERIFIED":
            assessment = "UP_REPORTED_BY_BOTH_UNVERIFIED"
        else:
            assessment = "DISAGREEMENT_OR_WARNING_REQUIRES_REVIEW"
        findings.append({"name": internal_name, "assessment": assessment})
    if set(external_to_internal_name) != seen or set(external_to_internal_name.values()) != set(rows):
        return blank
    return {
        **blank,
        "status": "CROSS_SOURCE_REVIEW_ONLY",
        "reason": "CONSISTENCY_DOES_NOT_AUTHENTICATE_SOURCE",
        "services": sorted(findings, key=lambda x: x["name"]),
    }
