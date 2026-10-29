"""Bounded, read-only Mission Control summary inside the authenticated NOC.

The upstream local 8787 monitor remains an independent service. This module
never forwards operator sessions, cookies, admin calls, arbitrary URLs or
browser QA screenshots. The NOC serves only a small allowlisted JSON summary.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from urllib.request import urlopen
from urllib.error import URLError

_BASE = "http://127.0.0.1:8787"
_MAX = 250_000

def _read_local(path: str) -> dict:
    if path not in ("/api/status", "/api/qa/latest"):
        raise ValueError("Unapproved local Mission Control endpoint")
    with urlopen(_BASE + path, timeout=1.6) as response:
        if response.status != 200:
            raise ValueError("Mission Control unavailable")
        body = response.read(_MAX + 1)
    if len(body) > _MAX:
        raise ValueError("Mission Control upstream too large")
    result = json.loads(body)
    if not isinstance(result, dict):
        raise ValueError("Mission Control upstream malformed")
    return result

def _short(value, maximum=100):
    return value[:maximum] if isinstance(value,str) else ""

def _fresh_local_claim(status, raw_services, *, now=None) -> bool:
    """A recent locally *reported* sample, never authenticated probe provenance."""
    if (not isinstance(status, dict)
            or status.get("mode") != "live"
            or type(status.get("cycle")) is not int
            or status["cycle"] < 1
            or status.get("error") is not None
            or not isinstance(raw_services, list)
            or len(raw_services) != 7
            or not all(isinstance(row, dict) for row in raw_services)):
        return False
    stamp = status.get("last_check")
    if not isinstance(stamp, str) or not 18 <= len(stamp) <= 42:
        return False
    try:
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        clock = datetime.now(timezone.utc) if now is None else now
        if (parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0
                or not isinstance(clock, datetime) or clock.tzinfo is None):
            return False
        seconds = (clock.astimezone(timezone.utc) - parsed).total_seconds()
        return -30 <= seconds <= 600
    except (TypeError, ValueError, OverflowError):
        return False


def snapshot(*, now=None) -> dict:
    status = _read_local("/api/status")
    # QA is advisory. A failed QA endpoint must not hide a valid monitor
    # observation, but it can never imply an authenticated application test.
    try:
        qa = _read_local("/api/qa/latest")
    except (OSError, ValueError, TypeError, KeyError, TimeoutError):
        qa = {"state": "unavailable", "results": []}
    raw_services = status.get("services") or []
    raw_results = qa.get("results") or []
    if not isinstance(raw_services,list) or not isinstance(raw_results,list):
        raise ValueError("Malformed Mission Control service list")
    fresh = _fresh_local_claim(status, raw_services, now=now)
    services=[]
    for item in raw_services[:24]:
        if not isinstance(item,dict): continue
        raw_state=item.get("status")
        state=(raw_state if fresh and raw_state in ("up","down","degraded","unknown")
               else "unknown")
        http=item.get("http")
        latency=item.get("ms")
        services.append({
            "name":_short(item.get("name"),65),
            "state":state,
            "http":http if fresh and type(http) is int and 100<=http<=599 else None,
            "latencyMs":latency if fresh and type(latency) is int and 0<=latency<=120_000 else None,
        })
    results=[]
    counts={"pass":0,"review":0,"auth-gated":0,"fail":0,"other":0}
    for item in raw_results[:100]:
        if not isinstance(item,dict): continue
        state=item.get("status")
        state=state if state in counts and state!="other" else "other"
        counts[state]+=1
        if len(results)<20:
            results.append({
                "name":_short(item.get("name"),65),
                "viewport":_short(item.get("viewport"),24),
                "state":state,
            })
    return {
        "source":"local-mission-control",
        "monitorMode":"live" if fresh else "stale-or-unverified",
        "monitorSampleFresh":fresh,
        "sourceSignatureValid":False,
        "sourceProvenanceVerified":False,
        "trustedForExecutiveUse":False,
        "automaticSecurityAlertsEnabled":False,
        "lastCheck":_short(status.get("last_check"),48),
        "services":services,
        "qa":{
            "runId":_short(qa.get("runId"),55),
            "checkedAt":_short(qa.get("at"),48),
            "state":_short(qa.get("state"),30),
            "policy":"Public-page browser QA only; account workflows are not verified.",
            "counts":counts,
            "results":results,
        },
    }
