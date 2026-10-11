"""Bounded, read-only Mission Control summary inside the authenticated NOC.

The upstream local 8787 monitor remains an independent service. This module
never forwards operator sessions, cookies, admin calls, arbitrary URLs or
browser QA screenshots. The NOC serves only a small allowlisted JSON summary.
"""
from __future__ import annotations
import json
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

def snapshot() -> dict:
    status = _read_local("/api/status")
    qa = _read_local("/api/qa/latest")
    raw_services = status.get("services") or []
    raw_results = qa.get("results") or []
    if not isinstance(raw_services,list) or not isinstance(raw_results,list):
        raise ValueError("Malformed Mission Control service list")
    services=[]
    for item in raw_services[:24]:
        if not isinstance(item,dict): continue
        raw_state=item.get("status")
        state=raw_state if raw_state in ("up","down","degraded","unknown") else "unknown"
        http=item.get("http")
        latency=item.get("ms")
        services.append({
            "name":_short(item.get("name"),65),
            "state":state,
            "http":http if type(http) is int and 100<=http<=599 else None,
            "latencyMs":latency if type(latency) is int and 0<=latency<=120_000 else None,
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
        "monitorMode":"live" if status.get("mode")=="live" else "staging",
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
