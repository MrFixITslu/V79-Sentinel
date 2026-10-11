"""Provider-only view model for the *mock* application incident ledger.

The file holds qualified event simulation, not a customer ticket or confirmed
SLA incident. Validation is strict; malformed or stale evidence cannot
become an authoritative "no incidents" or "healthy" status.
"""
from __future__ import annotations
from datetime import datetime
import time

ALLOWED_APPS=frozenset(("Website","Hub","Tiquet","FFPRO","Marketing",
                        "Academy","POS","Gaming Studio J"))
MOCK_SCOPE="OWNER_ONLY_APPLICATION_INCIDENT_SIMULATION"
MAX_AGE=45*60
MAX_ITEMS=500

def parse_time(value):
    if not isinstance(value,str):
        raise ValueError("Expected timezone-aware date")
    date=datetime.fromisoformat(value)
    if date.tzinfo is None:
        raise ValueError("Naive mock incident timestamps are not accepted")
    return int(date.timestamp())

def summary(report,now=None):
    result={"mock_incidents_current":False,"mock_incidents":[],
            "mock_incidents_open":None,"mock_events_pending":None,
            "mock_integrations":"disabled","mock_status":"unavailable"}
    if report is None:
        return result
    if not isinstance(report,dict) or report.get("scope")!=MOCK_SCOPE or (
        report.get("live_integrations")!="disabled"):
        raise PermissionError("Unexpected mock-only incident source")
    current=int(time.time()) if now is None else now
    if type(current) is not int:
        raise ValueError("Evaluation time must be integer")
    timestamp=parse_time(report.get("generated_at"))
    fresh=0<=current-timestamp<=MAX_AGE
    incidents=report.get("incidents")
    pending=report.get("pending_mock_events")
    if not isinstance(incidents,list) or len(incidents)>MAX_ITEMS or (
        type(pending) is not int or pending<0):
        raise ValueError("Invalid mock incident summary")
    items=[]
    for row in incidents:
        if not isinstance(row,dict) or set(row)!={"app","status","opened_at","resolved_at"}:
            raise ValueError("Unexpected mock incident properties")
        app=row["app"]
        state=row["status"]
        opened=row["opened_at"]
        resolved=row["resolved_at"]
        if app not in ALLOWED_APPS or state not in ("open","resolved") or (
            type(opened) is not int or opened<1 or opened>timestamp):
            raise ValueError("Invalid mock incident")
        if (state=="open" and resolved is not None) or (
            state=="resolved" and (type(resolved) is not int or
                                    resolved<opened or resolved>timestamp)):
            raise ValueError("Inconsistent mock recovery evidence")
        items.append({"app":app,"state":state,"opened_at":opened,
                      "resolved_at":resolved,"classification":"MOCK_ONLY"})
    result["mock_status"]="current" if fresh else "stale"
    if fresh:
        result.update(mock_incidents_current=True,
            mock_incidents=items[-MAX_ITEMS:],
            mock_incidents_open=sum(i["state"]=="open" for i in items),
            mock_events_pending=pending)
    return result
