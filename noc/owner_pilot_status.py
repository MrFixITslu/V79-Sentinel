"""Authenticated read-only V79 Digital pilot status projection for NOC operators.

Only published, owner-only evidence snapshots are consulted. No new sockets,
network scans, credentials, config changes or cross-database writes.
The independent lab NOC remains authoritative for its simulated tenants.
"""
from __future__ import annotations

from datetime import datetime,timezone
from .owner_mock_incidents import summary as mock_incident_summary
import json
from pathlib import Path
import os
import stat
import time

PILOT_ROOT=Path(os.environ.get("SENTINEL_OWNER_PILOT_ROOT",
    "/home/firelion/V79-Sentinel/secure-edge-transport-staging/data/v79-owned-pilot"))
APP_NAMES=frozenset(("Website","Hub","Tiquet","FFPRO","Marketing",
                     "Academy","POS","Gaming Studio J"))
# Fixed first-party canaries verified on the Acer. Never accept URL/path
# specifications from telemetry: that could become an SSRF or routing oracle.
APP_ENDPOINTS={
    "Website":("v79sl.com","/api/ready"),
    "Hub":("hub.v79sl.com","/api/health"),
    "Tiquet":("tiquet.v79sl.com","/api/health"),
    "FFPRO":("ffpro.v79sl.com","/api/health"),
    "Marketing":("marketing.v79sl.com","/api/health"),
    "Academy":("academy.v79sl.com","/healthz"),
    "POS":("pos.v79sl.com","/api/health"),
    "Gaming Studio J":("games.v79sl.com","/healthz"),
}
SERVICE_READINESS_STATES=frozenset(("ready","failed","protected","unverified"))
ALLOWED_TARGETS=frozenset((
    ("192.168.100.1",53),("192.168.100.1",80),
    ("192.168.100.163",22),("192.168.100.163",80),("192.168.100.163",443)
))
MAX_EVIDENCE_BYTES=65536
LAN_TTL=12*60
APP_TTL=40*60
CERT_TTL=8*3600
MOCK_INCIDENT_TTL=45*60
MAX_MOCK_INCIDENTS=500

def private_json(root,name,required=False):
    path=Path(root)/name
    # Reject even dangling symlinks: Path.exists() follows their target and
    # incorrectly labels unsafe pointers to missing files as absent evidence.
    if path.is_symlink():
        raise PermissionError("Symlink telemetry source not allowed")
    if not path.exists():
        if required:raise OSError("Owner network pilot evidence is missing")
        return None
    info=path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode&0o077 or info.st_size>MAX_EVIDENCE_BYTES:
        raise PermissionError("Telemetry source is not bounded owner-only data")
    data=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data,dict):raise ValueError("Invalid telemetry record")
    return data

def recent(epoch,ttl,now):
    return type(epoch) is int and 0<=now-epoch<=ttl

def snapshot(root=PILOT_ROOT,now=None):
    root=Path(root)
    if not root.is_dir() or root.is_symlink() or root.stat().st_mode&0o077:
        raise PermissionError("Pilot evidence directory must be owner-only")
    observed=int(time.time()) if now is None else now
    if type(observed) is not int:raise ValueError("Invalid evaluation timestamp")
    pilot=private_json(root,"last-observation.json")
    apps=private_json(root,"app-checks-latest.json")
    readiness=private_json(root,"service-readiness-latest.json")
    impact=private_json(root,"impactiq-latest.json")
    cert=private_json(root,"certificate-health.json")
    qualified_incidents=private_json(root,"app-incidents-mock-latest.json")
    result={
        "mode":"V79_OWNER_NETWORK_LIVE_READ_ONLY",
        "available":False,
        "data_age_seconds":None,
        "data_current":False,
        "connectivity_status":"no_pilot_observations",
        "approved_checks":[],
        "applications":[],
        "app_data_current":False,
        "service_readiness_current":False,
        "service_readiness_summary":{"ready":0,"protected":0,"failed":0,"unverified":8},
        "impact_hypothesis":None,
        "impact_confidence":"none",
        "cert_status":"unknown",
        "client_hours_remaining":None,
        "server_hours_remaining":None,
        "ca_days_remaining":None,
        "queue_pending":None,
        "integrations":"disabled",
        "no_customer_ticket_creation":True,
        **mock_incident_summary(qualified_incidents,now=observed),
        "disclaimer":"TCP/HEAD reachability is not proof of application health or SLA."
    }
    if pilot is None:return result
    if pilot.get("scope")!="V79_DIGITAL_OWN_NETWORK_PILOT":
        raise ValueError("Unexpected pilot monitoring scope")
    timestamp=pilot.get("collected_at")
    age=observed-timestamp if type(timestamp) is int else None
    result["data_age_seconds"]=age if age is not None and age>=0 else None
    result["data_current"]=recent(timestamp,LAN_TTL,observed)
    if type(pilot.get("queued_readings")) is int and pilot["queued_readings"]>=0:
        result["queue_pending"]=pilot["queued_readings"]
    checks=pilot.get("checks")
    if not isinstance(checks,list) or len(checks)!=5:
        raise ValueError("Pilot check count mismatch")
    seen=set()
    validated=[]
    for reading in checks:
        if not isinstance(reading,dict):
            raise ValueError("Invalid pilot check")
        address=reading.get("ip")
        port=reading.get("port")
        if type(port) is not int or (address,port) not in ALLOWED_TARGETS or (address,port) in seen:
            raise PermissionError("Pilot evidence contains unapproved target")
        seen.add((address,port))
        if type(reading.get("ok")) is not bool:
            raise ValueError("Invalid probe outcome")
        latency=reading.get("latency_ms")
        if latency is not None and (type(latency) not in (int,float) or not 0<=latency<=60000):
            raise ValueError("Invalid probe latency")
        validated.append({"ip":address,"port":port,"connected":reading["ok"],
                          "latency_ms":latency})
    if seen!=ALLOWED_TARGETS:raise ValueError("Pilot expected connectivity evidence is missing")
    result["approved_checks"]=sorted(validated,key=lambda r:(r["ip"],r["port"]))
    result["available"]=True
    result["connectivity_status"]=(
        "stale_do_not_assume_healthy" if not result["data_current"] else
        "all_approved_tcp_checks_connected" if all(x["connected"] for x in validated) else
        "one_or_more_tcp_checks_failed")
    if apps is not None:
        try:
            app_timestamp=int(datetime.fromisoformat(apps["captured_at"]).timestamp())
        except (ValueError,TypeError,KeyError):app_timestamp=None
        result["app_data_current"]=recent(app_timestamp,APP_TTL,observed)
        records=apps.get("results",[])
        if not isinstance(records,list) or len(records)>len(APP_NAMES):
            raise ValueError("Unexpected app records")
        names=set()
        for item in records:
            if not isinstance(item,dict) or item.get("app") not in APP_NAMES or item["app"] in names:
                raise PermissionError("Unrecognized application health record")
            names.add(item["app"])
            code=item.get("status")
            if code is not None and (type(code) is not int or not 100<=code<=599):
                raise ValueError("Invalid application HTTP status")
            result["applications"].append({
                "app":item["app"],"http_status":code,
                "tls_verified":item.get("tls_verified") is True,
                "category":item.get("category") if item.get("category") in
                ("reachable","protected","route_absent","method_unsupported",
                 "error_status","unexpected_status","unverified") else "unverified"
            })
    # A successful homepage HEAD is not a working application-health endpoint.
    # Verify independently sourced, fixed-path readiness evidence before
    # showing a "ready" icon anywhere on this operator dashboard.
    services={}
    if readiness is not None:
        if readiness.get("schema_version")!=1 or readiness.get("scope")!="approved_V79_public_readiness_get_only":
            raise ValueError("Readiness evidence has an unexpected scope")
        try:
            captured=int(datetime.fromisoformat(readiness["captured_at"]).timestamp())
        except (ValueError,TypeError,KeyError):
            captured=None
        result["service_readiness_current"]=recent(captured,APP_TTL,observed)
        entries=readiness.get("results")
        if not isinstance(entries,list) or len(entries)!=len(APP_ENDPOINTS):
            raise ValueError("Incomplete service readiness catalog")
        for entry in entries:
            if not isinstance(entry,dict):
                raise ValueError("Malformed readiness record")
            name=entry.get("app")
            if name not in APP_ENDPOINTS or name in services or (
                entry.get("hostname"),entry.get("path"))!=APP_ENDPOINTS[name]:
                raise PermissionError("Unapproved application readiness evidence")
            state=entry.get("readiness")
            reason=entry.get("reason")
            status=entry.get("status")
            if state not in SERVICE_READINESS_STATES or not isinstance(reason,str) or len(reason)>60:
                raise ValueError("Invalid readiness classification")
            if status is not None and (type(status) is not int or not 100<=status<=599):
                raise ValueError("Invalid service HTTP response")
            if state=="ready" and (status!=200 or entry.get("tls_verified") is not True or
                                    reason!="expected_response_verified"):
                raise PermissionError("Unverified service cannot claim to be ready")
            if state=="protected" and status not in (401,403):
                raise ValueError("Protected service state requires authentication response")
            services[name]={"readiness":state,"http_status":status,
                            "path":entry["path"],"reason":reason}
    if result["service_readiness_current"]:
        summary={"ready":0,"protected":0,"failed":0,"unverified":0}
        for service in services.values():
            summary[service["readiness"]]+=1
        result["service_readiness_summary"]=summary
    for entry in result["applications"]:
        record=services.get(entry["app"]) if result["service_readiness_current"] else None
        entry["service_readiness"]=record["readiness"] if record else "unverified"
        entry["service_path"]=record["path"] if record else None
        entry["service_http_status"]=record["http_status"] if record else None
        entry["service_reason"]=record["reason"] if record else "missing_or_stale"
    if impact is not None and recent(impact.get("at"),LAN_TTL,observed):
        name=impact.get("primary_hypothesis")
        if name in (None,"local_gateway_or_lan_path","dell_host_or_access_path",
                    "dell_https_listener_or_proxy","one_or_more_public_app_entry_points"):
            result["impact_hypothesis"]=name
        confidence=impact.get("confidence")
        if confidence in ("none","limited","low","medium"):
            result["impact_confidence"]=confidence
    if cert is not None:
        try:
            clock=int(datetime.fromisoformat(cert["checked_at"]).timestamp())
            scoped=cert.get("scope")=="OWNER_LAN_PILOT_ONLY"
            fresh=recent(clock,CERT_TTL,observed)
            if scoped and fresh:
                client=float(cert["client_hours_remaining"])
                server=float(cert["server_hours_remaining"])
                ca=float(cert["ca_hours_remaining"])
                if min(client,server,ca)>=0:
                    result.update(cert_status="valid_time_remaining",
                      client_hours_remaining=round(client,1),
                      server_hours_remaining=round(server,1),
                      ca_days_remaining=round(ca/24,1))
                else:result["cert_status"]="expired"
            else:result["cert_status"]="stale_or_scope_mismatch"
        except (ValueError,TypeError,KeyError,OverflowError):
            result["cert_status"]="invalid"
    return result
