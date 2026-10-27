"""Opt-in founder-only V79 security alerts, fixed Resend HTTPS endpoint.

No automatic sends until deployed with verified domain, recipient and API key.
Never includes raw log lines, session tokens, customer details or remote IPs.
"""
from __future__ import annotations
import json
import re
from urllib.request import Request, urlopen

ENDPOINT="https://api.resend.com/emails"
EMAIL_RX=re.compile(r"^[^\s@\x00-\x1f]{1,80}@[^\s@\x00-\x1f]{1,120}\.[a-zA-Z]{2,24}$")
HEX_RX=re.compile(r"^[a-f0-9]{64}$")

def send_security_notification(alert, *, enabled=False, api_key=None,
                               from_address=None, to_address=None,
                               transport=urlopen):
    """True only on provider-confirmed HTTP 2xx; caller must mark outbox then."""
    if not enabled:
        return False
    if not isinstance(api_key,str) or len(api_key)<15:
        return False
    if not isinstance(from_address,str) or not EMAIL_RX.fullmatch(from_address):
        return False
    if not isinstance(to_address,str) or not EMAIL_RX.fullmatch(to_address):
        return False
    if not isinstance(alert,dict) or not HEX_RX.fullmatch(str(alert.get("id",""))):
        return False
    if alert.get("severity") not in ("high","medium"):
        return False
    # Construct trusted text from bounded machine-defined categories, never logs.
    host=str(alert.get("host",""))
    rule=str(alert.get("rule",""))
    if not re.fullmatch(r"[a-zA-Z0-9.-]{1,100}",host) or not re.fullmatch(r"[a-z_]{1,60}",rule):
        return False
    payload={
        "from":from_address,"to":[to_address],
        "subject":f"[V79 Sentinel] {alert['severity'].upper()} security review: {host}",
        "text":(
            "Sentinel observed a suspicious security event. This does NOT confirm unauthorised access.\n\n"
            f"Host: {host}\nRule: {rule}\n"
            f"UTC epoch: {int(alert['ts'])}\nEvidence ID: {alert['id'][:16]}\n\n"
            "Review trusted SSH/application audit evidence with an authorised operator. "
            "Do not follow links or make server changes based solely on this notice."
        ),
    }
    req=Request(ENDPOINT,data=json.dumps(payload).encode("utf-8"),method="POST",
                headers={"Authorization":"Bearer "+api_key,
                         "Content-Type":"application/json",
                         "User-Agent":"V79Sentinel-SecurityWatch/1.0",
                         "Idempotency-Key":"sentinel-security-"+alert["id"][:48]})
    try:
        with transport(req,timeout=5) as response:
            return 200 <= int(response.status) < 300
    except (OSError,ValueError,TimeoutError):
        return False
