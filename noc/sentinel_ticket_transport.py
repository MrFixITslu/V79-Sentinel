"""Fail-closed, explicitly invoked Sentinel -> Tiquet delivery adapter.

No worker is launched by this module. Every delivery revalidates signed source,
human approval and current Hub/reviewer authorization. A secure HTTPS transport
is injectable for isolated tests; NEVER auto-enable live dispatch.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import re
import ssl
import time
import urllib.request
import urllib.error
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .sentinel_approval_issuer import approval_claim_bytes,event_sha256
from .sentinel_ticket_outbox import record_delivery

PATH="/api/integrations/sentinel/v1/events"
DESTINATION="https://tiquet.v79sl.com"+PATH
UUID_PATTERN=re.compile(
 r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",re.I)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,msg,headers,newurl):
        return None


def verified_https_transport(destination,body,headers,timeout=5):
    """Explicit TLS-authenticated HTTPS, no redirects or cookies."""
    if destination!=DESTINATION:raise PermissionError("Unexpected ticket endpoint")
    req=urllib.request.Request(destination,data=body,method="POST",headers=headers)
    handler=urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        NoRedirect)
    try:
        with handler.open(req,timeout=timeout) as response:
            if response.url!=destination:raise PermissionError("Redirect forbidden")
            return {"status":response.status,
                    "content_type":response.headers.get("Content-Type",""),
                    "body":response.read(2049)}
    except (urllib.error.URLError,TimeoutError):
        return {"status":503,"content_type":"","body":b""}


def _uuid(value):
    return isinstance(value,str) and UUID_PATTERN.fullmatch(value) is not None


def _approval_valid(event,approved,verification_key,now):
    if not isinstance(approved,dict) or not isinstance(verification_key,Ed25519PublicKey):
        return False
    if not _uuid(approved.get("approval_id")) or (
        approved.get("event_id")!=event.get("event_id") or
        approved.get("incident_id")!=event.get("source_incident_id") or
        approved.get("event_sha256")!=event_sha256(event)):
        return False
    tenant=event.get("tenant",{})
    if not isinstance(tenant,dict) or any(
        approved.get(k)!=tenant.get(k) for k in (
         "sentinel_customer_id","tiquet_organization_id","tiquet_client_id")):
        return False
    try:
        expiry=datetime.fromisoformat(approved["expires_at"].replace("Z","+00:00"))
        if expiry.tzinfo is None or expiry.timestamp()<=now:return False
        import base64
        signature=base64.urlsafe_b64decode(approved["signature"]+"==")
        verification_key.verify(signature,approval_claim_bytes(approved))
    except (InvalidSignature,ValueError,TypeError,KeyError):
        return False
    return True


def dispatch_once(store,event_id,*,enabled=False,service_secret=None,
    approval_public_key=None,verify_source=None,authorize_machine=None,
    authorize_reviewer=None,transport=None,now=None):
    """One explicit attempt; return status, not secrets. No background worker."""
    if enabled is not True:return {"status":"disabled"}
    if not _uuid(event_id):raise ValueError("Invalid dispatch ID")
    if not isinstance(service_secret,str) or len(service_secret)<48 or any(
        not callable(fn) for fn in (
            verify_source,authorize_machine,authorize_reviewer,transport)):
        raise PermissionError("Incomplete independent delivery authorities")
    when=int(time.time() if now is None else now)
    with store.db() as db:
        row=db.execute("""SELECT payload,payload_sha256,status,next_attempt,
           approval_expires FROM sentinel_dispatch_outbox WHERE event_id=?""",
           (event_id,)).fetchone()
    if not row or row["status"]!="pending" or row["next_attempt"]>when or (
        row["approval_expires"]<=when):
        raise PermissionError("No currently authorized queued event")
    body=row["payload"].encode("utf8")
    if len(body)>12000 or hashlib.sha256(body).hexdigest()!=row["payload_sha256"]:
        raise PermissionError("Queued event digest corrupted")
    payload=json.loads(body)
    approved=payload.get("approval")
    event={key:value for key,value in payload.items() if key!="approval"}
    if event.get("event_id")!=event_id or event.get("action")!="ticket.create" or (
        event.get("classification")!="PRODUCTION_VERIFIED" or
        not _approval_valid(event,approved,approval_public_key,when)):
        raise PermissionError("Unverified signed dispatch approval")
    if verify_source(event) is not True:raise PermissionError("Source evidence no longer valid")
    scope={"serviceId":"v79-sentinel",
        "sentinelCustomerId":event["tenant"]["sentinel_customer_id"],
        "organizationId":event["tenant"]["tiquet_organization_id"],
        "accountId":None,"clientId":event["tenant"]["tiquet_client_id"],
        "action":"ticket.create"}
    # Machine authority fills the registered account ID; no request may invent it.
    authority=authorize_machine(scope)
    if not isinstance(authority,dict) or authority.get("allowed") is not True or (
        not _uuid(authority.get("accountId"))):
        raise PermissionError("Current scoped machine entitlement denied")
    scope["accountId"]=authority["accountId"]
    reviewer=authorize_reviewer({
        "approverUserId":approved["approver_user_id"],
        "approvalId":approved["approval_id"],
        "sentinelCustomerId":scope["sentinelCustomerId"],
        "organizationId":scope["organizationId"],"action":"ticket.create"})
    if reviewer is not True:raise PermissionError("Approving operator now unauthorized")
    stamp=str(when)
    signature=hmac.new(service_secret.encode("utf8"),
        ("POST\n"+PATH+"\n"+stamp+"\n"+hashlib.sha256(body).hexdigest()).encode("utf8"),
        hashlib.sha256).hexdigest()
    headers={"Content-Type":"application/json",
             "X-V79-Service-Id":"v79-sentinel",
             "X-V79-Sentinel-Customer":scope["sentinelCustomerId"],
             "X-V79-Timestamp":stamp,"X-V79-Signature":signature}
    response=transport(DESTINATION,body,headers)
    accepted=False;job_id=None
    try:
        if response["status"] in (200,201) and (
            "application/json" in response["content_type"].lower()) and (
            isinstance(response["body"],bytes) and len(response["body"])<=2048):
            receipt=json.loads(response["body"])
            accepted=(receipt.get("accepted") is True and
                      receipt.get("state") in ("created","existing","duplicate") and
                      _uuid(receipt.get("jobId")) and
                      receipt.get("correlationKey")==event["correlation_key"])
            if accepted:job_id=receipt["jobId"]
    except (KeyError,TypeError,ValueError,UnicodeError,AttributeError):
        accepted=False
    return record_delivery(store,event_id,accepted=accepted,job_id=job_id,now=when)
