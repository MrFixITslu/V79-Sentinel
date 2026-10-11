"""Only real server-correlated, signed Edge incidents can reach ticket review."""
import base64
from datetime import datetime,timezone
import time
from uuid import UUID, uuid5, NAMESPACE_URL

from cryptography.exceptions import InvalidSignature

from .sentinel_real_edge import independently_verified_incident
from .sentinel_approval_issuer import issue_supervised_approval,approval_claim_bytes
from .sentinel_ticket_outbox import initialize as initialize_outbox,queue_reviewed_ticket


def _utc(epoch):
    return datetime.fromtimestamp(epoch,timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00","Z")


def build_real_ticket(store,incident_id,mapping,keys,targets,now=None):
    if not isinstance(mapping,dict) or set(mapping)!={
        "sentinel_customer_id","tiquet_organization_id","tiquet_client_id"}:
        raise PermissionError("Owner mapping incomplete")
    with store.db() as db:
        row=db.execute("""SELECT i.*,s.name site_name
          FROM sentinel_real_incidents i JOIN sites s ON s.id=i.site_id
          WHERE i.id=? AND i.customer_id=? AND i.state='open'
            AND s.customer_id=i.customer_id""",
          (incident_id,mapping["sentinel_customer_id"])).fetchone()
        if not row:raise PermissionError("Incident is not an open signed owner incident")
        event_id=str(uuid5(NAMESPACE_URL,"v79-sentinel:ticket.create:"+row["id"]))
        e={"schema_version":1,"source":"v79-sentinel",
          "classification":"PRODUCTION_VERIFIED",
          "event_id":event_id,"idempotency_key":"sentinel:event:"+event_id,
          "source_incident_id":row["id"],
          "correlation_key":"sentinel:incident:"+row["id"],
          "tenant":dict(mapping),
          "impact":{"site_id":row["site_id"],"site_name":row["site_name"],
                    "failure_domain":row["domain"]},
          "incident":{"title":row["title"],"severity":"critical",
                      "detected_at":_utc(row["opened"]),"observed_state":"open"},
          "action":"ticket.create"}
    if not independently_verified_incident(store,incident_id,keys,targets,now=now):
        raise PermissionError("No current independently signed observations")
    return e


def review_real_and_queue(store,operator_id,otp,incident_id,mapping,keys,
                          targets,signing_key,key_id,confirmed=False,now=None):
    when=int(time.time() if now is None else now)
    if confirmed is not True:raise PermissionError("Explicit human approval required")
    event=build_real_ticket(store,incident_id,mapping,keys,targets,now=when)
    def fresh(e):
        return e==build_real_ticket(store,incident_id,mapping,keys,targets,now=when)
    proof=issue_supervised_approval(store,operator_id,otp,event,signing_key,key_id,
        verify_evidence=fresh,confirmed=True,now_ms=when*1000)
    try:
        signature=base64.urlsafe_b64decode(proof["signature"]+"==")
        signing_key.public_key().verify(signature,approval_claim_bytes(proof))
    except (InvalidSignature,TypeError,ValueError):
        raise PermissionError("Signed owner approval failed validation") from None
    initialize_outbox(store)
    result=queue_reviewed_ticket(store,event,proof,
        verify_approval=lambda e,p:p==proof,
        verify_source=fresh,now=when)
    return {"event_id":event["event_id"],"incident_id":incident_id,
            "queued":result["queued"],"state":result["state"]}
