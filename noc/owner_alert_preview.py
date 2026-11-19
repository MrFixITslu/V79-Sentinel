"""Pure founder-only preview of a review-required HTTPS monitor candidate.

Never sends email, imports a network client, reads secrets or mutates state.
A signed key alone does NOT authenticate that a physical check occurred.
No personal, customer or raw monitor text is included in the template.
"""
from __future__ import annotations
import hashlib
import re

from .signed_owned_evidence import COLLECTOR_RE

KIND = frozenset(("down", "recovered"))
EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,160}\.[A-Za-z]{2,24}$")
ALLOWED = frozenset(("collector", "service", "kind", "sequence",
                     "observed_at", "state"))
EVENT_TEXT = {
    "down": "Two consecutive HTTPS reachability reports indicated a failure",
    "recovered": "Two consecutive HTTPS reachability reports indicated recovery",
}


def founder_review_preview(record, *, approved_names, recipient,
                           confirmed_owner_recipient):
    """Return safe words and a stable provider idempotency hint, never send."""
    if (not isinstance(record, dict) or set(record) != ALLOWED or
            not isinstance(approved_names, (frozenset, set, tuple)) or
            not approved_names or len(approved_names) > 20):
        raise ValueError("Exact founder review record and scope required")
    c, service, kind = record["collector"], record["service"], record["kind"]
    seq = record["sequence"]
    if (type(c) is not str or not COLLECTOR_RE.fullmatch(c) or
            type(service) is not str or service not in approved_names or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}", service) or
            kind not in KIND or type(seq) is not int or seq < 1 or
            record["state"] != "review_required"):
        raise ValueError("Unapproved or unreviewed candidate event")
    if (type(recipient) is not str or
            type(confirmed_owner_recipient) is not str or
            recipient != confirmed_owner_recipient or
            not EMAIL.fullmatch(recipient)):
        raise ValueError("Explicit fixed founder recipient required")
    observed = record["observed_at"]
    if (not isinstance(observed, str) or len(observed) > 40 or
            not re.fullmatch(
                r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)",
                observed)):
        raise ValueError("Exact UTC incident timestamp required")
    from datetime import datetime
    try:
        stamped = datetime.fromisoformat(observed.replace("Z", "+00:00"))
        if stamped.utcoffset().total_seconds() != 0:
            raise ValueError()
    except (ValueError, OverflowError):
        raise ValueError("UTC time required") from None
    # Only owner-approved service display names reach text. Strip arbitrary
    # record data; never quote upstream HTTP messages or customer data.
    identifier = hashlib.sha256(
        ("sentinel-advisory-v1\0" + "\0".join(
            [c, service, kind, str(seq), observed]
        )).encode("utf-8")
    ).hexdigest()
    return {
        "category": "FOUNDER_REVIEW_PREVIEW_ONLY",
        "recipient": recipient,
        "subject": "[V79 Sentinel] Review reported HTTPS " +
                   ("failure" if kind == "down" else "recovery"),
        "text": (
            "This is a candidate advisory, NOT a verified application outage, "
            "confirmed host intrusion or proof of independent monitoring.\n\n"
            "V79-owned service: " + service + "\n"
            "Report: " + EVENT_TEXT[kind] + ".\n"
            "UTC reported observation: " + observed + "\n"
            "Signed report sequence: " + str(seq) + "\n"
            "Evidence receipt: " + identifier[:16] + "\n\n"
            "Check the approved source and application health separately. "
            "Do not perform server actions based solely on this notice."
        ),
        "idempotencyKeyHint": "sentinel-owner-review-" + identifier,
        "sendAllowed": False,
        "recipientDelivered": False,
        "sourceProvenanceVerified": False,
        "ownerApprovalRequired": True,
    }
