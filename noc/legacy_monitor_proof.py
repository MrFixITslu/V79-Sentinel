"""Source-only translation of the existing Sentinel live HTTPS monitor snapshot.

The legacy monitor reports HEAD reachability; it is NOT authenticated, does
not attest the actual DNS/TLS/socket operation, and cannot detect its own host
being offline. This module never starts a probe, fetches a URL, reads a key,
writes a file, sends an alert or executes a customer action.

An owner-provisioned Ed25519 signer can produce a *candidate* envelope only
after strict source data validation. The separate signed evidence evaluator
and durable replay checkpoint remain required on the recipient side.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .owned_https_evidence_gate import _approved
from .signed_owned_evidence import canonical_signed_payload, COLLECTOR_RE

MAX_REPORT_AGE = 600
MAX_CLOCK_SKEW = 120
MAX_RAW_SERVICES = 20
VALID_STATUS = frozenset(("up", "warning", "down"))
TIME = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)$")


def normalize_legacy_monitor(snapshot, approved_targets, *, now=None):
    """Strip arbitrary fields; refuse replay-prone, stale, demo or false-up rows.

    The output is an *unauthenticated observation claim*. It must not be
    displayed as independently measured or verified application health.
    """
    approved = _approved(approved_targets)
    instant = datetime.now(timezone.utc) if now is None else now
    if not isinstance(instant, datetime) or instant.tzinfo is None:
        raise ValueError("A timezone-aware instant is required")
    instant = instant.astimezone(timezone.utc)
    if (not isinstance(snapshot, dict) or snapshot.get("mode") != "live" or
            type(snapshot.get("cycle")) is not int or snapshot["cycle"] < 1 or
            snapshot["cycle"] > 2**63 - 1 or snapshot.get("error") is not None):
        raise ValueError("Unverified or failed monitor cycle")
    stamp = snapshot.get("last_check")
    if not isinstance(stamp, str) or not TIME.fullmatch(stamp):
        raise ValueError("Monitor UTC timestamp is missing or invalid")
    observed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    delta = (instant - observed).total_seconds()
    if not -MAX_CLOCK_SKEW <= delta <= MAX_REPORT_AGE:
        raise ValueError("Monitor cycle is stale or future-dated")
    readings = snapshot.get("services")
    if (not isinstance(readings, list) or len(readings) != len(approved)
            or len(readings) > MAX_RAW_SERVICES):
        raise ValueError("Incomplete or broad monitor scope")
    seen, result = set(), []
    for row in readings:
        if not isinstance(row, dict):
            raise ValueError("Invalid monitor observation")
        name, url, status = row.get("name"), row.get("url"), row.get("status")
        if (type(name) is not str or type(url) is not str or
                name not in approved or url != approved[name] or name in seen or
                type(status) is not str or status not in VALID_STATUS):
            raise ValueError("Unapproved, repeated or invalid monitoring row")
        seen.add(name)
        code = row.get("http")
        if (code is not None and (type(code) is not int or
                                  not 100 <= code <= 599)):
            raise ValueError("Invalid HTTP result")
        if status == "up" and (code is None or not 200 <= code <= 399):
            raise ValueError("An UP claim needs a successful HTTP status")
        if status == "warning" and code is not None and code < 400:
            # A valid 2xx response with an expiring certificate is a warning.
            cert = row.get("cert_days")
            if type(cert) is not int or cert >= 14:
                raise ValueError("Inconsistent monitor warning")
        cert = row.get("cert_days")
        if cert is not None and (type(cert) is not int or not -1000 <= cert <= 5000):
            raise ValueError("Invalid certificate age")
        if status == "up" and cert is not None and cert < 14:
            raise ValueError("Expired/expiring certificate cannot be reported UP")
        # Never forward original message, error, IP, request data, credentials,
        # account data, arbitrary untrusted fields or reachability percentages.
        result.append({"name": name, "url": url, "status": status, "cert_days": cert})
    result.sort(key=lambda x: x["name"])
    return {"mode": "live", "cycle": snapshot["cycle"],
            "last_check": observed.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "error": None, "services": result}


def candidate_envelope(snapshot, approved_targets, *, collector_id, signer,
                       previous_cycle, now=None):
    """Sign candidate evidence with a separately owner-provisioned key.

    Sequence equals the original monitor cycle, not a mintable wall clock.
    If monitor restarts and resets cycle, caller must halt for supervised
    re-enrollment (no automatic sequence-reset bypass). previous_cycle MUST
    come from durable trusted storage, not an in-memory constant.
    """
    if (type(collector_id) is not str or
            not COLLECTOR_RE.fullmatch(collector_id) or
            not isinstance(signer, Ed25519PrivateKey) or
            type(previous_cycle) is not int or previous_cycle < 0):
        raise ValueError("Pinned collector, explicit signer and durable cycle required")
    minimal = normalize_legacy_monitor(snapshot, approved_targets, now=now)
    cycle = minimal["cycle"]
    if cycle <= previous_cycle:
        raise ValueError("Duplicate or reset monitor cycle: owner review required")
    content = {"version": 1, "collectorId": collector_id,
               "sequence": cycle, "snapshot": minimal}
    raw = canonical_signed_payload(content)
    if len(raw) > 32768:
        raise ValueError("Oversized signed report")
    sig = signer.sign(raw)
    return content | {"signature": base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")}
