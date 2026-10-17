"""Bounded Ed25519 verification of *candidate* V79-owned HTTPS evidence.

A valid signature proves only that a pinned key signed the bytes; it does NOT
prove the sensor really probed the service or that the NOC is running. This
module has no secrets, network calls, DB writes, alerting or ticket actions.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .owned_https_evidence_gate import evaluate_owner_https_report

MAX_ENVELOPE_BYTES = 32_768
COLLECTOR_RE = re.compile(r"^v79-[a-z0-9-]{4,54}$")
SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")
MAX_SEQUENCE = 2**63 - 1


def canonical_signed_payload(envelope):
    """Serialize exactly the four attested fields; no arbitrary key or URLs."""
    signed = {key: envelope[key] for key in ("version", "collectorId", "sequence", "snapshot")}
    return json.dumps(signed, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def evaluate_signed_owned_evidence(envelope, *, trusted_collector_id,
                                   pinned_public_key, approved_targets,
                                   last_seen_sequence, now=None):
    """Operator-only verifier requiring externally pinned key and replay state.

    last_seen_sequence MUST come from durable trusted per-collector storage in
    a future integration. In-memory 0/None is not production replay defense.
    """
    blank = {
        "status": "UNKNOWN",
        "reason": "SIGNATURE_OR_SCOPE_UNVERIFIED",
        "mode": "read-only",
        "sourceSignatureValid": False,
        "trustedForExecutiveUse": False,
        "continuousMonitoringVerified": False,
        "ticketCreationEnabled": False,
        "alertsDispatched": False,
        "customerReady": False,
        "replayStatePersisted": False,
        "services": [],
    }
    try:
        if not isinstance(envelope, dict) or set(envelope) != {
            "version", "collectorId", "sequence", "snapshot", "signature"
        }:
            return blank
        if envelope["version"] != 1 or type(envelope["version"]) is not int:
            return blank
        collector_id = envelope["collectorId"]
        if not isinstance(collector_id, str) or not COLLECTOR_RE.fullmatch(collector_id):
            return blank
        if collector_id != trusted_collector_id:
            return blank
        seq = envelope["sequence"]
        if type(seq) is not int or not 1 <= seq <= MAX_SEQUENCE:
            return blank
        if type(last_seen_sequence) is not int or last_seen_sequence < 0 or seq <= last_seen_sequence:
            return blank | {"reason": "MISSING_OR_REPLAYED_SEQUENCE"}
        if type(pinned_public_key) is not bytes or len(pinned_public_key) != 32:
            return blank
        sig = envelope["signature"]
        if not isinstance(sig, str) or not SIGNATURE_RE.fullmatch(sig):
            return blank
        canonical = canonical_signed_payload(envelope)
        if len(canonical) > MAX_ENVELOPE_BYTES:
            return blank
        signature = base64.urlsafe_b64decode(sig + "==")
        if len(signature) != 64:
            return blank
        Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(signature, canonical)
        # Only after cryptographic validation inspect service observations.
        advisory = evaluate_owner_https_report(
            envelope["snapshot"], approved_targets, now=now
        )
        if advisory["status"] != "REPORTED_NOT_AUTHENTICATED":
            return blank | {"reason": advisory["reason"]}
        return {
            **blank,
            "status": "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE",
            "reason": "VALID_KEY_SIGNATURE_NOT_LIVE_PROBE_PROOF",
            "sourceSignatureValid": True,
            "collectorId": collector_id,
            "sequence": seq,
            "observedAt": advisory["observedAt"],
            "ageSeconds": advisory["ageSeconds"],
            "services": advisory["services"],
        }
    except (InvalidSignature, ValueError, TypeError, KeyError, OverflowError):
        return blank
