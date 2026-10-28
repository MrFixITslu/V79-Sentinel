"""Isolated, OFF-BY-DEFAULT signing adapter for source-bound Sentinel probe receipts.

This module has no runtime registration, secrets loader, network calls, file
writes, notification delivery, or customer actions. Only a trusted in-process
caller should invoke it with the receipt returned by project_probe_cycle()
AFTER probe_many() and telemetry recording. Receipt-shaped JSON alone does
not authenticate a collector; the receiver must still pin the public key and
check a durable per-collector replay checkpoint. A compromised signing process
can lie about observations. Never label this actual protection.
"""
from __future__ import annotations

import base64
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .owned_https_evidence_gate import evaluate_owner_https_report
from .signed_owned_evidence import (
    COLLECTOR_RE, MAX_ENVELOPE_BYTES, MAX_SEQUENCE, canonical_signed_payload,
)

_RECEIPT_FLAGS = (
    "sourceProvenanceVerified", "sourceSignatureValid",
    "durableReplayVerified", "externalObserverRunning",
    "trustedForExecutiveUse", "hostUpProven", "alertsDispatched",
    "ticketCreationEnabled",
)
_RECEIPT_KEYS = {"mode", "report", *_RECEIPT_FLAGS}
_REPORT_KEYS = {"mode", "cycle", "last_check", "error", "services"}
_SERVICE_KEYS = {"name", "url", "status", "cert_days"}


def sign_review_receipt(
    receipt: Any, *, signer: Ed25519PrivateKey,
    collector_id: str, approved_targets: list[dict],
    previous_cycle: int, now: datetime | None = None,
) -> dict:
    """Sign a minimal advisory only, with explicit caller-owned key/counter.

    The caller is responsible for verified source provenance, protected key
    custody, and a durable monotonic previous_cycle. Never use this function
    with browser/API JSON, unverified files, or externally supplied receipts.
    No key is generated, persisted, exported or loaded here. No automatic
    activation exists; this is an isolated engineering proof only.
    """
    if (not isinstance(receipt, dict) or set(receipt) != _RECEIPT_KEYS
            or receipt.get("mode") != "IN_PROCESS_PROBE_CANDIDATE_ONLY"
            or any(receipt.get(k) is not False for k in _RECEIPT_FLAGS)):
        raise ValueError("UNTRUSTED_OR_INVALID_INPROCESS_RECEIPT")
    if (not isinstance(signer, Ed25519PrivateKey)
            or type(collector_id) is not str
            or not COLLECTOR_RE.fullmatch(collector_id)
            or type(previous_cycle) is not int or previous_cycle < 0):
        raise ValueError("PINNED_SIGNER_AND_DURABLE_CYCLE_REQUIRED")

    report = receipt.get("report")
    if not isinstance(report, dict) or set(report) != _REPORT_KEYS:
        raise ValueError("INVALID_MINIMAL_REPORT")
    sequence = report.get("cycle")
    if (type(sequence) is not int or not 1 <= sequence <= MAX_SEQUENCE
            or sequence <= previous_cycle):
        raise ValueError("REPLAY_OR_RESET_REQUIRES_OPERATOR_REENROLMENT")
    rows = report.get("services")
    if (not isinstance(rows, list) or
            any(not isinstance(row, dict) or set(row) != _SERVICE_KEYS
                for row in rows)):
        raise ValueError("INVALID_SANITIZED_SERVICE_SCOPE")

    # Re-check exact owner allowlist, freshness, valid status, and all targets.
    # This is only an advisory classifier, not independent probe attestation.
    evaluated = evaluate_owner_https_report(report, approved_targets, now=now)
    if evaluated.get("status") != "REPORTED_NOT_AUTHENTICATED":
        raise ValueError("UNVERIFIED_OR_STALE_PROBE_RECEIPT")

    payload = {
        "version": 1, "collectorId": collector_id,
        "sequence": sequence, "snapshot": report,
    }
    canonical = canonical_signed_payload(payload)
    if len(canonical) > MAX_ENVELOPE_BYTES:
        raise ValueError("SIGNED_ENVELOPE_OVERSIZE")
    signature = signer.sign(canonical)
    return payload | {
        "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    }
