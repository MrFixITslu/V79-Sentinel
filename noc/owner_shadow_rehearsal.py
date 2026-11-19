"""Offline dry-run of legacy HTTPS snapshot -> ephemeral Ed25519 -> verifier.

Deliberately not a trusted production signer. The caller supplies a snapshot
from an independently reviewed source; JSON, including 'live', is untrusted.
One short-lived key generated in memory is discarded at process exit.
No network, Docker control, credential file, disk state, mail or customer action.
"""
from __future__ import annotations

from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .legacy_monitor_proof import candidate_envelope
from .signed_owned_evidence import evaluate_signed_owned_evidence

REHEARSAL_COLLECTOR = "v79-local-shadow-rehearsal"


def rehearse_legacy_snapshot(snapshot, approved_targets, *, now=None):
    """Return only machine-safe indicators; never raw input, signed body, or key."""
    instant = datetime.now(timezone.utc) if now is None else now
    key = Ed25519PrivateKey.generate()  # In-memory, intentionally not persistent.
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    # Rehearsal is completely isolated from any previously accepted source.
    # last_seen_sequence=0 is ONLY valid for an ephemeral in-memory demo.
    envelope = candidate_envelope(
        snapshot, approved_targets, collector_id=REHEARSAL_COLLECTOR,
        signer=key, previous_cycle=0, now=instant)
    result = evaluate_signed_owned_evidence(
        envelope, trusted_collector_id=REHEARSAL_COLLECTOR,
        pinned_public_key=public, approved_targets=approved_targets,
        last_seen_sequence=0, now=instant)
    if result["status"] != "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE":
        raise ValueError("Ephemeral rehearsal verification refused")
    if not result["sourceSignatureValid"] or len(result["services"]) != len(approved_targets):
        raise ValueError("Ephemeral rehearsal scope invalid")
    labels = [s["signal"] for s in result["services"]]
    return {
        "mode": "EPHEMERAL_LOCAL_SHADOW_ONLY",
        "result": "SIGNED_PAYLOAD_VERIFIED_IN_MEMORY",
        "scopeCount": len(labels),
        "reportedUpUnverified": labels.count("REPORTED_UP_UNVERIFIED"),
        "reportedDown": labels.count("REPORTED_DOWN"),
        "reportedReview": labels.count("REVIEW_REPORTED"),
        "freshAgeSeconds": result.get("ageSeconds"),
        "trustedSourceIdentity": False,
        "persistentSigner": False,
        "durableReplayStore": False,
        "externalHeartbeat": False,
        "ownerMailDispatched": False,
        "productionChanges": False,
    }
