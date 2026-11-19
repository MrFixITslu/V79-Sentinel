"""Owner-controlled PRIVATE signed-candidate lane, not a live telemetry service.

* No network/Docker access; a caller supplies existing monitor snapshot.
* Signing with an owner-pinned Ed25519 key is NOT evidence that a physical
  sensor performed HTTPS probes. Do not trust user supplied JSON as telemetry.
* This code never creates a key, configures a service, sends alerts, writes
  tickets or prints secrets; only an owner-private SQLite candidate ledger may
  be updated after cryptographic validation.
* Never auto-reset a monitor cycle on restart. Current candidate sequence must
  strictly exceed the durable per-collector checkpoint.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import sqlite3
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .legacy_monitor_proof import candidate_envelope
from .owned_alert_state import _safe_store, ingest_candidate
from .signed_owned_evidence import COLLECTOR_RE


KEY_BASENAME = "signer.ed25519.raw"
MAX_CHECKPOINT = 2**63 - 1


class OwnerSignerRefusal(ValueError):
    """Never include private path, candidate content or crypto bytes in text."""


def _protected_signer(key_dir, *, expected_fingerprint):
    """Load only an explicitly owner-created 0600 Ed25519 raw key under 0700.

    expected_fingerprint is a SHA-256 pin of the **public key** established
    out-of-band by the owner. It must not be derived from untrusted input.
    Component-wise dirfd + O_NOFOLLOW rejects ancestor and final symlinks.
    """
    if (type(expected_fingerprint) is not str or len(expected_fingerprint) != 64 or
            any(x not in "0123456789abcdef" for x in expected_fingerprint) or
            not isinstance(key_dir, (str, Path)) or os.geteuid() == 0):
        raise OwnerSignerRefusal("PROTECTED_USER_PUBLIC_KEY_PIN_REQUIRED")
    directory = Path(key_dir)
    if (not directory.is_absolute() or ".." in directory.parts or
            directory == directory.anchor):
        raise OwnerSignerRefusal("OWNER_PRIVATE_SIGNER_DIRECTORY_REQUIRED")
    dfd = kfd = None
    try:
        # O_NOFOLLOW on the final directory alone is insufficient. A symlink
        # anywhere in an absolute path may replace the signer parent silently.
        # Walk one component at a time from the root using stable dirfds.
        dfd = os.open(directory.anchor, os.O_RDONLY | os.O_DIRECTORY)
        for part in directory.parts[1:]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=dfd,
            )
            os.close(dfd)
            dfd = child
        d = os.fstat(dfd)
        if (not stat.S_ISDIR(d.st_mode) or d.st_uid != os.geteuid()
                or stat.S_IMODE(d.st_mode) != 0o700):
            raise OwnerSignerRefusal("OWNER_PRIVATE_SIGNER_DIRECTORY_REQUIRED")
        kfd = os.open(KEY_BASENAME, os.O_RDONLY | os.O_NOFOLLOW,
                      dir_fd=dfd)
        k = os.fstat(kfd)
        if (not stat.S_ISREG(k.st_mode) or k.st_uid != os.geteuid()
                or stat.S_IMODE(k.st_mode) != 0o600 or k.st_nlink != 1 or k.st_size != 32):
            raise OwnerSignerRefusal("OWNER_PRIVATE_SIGNER_KEY_REQUIRED")
        data = os.read(kfd, 33)
        if len(data) != 32:
            raise OwnerSignerRefusal("OWNER_PRIVATE_SIGNER_KEY_REQUIRED")
        signer = Ed25519PrivateKey.from_private_bytes(data)
        public = signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if not hmac.compare_digest(hashlib.sha256(public).hexdigest(),
                                   expected_fingerprint):
            raise OwnerSignerRefusal("PINNED_SIGNER_IDENTITY_MISMATCH")
        return signer, public
    except OSError:
        raise OwnerSignerRefusal("OWNER_PRIVATE_SIGNER_UNAVAILABLE") from None
    finally:
        if kfd is not None:
            os.close(kfd)
        if dfd is not None:
            os.close(dfd)


def accept_owner_private_candidate(
    snapshot, approved_targets, *, conn, collector_id,
    key_dir, expected_public_fingerprint, now=None
):
    """Validate, sign, then atomically checkpoint a REVIEW-ONLY candidate.

    Do not feed this function manually authored 'live' JSON in production.
    Only a separate, attested real-probe-origin guard may supply source data
    during a future owner-approved pilot; this function DOES NOT provide it.
    """
    blocked = {
        "status": "UNKNOWN", "reason": "PRIVATE_SIGNED_CANDIDATE_NOT_ACCEPTED",
        "replayCommitted": False, "outboxProposals": 0,
        "trustedForExecutiveUse": False,
        "continuousMonitoringVerified": False, "alertsDispatched": False,
        "ticketCreationEnabled": False, "sourceProvenanceVerified": False,
    }
    if (type(collector_id) is not str or not COLLECTOR_RE.fullmatch(collector_id)
            or not _safe_store(conn)):
        return blocked | {"reason": "OWNER_PRIVATE_DURABLE_STORE_REQUIRED"}
    try:
        signer, public = _protected_signer(
            key_dir, expected_fingerprint=expected_public_fingerprint)
        previous = conn.execute(
            "SELECT sequence FROM advisory_cursor WHERE collector = ?",
            (collector_id,)).fetchone()
        last_seq = previous[0] if previous else 0
        if type(last_seq) is not int or not 0 <= last_seq <= MAX_CHECKPOINT:
            raise OwnerSignerRefusal("INVALID_DURABLE_CURSOR")
        envelope = candidate_envelope(
            snapshot, approved_targets, collector_id=collector_id,
            signer=signer, previous_cycle=last_seq, now=now)
        receipt = ingest_candidate(
            conn, envelope, trusted_collector_id=collector_id,
            pinned_public_key=public, approved_targets=approved_targets,
            now=now)
        # Re-affirm that even successful local signed acceptance is NOT
        # verified physical sampling or an authorization to deliver alerts.
        return {
            **blocked,
            "status": receipt["status"],
            "reason": receipt["reason"],
            "replayCommitted": receipt["replayCommitted"],
            "outboxProposals": receipt["outboxProposals"],
            "acceptedSequence": receipt.get("acceptedSequence"),
            "sourceSignatureValid": bool(receipt.get("sourceSignatureValid")),
        }
    except (OwnerSignerRefusal, ValueError, TypeError, sqlite3.Error):
        return blocked
