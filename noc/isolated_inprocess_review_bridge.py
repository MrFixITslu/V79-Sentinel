"""OFFLINE, review-only integration of one in-process probe receipt to SQLite.

This is a rehearsal adapter, NOT a runtime service. Nothing registers it in
sentinel.main(). It has no keys loader, network/file sender or alert transport.
Use only with a separately reviewed true in-process sampler callback; this
class cannot authenticate the producer's process or the physical HTTPS probe.

Never share these isolated sender/receiver SQLite handles with the actual
Sentinel /app/data, NOC, Hub or Tiquet databases. Key custody, separate
receiver process, off-host attestation and release approval remain NO-GO.
"""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .isolated_sqlite_durability import is_durable_isolated_sqlite
from .isolated_sender_counter import sign_with_atomic_sender_counter
from .isolated_atomic_advisory_outbox import evaluate_and_enqueue_isolated_advisory
from .signed_owned_evidence import COLLECTOR_RE


def _separate_protected_stores(sender, receiver) -> bool:
    if (not isinstance(sender, sqlite3.Connection)
            or not isinstance(receiver, sqlite3.Connection)
            or sender is receiver
            or not is_durable_isolated_sqlite(sender)
            or not is_durable_isolated_sqlite(receiver)):
        return False
    try:
        a = sender.execute("PRAGMA database_list").fetchall()
        b = receiver.execute("PRAGMA database_list").fetchall()
        if len(a) != 1 or len(b) != 1:
            return False
        left, right = a[0][2], b[0][2]
        def protected(path):
            if (not path or not os.path.isabs(path)
                    or os.path.normpath(path) != path
                    # All path components must already be real directories.
                    # SQLite itself still opens the file: this metadata
                    # preflight is NOT a process or inode attestation.
                    or os.path.realpath(path) != path):
                return False
            file = Path(path)
            parent = file.parent
            info = file.stat()
            directory = parent.stat()
            return (
                stat.S_ISREG(info.st_mode)
                and info.st_uid == os.geteuid()
                and info.st_nlink == 1
                and not (info.st_mode & 0o077)
                and stat.S_ISDIR(directory.st_mode)
                and directory.st_uid == os.geteuid()
                and not (directory.st_mode & 0o077)
            )
        return bool(
            protected(left) and protected(right)
            and not os.path.samefile(left, right)
        )
    except (OSError, sqlite3.Error):
        return False


class IsolatedInProcessReviewBridge:
    """Optional isolated callback for sentinel.monitor_forever(evidence_sink=...).

    This emits ONLY a local signed review proposal. The receiver is deliberately
    in the same test process, so this is NOT a production trust boundary.
    """

    def __init__(self, *, sender_store, receiver_store, signer,
                 pinned_receiver_public_key, collector_id, approved_targets):
        if (not _separate_protected_stores(sender_store, receiver_store)
                or not isinstance(signer, Ed25519PrivateKey)
                or type(pinned_receiver_public_key) is not bytes
                or len(pinned_receiver_public_key) != 32
                or type(collector_id) is not str
                or not COLLECTOR_RE.fullmatch(collector_id)
                or not isinstance(approved_targets, list)
                or not approved_targets):
            raise ValueError("ISOLATED_SOURCE_REVIEW_BRIDGE_NOT_PROVISIONED")
        # Require a fixed snapshot of owner allowlist instead of caller
        # mutation changing scope between signing and receiver verification.
        if any(not isinstance(x, dict) or set(x) != {"name", "url"}
               or type(x["name"]) is not str or type(x["url"]) is not str
               for x in approved_targets):
            raise ValueError("ISOLATED_SOURCE_REVIEW_ALLOWLIST_REQUIRED")
        copied = [{"name": x["name"], "url": x["url"]} for x in approved_targets]
        if len({x["name"] for x in copied}) != len(copied):
            raise ValueError("DUPLICATE_REVIEW_TARGET")
        self._sender = sender_store
        self._receiver = receiver_store
        self._signer = signer
        self._receiver_pin = pinned_receiver_public_key
        self._collector = collector_id
        self._targets = copied

    def __call__(self, receipt):
        """Sign the sanitized in-process receipt; never send or claim trust.

        Any receiver failure intentionally leaves a consumed sender sequence
        after the sender commit. Never reset the sender counter to fill a gap.
        The calling monitor catches this exception and continues probing.
        """
        if not _separate_protected_stores(self._sender, self._receiver):
            raise ValueError("ISOLATED_SOURCE_REVIEW_STORE_UNAVAILABLE")
        envelope = sign_with_atomic_sender_counter(
            receipt, conn=self._sender, signer=self._signer,
            collector_id=self._collector, approved_targets=self._targets,
        )
        outcome = evaluate_and_enqueue_isolated_advisory(
            envelope, conn=self._receiver,
            trusted_collector_id=self._collector,
            pinned_public_key=self._receiver_pin,
            approved_targets=self._targets,
        )
        if (outcome.get("status") != "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE"
                or outcome.get("replayStatePersisted") is not True
                or outcome.get("advisoryOutboxPersisted") is not True):
            raise ValueError("SIGNED_REVIEW_RECEIVER_REJECTED")
        return {
            "status": "LOCAL_SIGNED_REVIEW_PROPOSAL_ONLY",
            "sequence": envelope["sequence"],
            "reviewOutboxPersisted": True,
            "sourceProvenanceVerified": False,
            "physicalProbeAttested": False,
            "trustedForExecutiveUse": False,
            "alertsDispatched": False,
            "ticketCreationEnabled": False,
            "productionApproved": False,
        }
