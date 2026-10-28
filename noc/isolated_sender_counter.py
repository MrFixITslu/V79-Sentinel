"""OFF-BY-DEFAULT atomic sender ledger for isolated Sentinel signed advisories.

No service registration, private-key loading, network access, or production DB.
The trusted in-process caller supplies a private Ed25519 key and an already
sanitized probe receipt. Sequence equals actual monitor cycle; a monitor reset
is a HOLD requiring operator-supervised reenrolment, never an automatic reset.
This ledger cannot independently prove source authenticity or prevent offline
rollback of BOTH signer and receiver disks. Do not share monitor /app/data.
"""
from __future__ import annotations

import os
import sqlite3

from .isolated_signed_probe_pilot import sign_review_receipt
from .signed_owned_evidence import COLLECTOR_RE, MAX_SEQUENCE


def prepare_isolated_sender_store(conn: sqlite3.Connection) -> None:
    """Explicit schema init in a disposable/operator-approved NEW database."""
    if not isinstance(conn, sqlite3.Connection) or conn.in_transaction:
        raise ValueError("IDLE_SQLITE_CONNECTION_REQUIRED")
    conn.execute("""CREATE TABLE IF NOT EXISTS sourcebound_sender_sequence (
        collector_id TEXT PRIMARY KEY,
        last_cycle INTEGER NOT NULL CHECK(last_cycle BETWEEN 1 AND 9223372036854775807)
    )""")
    conn.commit()


def _durable(conn):
    if not isinstance(conn, sqlite3.Connection) or conn.in_transaction:
        return False
    locations = conn.execute("PRAGMA database_list").fetchall()
    main = next((entry[2] for entry in locations if entry[1] == "main"), "")
    sync = conn.execute("PRAGMA synchronous").fetchone()
    return (isinstance(main, str) and os.path.isabs(main)
            and bool(sync) and sync[0] >= 2)


def sign_with_atomic_sender_counter(
    receipt, *, conn, signer, collector_id, approved_targets, now=None
):
    """Commit a signed cycle before returning its envelope.

    Concurrent callers are serialized by BEGIN IMMEDIATE. Validation and
    signing occur inside the transaction; a failed validation rolls back.
    If the commit fails or the process crashes before commit, no envelope is
    returned; if it crashes after commit but before delivery, the gap is safe.
    No secrets, signatures or observations are stored in the sender ledger.
    """
    if (type(collector_id) is not str
            or not COLLECTOR_RE.fullmatch(collector_id)):
        raise ValueError("UNAPPROVED_COLLECTOR_ID")
    if not _durable(conn):
        raise ValueError("DURABLE_SENDER_STORE_UNAVAILABLE")
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT last_cycle FROM sourcebound_sender_sequence WHERE collector_id=?",
            (collector_id,),
        ).fetchone()
        previous = row[0] if row else 0
        if type(previous) is not int or not 0 <= previous <= MAX_SEQUENCE:
            raise ValueError("INVALID_SENDER_SEQUENCE")
        # The existing strict adapter validates exact receipt shape, freshness,
        # all targets and signature inputs; no external JSON is accepted as
        # evidence merely by calling this function.
        envelope = sign_review_receipt(
            receipt, signer=signer, collector_id=collector_id,
            approved_targets=approved_targets, previous_cycle=previous, now=now,
        )
        seq = envelope["sequence"]
        if row:
            cursor = conn.execute(
                "UPDATE sourcebound_sender_sequence SET last_cycle=? "
                "WHERE collector_id=? AND last_cycle<?",
                (seq, collector_id, seq),
            )
        else:
            cursor = conn.execute(
                "INSERT INTO sourcebound_sender_sequence (collector_id,last_cycle) "
                "VALUES (?,?)", (collector_id, seq),
            )
        if cursor.rowcount != 1:
            raise ValueError("SENDER_SEQUENCE_CONFLICT")
        conn.commit()
        return envelope
    except (sqlite3.Error, ValueError, TypeError, KeyError):
        if conn.in_transaction:
            conn.rollback()
        raise ValueError("SENDER_SIGN_OR_CHECKPOINT_REJECTED") from None
