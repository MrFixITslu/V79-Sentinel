"""Durable local replay checkpoint for signed V79-owned HTTPS advisory reports.

Standalone isolated candidate: no network, no raw telemetry persistence, no
collector setup, no alert or ticket side effect. Does NOT certify live probes.
Caller supplies a protected, fully synchronized file-backed sqlite connection.
"""
from __future__ import annotations

import os
import sqlite3

from .signed_owned_evidence import evaluate_signed_owned_evidence


def prepare_owned_replay_store(conn: sqlite3.Connection) -> None:
    """Explicit, owner-approved scratch DB initialization. No implicit DDL."""
    if not isinstance(conn, sqlite3.Connection) or conn.in_transaction:
        raise ValueError("EXPLICIT_IDLE_SQLITE_CONNECTION_REQUIRED")
    conn.execute("""CREATE TABLE IF NOT EXISTS owned_observation_sequence (
        collector_id TEXT PRIMARY KEY,
        last_sequence INTEGER NOT NULL CHECK(last_sequence >= 1),
        accepted_at_utc TEXT NOT NULL
    )""")
    conn.commit()


def evaluate_and_checkpoint_owned_evidence(
    envelope, *, conn, trusted_collector_id, pinned_public_key,
    approved_targets, now=None
):
    """Validate then atomically commit strictly increasing sequence.

    Returns advisory only. Trust of real measurements, sensor identity custody,
    effective ownership, and delivery remains outside this contract.
    """
    unavailable = {
        "status": "UNKNOWN", "reason": "DURABLE_REPLAY_STORE_UNAVAILABLE",
        "mode": "read-only", "sourceSignatureValid": False,
        "trustedForExecutiveUse": False, "continuousMonitoringVerified": False,
        "customerReady": False, "ticketCreationEnabled": False,
        "alertsDispatched": False, "replayStatePersisted": False,
        "services": [],
    }
    if not isinstance(conn, sqlite3.Connection) or conn.in_transaction:
        return unavailable
    try:
        # Reject in-memory and synchronous=OFF/NORMAL stores. Unverified replay
        # checkpoints must not be described as persistent across restart.
        databases = conn.execute("PRAGMA database_list").fetchall()
        main_file = next((r[2] for r in databases if r[1] == "main"), "")
        synchronous = conn.execute("PRAGMA synchronous").fetchone()
        if (not isinstance(main_file, str) or not os.path.isabs(main_file)
                or not synchronous or synchronous[0] < 2):
            return unavailable
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT last_sequence FROM owned_observation_sequence WHERE collector_id = ?",
            (trusted_collector_id,),
        ).fetchone()
        previous = row[0] if row else 0
        if type(previous) is not int or previous < 0:
            conn.rollback()
            return unavailable

        status = evaluate_signed_owned_evidence(
            envelope,
            trusted_collector_id=trusted_collector_id,
            pinned_public_key=pinned_public_key,
            approved_targets=approved_targets,
            last_seen_sequence=previous,
            now=now,
        )
        if status.get("status") != "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE":
            conn.rollback()
            return status

        seq = status["sequence"]
        if row:
            changed = conn.execute(
                "UPDATE owned_observation_sequence SET last_sequence=?,accepted_at_utc=? "
                "WHERE collector_id=? AND last_sequence < ?",
                (seq, status["observedAt"], trusted_collector_id, seq),
            )
        else:
            changed = conn.execute(
                "INSERT INTO owned_observation_sequence"
                "(collector_id,last_sequence,accepted_at_utc) VALUES(?,?,?)",
                (trusted_collector_id, seq, status["observedAt"]),
            )
        if changed.rowcount != 1:
            conn.rollback()
            return unavailable
        conn.commit()
        return {
            **status,
            "reason": "SIGNED_CANDIDATE_SEQUENCE_COMMITTED_NOT_LIVE_PROBE_PROOF",
            "replayStatePersisted": True,
            "trustedForExecutiveUse": False,
            "continuousMonitoringVerified": False,
            "customerReady": False,
            "alertsDispatched": False,
            "ticketCreationEnabled": False,
        }
    except (sqlite3.Error, ValueError, TypeError, KeyError):
        if conn.in_transaction:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
        return unavailable
