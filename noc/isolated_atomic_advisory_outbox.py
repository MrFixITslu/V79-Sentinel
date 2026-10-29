"""Isolated atomic receiver replay + PENDING advisory outbox, no dispatch.

No HTTP listener, Hub integration, ticket creation, email, or secret loading.
This verifier never labels a signed source as a measured or trusted probe.
The pinned public key, collector identity, owner allowlist and protected SQLite
connection must be independently provisioned by a future reviewed caller.
"""
from __future__ import annotations

import json
import sqlite3

from .isolated_sqlite_durability import is_durable_isolated_sqlite

from .signed_owned_evidence import evaluate_signed_owned_evidence
from .owned_replay_checkpoint import prepare_owned_replay_store

MAX_PENDING_BYTES = 8192


def prepare_isolated_advisory_outbox(conn: sqlite3.Connection) -> None:
    """Explicit test/owner-approved new database schema; never in Hub/NOC DB."""
    if not isinstance(conn, sqlite3.Connection) or conn.in_transaction:
        raise ValueError("IDLE_ISOLATED_RECEIVER_CONNECTION_REQUIRED")
    prepare_owned_replay_store(conn)
    conn.execute("""CREATE TABLE IF NOT EXISTS signed_advisory_outbox (
        event_id TEXT PRIMARY KEY,
        collector_id TEXT NOT NULL,
        sequence INTEGER NOT NULL CHECK(sequence >= 1),
        observed_at_utc TEXT NOT NULL,
        advisory_json TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'PENDING' CHECK(state = 'PENDING'),
        UNIQUE(collector_id, sequence)
    )""")
    conn.commit()


def _durable(conn):
    return is_durable_isolated_sqlite(conn)

def evaluate_and_enqueue_isolated_advisory(
    envelope, *, conn, trusted_collector_id, pinned_public_key,
    approved_targets, now=None,
):
    """Accept a signed advisory once, checkpoint replay and queue atomically.

    The one transaction contains BOTH per-collector replay counter and a
    minimal pending advisory. A missing/failing outbox rolls back replay state.
    No event is sent or treated as verified protection by this function.
    No raw signature, private key, URL, account, IP or untrusted message stored.
    """
    unavailable = {
        "status": "UNKNOWN", "reason": "ATOMIC_ADVISORY_STORE_UNAVAILABLE",
        "sourceSignatureValid": False, "replayStatePersisted": False,
        "advisoryOutboxPersisted": False,
        "trustedForExecutiveUse": False,
        "continuousMonitoringVerified": False,
        "customerReady": False, "ticketCreationEnabled": False,
        "alertsDispatched": False, "services": [],
    }
    if not _durable(conn):
        return unavailable
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT last_sequence FROM owned_observation_sequence WHERE collector_id=?",
            (trusted_collector_id,),
        ).fetchone()
        previous = row[0] if row else 0
        if type(previous) is not int or previous < 0:
            raise ValueError("INVALID_RECEIVER_SEQUENCE")

        status = evaluate_signed_owned_evidence(
            envelope, trusted_collector_id=trusted_collector_id,
            pinned_public_key=pinned_public_key,
            approved_targets=approved_targets,
            last_seen_sequence=previous, now=now,
        )
        if status.get("status") != "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE":
            conn.rollback()
            return status | {"advisoryOutboxPersisted": False}

        seq = status["sequence"]
        event_id = f"{trusted_collector_id}:{seq}"
        # NEVER persist raw source messages, envelope or signed snapshot.
        sanitized = {
            "status": "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE",
            "trustedForExecutiveUse": False,
            "alertsDispatched": False,
            "services": [
                {"name": s["name"], "signal": s["signal"]}
                for s in status["services"]
            ],
        }
        encoded = json.dumps(sanitized, separators=(",", ":"), sort_keys=True)
        if len(encoded.encode("utf-8")) > MAX_PENDING_BYTES:
            raise ValueError("ADVISORY_EVENT_TOO_LARGE")

        if row:
            changed = conn.execute(
                "UPDATE owned_observation_sequence SET last_sequence=?,accepted_at_utc=? "
                "WHERE collector_id=? AND last_sequence<?",
                (seq, status["observedAt"], trusted_collector_id, seq),
            )
        else:
            changed = conn.execute(
                "INSERT INTO owned_observation_sequence "
                "(collector_id,last_sequence,accepted_at_utc) VALUES (?,?,?)",
                (trusted_collector_id, seq, status["observedAt"]),
            )
        if changed.rowcount != 1:
            raise ValueError("REPLAY_SEQUENCE_CHANGED")
        conn.execute(
            "INSERT INTO signed_advisory_outbox "
            "(event_id,collector_id,sequence,observed_at_utc,advisory_json) "
            "VALUES (?,?,?,?,?)",
            (event_id, trusted_collector_id, seq, status["observedAt"], encoded),
        )
        conn.commit()
        return status | {
            "reason": "SIGNED_ADVISORY_PENDING_OUTBOX_NOT_DISPATCHED",
            "replayStatePersisted": True,
            "advisoryOutboxPersisted": True,
            "trustedForExecutiveUse": False,
            "continuousMonitoringVerified": False,
            "alertsDispatched": False, "ticketCreationEnabled": False,
            "customerReady": False,
        }
    except (sqlite3.Error, ValueError, TypeError, KeyError):
        if conn.in_transaction:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
        return unavailable
