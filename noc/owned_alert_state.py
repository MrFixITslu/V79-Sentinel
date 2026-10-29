"""Atomic *advisory-only* state machine for signed candidate HTTPS readings.

SOURCE ONLY. No socket, credentials, sender, timer, customer incidents, Tiquet
writes or privileged operations. Signatures attest a PINNED REPORTER KEY, not
the actual physical probe or complete host availability. Owner must independently
attest the source before permitting any alert delivery.

All replay cursors, consecutive transitions and REVIEW-ONLY outbox entries are
committed in ONE SQLite transaction, preventing a crash after checkpoint from
silently losing a proposed alert. No retry of external messages occurs here.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import stat

from .signed_owned_evidence import evaluate_signed_owned_evidence
from .isolated_sqlite_durability import is_durable_isolated_sqlite

DOWN = "REPORTED_DOWN"
UP = "REPORTED_UP_UNVERIFIED"
REVIEW = "REVIEW_REPORTED"
MIN_SPACING = 240
MAX_AGE = 600
MAX_REVIEW_EVENTS = 5000  # Bounded; full queue fails closed for owner review.
STATES = frozenset((DOWN, UP, REVIEW))


def _safe_store(conn):
    """Reject in-memory, weakened, world-accessible or symlinked SQLite stores."""
    if not is_durable_isolated_sqlite(conn):
        return False
    try:
        found = conn.execute("PRAGMA database_list").fetchall()
        path = next((row[2] for row in found if row[1] == "main"), "")
        sync = conn.execute("PRAGMA synchronous").fetchone()
        if not path or not os.path.isabs(path) or not sync or sync[0] < 2:
            return False
        file = Path(path)
        if file.is_symlink() or file.parent.is_symlink():
            return False
        f = file.stat()
        p = file.parent.stat()
        return (
            stat.S_ISREG(f.st_mode) and f.st_uid == os.getuid()
            and not (f.st_mode & 0o077) and
            stat.S_ISDIR(p.st_mode) and p.st_uid == os.getuid()
            and not (p.st_mode & 0o077)
        )
    except (OSError, sqlite3.Error):
        return False


def prepare_advisory_store(conn):
    """Explicit provision on an owner-private file. Never implicitly migrate."""
    if not _safe_store(conn):
        raise PermissionError("OWNER_PRIVATE_DURABLE_STORE_REQUIRED")
    conn.executescript("""
      CREATE TABLE IF NOT EXISTS advisory_cursor(
        collector TEXT PRIMARY KEY,
        sequence INTEGER NOT NULL CHECK(sequence>=1),
        observed_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS advisory_checks(
        collector TEXT NOT NULL, service TEXT NOT NULL,
        phase TEXT NOT NULL CHECK(phase IN ('normal','open')),
        prior_signal TEXT NOT NULL, prior_sequence INTEGER NOT NULL,
        bad_count INTEGER NOT NULL, good_count INTEGER NOT NULL,
        first_bad TEXT, first_good TEXT,
        PRIMARY KEY(collector,service)
      );
      CREATE TABLE IF NOT EXISTS advisory_outbox(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        collector TEXT NOT NULL, service TEXT NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('down','recovered')),
        sequence INTEGER NOT NULL, observed_at TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'review_required'
             CHECK(state='review_required'),
        UNIQUE(collector,service,kind,sequence)
      );
    """)
    conn.commit()


def _epoch(value):
    if not isinstance(value, str):
        raise ValueError("Invalid observation timestamp")
    t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if t.tzinfo is None or t.utcoffset().total_seconds() != 0:
        raise ValueError("Expected UTC observation")
    return t.timestamp()


def _transition(old, signal, *, current_seq, time_text, elapsed, consecutive):
    """Return immutable transition proposal, never send any message."""
    if old is None:
        phase, bad, good, first_bad, first_good = "normal", 0, 0, None, None
    else:
        phase, _, _, bad, good, first_bad, first_good = old
    event = None
    prior_signal = signal
    if signal == DOWN:
        if consecutive and old is not None and old[1] == DOWN:
            bad += 1
        else:
            bad = 1
            first_bad = time_text
        good = 0
        first_good = None
        if phase == "normal" and bad >= 2 and elapsed(first_bad) >= MIN_SPACING:
            phase = "open"
            event = "down"
    elif signal == UP:
        if consecutive and old is not None and old[1] == UP:
            good += 1
        else:
            good = 1
            first_good = time_text
        bad = 0
        first_bad = None
        if phase == "open" and good >= 2 and elapsed(first_good) >= MIN_SPACING:
            phase = "normal"
            event = "recovered"
    else:
        # An ambiguous warning never qualifies as UP nor as DOWN.
        bad = good = 0
        first_bad = first_good = None
    return (phase, prior_signal, current_seq, bad, good, first_bad, first_good), event


def ingest_candidate(conn, envelope, *, trusted_collector_id,
                     pinned_public_key, approved_targets, now=None):
    """Verify signed source + atomically checkpoint sequence and review events.

    Commit a prospective REVIEW-ONLY event after two *consecutive* reports
    separated by at least four minutes. No model self-approval and no mail.
    """
    denied = {
        "status": "UNKNOWN", "reason": "PRIVATE_SIGNED_LEDGER_UNAVAILABLE",
        "replayCommitted": False, "outboxProposals": 0,
        "trustedForExecutiveUse": False, "continuousMonitoringVerified": False,
        "alertsDispatched": False, "ticketCreationEnabled": False,
    }
    if not _safe_store(conn):
        return denied
    try:
        conn.execute("BEGIN IMMEDIATE")
        prior = conn.execute(
            "SELECT sequence,observed_at FROM advisory_cursor WHERE collector=?",
            (trusted_collector_id,)).fetchone()
        prev_seq = prior[0] if prior else 0
        if type(prev_seq) is not int or prev_seq < 0:
            raise ValueError("Bad durable sequence")
        result = evaluate_signed_owned_evidence(
            envelope, trusted_collector_id=trusted_collector_id,
            pinned_public_key=pinned_public_key, approved_targets=approved_targets,
            last_seen_sequence=prev_seq, now=now)
        if result["status"] != "SIGNED_REPORT_PENDING_OPERATOR_ACCEPTANCE":
            conn.rollback()
            return denied | {"reason": result.get("reason", "SIGNATURE_OR_SCOPE_UNVERIFIED")}
        seq = result["sequence"]
        timestamp = result["observedAt"]
        claim = envelope["snapshot"]
        # Never trust a purported sequence unrelated to the monitor cycle.
        if claim.get("cycle") != seq or type(claim.get("cycle")) is not int:
            raise ValueError("Signed cycle/sequence mismatch")
        if prior and _epoch(timestamp) <= _epoch(prior[1]):
            raise ValueError("Nonmonotonic signed observation time")
        records = result["services"]
        if not records or any(r.get("signal") not in STATES for r in records):
            raise ValueError("Incomplete signed projection")
        consecutive = bool(prior and seq == prev_seq + 1)
        created = 0
        for record in records:
            name, signal = record["name"], record["signal"]
            row = conn.execute(
                "SELECT phase,prior_signal,prior_sequence,bad_count,good_count,"
                "first_bad,first_good FROM advisory_checks WHERE collector=? AND service=?",
                (trusted_collector_id, name)).fetchone()
            def elapsed(start):
                return _epoch(timestamp) - _epoch(start)
            nxt, event = _transition(
                row, signal, current_seq=seq,
                time_text=timestamp, elapsed=elapsed,
                consecutive=bool(consecutive and row and row[2] == prev_seq))
            conn.execute("""
              INSERT INTO advisory_checks
                (collector,service,phase,prior_signal,prior_sequence,bad_count,
                 good_count,first_bad,first_good)
              VALUES(?,?,?,?,?,?,?,?,?)
              ON CONFLICT(collector,service) DO UPDATE SET
                phase=excluded.phase,prior_signal=excluded.prior_signal,
                prior_sequence=excluded.prior_sequence,
                bad_count=excluded.bad_count,good_count=excluded.good_count,
                first_bad=excluded.first_bad,first_good=excluded.first_good
            """, (trusted_collector_id, name, *nxt))
            if event:
                backlog = conn.execute("SELECT COUNT(*) FROM advisory_outbox").fetchone()[0]
                if backlog >= MAX_REVIEW_EVENTS:
                    raise ValueError("Owner review outbox capacity reached")
                conn.execute(
                    "INSERT INTO advisory_outbox"
                    "(collector,service,kind,sequence,observed_at) VALUES(?,?,?,?,?)",
                    (trusted_collector_id, name, event, seq, timestamp))
                created += 1
        conn.execute("""
          INSERT INTO advisory_cursor(collector,sequence,observed_at)
          VALUES(?,?,?)
          ON CONFLICT(collector) DO UPDATE SET
            sequence=excluded.sequence, observed_at=excluded.observed_at
        """, (trusted_collector_id, seq, timestamp))
        conn.commit()
        return {
            **denied, "status": "SIGNED_CANDIDATE_REVIEW_ONLY",
            "reason": "SOURCE_KEY_CHECKED_PHYSICAL_PROBE_NOT_ATTESTED",
            "replayCommitted": True, "outboxProposals": created,
            "acceptedSequence": seq, "sourceSignatureValid": True,
        }
    except (sqlite3.Error, ValueError, TypeError, KeyError, OverflowError, AttributeError):
        if conn.in_transaction:
            conn.rollback()
        return denied | {"reason": "SIGNED_CANDIDATE_TRANSACTION_ABORTED"}


def passive_heartbeat(last_observed, *, now=None, max_age=MAX_AGE):
    """Only meaningful when called independently OFF the monitored Dell."""
    try:
        time = datetime.now(timezone.utc) if now is None else now
        if not isinstance(time, datetime) or time.tzinfo is None or not isinstance(last_observed, str):
            raise ValueError()
        delta = (time.astimezone(timezone.utc).timestamp() - _epoch(last_observed))
        if type(max_age) is not int or not 60 <= max_age <= 3600 or not 0 <= delta <= max_age:
            return {"status": "UNKNOWN", "reason": "MISSING_OR_STALE_HEARTBEAT"}
        return {"status": "RECENT_SIGNED_REPORT_ONLY",
                "reason": "HOST_ALIVE_NOT_INDEPENDENTLY_PROVEN"}
    except (TypeError, ValueError, OverflowError):
        return {"status": "UNKNOWN", "reason": "MISSING_OR_STALE_HEARTBEAT"}
