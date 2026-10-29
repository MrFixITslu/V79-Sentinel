"""Shared fail-closed durability gate for isolated Sentinel advisory SQLite stores.

A filename and synchronous=FULL are not enough: journal_mode=OFF or MEMORY
can lose atomic replay/outbox state after an interruption. This function
checks local configuration only; it does not attest storage hardware, mount
ownership, backup/restore, fsync guarantees, or genuine probe provenance.
"""
from __future__ import annotations

import os
import sqlite3

_ALLOWED_DURABLE_JOURNALS = frozenset(("delete", "truncate", "persist", "wal"))


def is_durable_isolated_sqlite(conn) -> bool:
    if not isinstance(conn, sqlite3.Connection) or conn.in_transaction:
        return False
    try:
        rows = conn.execute("PRAGMA database_list").fetchall()
        main = next((row[2] for row in rows if row[1] == "main"), "")
        synchronous = conn.execute("PRAGMA synchronous").fetchone()
        journal = conn.execute("PRAGMA journal_mode").fetchone()
        return (
            isinstance(main, str) and os.path.isabs(main)
            and bool(synchronous) and type(synchronous[0]) is int
            and synchronous[0] >= 2
            and bool(journal) and isinstance(journal[0], str)
            and journal[0].lower() in _ALLOWED_DURABLE_JOURNALS
        )
    except sqlite3.Error:
        return False
