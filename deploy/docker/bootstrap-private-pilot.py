#!/usr/bin/env python3
"""Bootstrap ONE disposable, synthetic NOC operator in a NEW staging volume.

Run from inside the non-root NOC container. Refuses to overwrite any existing
database, secret or operator. Never prints the password.
"""
from __future__ import annotations
import os
from pathlib import Path
import secrets

from noc.server import bootstrap
from noc.store import NocStore

DATA = Path("/app/data")
DATABASE = DATA / "noc-staging.sqlite3"
SECRET = DATA / "synthetic-pilot-operator-password"
USERNAME = "sentinel-pilot-admin"


def main():
    os.umask(0o077)
    if DATABASE.exists() or DATABASE.is_symlink() or SECRET.exists() or SECRET.is_symlink():
        raise SystemExit("STOP: staging database or operator secret already exists; no changes made.")
    if not DATA.is_dir() or DATA.is_symlink():
        raise SystemExit("STOP: expected private staging data volume missing.")
    descriptor = os.open(str(SECRET), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    password = secrets.token_urlsafe(36)
    with os.fdopen(descriptor, "w", encoding="utf8") as handle:
        handle.write(password + "\n")
    try:
        bootstrap(NocStore(DATABASE), USERNAME, password)
    except Exception:
        # Retain the evidence for supervised diagnosis; never silently reset DB.
        raise SystemExit("STOP: synthetic operator bootstrap failed; do not delete or reinitialize data.")
    print("SYNTHETIC_PILOT_BOOTSTRAPPED")
    print("Operator: sentinel-pilot-admin")
    print("Password kept inside owner-restricted staging Docker volume; never printed.")
    print("A new staging database was initialized; no Acer or customer records touched.")


if __name__ == "__main__":
    main()
