#!/usr/bin/env python3
"""Select an unused loopback host port for Sentinel's isolated internal pilot.

Run this on the TARGET server only. Does not start/stop containers, touch
databases, require root, or change any existing listener.
"""
from __future__ import annotations
import os
from pathlib import Path
import socket
import sys

HERE = Path(__file__).resolve().parent
DEST = HERE / ".env"

def free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False

def main():
    if DEST.exists() or DEST.is_symlink():
        print("STOP: Existing pilot port selection .env found. Do not overwrite it.")
        return 1
    candidates = [13078, *range(13079, 13150)]
    for port in candidates:
        if port == 3000 or not free(port):
            continue
        content = (f"SENTINEL_HOST_PORT={port}\n"
                   f"SENTINEL_BROWSER_ORIGIN=http://127.0.0.1:{port}\n")
        fd = os.open(str(DEST), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
        except Exception:
            DEST.unlink(missing_ok=True)
            raise
        print(f"Selected an available localhost port at preflight: {port}")
        print("No container changed. Port may need rechecking immediately before launch.")
        print(f"Nonsecret Compose configuration: {DEST}")
        return 0
    print("STOP: No free reserved port found; nothing changed.")
    return 1

if __name__ == "__main__":
    sys.exit(main())
