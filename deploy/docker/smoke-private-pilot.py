#!/usr/bin/env python3
"""Authenticated synthetic staging smoke; no credentials or cookies printed.

Exec INSIDE the private NOC container after the Nginx sidecar is healthy.
Never creates, edits or deletes customer data or external integrations.
"""
from __future__ import annotations
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen
import json
import os

BASE = "http://127.0.0.1:8080"
ORIGIN = os.environ.get("SENTINEL_NOC_EXTERNAL_ORIGIN", "")
PASSWORD = Path("/app/data/synthetic-pilot-operator-password")


def _read_private_pilot_password(path: Path) -> str:
    """Read one local staging-only secret, without following symlink components.

    Never log or return secret bytes on failure; no network or credential
    creation. The directory components are opened relative to verified dirfds.
    """
    import stat

    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise RuntimeError("STOP: private pilot credential path invalid")
    dfd = keyfd = None
    try:
        dfd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for component in path.parts[1:-1]:
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY
                | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd,
            )
            os.close(dfd)
            dfd = child
        keyfd = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW
            | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dfd,
        )
        s = os.fstat(keyfd)
        if (
            not stat.S_ISREG(s.st_mode)
            or s.st_uid not in (os.geteuid(), 0)
            or s.st_nlink != 1
            or s.st_mode & 0o077
            or not 8 <= s.st_size <= 256
        ):
            raise RuntimeError("STOP: private pilot credential metadata unsafe")
        data = os.read(keyfd, 257)
        if len(data) > 256:
            raise RuntimeError("STOP: private pilot credential too large")
        secret = data.decode("utf-8").strip()
        if not (8 <= len(secret) <= 256 and all(33 <= ord(ch) <= 126 for ch in secret)):
            raise RuntimeError("STOP: private pilot credential invalid")
        return secret
    except (OSError, UnicodeDecodeError):
        raise RuntimeError("STOP: private pilot credential unavailable") from None
    finally:
        if keyfd is not None:
            os.close(keyfd)
        if dfd is not None:
            os.close(dfd)



def request(opener, path, method="GET", payload=None, origin=False):
    headers = {"Content-Type": "application/json"}
    if origin:
        headers["Origin"] = ORIGIN
    data = json.dumps(payload).encode() if payload is not None else None
    req = Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with opener.open(req, timeout=5) as response:
            body = response.read(262145)
            if len(body) > 262144:
                raise RuntimeError("Unbounded NOC response")
            return response.status, body
    except HTTPError as exc:
        return exc.code, exc.read(4096)


def main():
    if not ORIGIN.startswith("http://127.0.0.1:"):
        raise SystemExit("STOP: synthetic local origin not configured")
    password = _read_private_pilot_password(PASSWORD)
    cookie_jar = CookieJar()
    opener = build_opener(HTTPCookieProcessor(cookie_jar))
    code, health = request(opener, "/readyz")
    assert code == 200 and b'"integrations":"disabled"' in health, "NOC is not in safe staging mode"
    code, _ = request(opener, "/api/v1/dashboard")
    assert code == 401, "Anonymous NOC dashboard unexpectedly accessible"
    status = urlopen("http://127.0.0.1:8787/healthz", timeout=5)
    assert status.status == 200, "Legacy monitor unavailable on namespace loopback"
    code, _ = request(opener, "/api/v1/login", "POST", {
        "username": "sentinel-pilot-admin", "password": password
    }, origin=True)
    assert code == 200, "Synthetic operator login failed"
    code, body = request(opener, "/api/v1/session")
    session = json.loads(body)
    assert code == 200 and session.get("role") == "admin", "Session/role validation failed"
    code, _ = request(opener, "/api/v1/dashboard")
    assert code == 200, "Authenticated dashboard unavailable"
    code, root = request(opener, "/")
    assert code == 200 and b"enterprise" in root.lower(), "NOC native Command Center missing"
    code, _ = request(opener, "/mission-native.js")
    assert code == 200, "Native Command Center JS missing"
    code, _ = request(opener, "/api/v1/netpulse/interfaces")
    assert code == 200, "Authenticated container counters route unavailable"
    req = Request(BASE + "/api/v1/logout", data=b"{}", headers={
        "Content-Type": "application/json", "Origin": ORIGIN,
        "X-Sentinel-CSRF": str(session["csrf"]),
    }, method="POST")
    with opener.open(req, timeout=5) as response:
        assert response.status == 200, "Logout failed"
    code, _ = request(opener, "/api/v1/dashboard")
    assert code == 401, "Session retained access after logout"
    print("SENTINEL_SYNTHETIC_DOCKER_AUTH_SMOKE_PASS")
    print("Anonymous denied; operator session/login/logout PASS; legacy monitor PASS;")
    print("native frontend PASS; NetPulse labeled namespace view; integrations disabled.")
    print("No passwords or session tokens shown; no customer data touched.")


if __name__ == "__main__":
    main()
