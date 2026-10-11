"""Authenticated, read-only full Mission Control viewer for V79 Sentinel NOC.

Never forwards NOC cookies, privileged HTTP methods, arbitrary hostnames,
or arbitrary filesystem paths. 8787 remains the independent live collector.
"""
from __future__ import annotations
from pathlib import Path
from urllib.request import urlopen
import re

SOURCE = Path("/home/firelion/V79-Sentinel/sentinel/web")
UPSTREAM = "http://127.0.0.1:8787"
PREFIX = "/mission-control"
ASSETS = {
    PREFIX + "/": ("index.html", "text/html; charset=utf-8"),
    PREFIX + "/index.html": ("index.html", "text/html; charset=utf-8"),
    PREFIX + "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    PREFIX + "/style.css": ("style.css", "text/css; charset=utf-8"),
}
API = {
    PREFIX + "/api/status": ("/api/status", "application/json; charset=utf-8", 550_000),
    PREFIX + "/api/qa/latest": ("/api/qa/latest", "application/json; charset=utf-8", 550_000),
    PREFIX + "/api/qa/auth-readiness": ("/api/qa/auth-readiness", "application/json; charset=utf-8", 100_000),
    PREFIX + "/api/report.csv": ("/api/report.csv", "text/csv; charset=utf-8", 550_000),
}
SCREENSHOT = re.compile(
    r"^/mission-control/api/qa/screenshot/([A-Za-z0-9_-]{6,80})/([a-zA-Z0-9_-]{1,80}-(?:desktop|mobile)\.png)$"
)


def read_only_resource(path: str) -> tuple[bytes, str, bool]:
    """Returns body, MIME, html_embeddable. Fixed-origin, path-allowlisted GET only."""
    if path in ASSETS:
        file, mime = ASSETS[path]
        data = (SOURCE / file).read_bytes()
        if len(data) > 320_000:
            raise ValueError("Oversized Mission Control static asset")
        if file == "index.html":
            data = (data.decode("utf-8")
                .replace('href="/style.css"', 'href="/mission-control/style.css"')
                .replace('src="/app.js"', 'src="/mission-control/app.js"')
                .replace('href="/api/report.csv"', 'href="/mission-control/api/report.csv"')
                .encode("utf-8"))
        elif file == "app.js":
            data = data.decode("utf-8").replace("'/api/", "'/mission-control/api/").encode("utf-8")
        return data, mime, file == "index.html"

    if path in API:
        remote, mime, limit = API[path]
    else:
        match = SCREENSHOT.fullmatch(path)
        if not match:
            raise ValueError("Unapproved Mission Control resource")
        remote = "/api/qa/screenshot/" + match.group(1) + "/" + match.group(2)
        mime, limit = "image/png", 5_000_000

    with urlopen(UPSTREAM + remote, timeout=2.5) as response:
        if response.status != 200:
            raise OSError("Read-only monitoring resource unavailable")
        # Never pass upstream headers/cookies/CSP to the authenticated NOC.
        content = response.read(limit + 1)
    if len(content) > limit:
        raise ValueError("Mission Control response exceeds permitted limit")
    return content, mime, False
