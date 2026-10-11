"""Minimal private Tailscale Serve gateway for NOC approver verification.

This is a one-purpose transport adapter, NOT an administrator NOC proxy.
Acer: 127.0.0.1:8794 -> 127.0.0.1:8788, exact signed POST only.
Tailscale Serve must separately provide identity-restricted HTTPS on :443.
No Sentinel Hub/Tiquet ticket event is emitted by this process.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import re
from urllib.parse import urlsplit

PATH = "/api/v1/sentinel/service/approver/check"
SAFE_HEADER = re.compile(r"^[a-f0-9]{64}$")
MAX_BODY = 4096


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        # Never log machine HMACs, approval identities or private headers.
        pass

    def respond(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode("utf8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(body)

    def do_GET(self):
        self.respond(404, {"error": "Not found"})

    def do_HEAD(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_OPTIONS(self):
        self.respond(404, {"error": "Not found"})

    def do_POST(self):
        if urlsplit(self.path).path != PATH or self.path != PATH:
            return self.respond(404, {"error": "Not found"})
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            return self.respond(403, {"error": "Forbidden"})
        # No cookies or browser authentication; only HMAC service calls.
        if (self.headers.get("Cookie") or self.headers.get("Authorization")
                or self.headers.get("Origin") or self.headers.get("Transfer-Encoding")):
            return self.respond(403, {"error": "Machine caller required"})
        length = self.headers.get("Content-Length", "")
        content_type = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        identity = self.headers.get("X-V79-Service-Id", "")
        timestamp = self.headers.get("X-V79-Timestamp", "")
        sig = self.headers.get("X-V79-Signature", "")
        if (any(len(self.headers.get_all(name, [])) != 1 for name in (
                    "Content-Length", "Content-Type", "X-V79-Service-Id",
                    "X-V79-Timestamp", "X-V79-Signature"))
                or not length.isdecimal() or not 1 <= int(length) <= MAX_BODY
                or content_type != "application/json"
                or identity != "v79-tiquet"
                or not timestamp.isdecimal() or not 10 <= len(timestamp) <= 11
                or not SAFE_HEADER.fullmatch(sig)):
            return self.respond(400, {"error": "Invalid service request"})
        raw = self.rfile.read(int(length))
        if len(raw) != int(length):
            return self.respond(400, {"error": "Incomplete service request"})
        try:
            backend = http.client.HTTPConnection("127.0.0.1", 8788, timeout=3)
            try:
                backend.request("POST", PATH, body=raw, headers={
                    "Content-Type": "application/json",
                    "X-V79-Service-Id": identity,
                    "X-V79-Timestamp": timestamp,
                    "X-V79-Signature": sig,
                })
                response = backend.getresponse()
                content = response.read(1025)
                if response.status not in (200, 400, 401, 403, 404, 503):
                    raise ValueError("Unexpected backend status")
                if len(content) > 1024:
                    raise ValueError("Oversized backend")
                if response.status != 200:
                    return self.respond(response.status, {"allowed": False})
                parsed = json.loads(content)
                if (not isinstance(parsed, dict)
                        or type(parsed.get("allowed")) is not bool
                        or type(parsed.get("validForSeconds")) is not int
                        or parsed["validForSeconds"] not in (0, 5)
                        or (parsed["validForSeconds"] == 5) != parsed["allowed"]):
                    raise ValueError("Unexpected verifier result")
                return self.respond(200, {
                    "allowed": parsed["allowed"],
                    "validForSeconds": parsed["validForSeconds"],
                })
            finally:
                backend.close()
        except (OSError, ValueError, TimeoutError, json.JSONDecodeError):
            return self.respond(503, {"allowed": False})


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 8794), Handler)
    server.daemon_threads = True
    print("Sentinel private approver-only gateway bound to 127.0.0.1:8794", flush=True)
    server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
