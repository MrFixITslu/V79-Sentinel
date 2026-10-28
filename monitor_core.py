"""Read-only, explicitly allowlisted V79 HTTPS health checks and telemetry storage."""
from __future__ import annotations

import http.client
import ipaddress
import json
import pathlib
import socket
import sqlite3
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlsplit

MAX_SERVICES = 20
TIMEOUT_SECONDS = 8
CHECK_WORKERS = 4
STORE_DAYS = 30


def validate_services(items):
    if not isinstance(items, list) or not items or len(items) > MAX_SERVICES:
        raise ValueError("Provide 1-20 explicitly configured services")
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Service must be an object")
        name = item.get("name")
        address = item.get("url")
        if not isinstance(name, str) or not (1 <= len(name.strip()) <= 80):
            raise ValueError("Each service needs a 1-80 character name")
        if not isinstance(address, str):
            raise ValueError("Each service requires an HTTPS URL")
        parsed = urlsplit(address)
        hostname = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("HTTPS URL without embedded credentials or fragments required")
        if parsed.port not in (None, 443):
            raise ValueError("Only standard HTTPS port 443 is allowed")
        if hostname != "v79sl.com" and not hostname.endswith(".v79sl.com"):
            raise ValueError("Only authorized v79sl.com domains can be monitored")
        if address in seen:
            raise ValueError("Duplicate monitoring URL")
        seen.add(address)
    return items


def _safe_addresses(hostname):
    records = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    addresses = sorted({rec[4][0] for rec in records})
    if not addresses or not all(ipaddress.ip_address(x).is_global for x in addresses):
        raise ValueError("Target DNS did not resolve exclusively to public IP addresses")
    return addresses


class PinnedPublicHTTPSConnection(http.client.HTTPSConnection):
    """TLS to the *validated public IP*, with original hostname as SNI.

    The DNS check and transport must use exactly the same address set.
    Standard HTTPSConnection.connect() re-resolves host and allows DNS rebinding
    between a public-IP allowlist check and the actual TCP socket. This class
    eliminates that second hostname resolution. It never accepts tunnels.
    """

    def __init__(self, hostname, public_addresses, *, timeout, context):
        if (type(hostname) is not str or not hostname or
                type(public_addresses) not in (tuple, list) or
                not 1 <= len(public_addresses) <= 20):
            raise ValueError("Validated DNS address set required")
        if not all(type(ip) is str and ipaddress.ip_address(ip).is_global
                   for ip in public_addresses):
            raise ValueError("Only validated public IP addresses are permitted")
        super().__init__(hostname, 443, timeout=timeout, context=context)
        self._pinned_addresses = tuple(public_addresses)

    def connect(self):
        if self._tunnel_host:
            raise ValueError("Proxy tunnels are not permitted")
        last_error = None
        for ip in self._pinned_addresses:
            raw = None
            try:
                # The TCP socket is pinned to a numeric IP. The TLS peer-name
                # and certificate verification still use the original domain.
                raw = socket.create_connection(
                    (ip, self.port), self.timeout, self.source_address)
                self.sock = self._context.wrap_socket(
                    raw, server_hostname=self.host)
                return
            except (OSError, ValueError) as exc:
                if raw is not None:
                    raw.close()
                self.sock = None
                last_error = exc
        if last_error is not None:
            raise last_error
        raise ValueError("Validated DNS address set required")


def probe(target):
    """One HEAD request, with TLS validation, no redirects, no credentials, no writes."""
    address = target["url"]
    hostname = urlsplit(address).hostname
    path = urlsplit(address).path or "/"
    if urlsplit(address).query:
        path += "?" + urlsplit(address).query
    started = time.monotonic()
    result = {
        "name": target["name"], "url": address, "status": "down",
        "http": None, "ms": None, "dns_ms": None, "cert_days": None,
        "ip_count": None, "message": "No response"
    }
    conn = None
    try:
        dns_start = time.monotonic()
        addresses = _safe_addresses(hostname)
        result["dns_ms"] = max(0, round((time.monotonic() - dns_start) * 1000))
        result["ip_count"] = len(addresses)
        conn = PinnedPublicHTTPSConnection(
            hostname, addresses, timeout=TIMEOUT_SECONDS,
            context=ssl.create_default_context())
        conn.connect()
        cert = conn.sock.getpeercert()
        expiry_raw = cert.get("notAfter")
        if expiry_raw:
            expiry_ts = ssl.cert_time_to_seconds(expiry_raw)
            result["cert_days"] = int((expiry_ts - time.time()) // 86400)
        conn.request("HEAD", path, headers={"User-Agent":"V79Sentinel/0.2 read-only"})
        response = conn.getresponse()
        code = response.status
        result["http"] = code
        if 200 <= code < 400:
            result["status"] = "up"
            result["message"] = "HTTPS reachable"
        elif code in (401, 403, 405, 429):
            result["status"] = "warning"
            result["message"] = "HTTP " + str(code) + " (review expected access/method)"
        else:
            result["status"] = "down"
            result["message"] = "HTTP " + str(code) + " returned"
        if result["cert_days"] is not None and result["cert_days"] < 14:
            if result["status"] == "up":
                result["status"] = "warning"
            result["message"] += "; TLS certificate expires soon"
    except Exception as error:
        result["status"] = "down"
        result["message"] = (type(error).__name__ + ": " + str(error))[:170]
    finally:
        if conn is not None:
            conn.close()
        result["ms"] = max(0, round((time.monotonic() - started) * 1000))
    return result


def probe_many(targets):
    validate_services(targets)
    with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as pool:
        return list(pool.map(probe, targets))


class Telemetry:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS observations (
                id INTEGER PRIMARY KEY,
                epoch INTEGER NOT NULL,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                http INTEGER,
                latency_ms INTEGER,
                dns_ms INTEGER,
                certificate_days INTEGER,
                note TEXT NOT NULL
            )""")
            con.execute("CREATE INDEX IF NOT EXISTS obs_name_epoch ON observations(name,epoch)")
            con.execute("""CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                epoch INTEGER NOT NULL,
                name TEXT NOT NULL,
                before TEXT,
                after TEXT NOT NULL,
                message TEXT NOT NULL
            )""")

    def connect(self):
        return sqlite3.connect(str(self.path), timeout=10)

    def record(self, readings):
        epoch = int(time.time())
        cutoff = epoch - STORE_DAYS * 86400
        with self.connect() as con:
            for result in readings:
                previous = con.execute(
                    "SELECT status FROM observations WHERE name=? ORDER BY id DESC LIMIT 1",
                    (result["name"],)).fetchone()
                con.execute(
                    """INSERT INTO observations
                    (epoch,name,status,http,latency_ms,dns_ms,certificate_days,note)
                    VALUES(?,?,?,?,?,?,?,?)""",
                    (epoch, result["name"], result["status"], result["http"],
                     result["ms"], result["dns_ms"], result["cert_days"], result["message"]))
                previous_state = previous[0] if previous else None
                if previous_state != result["status"]:
                    message = (f"{result['name']}: initial {result['status']}" if previous_state is None
                               else f"{result['name']}: {previous_state} → {result['status']}")
                    con.execute(
                        "INSERT INTO events(epoch,name,before,after,message) VALUES(?,?,?,?,?)",
                        (epoch, result["name"], previous_state, result["status"], message))
            con.execute("DELETE FROM observations WHERE epoch<?", (cutoff,))
            con.execute("DELETE FROM events WHERE epoch<?", (cutoff,))

    def summary(self, services):
        cutoff = int(time.time()) - 86400
        with self.connect() as con:
            measures = con.execute(
                """SELECT name, COUNT(*), SUM(CASE WHEN status='up' THEN 1 ELSE 0 END)
                   FROM observations WHERE epoch>=? GROUP BY name""",
                (cutoff,)).fetchall()
            uptime = {name: {"observed": count, "ok": ok or 0,
                              "percent": round(100*(ok or 0)/count,1)}
                      for name, count, ok in measures if count}
            timeline = con.execute(
                """SELECT epoch,name,after,message FROM events
                   ORDER BY id DESC LIMIT 20""").fetchall()
            events = [{"when": datetime.fromtimestamp(ts,timezone.utc).isoformat(timespec="seconds"),
                       "name": name, "status": new, "message": message}
                      for ts,name,new,message in timeline]
            hourly = con.execute(
                """SELECT (epoch/3600)*3600 AS hour, AVG(latency_ms), COUNT(*)
                   FROM observations WHERE epoch>=? AND status='up'
                   GROUP BY hour ORDER BY hour DESC LIMIT 24""",(cutoff,)).fetchall()
            trend = [{"hour": datetime.fromtimestamp(hour,timezone.utc).strftime("%H:%M"),
                      "ms": round(ms), "samples": count}
                     for hour, ms, count in reversed(hourly)]
        return {"uptime24h":{s["name"]:uptime.get(s["name"], {"observed":0,"ok":0,"percent":None})
                              for s in services},
                "history": events,"trend":trend}
