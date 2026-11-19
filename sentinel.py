#!/usr/bin/env python3
"""V79 Sentinel — local-only, read-only service monitoring and incident timeline."""
from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import pathlib
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from monitor_core import Telemetry, probe_many, validate_services
from lab_probe import dell_status
from qa_results import load_qa_latest, screenshot as qa_screenshot
from protected_preflight import protected_readiness

BASE = pathlib.Path(__file__).resolve().parent
CONFIG_PATH = BASE / "config.json"
DB_PATH = BASE / "data" / "sentinel.sqlite3"
POLL_SECONDS = 300
state_lock = threading.Lock()
state = {"mode": "demo", "last_check": None, "services": [],
         "history": [], "uptime24h": {}, "trend": [], "cycle": 0, "error": None, "lab": None}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_targets():
    data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return validate_services(data.get("services"))


def demo_snapshot(targets):
    """All values here are intentionally fictitious and labeled accordingly."""
    samples = [("up", 158, 38), ("up", 243, 82), ("up", 301, 61),
               ("up", 221, 38), ("warning", 730, 61), ("up", 278, 38),
               ("up", 187, 38)]
    services = []
    uptime = {}
    for target, (level, latency, cert_days) in zip(targets, samples):
        services.append({"name": target["name"],"url": target["url"],
                         "status": level, "http": 200 if level=="up" else 405,
                         "ms": latency,"dns_ms":28, "ip_count":1,
                         "cert_days":cert_days,
                         "message": "Simulated example; no request was sent"})
        uptime[target["name"]]={"percent":99.3 if level=="up" else 94.7,
                                 "observed":84,"ok":83 if level=="up" else 79}
    return {"mode":"demo","last_check":None,"services":services,
            "uptime24h":uptime, "trend":[
                {"hour":"08:00","ms":192,"samples":7},
                {"hour":"09:00","ms":210,"samples":7},
                {"hour":"10:00","ms":231,"samples":7},
                {"hour":"11:00","ms":216,"samples":7},
                {"hour":"12:00","ms":243,"samples":7},
                {"hour":"13:00","ms":198,"samples":7}],
            "history":[{"when":"Example event","name":"V79 Tiquet",
                        "message":"Illustrative warning (not a measured incident)",
                        "status":"warning"}],
            "cycle":0, "error":None,
            "lab":{"name":"Sentinel target Dell","ip":"192.168.100.136","status":"demo",
                   "ssh":"simulated","rtt_ms":None,"message":"No live lab-node checks in demo mode"}}


def get_snapshot():
    with state_lock:
        return json.loads(json.dumps(state))


def monitor_forever(targets, store, evidence_sink=None):
    """Read-only sampler. Optional source candidate tap is OFF by default.

    This source-only review hook is not registered by main() and is not an
    API, signer, sender, network publisher or production trust assertion.
    """
    while True:
        started=time.monotonic()
        try:
            readings=probe_many(targets)
            store.record(readings)
            summary=store.summary(targets)
            lab=dell_status()
            with state_lock:
                checked_at=now_iso()
                cycle=state["cycle"]+1
                state.update({"mode":"live", "last_check":checked_at,
                              "services":readings, "history":summary["history"],
                              "uptime24h":summary["uptime24h"],
                              "trend":summary["trend"],
                              "cycle":cycle, "error":None, "lab":lab})
            logging.info("Cycle %s: %s/%s healthy",
                         cycle, sum(x["status"]=="up" for x in readings),len(readings))
            if evidence_sink is not None:
                # Only the just-sampled in-process readings may enter this
                # optional review projection; never reuse /api/status JSON.
                # Do NOT enable a signing or alert sink without separate
                # process-origin, key-custody and off-host acceptance.
                try:
                    from noc.inprocess_probe_receipt import project_probe_cycle
                    candidate=project_probe_cycle(
                        targets=targets, readings=readings,
                        cycle=cycle, observed_at=checked_at)
                    evidence_sink(candidate)
                except Exception:
                    # Never leak untrusted probe text or sink exceptions.
                    # A review sink failure must not stop the live sampler.
                    logging.warning("INPROCESS_REVIEW_CANDIDATE_REFUSED")
        except Exception as exc:
            logging.exception("Monitoring cycle failure")
            with state_lock:
                state["error"] = f"Monitoring engine error: {type(exc).__name__}"
        time.sleep(max(5, POLL_SECONDS-(time.monotonic()-started)))


class Handler(BaseHTTPRequestHandler):
    def send_payload(self,status,mime,data):
        self.send_response(status)
        for k,v in {
            "Content-Type":mime, "Content-Length":str(len(data)),
            "Cache-Control":"no-store", "X-Content-Type-Options":"nosniff",
            "X-Frame-Options":"DENY","Referrer-Policy":"no-referrer",
            "Content-Security-Policy":(
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self'; connect-src 'self'; object-src 'none'; "
                "frame-ancestors 'none'; base-uri 'none'")
        }.items():
            self.send_header(k,v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path=self.path.split("?",1)[0]
        try:
            if path=="/api/status":
                self.send_payload(200,"application/json; charset=utf-8",
                                  json.dumps(get_snapshot(),separators=(",",":")).encode())
            elif path=="/api/qa/auth-readiness":
                self.send_payload(200,"application/json; charset=utf-8",
                                  json.dumps(protected_readiness(),separators=(",",":")).encode())
            elif path=="/api/qa/latest":
                self.send_payload(200,"application/json; charset=utf-8",
                                  json.dumps(load_qa_latest(),separators=(",",":")).encode())
            elif path.startswith("/api/qa/screenshot/"):
                parts=path.split("/")
                content=qa_screenshot(parts[4],parts[5]) if len(parts)==6 else None
                if content is None:
                    self.send_payload(404,"text/plain; charset=utf-8",b"Not found\n")
                else:
                    self.send_payload(200,"image/png",content)
            elif path=="/api/report.csv":
                snap=get_snapshot()
                out=io.StringIO()
                writer=csv.writer(out)
                writer.writerow(["mode","checked_at","application","url","status",
                                 "http","latency_ms","dns_ms","cert_days","uptime24h_percent","message"])
                for s in snap["services"]:
                    writer.writerow([snap["mode"],snap["last_check"] or "NOT CHECKED",
                        s["name"],s["url"],s["status"],s.get("http"),s.get("ms"),s.get("dns_ms"),
                        s.get("cert_days"),snap.get("uptime24h",{}).get(s["name"],{}).get("percent"),
                        s.get("message")])
                self.send_payload(200,"text/csv; charset=utf-8",out.getvalue().encode())
            elif path in ("/","/index.html"):
                self.send_payload(200,"text/html; charset=utf-8",
                                  (BASE/"web"/"index.html").read_bytes())
            elif path=="/app.js":
                self.send_payload(200,"text/javascript; charset=utf-8",
                                  (BASE/"web"/"app.js").read_bytes())
            elif path=="/style.css":
                self.send_payload(200,"text/css; charset=utf-8",
                                  (BASE/"web"/"style.css").read_bytes())
            elif path=="/healthz":
                self.send_payload(200,"text/plain; charset=utf-8",b"ok\n")
            else:
                self.send_payload(404,"text/plain; charset=utf-8",b"Not found\n")
        except Exception:
            logging.exception("Request failed")
            self.send_payload(500,"text/plain; charset=utf-8",b"Server error\n")


def main():
    parser=argparse.ArgumentParser(description="V79 Sentinel read-only monitoring")
    parser.add_argument("--live",action="store_true",help="Enable configured HTTPS HEAD probes every 5 minutes")
    parser.add_argument("--once",action="store_true",help="Print one set of read-only checks; do not serve a dashboard")
    parser.add_argument("--port",type=int,default=8787)
    parser.add_argument("--bind",default="127.0.0.1",
                        help="Loopback by default; never expose unauthenticated dashboard")
    args=parser.parse_args()
    targets=load_targets()
    if args.once:
        print(json.dumps({"mode":"one-shot","checked_at":now_iso(),
                          "services":probe_many(targets)},indent=2))
        return
    if args.live:
        store=Telemetry(DB_PATH)
        with state_lock:
            state.update({"mode":"live","lab":{"name":"Sentinel target Dell","ip":"192.168.100.136",
                          "status":"pending","ssh":"not tested","message":"Awaiting first check"},
                          "services":[
                {"name":t["name"],"url":t["url"],"status":"pending",
                 "http":None,"ms":None,"dns_ms":None,"cert_days":None,
                 "message":"Awaiting first cycle"} for t in targets]})
        threading.Thread(target=monitor_forever,args=(targets,store),daemon=True).start()
    else:
        with state_lock:
            state.update(demo_snapshot(targets))
    logging.basicConfig(level=logging.INFO,format="%(asctime)s %(levelname)s %(message)s")
    srv=ThreadingHTTPServer((args.bind,args.port),Handler)
    srv.daemon_threads=True
    print(f"Sentinel {'LIVE' if args.live else 'DEMO'} available at http://{args.bind}:{args.port}",
          flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__=="__main__":
    main()
