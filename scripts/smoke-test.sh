#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m py_compile sentinel.py
node --check web/app.js
python3 -m json.tool config.json >/dev/null
python3 sentinel.py --port 18787 >/tmp/v79-sentinel-smoke.log 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT
sleep 1
python3 - <<'PY'
from urllib.request import urlopen
from urllib.error import HTTPError
import json, csv, io
base="http://127.0.0.1:18787"
for p in ["/","/style.css","/app.js","/healthz","/api/status","/api/report.csv"]:
    with urlopen(base+p,timeout=5) as resp:
        assert resp.status==200, (p,resp.status)
        assert resp.read(), p
        print("PASS",p)
with urlopen(base+"/api/status") as r: data=json.load(r)
assert data["mode"]=="demo" and data["last_check"] is None
assert len(data["services"])==7
assert all("Simulated" in x["message"] for x in data["services"])
print("PASS demo labeling and simulation disclosure")
with urlopen(base+"/api/report.csv") as r:
    report=list(csv.DictReader(io.StringIO(r.read().decode())))
assert len(report)==7 and all(x["mode"]=="demo" for x in report)
print("PASS CSV mode disclosure")
try: urlopen(base+"/does-not-exist",timeout=5)
except HTTPError as e: assert e.code==404; print("PASS 404")
else: raise AssertionError("Unexpected 200 for missing endpoint")
print("ALL SENTINEL LOCAL TESTS PASSED")
PY
