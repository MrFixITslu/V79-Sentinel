"""Isolated Chrome smoke for provider NOC pilot panel; synthetic admin only."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from datetime import datetime,timezone

from noc.owner_pilot_status import ALLOWED_TARGETS,APP_ENDPOINTS
from noc.server import NocAPI,bootstrap
from noc.store import NocStore

PASSWORD="synthetic-owner-pilot-browser-admin-password"

def main():
    with tempfile.TemporaryDirectory(prefix="sentinel-pilot-browser-") as directory:
        root=Path(directory)
        evidence=root/"pilot-data"
        evidence.mkdir(mode=0o700)
        def write(name,data):
            path=evidence/name
            path.write_text(json.dumps(data))
            path.chmod(0o600)
        write("last-observation.json",{
            "scope":"V79_DIGITAL_OWN_NETWORK_PILOT","collected_at":int(time.time()),
            "queued_readings":0,
            "checks":[{"ip":ip,"port":port,"ok":True,"latency_ms":2}
                      for ip,port in sorted(ALLOWED_TARGETS)]
        })
        write("app-checks-latest.json",{"captured_at":datetime.now(timezone.utc).isoformat(),
            "results":[{"app":name,"status":200,"tls_verified":True,"category":"reachable"}
                       for name in APP_ENDPOINTS]})
        write("service-readiness-latest.json",{
            "schema_version":1,"scope":"approved_V79_public_readiness_get_only",
            "captured_at":datetime.now(timezone.utc).isoformat(),
            "results":[{
               "app":name,"hostname":host,"path":path,
               "readiness":"protected" if name=="POS" else "ready",
               "reason":"authentication_required" if name=="POS" else "expected_response_verified",
               "tls_verified":True,"status":401 if name=="POS" else 200
            } for name,(host,path) in APP_ENDPOINTS.items()]})
        write("app-incidents-mock-latest.json",{
            "scope":"OWNER_ONLY_APPLICATION_INCIDENT_SIMULATION",
            "generated_at":datetime.now(timezone.utc).isoformat(),
            "incidents":[{"app":"Hub","status":"open",
                           "opened_at":int(time.time())-480,"resolved_at":None}],
            "pending_mock_events":1,"live_integrations":"disabled"
        })
        password_file=root/"browser-test-password"
        password_file.write_text(PASSWORD)
        password_file.chmod(0o600)
        db=root/"testing.sqlite3"
        bootstrap(NocStore(db),"noc-admin",PASSWORD)
        server=NocAPI("127.0.0.1",0,db,pilot_root=evidence)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            environment=dict(os.environ)
            environment.update({
                "SENTINEL_PILOT_TEST_URL":f"http://127.0.0.1:{server.server_port}/",
                "SENTINEL_PILOT_TEST_PASSWORD_FILE":str(password_file),
                "SENTINEL_EXPECT_SYNTHETIC_MOCK_OPEN":"1"
            })
            script=Path(__file__).with_name("test_owner_pilot_browser.cjs")
            subprocess.run(["node",str(script)],env=environment,check=True,timeout=65)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=6)

if __name__=="__main__":main()
