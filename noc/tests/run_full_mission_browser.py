"""Synthetic-only end-to-end visual test: original Mission Control embedded after NOC login."""
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from subprocess import run
import os

from noc.server import NocAPI,bootstrap
from noc.store import NocStore

PASSWORD="synthetic-full-mission-browser-password-20261010"
def main():
    with TemporaryDirectory(prefix="v79-sentinel-fullmission-browser-") as temp:
        db=Path(temp)/"noc.sqlite"
        bootstrap(NocStore(db),"full-mission-browser-test",PASSWORD)
        server=NocAPI("127.0.0.1",0,db)
        thread=Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            env={**os.environ,
                "SYNTHETIC_NOC_ORIGIN":f"http://127.0.0.1:{server.server_port}",
                "SYNTHETIC_NOC_BROWSER_PASSWORD":PASSWORD}
            script=Path(__file__).with_name("run_full_mission_browser.js")
            result=run(["node",str(script)],env=env,timeout=75,check=False)
            if result.returncode:raise RuntimeError(f"Headless browser returned {result.returncode}")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=6)

if __name__=="__main__": main()
