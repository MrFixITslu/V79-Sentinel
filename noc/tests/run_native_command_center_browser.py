"""Synthetic NOC browser test of native visuals and NetPulse local-only metadata."""
import os,json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from subprocess import run
from noc.server import NocAPI,bootstrap
from noc.store import NocStore

PASSWORD="synthetic-native-command-browser-strong-password-20261010"
def main():
    with TemporaryDirectory(prefix="v79-sentinel-native-") as dirname:
        root=Path(dirname);db=root/"noc.sqlite"
        bootstrap(NocStore(db),"native-command-browser-test",PASSWORD)
        fixture=root/"investigation.json"
        fixture.write_text(json.dumps({"format":"v79-netpulse-investigation-v1","savedAt":"2026-10-10T00:00:00Z",
            "analysis":{"source":"synthetic-pcap-fixture","provenance":"synthetic fixture only","limit":3000,
                "packets":[{"number":i+1,"timestamp":0,"lengthBytes":123+i,"protocol":proto,
                  "source":src,"destination":dst,"dnsQuery":None}
                  for i,(proto,src,dst) in enumerate([("TCP","192.0.2.1","192.0.2.2"),("DNS","192.0.2.2","192.0.2.53"),("TCP","192.0.2.1","192.0.2.2")])]}}))
        server=NocAPI("127.0.0.1",0,db)
        thread=Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            env={**os.environ,"SYNTHETIC_NOC_ORIGIN":f"http://127.0.0.1:{server.server_port}",
              "SYNTHETIC_NOC_BROWSER_PASSWORD":PASSWORD,
              "SYNTHETIC_NETPULSE_JSON_FILE":str(fixture),
              "SYNTHETIC_SCREENSHOT_PATH":str(root/"native-overview.png")}
            result=run(["node",str(Path(__file__).with_name("run_native_command_center_browser.js"))],
                       env=env,timeout=85,check=False)
            if result.returncode:raise RuntimeError(f"Native Chrome test exited {result.returncode}")
            image=root/"native-overview.png"
            if not image.is_file() or image.stat().st_size<8000:raise RuntimeError("Missing browser screenshot")
        finally:
            server.shutdown();server.server_close();thread.join(timeout=6)
if __name__=="__main__":main()
