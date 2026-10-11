"""Run full operator security UI test against a disposable local NOC database.

Never uses the active Acer NOC service, production DB, or the real admin password.
Temporary site and user records are deleted when the context exits.
"""
from __future__ import annotations
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.request

PROJECT=Path(__file__).resolve().parents[2]
TEST=PROJECT/"noc/tests/test_operator_security_browser.cjs"
PORT=8790

def main():
    (PROJECT/"data").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="isolated-operator-security-",
                                     dir=PROJECT/"data") as directory:
        root=Path(directory)
        pwd=root/"test-password.txt"
        pwd.write_text(secrets.token_urlsafe(36)+"\n")
        pwd.chmod(0o600)
        db=root/"noc-security-test.sqlite3"
        env=dict(os.environ)
        env.pop("SENTINEL_NOC_EXTERNAL_ORIGIN",None)
        subprocess.run([sys.executable,"-m","noc.server",
                        "--db",str(db),"--bootstrap-operator","noc-admin",
                        "--bootstrap-password-file",str(pwd)],
                       cwd=PROJECT,env=env,check=True,capture_output=True,text=True)
        log=root/"server-output.txt"
        with log.open("w") as output:
            process=subprocess.Popen(
                [sys.executable,"-m","noc.server","--bind","127.0.0.1",
                 "--port",str(PORT),"--db",str(db)],
                cwd=PROJECT,env=env,stdout=output,stderr=subprocess.STDOUT)
            try:
                ready=False
                for _ in range(60):
                    if process.poll() is not None:
                        raise RuntimeError("Synthetic NOC exited during startup")
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{PORT}/readyz",timeout=0.5
                        ) as response:
                            if response.status==200:
                                ready=True
                                break
                    except OSError:
                        time.sleep(0.15)
                if not ready:
                    raise RuntimeError("Synthetic NOC readiness timed out")
                client_env=dict(env)
                client_env["SENTINEL_SECURITY_TEST_URL"]=f"http://127.0.0.1:{PORT}"
                client_env["SENTINEL_SECURITY_TEST_PASSWORD_FILE"]=str(pwd)
                print("Running synthetic browser security integration (localhost only)",flush=True)
                subprocess.run(["node",str(TEST)],cwd=PROJECT,
                               env=client_env,check=True,timeout=95)
            finally:
                process.terminate()
                try:process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    print("Temporary synthetic database and credentials cleaned up",flush=True)

if __name__=="__main__":
    main()
