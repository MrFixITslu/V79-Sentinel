"""Controlled OWASP ZAP passive baseline launcher for EPHEMERAL GitHub CI only.

This is NOT a penetration test against production. ZAP spider makes GET
requests, so a disposable staging clone is required. Never run on the Dell.
No arbitrary shell and no arbitrary target URLs.
"""
import argparse
import os
import re
import subprocess
from .security_scan_policy import authorize_scan

PINNED_ZAP_IMAGE=re.compile(r"^ghcr\.io/zaproxy/zaproxy@sha256:[a-f0-9]{64}$")

def build_staging_zap_command(*, target, image, approved, staging_verified,
                              ci_environment, environment_kind):
    decision=authorize_scan(mode="zap-passive-baseline",target=target,
                            production=False,
                            approval="APPROVED_STAGING_PASSIVE" if approved else "")
    if not decision.allowed:
        raise ValueError("Target denied: passive staging-only scan")
    if not staging_verified:
        raise ValueError("Staging clone provenance and isolation have not been verified")
    if ci_environment != "true" or environment_kind != "github-hosted":
        raise ValueError("Scanner is restricted to disposable GitHub-hosted runners")
    if not isinstance(image,str) or not PINNED_ZAP_IMAGE.fullmatch(image):
        raise ValueError("Approved immutable ZAP image digest required")
    # Host network is permitted here ONLY in a disposable GitHub-hosted runner.
    # The validated scanner target is exactly loopback and an approved port.
    return [
        "docker","run","--rm","--network=host","--read-only",
        "--cap-drop=ALL","--security-opt=no-new-privileges",
        "--memory=1024m","--cpus=1","--pids-limit=100",
        "--tmpfs=/tmp:rw,nosuid,nodev,size=128m",
        image,"zap-baseline.py","-t",target,"-m","1","-T","3",
        "-I",  # report passive findings without interpreting all WARN as security certification
    ]


def main(argv=None):
    cli=argparse.ArgumentParser()
    cli.add_argument("--target",required=True)
    cli.add_argument("--zap-image",required=True,
                     help="Verified image pinned to ghcr.io/zaproxy/zaproxy@sha256 digest")
    cli.add_argument("--execute",action="store_true")
    opts=cli.parse_args(argv)
    plan=build_staging_zap_command(
        target=opts.target,image=opts.zap_image,
        approved=os.environ.get("SENTINEL_STAGING_SCAN_APPROVED")=="1",
        staging_verified=os.environ.get("SENTINEL_STAGING_CLONE_VERIFIED")=="1",
        ci_environment=os.environ.get("GITHUB_ACTIONS",""),
        environment_kind=os.environ.get("RUNNER_ENVIRONMENT",""))
    if not opts.execute:
        print("PASSIVE_STAGING_SCAN_PLAN_VALID_NO_NETWORK_REQUESTS")
        return 0
    # Bound runner duration. No automated alerts or deployment on scan completion.
    finished=subprocess.run(plan,check=False,timeout=300)
    return finished.returncode


if __name__=="__main__":
    raise SystemExit(main())
