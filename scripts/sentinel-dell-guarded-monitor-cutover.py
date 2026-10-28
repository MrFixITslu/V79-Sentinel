#!/usr/bin/env python3
"""One guarded V79 Sentinel monitor-only Dell deployment; no signer or alert promotion.

Call with --apply only from v79sl under group docker.
Only accepted image: an authenticated, previously downloaded GHCR digest.
Never log Docker config/env, credentials, Compose content, or HTTP error bodies.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

IMAGE = ("ghcr.io/mrfixitslu/v79-sentinel-candidate@"
         "sha256:453f8ac13f6269a9499b2153a664f781de6985fe2f44acfe1a65ff8ee7f4432e")
MANIFEST = "sha256:453f8ac13f6269a9499b2153a664f781de6985fe2f44acfe1a65ff8ee7f4432e"
SOURCE = "39dfcff98ed790e18ff24ec43a0fcade90e67981"
ROOT = Path("/home/firelion/V79-Sentinel-Dell-Owned-v1")
BASE = ROOT / "compose.private.json"
PROJECT = "v79-sentinel-dell-owned-v1"
EXPECTED_SOURCES = {
    "sentinel.py": "28350c24bf6413e6f5128748b823e841dee6bb6ea838c384e9ac23adcefab33d",
    "monitor_core.py": "4e175f32fa05253f6e87acb2bdb36ad2e7fefd3b394f9c19d00937b38f011c47",
    "noc/inprocess_probe_receipt.py": "9672151b7c776e9f6de2ecba96115069b0242a7d6842c65f7b212d0830cd6cd5",
}
EXPECTED_OLD = {
    "monitor": "sha256:c9ae010b7971496855785f275bda9e40e33617044376e2225d5488e2fbfdc6fc",
    "noc": "sha256:f9cef385aadd96229bea161473f627b006505216b1025692adfa6c5e832e5464",
    "ingress": "sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752",
}
NAMES = {key: "v79-sentinel-dell-" + key for key in EXPECTED_OLD}
EXPECTED_CMD = ["python", "sentinel.py", "--live", "--bind", "127.0.0.1", "--port", "8787"]


class Hold(Exception):
    pass


def need(ok, reason):
    if not ok:
        raise Hold(reason)


def command(argv, timeout=90, check=True):
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Hold("COMMAND_UNAVAILABLE_OR_TIMEOUT") from None
    if check and p.returncode:
        raise Hold("COMMAND_FAILED_" + str(p.returncode))
    return p


def docker_json(kind, reference):
    p = command(["docker", kind, "inspect", reference], timeout=25)
    value = json.loads(p.stdout)
    need(isinstance(value, list) and len(value) == 1, "INSPECTION_FORMAT")
    return value[0]


def base_cmd():
    return ["docker", "compose", "-p", PROJECT, "--project-directory", str(ROOT),
            "-f", str(BASE)]


def model(extra=None):
    args = base_cmd()
    if extra:
        args += ["-f", str(extra)]
    p = command(args + ["config", "--format", "json"], timeout=40)
    return json.loads(p.stdout)


def compose_up():
    return command(base_cmd() + [
        "up", "-d", "--no-deps", "--no-build", "--pull", "never",
        "--force-recreate", "--wait", "--wait-timeout", "75", "monitor"
    ], timeout=120)


def health(c):
    return (c.get("State") or {}).get("Running") is True and (
        ((c.get("State") or {}).get("Health") or {}).get("Status") == "healthy"
    )


def mounts(c):
    return sorted((x.get("Type"), x.get("Name"), x.get("Destination"), x.get("RW"))
                  for x in c.get("Mounts", []))


def runtime(c):
    h = c["HostConfig"]
    return {
        "network": h.get("NetworkMode"),
        "ports": h.get("PortBindings") or {},
        "mounts": mounts(c),
        "readonly": h.get("ReadonlyRootfs"),
        "privileged": h.get("Privileged"),
        "capdrop": sorted(h.get("CapDrop") or []),
        "securityopt": sorted(h.get("SecurityOpt") or []),
        "restart": h.get("RestartPolicy"),
    }


def verify_baseline():
    current = {}
    for service, name in NAMES.items():
        c = docker_json("container", name)
        need(health(c), "ORIGINAL_" + service.upper() + "_NOT_HEALTHY")
        need(c["Image"] == EXPECTED_OLD[service],
             "ORIGINAL_" + service.upper() + "_IMAGE_CHANGED")
        labels = c["Config"].get("Labels") or {}
        need(labels.get("com.docker.compose.project") == PROJECT and
             labels.get("com.docker.compose.service") == service,
             "COMPOSE_OWNER_OR_SERVICE_CHANGED")
        need(c["HostConfig"].get("ReadonlyRootfs") is True,
             "ORIGINAL_READONLY_MISSING")
        current[service] = c
    noc_id = current["noc"]["Id"]
    for service in ("monitor", "ingress"):
        need(current[service]["HostConfig"]["NetworkMode"] == "container:" + noc_id,
             "NOC_NETWORK_IDENTITY_CHANGED")
        need(not (current[service]["HostConfig"].get("PortBindings") or {}),
             "UNEXPECTED_PORT_PUBLISH")
    monitor_data = [m for m in current["monitor"].get("Mounts", [])
                    if m.get("Destination") == "/app/data"]
    need(len(monitor_data) == 1 and
         monitor_data[0].get("Type") == "volume" and
         monitor_data[0].get("Name") == "v79-p1-internal-stage_stage_monitor_data" and
         monitor_data[0].get("RW") is True, "MONITOR_DATA_VOLUME_CHANGED")
    need((current["noc"]["HostConfig"].get("PortBindings") or {}) ==
         {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "14878"}]},
         "NOC_EXPOSURE_CHANGED")
    print("ORIGINAL_THREE_SERVICES_HEALTHY=PASS")
    print("ORIGINAL_DATA_AND_NOC_NETWORK_LOCK=PASS")
    return current


def image_preflight():
    im = docker_json("image", IMAGE)
    need(IMAGE in (im.get("RepoDigests") or []), "IMMUTABLE_DIGEST_MISSING")
    need((im.get("Descriptor") or {}).get("digest", MANIFEST) == MANIFEST,
         "IMAGE_DESCRIPTOR_DIFFERENT")
    need(im.get("Id") in (MANIFEST,
                         "sha256:7341bf49e76b8115f859e0524a69c212e3d1564cc2dcd947bcaf6807d262327a"),
         "UNKNOWN_IMAGE_ID")
    c = im.get("Config") or {}
    need(im.get("Architecture") == "amd64" and im.get("Os") == "linux",
         "IMAGE_PLATFORM_MISMATCH")
    need(c.get("User") == "10001:10001" and c.get("Cmd") == EXPECTED_CMD,
         "IMAGE_USER_OR_COMMAND_MISMATCH")
    need((c.get("Labels") or {}).get("org.opencontainers.image.revision") == SOURCE,
         "IMAGE_REVISION_MISMATCH")
    print("PRIVATE_DIGEST_AND_IMAGE_METADATA=PASS")
    if im.get("Id") == MANIFEST:
        print("CONTAINERD_MANIFEST_IMAGE_ID=EXPECTED")
    return im


def isolation_args():
    return ["--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "64",
            "--memory", "256m",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=8m,uid=10001,gid=10001",
            "--tmpfs", "/app/data:rw,nosuid,nodev,size=8m,uid=10001,gid=10001"]


def verify_sources_no_network():
    code = ("import hashlib,pathlib,os; "
            "from monitor_core import PinnedPublicHTTPSConnection; "
            "assert os.geteuid()==10001; "
            "expected=" + repr(EXPECTED_SOURCES) + "; "
            "assert all(hashlib.sha256((pathlib.Path('/app')/p).read_bytes()).hexdigest()==d "
            "for p,d in expected.items()); "
            "print('CANDIDATE_SOURCE_BYTES=PASS')")
    command(["docker", "run", "--rm", "--network", "none"] +
            isolation_args() + [IMAGE, "python", "-B", "-c", code], timeout=60)
    print("SOURCE_AND_PINNED_HTTPS_IMPORT=PASS")


def demo_check():
    name = "v79-sentinel-private-demo-" + str(os.getpid())
    need(command(["docker", "container", "inspect", name], check=False).returncode != 0,
         "DEMO_NAME_IN_USE")
    started = False
    try:
        command(["docker", "run", "-d", "--name", name, "--network", "none"] +
                isolation_args() + [IMAGE, "python", "sentinel.py",
                                    "--bind", "127.0.0.1", "--port", "8787"], timeout=60)
        started = True
        good = False
        for _ in range(18):
            code = ("import urllib.request,json,os; "
                    "u=urllib.request.urlopen('http://127.0.0.1:8787/api/status',timeout=2); "
                    "x=json.load(u); "
                    "assert u.status==200 and os.geteuid()==10001 and "
                    "x.get('mode')=='demo' and x.get('cycle')==0 and "
                    "x.get('last_check') is None")
            if command(["docker", "exec", name, "python", "-B", "-c", code],
                       timeout=8, check=False).returncode == 0:
                good = True
                break
            time.sleep(1)
        need(good, "NETWORKLESS_DEMO_SMOKE_FAILED")
        print("NETWORKLESS_NONROOT_DEMO=PASS")
    finally:
        if started:
            command(["docker", "rm", "-f", name], timeout=25, check=False)


def live_once(noc_id):
    # Exactly seven owner-approved HTTPS HEAD checks; no daemon, port, signer,
    # production /app/data mount or persistent storage.
    p = command(["docker", "run", "--rm", "--network", "container:" + noc_id] +
                isolation_args() + [IMAGE, "python", "sentinel.py", "--once"], timeout=100)
    try:
        data = json.loads(p.stdout)
    except (ValueError, TypeError):
        raise Hold("ONESHOT_OUTPUT_INVALID")
    services = data.get("services") or []
    need(data.get("mode") == "one-shot" and len(services) == 7,
         "ONESHOT_NOT_SEVEN_TARGETS")
    need(all(s.get("status") in ("up", "warning") for s in services),
         "ONESHOT_PUBLIC_HTTPS_DOWN")
    need(sum(s.get("status") == "up" for s in services) >= 1,
         "ONESHOT_NO_HEALTHY_TARGET")
    print("ONESHOT_7_TLS_PINNED_HEAD_CHECKS=PASS")
    print("ONESHOT_WARNINGS=" + str(sum(s.get("status") == "warning" for s in services)))


def verify_after(before, wanted_id):
    deadline = time.monotonic() + 85
    last = "NONE"
    new = None
    while time.monotonic() < deadline:
        try:
            c = docker_json("container", NAMES["monitor"])
            if health(c):
                new = c
                break
            last = "WAITING_FOR_HEALTH"
        except Hold:
            last = "WAITING_FOR_CONTAINER"
        time.sleep(3)
    need(new is not None, "NEW_MONITOR_UNHEALTHY_" + last)
    need(new["Id"] != before["monitor"]["Id"], "MONITOR_NOT_RECREATED")
    need(new["Image"] == wanted_id, "RUNNING_IMAGE_MISMATCH")
    need(runtime(new) == runtime(before["monitor"]),
         "MONITOR_RUNTIME_OR_MOUNT_CHANGED")
    need(new["Config"].get("User") == "10001:10001" and
         new["Config"].get("Cmd") == EXPECTED_CMD,
         "NEW_MONITOR_COMMAND_OR_USER")
    for svc in ("noc", "ingress"):
        c = docker_json("container", NAMES[svc])
        need(c["Id"] == before[svc]["Id"] and c["Image"] == before[svc]["Image"]
             and health(c), svc.upper() + "_CHANGED_OR_UNHEALTHY")
    print("NOC_AND_INGRESS_IDS_UNCHANGED=PASS")
    print("MONITOR_MOUNTS_NETWORK_SECURITY_UNCHANGED=PASS")
    print("NEW_MONITOR_HEALTHY=PASS")

    deadline = time.monotonic() + 85
    while time.monotonic() < deadline:
        code = ("import json,urllib.request,os,datetime; "
                "u=urllib.request.urlopen('http://127.0.0.1:8787/api/status',timeout=2); "
                "x=json.load(u); "
                "assert os.geteuid()==10001 and x['mode']=='live' and "
                "x['cycle']>=1 and x['last_check'] and len(x['services'])==7 and "
                "all(s['status'] in ('up','warning') for s in x['services']); "
                "assert (datetime.datetime.now(datetime.timezone.utc)-"
                "datetime.datetime.fromisoformat(x['last_check'])).total_seconds()<180")
        if command(["docker", "exec", NAMES["monitor"], "python", "-B", "-c", code],
                   timeout=8, check=False).returncode == 0:
            print("NEW_MONITOR_7_LIVE_TARGETS=PASS")
            return
        time.sleep(3)
    raise Hold("NEW_MONITOR_LIVE_CYCLE_NOT_ACCEPTED")


def atomic_write(path, data, mode):
    handle, temp = tempfile.mkstemp(prefix=".v79compose.", dir=str(ROOT))
    try:
        os.fchmod(handle, mode)
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main():
    need(sys.argv[1:] == ["--apply"], "EXPLICIT_APPLY_FLAG_REQUIRED")
    need(os.geteuid() != 0, "DO_NOT_RUN_AS_ROOT")
    need(ROOT.is_dir() and BASE.is_file() and not BASE.is_symlink(),
         "BASE_COMPOSE_UNAVAILABLE")
    lockpath = ROOT / ".sentinel-monitor-only-release.lock"
    lockfd = os.open(lockpath, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    old_bytes = BASE.read_bytes()
    need(len(old_bytes) < 1_000_000, "COMPOSE_TOO_LARGE")
    original_mode = stat.S_IMODE(BASE.stat().st_mode)
    before = verify_baseline()
    image = image_preflight()
    prior_model = model()
    raw = json.loads(old_bytes)
    need(raw.get("services", {}).get("monitor", {}).get("image"),
         "PERSISTENT_MONITOR_IMAGE_FIELD_MISSING")
    base_image = prior_model["services"]["monitor"].get("image")
    need(isinstance(base_image, str) and base_image != IMAGE,
         "ORIGINAL_IMAGE_REF_INVALID")
    old_resolved = docker_json("image", base_image)
    need(old_resolved.get("Id") == before["monitor"]["Image"],
         "ORIGINAL_IMAGE_NOT_RECOVERABLE")
    need(docker_json("image", before["monitor"]["Image"]).get("Id") ==
         before["monitor"]["Image"], "ORIGINAL_IMAGE_ID_NOT_AVAILABLE")
    with tempfile.TemporaryDirectory(prefix="v79-monitor-compare-") as temp:
        overlay = Path(temp) / "only-image.json"
        overlay.write_text(json.dumps({"services": {"monitor": {"image": IMAGE}}}))
        after = model(overlay)
    expected = copy.deepcopy(prior_model)
    expected["services"]["monitor"]["image"] = IMAGE
    need(after == expected, "COMPOSE_HAS_NON_IMAGE_CHANGES")
    print("PERSISTENT_BASE_AND_IMAGE_ONLY_MODEL=PASS")
    print("ORIGINAL_IMAGE_RECOVERY_READY=PASS")

    verify_sources_no_network()
    demo_check()
    live_once(before["noc"]["Id"])

    new_raw = copy.deepcopy(raw)
    new_raw["services"]["monitor"]["image"] = IMAGE
    backup = ROOT / (".compose.private.monitor-before-" +
                     datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json")
    need(not backup.exists(), "RECOVERY_PATH_ALREADY_EXISTS")
    changed = False
    started = False
    try:
        # Private, exact-byte recovery copy. No customer DB backup/restore.
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(old_bytes)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            raise
        atomic_write(BASE, (json.dumps(new_raw, indent=2) + "\n").encode(),
                     original_mode)
        changed = True
        need(model() == expected, "PERSISTED_COMPOSE_MODEL_CHANGED")
        print("IMAGE_ONLY_COMPOSE_FILE_PERSISTED=PASS")
        started = True
        compose_up()
        verify_after(before, image["Id"])
        print("SENTINEL_MONITOR_ONLY_DEPLOYMENT=PASS")
        print("ORIGINAL_IMAGE_RETAINED=YES")
        print("RECOVERY_CONFIG_FILE=" + str(backup))
        print("SIGNER_AND_AUTO_ALERTS_ENABLED=NO")
        print("G2_HUB_NOC_INGRESS_DEPLOYED_CHANGES=NONE")
    except Exception as exc:
        print("CUTOVER_FAILED=" + type(exc).__name__)
        if changed:
            try:
                atomic_write(BASE, old_bytes, original_mode)
                need(model() == prior_model, "ORIGINAL_COMPOSE_RESTORE_DIFF")
                print("ORIGINAL_COMPOSE_FILE_RESTORED=PASS")
                if started:
                    compose_up()
                    c = docker_json("container", NAMES["monitor"])
                    need(c["Image"] == before["monitor"]["Image"] and health(c),
                         "ORIGINAL_MONITOR_RESTORE_UNVERIFIED")
                    for svc in ("noc", "ingress"):
                        c2 = docker_json("container", NAMES[svc])
                        need(c2["Id"] == before[svc]["Id"] and health(c2),
                             "DEPENDENCY_AFTER_RESTORE_CHANGED")
                    print("ORIGINAL_MONITOR_RESTORE=PASS")
            except Exception as rollback_error:
                print("RESTORE_CRITICAL_HOLD=" + type(rollback_error).__name__)
        raise Hold("CUTOVER_NOT_ACCEPTED") from None


if __name__ == "__main__":
    try:
        main()
    except (Hold, ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError,
            BlockingIOError) as error:
        print("RELEASE_STATUS=HOLD", type(error).__name__, str(error)[:140])
        raise SystemExit(1)
