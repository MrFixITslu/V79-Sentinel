"""Targeted, read-only health probe of the user's known *new Dell* only."""
import re
import socket
import subprocess
import time

DELL_IP = "192.168.100.136"
DELL_MAC = "54:bf:64:73:9f:fd"

def dell_status():
    observation = {
        "name": "Sentinel target Dell", "ip": DELL_IP,
        "status": "unknown", "ssh": "not tested", "rtt_ms": None,
        "message": "Target observation unavailable"
    }
    started = time.monotonic()
    try:
        response = subprocess.run(
            ["ping","-n","-c","1","-W","2",DELL_IP],
            text=True, capture_output=True, timeout=4, check=False)
        if response.returncode != 0:
            observation.update(status="offline",message="No ICMP response from known Dell IP")
            return observation
        match = re.search(r"time[=<]([0-9.]+)\s*ms", response.stdout)
        if match:
            observation["rtt_ms"] = round(float(match.group(1)),2)
        neighbors = subprocess.run(
            ["ip","neigh","show",DELL_IP],text=True,
            capture_output=True,timeout=3,check=False)
        neighbor = neighbors.stdout.lower()
        if DELL_MAC not in neighbor:
            observation.update(status="unverified",message="Host replied, but known Dell MAC is not verified")
            return observation
        observation["status"] = "online"
        try:
            with socket.create_connection((DELL_IP,22), timeout=1.5):
                observation["ssh"] = "open"
                observation["message"] = "Known Dell reachable; SSH connection available"
        except ConnectionRefusedError:
            observation["ssh"] = "closed"
            observation["message"] = "Known Dell reachable; SSH refused on port 22"
        except OSError:
            observation["ssh"] = "unreachable"
            observation["message"] = "Known Dell responds to ping, but SSH is not accessible"
    except (OSError,subprocess.TimeoutExpired) as exc:
        observation.update(status="unknown",message="Local probe unavailable: "+type(exc).__name__)
    observation["check_ms"] = round((time.monotonic()-started)*1000)
    return observation
