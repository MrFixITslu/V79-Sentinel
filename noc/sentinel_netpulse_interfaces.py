"""V79 NetPulse-inspired measured host NIC counters; never capture or scan.

Only Linux /proc/net/dev byte counters for the Acer collector itself are read.
Counters from the host do not imply bandwidth, topology, packets, or the Dell's
traffic, and cannot be compared between hosts.
"""
from __future__ import annotations
from pathlib import Path
import os
from threading import Lock
import time

_LOCK = Lock()
_PREVIOUS: dict[str, tuple[int, int]] = {}
_PREVIOUS_TIME: float | None = None

def _rows(raw: str):
    output=[]
    for line in raw.splitlines()[2:]:
        if ":" not in line: continue
        name,metrics=line.strip().split(":",1)
        pieces=metrics.split()
        if not name or len(pieces)<16 or len(output)>=24: continue
        if not (name.replace("-","").replace("_","").replace(".","").isalnum()):
            continue
        try:rx,tx=int(pieces[0]),int(pieces[8])
        except ValueError:continue
        if rx<0 or tx<0:continue
        output.append((name[:40],rx,tx))
    return output

def sample_host_interfaces():
    global _PREVIOUS_TIME,_PREVIOUS
    rows=_rows(Path("/proc/net/dev").read_text(encoding="utf8"))
    now=time.monotonic()
    with _LOCK:
        elapsed=now-_PREVIOUS_TIME if _PREVIOUS_TIME is not None else None
        current={name:(rx,tx) for name,rx,tx in rows}
        result=[]
        for name,rx,tx in rows:
            past=_PREVIOUS.get(name)
            elapsed_s=elapsed if elapsed and elapsed>=.25 else None
            drx=rx-past[0] if past and rx>=past[0] else None
            dtx=tx-past[1] if past and tx>=past[1] else None
            result.append({
              "name":name,"totalReceivedBytes":rx,"totalTransmittedBytes":tx,
              "receivedBytes":drx if elapsed_s else None,
              "transmittedBytes":dtx if elapsed_s else None,
              "sampleIntervalSeconds":round(elapsed_s,2) if elapsed_s else None
            })
        _PREVIOUS=current
        _PREVIOUS_TIME=now
    is_container=os.environ.get("SENTINEL_MONITORING_CONTEXT")=="docker"
    return {
      "source":"container-netns:/proc/net/dev" if is_container else "acer-host:/proc/net/dev",
      "measurement":"actual operating-system interface byte counters",
      "scope":("Sentinel Docker network namespace only; does not represent host, LAN or captured packets"
               if is_container else
               "local Acer host only; includes all interface traffic, not captured packets"),
      "interfaces":result,
    }
