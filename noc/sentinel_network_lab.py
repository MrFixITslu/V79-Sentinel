"""Bounded local observation and explicitly requested diagnostics. No scanning or root elevation."""
from __future__ import annotations
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import threading
import time

LOCK=threading.Lock()
TARGETS={"Gateway":("192.168.100.1",443),"Dell server":("192.168.100.163",22),
 "Website":("v79sl.com",443),"Hub":("hub.v79sl.com",443),
 "Academy":("academy.v79sl.com",443),"FFPRO":("ffpro.v79sl.com",443),
 "Tiquet":("tiquet.v79sl.com",443),"Marketing":("marketing.v79sl.com",443),"POS":("pos.v79sl.com",443)}
def stamp():return datetime.now(timezone.utc).isoformat(timespec="seconds")
def inventory():
    """Read the kernel neighbor table; no packets are sent for discovery."""
    ip=shutil.which("ip")
    if not ip:return {"at":stamp(),"source":"Acer kernel neighbor table","devices":[],"available":False,"scope":"Local neighbor cache unavailable; not a complete network inventory."}
    result=subprocess.run([ip,"-j","neigh","show"],capture_output=True,text=True,timeout=3,check=True)
    if len(result.stdout)>262144:raise ValueError("Neighbor output exceeded safe limit")
    rows=json.loads(result.stdout);devices=[]
    for row in rows[:512]:
        try:address=ipaddress.ip_address(row.get("dst",""))
        except ValueError:continue
        if not address.is_private or address.is_loopback or address.is_multicast:continue
        interface=row.get("dev","");mac=row.get("lladdr","")
        if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,32}",interface):continue
        if mac and not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}",mac):continue
        state=row.get("state",[]);state=state if isinstance(state,list) else [str(state)]
        devices.append({"address":str(address),"mac":mac,"interface":interface,"state":state[:4],"evidence":"Kernel neighbor cache; device identity not verified"})
    return {"at":stamp(),"source":"Acer kernel neighbor table","devices":devices,"available":True,"scope":"Only neighbors known to Acer. Cached/stale entries are not proof a device is online. No active scan; other VLANs may be unseen."}
def capabilities():
    return {"source":"Acer local tools","targets":[{"name":k,"host":v[0],"port":v[1]} for k,v in TARGETS.items()],
            "tcp":True,"traceroute":bool(shutil.which("traceroute")),
            "capture":False,"pcapImport":False,
            "captureReason":"Native capture bridge is not enabled in Sentinel NOC. Host tool availability does not grant packet-capture privileges to this application.",
            "retention":"Neighbor observations are read-only; imported investigation data stays in browser memory."}
def diagnostic(data):
    if not isinstance(data,dict) or set(data)!={"target","kind"} or data.get("target") not in TARGETS or data.get("kind") not in ("tcp","route"):
        raise ValueError("Select a pre-approved pilot target and TCP or route test")
    if not LOCK.acquire(blocking=False):raise ValueError("Another diagnostic is running; try again shortly")
    try:
        host,port=TARGETS[data["target"]];kind=data["kind"];started=time.monotonic()
        # DNS is isolated in a killable child to enforce a hard time budget.
        import sys
        resolver=subprocess.run([sys.executable,"-c","import socket,json,sys; print(json.dumps(socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)))",host,str(port)],capture_output=True,text=True,timeout=5,check=True)
        if len(resolver.stdout)>65536:raise ValueError("DNS output exceeded limit")
        addresses=json.loads(resolver.stdout);resolution=round((time.monotonic()-started)*1000,2);results=[];seen=set()
        if not addresses:raise ValueError("No target addresses resolved")
        for record in addresses:
            resolved=ipaddress.ip_address(record[4][0])
            if host.endswith("v79sl.com") and not resolved.is_global:raise ValueError("Public target resolved to a non-public address")
            if not host.endswith("v79sl.com") and str(resolved)!=host:raise ValueError("Pilot IP target changed")
        if kind=="route":
            tool=shutil.which("traceroute")
            if not tool:raise ValueError("System traceroute is unavailable")
            # Pin the literal resolved address, never let traceroute re-resolve a hostname.
            target=addresses[0][4][0]
            try:result=subprocess.run([tool,"-n","-m","12","-w","1","-q","1",target],capture_output=True,text=True,timeout=20)
            except subprocess.TimeoutExpired:raise ValueError("Route test reached its 20-second limit") from None
            return {"at":stamp(),"target":host,"resolvedAddress":target,"kind":kind,"output":result.stdout[:8192],"note":"Maximum 12 hops/20 seconds. Missing responses do not prove packet loss."}
        for family,stype,proto,_,address in addresses:
            ip=address[0]
            if ip in seen:continue
            seen.add(ip)
            # Public domains must not become access to local/link-local services through DNS rebinding.
            resolved=ipaddress.ip_address(ip)
            if host.endswith("v79sl.com") and not resolved.is_global:raise ValueError("Public target resolved to a non-public address")
            begin=time.monotonic();connected=False
            try:
                with socket.socket(family,stype,proto) as sock:
                    sock.settimeout(2);sock.connect(tuple(address));connected=True
            except OSError:pass
            results.append({"address":ip,"connected":connected,"elapsedMs":round((time.monotonic()-begin)*1000,2)})
            if len(results)>=4:break
        return {"at":stamp(),"kind":kind,"target":host,"port":port,"resolutionMs":resolution,"results":results,"note":"TCP connection time is not ping, bandwidth or application response time."}
    finally:LOCK.release()
