"""Bounded, read-only trusted structured reverse-proxy log adapter.

Never executes input, follows symlinks, reads arbitrary files, or stores raw
request paths/bodies/headers. The host must create the JSONL audit feed.
"""
import json
import os
from pathlib import Path
import stat

DEFAULT_ROOT=Path("/var/log/v79-security")
MAX_TAIL=128*1024
MAX_LINES=300

def read_owned_proxy_jsonl(path, *, approved_root=DEFAULT_ROOT, owner_uid=0):
    root=Path(approved_root).resolve(strict=True)
    candidate=Path(path)
    if candidate.is_symlink() or candidate.parent.resolve(strict=True) != root:
        raise ValueError("Unapproved proxy audit feed path")
    if not candidate.name.endswith(".jsonl"):
        raise ValueError("Trusted JSONL required")
    flags=os.O_RDONLY | getattr(os,"O_NOFOLLOW",0) | getattr(os,"O_NONBLOCK",0)
    fd=os.open(candidate,flags)
    try:
        metadata=os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=owner_uid or metadata.st_mode & 0o022:
            raise ValueError("Audit feed must be root-owned regular file, not group/world writable")
        # Use bounded seek; no unbounded memory even on large access logs.
        size=os.lseek(fd,0,os.SEEK_END)
        start=max(0,size-MAX_TAIL)
        os.lseek(fd,start,os.SEEK_SET)
        chunk=os.read(fd,MAX_TAIL)
        lines=chunk.splitlines()
        if start>0 and lines: lines=lines[1:]  # discard partial first JSONL record
        records=[]
        for raw in lines[-MAX_LINES:]:
            if len(raw)>4096: continue
            try:
                record=json.loads(raw)
                if isinstance(record,dict): records.append(record)
            except (ValueError,UnicodeDecodeError):
                continue
        return records
    finally:
        os.close(fd)
