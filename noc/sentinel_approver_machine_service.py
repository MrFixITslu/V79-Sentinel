"""Private, separately authenticated NOC approver-status machine service.

The HTTP integration remains OFF without explicit operator configuration.
The endpoint only returns a scoped boolean and is never a human auth API.
"""
import hashlib
import hmac
import os
from pathlib import Path
import re
import stat
import time

PATH="/api/v1/sentinel/service/approver/check"
HEX=re.compile(r"^[a-f0-9]{64}$")


def load_machine_secret(path):
    if not isinstance(path,str) or not path or len(path)>300:
        raise PermissionError("NOC machine verifier secret not configured")
    file=Path(path)
    if file.is_symlink() or file.parent.is_symlink():
        raise PermissionError("Unsafe NOC machine secret path")
    fd=os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid()
                or stat.S_IMODE(info.st_mode)!=0o600 or
                info.st_size<48 or info.st_size>1024):
            raise PermissionError("NOC machine secret must be owner-only")
        with os.fdopen(fd,"rb",closefd=False) as reader:
            data=reader.read(1025)
    finally:
        os.close(fd)
    if not 48<=len(data)<=1024 or not all(33<=b<=126 for b in data):
        raise PermissionError("Invalid NOC machine secret material")
    return data


def validate_machine_signature(headers,raw_body,secret,now=None):
    when=int(time.time() if now is None else now)
    if (not isinstance(raw_body,bytes) or not 1<=len(raw_body)<=4096
        or not isinstance(secret,bytes) or len(secret)<48):
        return False
    if (headers.get("Origin") or headers.get("Cookie") or
        headers.get("Authorization") or
        headers.get("X-V79-Service-Id")!="v79-tiquet"):
        return False
    stamp=headers.get("X-V79-Timestamp","")
    sig=headers.get("X-V79-Signature","")
    if (not isinstance(stamp,str) or not stamp.isdigit() or
        len(stamp) not in (10,11) or abs(int(stamp)-when)>120 or
        not isinstance(sig,str) or not HEX.fullmatch(sig)):
        return False
    canonical="POST\n"+PATH+"\n"+stamp+"\n"+hashlib.sha256(raw_body).hexdigest()
    expected=hmac.new(secret,canonical.encode("utf8"),hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected,sig)
