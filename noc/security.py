"""Standalone Sentinel operator security helpers (no Hub or external identity imports).

TOTP RFC 6238 (HMAC-SHA1, 30 seconds, six digits) for opt-in staging MFA.
Secrets are stored in owner-restricted staging SQLite until an encryption-at-rest
design is implemented. Do not onboard real operator accounts yet.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

ROLES=frozenset({"admin","operator","viewer"})
TOTP_PERIOD=30
TOTP_DIGITS=6
PASSWORD_ROUNDS=260000

def hash_password(password, salt=None):
    if not isinstance(password,str) or len(password)<18 or len(password)>1024:
        raise ValueError("Password must contain 18-1024 characters")
    salt=salt or secrets.token_bytes(16)
    return "pbkdf2_sha256$"+str(PASSWORD_ROUNDS)+"$"+salt.hex()+"$"+hashlib.pbkdf2_hmac(
        "sha256",password.encode(),salt,PASSWORD_ROUNDS).hex()

def valid_password(password,saved):
    if not isinstance(password,str) or len(password)>1024: return False
    try:
        algo,rounds,salt,digest=saved.split("$")
        n=int(rounds)
        if algo!="pbkdf2_sha256" or n<100000 or n>2000000:return False
        salt_bytes=bytes.fromhex(salt)
        if len(salt_bytes)!=16:return False
        candidate=hashlib.pbkdf2_hmac("sha256",password.encode(),salt_bytes,n)
        return hmac.compare_digest(candidate,bytes.fromhex(digest))
    except (ValueError,TypeError,OverflowError):return False

def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")

def new_recovery_codes(count=8):
    if type(count) is not int or not 1<=count<=20:
        raise ValueError("Invalid recovery-code count")
    return ["sc_"+secrets.token_hex(12) for _ in range(count)]

def hash_recovery_code(code):
    if not isinstance(code,str) or len(code)!=27 or not code.startswith("sc_"):
        return None
    if any(ch not in "0123456789abcdef" for ch in code[3:]):
        return None
    return hashlib.sha256(code.encode("ascii")).hexdigest()

def _key(secret):
    if not isinstance(secret,str) or not secret or len(secret)>128:
        raise ValueError("Invalid MFA secret")
    return base64.b32decode(secret+"="*((-len(secret))%8),casefold=False)

def totp(secret, counter):
    if type(counter) is not int or counter<0 or counter>=2**64:
        raise ValueError("Invalid MFA counter")
    digest=hmac.new(_key(secret),struct.pack(">Q",counter),hashlib.sha1).digest()
    start=digest[-1]&15
    number=(struct.unpack(">I",digest[start:start+4])[0]&0x7fffffff)%10**TOTP_DIGITS
    return f"{number:0{TOTP_DIGITS}d}"

def accepted_totp_counter(secret, code, now=None, last=-1):
    """Return fresh counter or None. Prevents replay even in ±one-step window."""
    if not isinstance(code,str) or len(code)!=TOTP_DIGITS or not code.isascii() or not code.isdecimal():
        return None
    current=int((time.time() if now is None else now)//TOTP_PERIOD)
    for counter in (current-1,current,current+1):
        if counter>last and counter>=0 and hmac.compare_digest(totp(secret,counter),code):
            return counter
    return None

def provisioning_uri(username,secret):
    if not isinstance(username,str) or not username:
        raise ValueError("Missing MFA username")
    label=quote("V79 Sentinel:"+username,safe="")
    return (f"otpauth://totp/{label}?secret={secret}&issuer=V79%20Sentinel"
            "&algorithm=SHA1&digits=6&period=30")
