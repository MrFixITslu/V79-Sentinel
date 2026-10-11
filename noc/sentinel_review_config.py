"""Owner-only Sentinel review configuration. Staging OFF unless explicitly enabled."""
import json
import os
from pathlib import Path
import stat
from uuid import UUID



def _uuid(value):
    try: return isinstance(value,str) and str(UUID(value))==value.lower()
    except (ValueError,TypeError,AttributeError):return False


def load_review_config(filename):
    """Read private approved mapping and trusted observer public keys; no secrets logged."""
    p=Path(filename)
    if p.is_symlink() or p.parent.is_symlink():
        raise PermissionError("Symlinked review configuration denied")
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or (
            stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>32768):
            raise PermissionError("Review config must be an owner-only file")
        with os.fdopen(fd,"rb",closefd=False) as stream:
            raw=stream.read(32769)
    finally:
        os.close(fd)
    if len(raw)>32768:raise PermissionError("Review configuration too large")
    config=json.loads(raw)
    if not isinstance(config,dict) or set(config)!={
        "mapping","observer_public_keys","approved_targets",
        "signing_key_path","signing_key_id"}:
        raise ValueError("Incomplete review configuration")
    mapping=config["mapping"]
    if not isinstance(mapping,dict) or set(mapping)!={
        "sentinel_customer_id","tiquet_organization_id","tiquet_client_id"
    } or not all(_uuid(v) for v in mapping.values()):
        raise ValueError("Unapproved mapping")
    observers=config["observer_public_keys"]
    if not isinstance(observers,dict) or not 1<=len(observers)<=16 or not all(
        _uuid(k) and isinstance(v,str) and len(v)<400 and
        v.startswith("-----BEGIN PUBLIC KEY-----") for k,v in observers.items()):
        raise ValueError("No pinned, correctly shaped real observer keys")
    targets=config["approved_targets"]
    if not isinstance(targets,dict) or not 1<=len(targets)<=40:
        raise ValueError("No approved Edge check-target mapping")
    from ipaddress import ip_address
    for check_id,record in targets.items():
        if not _uuid(check_id) or not isinstance(record,dict) or set(record)!={
            "ip","port","customer_id","site_id","agent_id"} or (
            not all(_uuid(record.get(k)) for k in ("customer_id","site_id","agent_id"))) or (
            record["agent_id"] not in observers) or (
            record["customer_id"]!=mapping["sentinel_customer_id"]) or (
            type(record["port"]) is not int or not 1<=record["port"]<=65535):
            raise ValueError("Invalid authorized Edge target")
        try:ip_address(record["ip"])
        except (ValueError,TypeError):raise ValueError("Numeric approved Edge address required")
    key_id=config["signing_key_id"]
    if not isinstance(key_id,str) or not 3<=len(key_id)<=128 or not key_id.isascii():
        raise ValueError("Invalid approval key ID")
    path=config["signing_key_path"]
    if not isinstance(path,str) or not Path(path).is_absolute() or (
        len(path)>300 or not path.endswith(".pem")):
        raise ValueError("Invalid private key path")
    # Loading the private key at startup is unnecessary; approval checks it
    # at each use, allowing safe revocation of file access.
    return config
