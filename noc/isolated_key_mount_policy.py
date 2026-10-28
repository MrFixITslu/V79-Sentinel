"""Metadata-only preflight for an owner-provisioned isolated signer key.

Does NOT open, read, generate, export, install, rotate or load any private key.
Caller must separately review container mount source, parent path ancestry,
UID namespace mapping, immutable image digest and signer process identity.
This is NOT an authorisation to deploy or use the key.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path


def verify_isolated_key_mount(*, key_path: str, approved_dir: str,
                              expected_uid: int) -> dict:
    """Fail closed on symlinks, traversal, unsafe owner/mode or linked secrets.

    The approved root must be a private 0700/0500 directory owned by the
    expected non-root UID. Secret must be a single-link regular 0400/0600
    file within it. This is a metadata guard, NOT cryptographic key proof.
    """
    if (type(key_path) is not str or type(approved_dir) is not str
            or not key_path.startswith("/") or not approved_dir.startswith("/")
            or type(expected_uid) is not int or expected_uid <= 0
            or os.path.normpath(key_path) != key_path
            or os.path.normpath(approved_dir) != approved_dir
            or approved_dir == "/"
            or key_path == approved_dir):
        raise ValueError("INVALID_ISOLATED_KEY_POLICY")
    root = Path(approved_dir)
    candidate = Path(key_path)
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        raise ValueError("KEY_OUTSIDE_APPROVED_MOUNT") from None
    if not relative.parts:
        raise ValueError("INVALID_KEY_FILE")

    try:
        root_stat = os.lstat(root)
        if (not stat.S_ISDIR(root_stat.st_mode)
                or root_stat.st_uid != expected_uid
                or stat.S_IMODE(root_stat.st_mode) not in (0o500, 0o700)):
            raise ValueError("INSECURE_APPROVED_KEY_DIRECTORY")
        parent = root
        for part in relative.parts[:-1]:
            parent = parent / part
            info = os.lstat(parent)
            if (not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != expected_uid
                    or stat.S_IMODE(info.st_mode) not in (0o500, 0o700)):
                raise ValueError("INSECURE_INTERMEDIATE_KEY_DIRECTORY")
        info = os.lstat(candidate)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != expected_uid
                or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)):
            raise ValueError("INSECURE_KEY_FILE_METADATA")
    except OSError:
        raise ValueError("KEY_MOUNT_NOT_ACCESSIBLE") from None
    return {
        "keyMetadataAccepted": True,
        "keyMaterialRead": False,
        "collectorIdentityVerified": False,
        "authorizedToDeploy": False,
    }
