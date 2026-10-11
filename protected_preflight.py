"""Offline, non-secret preflight for protected-app test accounts.

This module never logs in or sends any network requests. It produces only
status metadata for planning a dedicated synthetic-account QA tenant.
"""
from __future__ import annotations
import json
from pathlib import Path

POLICY = Path(__file__).resolve().parent / "qa" / "protected-qa-policy.json"
REQUIRED = (
    "testOrganizationVerified",
    "syntheticAccountsProvided",
    "permissionsReviewed",
    "dedicatedTestDataVerified",
    "accountIsolationVerified",
    "credentialStorageReviewed",
    "signedApprovalToExecute",
    "cleanupWorkflowVerified",
    "externalAppDeprovisionVerified",
)

def protected_readiness():
    try:
        doc = json.loads(POLICY.read_text(encoding="utf-8"))
        gates = doc["gates"]
        if doc.get("schema_version") != 1 or not isinstance(gates,dict):
            raise ValueError("Unexpected policy format")
        checklist = [{
            "name": item,
            "ready": gates.get(item) is True,
        } for item in REQUIRED]
        complete = sum(v["ready"] for v in checklist)
        # A ready checklist is NOT authority to run automated logins;
        # execution must be implemented/reviewed as a separate release.
        return {
            "mode": "preflight-only",
            "state": "blocked" if complete < len(REQUIRED) or doc.get("enabled") is not True
                     else "awaiting-separate-release-review",
            "complete": complete,
            "total": len(REQUIRED),
            "checklist": checklist,
            "protected_apps": [row["app"] for row in doc.get("flows",[])],
            "automation_enabled": False,
            "message": "Test organization and synthetic users NOT created. Cleanup and external app deprovision must be verified before protected workflows. No credentials stored.",
        }
    except (OSError,KeyError,TypeError,ValueError, json.JSONDecodeError):
        return {"mode": "preflight-only","state":"blocked","complete":0,"total":len(REQUIRED),
                "checklist":[],"protected_apps":[],"automation_enabled":False,
                "message":"Test-account policy missing or invalid. No protected workflows will run."}
