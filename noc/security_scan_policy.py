"""Fail-closed scan scope for Sentinel. Active tests are NEVER permitted here.

Passive baseline crawling can still generate HTTP requests. Run ZAP baseline
only against a disposable loopback staging clone after explicit human approval.
Production services use Sentinel's existing single-HEAD HTTPS check.
"""
from dataclasses import dataclass
from urllib.parse import urlsplit
import ipaddress

@dataclass(frozen=True)
class ScanDecision:
    mode: str
    target: str
    allowed: bool
    reason: str

def authorize_scan(*, mode, target, production, approval, approved_local_ports=(8080,)):
    if mode not in ("head-headers", "zap-passive-baseline"):
        return ScanDecision(str(mode), str(target), False, "Active/unknown scan prohibited")
    try:
        p=urlsplit(target)
        if p.username or p.password or p.query or p.fragment or p.path not in ("", "/"):
            raise ValueError("Only approved origin roots permitted")
        if mode == "zap-passive-baseline":
            # No arbitrary URLs, userinfo, wildcard subdomains or redirected public scope.
            ip=ipaddress.ip_address(p.hostname or "")
            if production or p.scheme != "http" or not ip.is_loopback or p.port not in approved_local_ports:
                raise ValueError("ZAP may only scan isolated loopback staging")
            if approval != "APPROVED_STAGING_PASSIVE":
                raise ValueError("Explicit per-run staging approval required")
            return ScanDecision(mode,target,True,"Staging-only passive crawler: max duration and rate capped by runner")
        # Existing continuous HEAD checks are independently allowlisted by monitor_core.
        if p.scheme != "https" or p.port not in (None,443):
            raise ValueError("HEAD requires HTTPS 443")
        host=(p.hostname or "").lower()
        if host != "v79sl.com" and not host.endswith(".v79sl.com"):
            raise ValueError("Only owner-controlled V79 hostnames")
        if approval != "APPROVED_OWNED_HEAD":
            raise ValueError("Approved owner target inventory required")
        return ScanDecision(mode,target,True,"One HEAD only; never crawl or submit forms")
    except (ValueError, AttributeError):
        return ScanDecision(str(mode),str(target),False,"Target/scope/approval not permitted")
