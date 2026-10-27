import unittest
from noc.security_scan_policy import authorize_scan

class ScanPolicyTests(unittest.TestCase):
    def test_stage_zap_passive_requires_explicit_approval_and_loopback(self):
        ok=authorize_scan(mode="zap-passive-baseline",target="http://127.0.0.1:8080",
                          production=False,approval="APPROVED_STAGING_PASSIVE")
        self.assertTrue(ok.allowed)
        for target in ("https://hub.v79sl.com","http://169.254.169.254:8080",
                       "http://localhost:8080","http://127.0.0.1:5432",
                       "http://127.0.0.1:8080/api/payments",
                       "http://127.0.0.1:8080/?admin=1"):
            self.assertFalse(authorize_scan(mode="zap-passive-baseline",target=target,production=False,
                                            approval="APPROVED_STAGING_PASSIVE").allowed)
        self.assertFalse(authorize_scan(mode="zap-passive-baseline",target="http://127.0.0.1:8080",
                                        production=True,approval="APPROVED_STAGING_PASSIVE").allowed)
    def test_no_active_pentesting_or_open_redirect_targets(self):
        for mode in ("active","zap-full","fuzz","nmap","sqlmap"):
            self.assertFalse(authorize_scan(mode=mode,target="http://127.0.0.1:8080",
                                            production=False,approval="APPROVED_STAGING_PASSIVE").allowed)
        self.assertTrue(authorize_scan(mode="head-headers",target="https://hub.v79sl.com/",
                                       production=True,approval="APPROVED_OWNED_HEAD").allowed)
        self.assertFalse(authorize_scan(mode="head-headers",target="https://attacker.invalid",
                                        production=True,approval="APPROVED_OWNED_HEAD").allowed)

if __name__=="__main__": unittest.main()
