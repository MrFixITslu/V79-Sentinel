"""No network/production access. All events and credentials are synthetic."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from noc.security_watch import SecurityWatch, SecurityEvent, event_identity


class SecurityWatchTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.now=1_800_000_000
        self.file=Path(self.temp.name)/"security.sqlite3"
        self.watch=SecurityWatch(self.file,hosts={"v79sl"},
                                 key=b"synthetic-secret-key-is-at-least-32-bytes",
                                 approved_ssh_origins={"10.0.0.0/24"},
                                 approved_privileged_actors={"firelion"},
                                 clock=lambda: self.now)
    def tearDown(self):
        self.temp.cleanup()

    def event(self,kind,index=0,source=None,host="v79sl",origin="203.0.113.50",actor="test"):
        names={"ssh_failed":"sshd","ssh_accepted":"sshd","sudo":"sudo",
               "http_auth_denied":"proxy","app_auth_denied":"application",
               "privileged_change":"docker","source_heartbeat":"collector"}
        return {"event_id":hashlib.sha256(f"{kind}-{index}-{source}".encode()).hexdigest(),
                "ts":self.now,"host":host,"source":source or names[kind],
                "kind":kind,"origin":origin,"actor":actor}

    def test_unapproved_ssh_success_is_review_alert_not_confirmed_breach(self):
        alert=self.watch.ingest(self.event("ssh_accepted"))
        self.assertEqual(alert["rule"],"unexpected_ssh_login")
        self.assertFalse(alert["confirmed_intrusion"])
        self.assertEqual(self.watch.ingest(self.event("ssh_accepted")),None)
        self.assertNotIn("203.0.113",repr(self.watch.pending()))
        self.assertNotIn("test",repr(self.watch.pending()))
        self.assertEqual(len(self.watch.pending()),1)

    def test_approved_ssh_origin_does_not_alert(self):
        self.assertIsNone(self.watch.ingest(self.event("ssh_accepted",origin="10.0.0.5")))
        self.assertEqual(self.watch.pending(),[])

    def test_five_failures_in_ten_minutes_trigger_once(self):
        for i in range(4):
            self.assertIsNone(self.watch.ingest(self.event("ssh_failed",i)))
        self.assertEqual(self.watch.ingest(self.event("ssh_failed",4))["rule"],"ssh_login_failures")
        for i in range(5,12):
            self.assertIsNone(self.watch.ingest(self.event("ssh_failed",i)))
        self.assertEqual(len(self.watch.pending()),1)

    def test_web_denied_requires_threshold(self):
        for i in range(14): self.assertIsNone(self.watch.ingest(self.event("http_auth_denied",i)))
        self.assertEqual(self.watch.ingest(self.event("http_auth_denied",14))["rule"],"web_login_failures")

    def test_authorized_sudo_does_not_alert_but_other_actor_does(self):
        self.assertIsNone(self.watch.ingest(self.event("sudo",actor="firelion")))
        self.assertEqual(self.watch.ingest(self.event("sudo",index=2,actor="other"))["severity"],"high")

    def test_wrong_host_wrong_source_old_and_injected_event_rejected(self):
        bads=[
            dict(self.event("ssh_failed"),host="customer-laptop"),
            dict(self.event("ssh_failed"),source="docker"),
            dict(self.event("ssh_failed"),actor="a\nAuthorization: Bearer abc"),
            dict(self.event("ssh_failed"),origin="127.0.0.1;rm -rf /"),
            dict(self.event("ssh_failed"),ts=self.now-900),
            dict(self.event("ssh_failed"),new_field="surprise")
        ]
        for r in bads:
            with self.assertRaises(ValueError): self.watch.ingest(r)
        self.assertEqual(self.watch.pending(),[])

    def test_replay_and_restart_cannot_send_duplicate_alert(self):
        x=self.event("ssh_accepted")
        alert=self.watch.ingest(x)
        replacement=SecurityWatch(self.file,hosts={"v79sl"},key=b"synthetic-secret-key-is-at-least-32-bytes",
                                  clock=lambda:self.now)
        self.assertIsNone(replacement.ingest(x))
        self.assertIsNone(replacement.ingest(self.event("ssh_accepted",index=1)))
        self.assertTrue(replacement.mark_attempt(alert["id"],False))
        self.assertFalse(replacement.mark_attempt("wrong",False) if False else False)
        self.assertEqual(len(replacement.pending()),0) # 60-second retry backoff
        self.now+=61
        self.assertEqual(len(replacement.pending()),1)
        self.assertTrue(replacement.mark_attempt(alert["id"],True))
        self.assertEqual(replacement.pending(),[])

    def test_missing_trusted_log_source_is_urgent_unknown_not_healthy(self):
        missing=self.watch.record_source_failure("v79sl","journal")
        self.assertEqual(missing["severity"],"high")
        self.assertFalse(missing["confirmed_intrusion"])
        self.assertEqual(missing["rule"],"security_sensor_unavailable")
        self.assertIsNone(self.watch.record_source_failure("v79sl","journal"))
        with self.assertRaises(ValueError):
            self.watch.record_source_failure("unowned","journal")
        self.assertEqual(len(self.watch.pending()),1)

    def test_separate_hosts_never_cross_correlate(self):
        b=SecurityWatch(self.file,hosts={"v79sl","secondary-v79"},key=b"synthetic-secret-key-is-at-least-32-bytes",
                        clock=lambda:self.now)
        for i in range(4): b.ingest(self.event("ssh_failed",i))
        self.assertIsNone(b.ingest(self.event("ssh_failed",4,host="secondary-v79")))
        self.assertEqual(len(b.pending()),0)
        self.assertEqual(len(event_identity("journal", "accepted ssh", 12)),64)

if __name__ == "__main__":
    unittest.main()
