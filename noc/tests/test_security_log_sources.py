import tempfile
import unittest
from pathlib import Path
from noc.security_watch import SecurityWatch
from noc.security_log_sources import parse_journal_entry, parse_proxy_access_json, safe_process_records

class LogSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.now=1_800_000_000
        self.watch=SecurityWatch(Path(self.temp.name)/"security.db",hosts={"v79sl"},
             key=b"synthetic-correlation-key-very-long-minimum-32-bytes",
             clock=lambda:self.now)
    def tearDown(self):
        self.temp.cleanup()
    def journal(self,msg,identifier="sshd",cursor="s=1"):
        return {"SYSLOG_IDENTIFIER":identifier,"MESSAGE":msg,
                "__REALTIME_TIMESTAMP":str(self.now*1000000),"__CURSOR":cursor}
    def test_ssh_success_unknown_source_generates_review_alert(self):
        record=parse_journal_entry(self.journal(
           "Accepted publickey for firelion from 203.0.113.20 port 443 ssh2"),host="v79sl")
        self.assertEqual(record["kind"],"ssh_accepted")
        self.assertEqual(self.watch.ingest(record)["rule"],"unexpected_ssh_login")
    def test_failed_ssh_and_sudo_parse_without_injection(self):
        f=parse_journal_entry(self.journal(
          "Failed password for invalid user guest from 203.0.113.20 port 2222 ssh2"),host="v79sl")
        self.assertEqual(f["kind"],"ssh_failed")
        u=parse_journal_entry(self.journal(
          "pam_unix(sudo:session): session opened for user root by unknown(uid=1000)",
          identifier="sudo",cursor="s=2"),host="v79sl")
        self.assertEqual(u["actor"],"unknown")
        self.assertIsNone(parse_journal_entry(self.journal("User supplied: Bearer eyA"),host="v79sl"))
    def test_proxy_auth_failure_but_expected_guest_access_ignored(self):
        base={"method":"POST","path":"/api/auth/login","status":401,
              "event_id":"r1","remote_addr":"203.0.113.20",
              "timestamp":"2027-01-15T08:00:00Z"}
        r=parse_proxy_access_json(base,host="v79sl")
        self.assertEqual(r["kind"],"http_auth_denied")
        self.assertIsNone(parse_proxy_access_json({**base,"path":"/api/auth/me"},host="v79sl"))
        self.assertIsNone(parse_proxy_access_json({**base,"path":"/api/posts"},host="v79sl"))
        self.assertIsNone(parse_proxy_access_json({**base,"method":"GET"},host="v79sl"))
    def test_invalid_log_objects_and_bounded_processing(self):
        self.assertIsNone(parse_proxy_access_json({"status":401},host="v79sl"))
        self.assertIsNone(parse_journal_entry(self.journal("Accepted publickey for x from badhost port 22"),host="v79sl"))
        records=[self.journal("Failed password for guest from 203.0.113.20 port 22 ssh2",cursor="s="+str(i)) for i in range(8)]
        metrics=safe_process_records(self.watch,records,parse_journal_entry,host="v79sl",maximum=5)
        self.assertEqual(metrics["processed"],5)
        self.assertEqual(metrics["new_alerts"],1)

if __name__=="__main__":unittest.main()
