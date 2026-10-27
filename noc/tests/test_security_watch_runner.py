import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from noc.security_watch import SecurityWatch
from noc.security_watch_runner import load_owner_policy, cycle, read_journal, JOURNAL_COMMAND

class RunnerTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory()
  self.path=Path(self.temp.name)/"owner.json"
  self.db=Path(self.temp.name)/"security.sqlite3"
  self.config={"enabled":True,"hostname":"test-owned-host",
   "approved_ssh_origins":["10.0.0.0/24"],"approved_privileged_actors":["firelion"],
   "email_enabled":False,"alert_from":"alerts@v79sl.com","alert_to":"owner@example.invalid"}
  self.path.write_text(json.dumps(self.config))
  self.path.chmod(0o600)
  self.now=1800000000
  self.watch=SecurityWatch(self.db,hosts={"test-owned-host"},
      key=b"synthetic-unique-long-event-signing-key-for-tests",
      clock=lambda:self.now)
 def tearDown(self):self.temp.cleanup()
 def test_missing_or_world_readable_policy_denied(self):
  self.assertEqual(load_owner_policy(self.path,"test-owned-host"),self.config)
  self.path.chmod(0o644)
  with self.assertRaises(ValueError): load_owner_policy(self.path,"test-owned-host")
  self.path.chmod(0o600)
  with self.assertRaises(ValueError): load_owner_policy(self.path,"wrong-host")
 def test_no_send_when_no_explicit_double_opt_in(self):
  logs=[{"__CURSOR":"synthetic-cursor-1","__REALTIME_TIMESTAMP":str(self.now*1000000),
     "SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted publickey for admin from 203.0.113.20 port 22 ssh2"}]
  with patch("noc.security_watch_runner.send_security_notification",side_effect=AssertionError("No mail allowed")):
   out=cycle(self.watch,self.config,logs,alerts_allowed=False)
  self.assertEqual(out["new_alerts"],1)
  self.assertEqual(out["email_sent"],0)
  self.assertEqual(out["email_pending"],1)
 def test_journal_fixed_arguments_and_failed_feed(self):
  self.assertNotIn("sudo",JOURNAL_COMMAND[:1])
  class Result:
   returncode=1
   stdout=b""
  with patch("noc.security_watch_runner.subprocess.run",return_value=Result()) as call:
   with self.assertRaises(RuntimeError):read_journal()
   self.assertEqual(call.call_args.args[0],JOURNAL_COMMAND)

if __name__=="__main__":unittest.main()
