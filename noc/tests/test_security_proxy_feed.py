import json
import os
import tempfile
import unittest
from pathlib import Path
from noc.security_proxy_feed import read_owned_proxy_jsonl

class ProxyFeedTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory()
  self.root=Path(self.temp.name)
  self.file=self.root/"proxy-security.jsonl"
  self.file.write_text(json.dumps({"event_id":"req-1","method":"POST","path":"/api/auth/login",
        "status":401,"remote_addr":"203.0.113.20",
        "timestamp":"2027-01-15T08:00:00Z"})+"\n")
  self.file.chmod(0o640)
 def tearDown(self):self.temp.cleanup()
 def call(self,path):
  return read_owned_proxy_jsonl(path,approved_root=self.root,owner_uid=os.getuid())
 def test_only_owner_scoped_regular_jsonl(self):
  x=self.call(self.file)
  self.assertEqual(len(x),1)
  self.assertEqual(x[0]["status"],401)
  self.assertFalse(self.file.is_symlink())
 def test_reject_symlink_nonjson_and_world_writable_feed(self):
  link=self.root/"proxy-link.jsonl"
  link.symlink_to(self.file)
  with self.assertRaises(ValueError):self.call(link)
  bad=self.root/"bad.txt"
  bad.write_text("{}\n")
  with self.assertRaises(ValueError):self.call(bad)
  self.file.chmod(0o666)
  with self.assertRaises(ValueError):self.call(self.file)
 def test_reject_directory_escape(self):
  foreign=self.root.parent/"outsider.jsonl"
  with self.assertRaises(ValueError):self.call(foreign)

if __name__=="__main__":unittest.main()
