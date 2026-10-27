import unittest
from noc.security_stage_zap import build_staging_zap_command

class StageZAPTests(unittest.TestCase):
 def get(self,**override):
  kw={"target":"http://127.0.0.1:8080","image":"ghcr.io/zaproxy/zaproxy@sha256:"+"a"*64,
      "approved":True,"staging_verified":True,
      "ci_environment":"true","environment_kind":"github-hosted"}
  kw.update(override)
  return build_staging_zap_command(**kw)
 def test_immutable_image_and_isolated_runner(self):
  c=self.get()
  self.assertEqual(c[:2],["docker","run"])
  self.assertIn("--read-only",c)
  self.assertIn("--cap-drop=ALL",c)
  self.assertIn("zap-baseline.py",c)
  self.assertIn("http://127.0.0.1:8080",c)
  self.assertNotIn("-a",c)
  self.assertNotIn("-j",c)
 def test_no_prod_scope_unsanctioned_runner_or_unpinned_supply_chain(self):
  for changes in [
    {"target":"https://hub.v79sl.com"},
    {"target":"http://127.0.0.1:8080/api/payments"},
    {"approved":False},
    {"staging_verified":False},
    {"ci_environment":""},
    {"environment_kind":"self-hosted"},
    {"image":"zaproxy/zap-stable"},
    {"image":"ghcr.io/zaproxy/zaproxy:latest"}]:
   with self.assertRaises(ValueError): self.get(**changes)

if __name__=="__main__":unittest.main()
