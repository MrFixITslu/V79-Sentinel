#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import protected_preflight

class ProtectedReadinessTests(unittest.TestCase):
    def setUp(self):
        self.original=protected_preflight.POLICY.read_text(encoding='utf-8')

    def load_temp(self, data):
        self.tmp=tempfile.TemporaryDirectory()
        p=Path(self.tmp.name)/'policy.json'
        p.write_text(json.dumps(data),encoding='utf-8')
        self.addCleanup(self.tmp.cleanup)
        self.patch=patch.object(protected_preflight,'POLICY',p)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_disabled_and_no_credentials(self):
        data=json.loads(self.original)
        self.load_temp(data)
        result=protected_preflight.protected_readiness()
        self.assertEqual(result['state'],'blocked')
        self.assertEqual(result['complete'],0)
        self.assertFalse(result['automation_enabled'])
        self.assertEqual(result['total'],9)
        self.assertNotIn('password',str(result).lower())

    def test_even_when_gates_ready_not_executed(self):
        data=json.loads(self.original)
        data['enabled']=True
        data['gates']={k:True for k in data['gates']}
        self.load_temp(data)
        result=protected_preflight.protected_readiness()
        self.assertEqual(result['state'],'awaiting-separate-release-review')
        self.assertFalse(result['automation_enabled'])

    def test_bad_manifest_disables(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'policy.json'
            p.write_text('{bad')
            with patch.object(protected_preflight,'POLICY',p):
                result=protected_preflight.protected_readiness()
                self.assertEqual(result['state'],'blocked')
                self.assertFalse(result['automation_enabled'])

if __name__=='__main__':
    unittest.main(verbosity=2)
