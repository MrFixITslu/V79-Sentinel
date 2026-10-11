#!/usr/bin/env python3
"""Tests for Sentinel QA report serving and path traversal protections."""
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import qa_results

class QATests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.base=pathlib.Path(self.tmp.name)
        self.runs=self.base/"qa-runs"
        self.runs.mkdir()
        self.latest=self.base/"qa-latest.json"
        self.run="20261009T215616Z"
        self.path=self.runs/self.run
        self.path.mkdir()
        self.name="website-desktop.png"
        self.report={
            "version":1, "mode":"public-browser-qa","runId":self.run,
            "complete":True,"results":[{"name":"Website","viewport":"desktop",
                                         "status":"pass","screenshot":self.name}]}
        self.latest.write_text(json.dumps(self.report))
        (self.path/"report.json").write_text(json.dumps(self.report))
        (self.path/self.name).write_bytes(b"\x89PNG\r\n\x1a\n"+b"x"*48)
        self.patches=[
            patch.object(qa_results,"LATEST",self.latest),
            patch.object(qa_results,"RUNS",self.runs)
        ]
        for p in self.patches:p.start()

    def tearDown(self):
        for p in self.patches:p.stop()
        self.tmp.cleanup()

    def test_completed_run(self):
        self.assertEqual(qa_results.load_qa_latest()["state"],"complete")
        self.assertEqual(qa_results.screenshot(self.run,self.name)[:4],b"\x89PNG")

    def test_incomplete_not_accepted(self):
        self.report["complete"]=False
        self.latest.write_text(json.dumps(self.report))
        self.assertEqual(qa_results.load_qa_latest()["state"],"error")

    def test_path_traversal_denied(self):
        for run,name in [(self.run,"../../etc/passwd"),("../etc","website-desktop.png"),
                         (self.run,"unlisted-desktop.png"),(self.run,"website-desktop.svg")]:
            with self.subTest(run=run,name=name):
                self.assertIsNone(qa_results.screenshot(run,name))

    def test_symlink_not_followed(self):
        (self.path/self.name).unlink()
        (self.path/self.name).symlink_to(self.latest)
        self.assertIsNone(qa_results.screenshot(self.run,self.name))

if __name__=="__main__":
    unittest.main(verbosity=2)
