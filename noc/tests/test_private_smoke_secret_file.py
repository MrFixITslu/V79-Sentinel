"""Isolated synthetic staging-credential boundary; never accesses a real key."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "deploy/docker/smoke-private-pilot.py"
spec = importlib.util.spec_from_file_location("sentinel_isolated_smoke_secret_reader", SOURCE)
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


class PrivatePilotSmokeSecretTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.password = self.root / "fixture.txt"
        # Runtime-created synthetic data only; no actual account password.
        self.fixture = "Z" * 33 + "9"
        self.password.write_text(self.fixture)
        self.password.chmod(0o600)

    def load(self, path=None):
        return reader._read_private_pilot_password(self.password if path is None else path)

    def test_private_regular_password_fixture_passes_without_logging(self):
        self.assertEqual(self.load(), self.fixture)

    def test_world_and_group_readable_files_are_rejected(self):
        for mode in (0o644, 0o640, 0o666, 0o777):
            with self.subTest(mode=oct(mode)):
                self.password.chmod(mode)
                with self.assertRaises(RuntimeError) as err:
                    self.load()
                self.assertNotIn(self.fixture, str(err.exception))

    def test_final_symlink_rejected(self):
        link = self.root / "symlink"
        link.symlink_to(self.password)
        with self.assertRaises(RuntimeError):
            self.load(link)

    def test_symlink_in_intermediate_parent_rejected(self):
        parent = self.root / "real"
        parent.mkdir(mode=0o700)
        secret = parent / "secret"
        secret.write_text(self.fixture)
        secret.chmod(0o600)
        alias = self.root / "link"
        alias.symlink_to(parent, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            self.load(alias / "secret")

    def test_hardlink_rejected(self):
        alias = self.root / "another-name"
        os.link(self.password, alias)
        with self.assertRaises(RuntimeError):
            self.load()

    def test_nonregular_fifo_and_directory_rejected(self):
        fifo = self.root / "pipe"
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(RuntimeError):
            self.load(fifo)
        with self.assertRaises(RuntimeError):
            self.load(self.root)

    def test_empty_too_short_too_long_and_bad_encoding_denied(self):
        for data in (b"", b"short", b"x" * 257, b"\xff" * 12, b"z" * 30 + b"\n" + b"x" * 9):
            with self.subTest(data_len=len(data)):
                self.password.write_bytes(data)
                self.password.chmod(0o600)
                with self.assertRaises(RuntimeError):
                    self.load()

    def test_path_traversal_and_relative_paths_rejected(self):
        with self.assertRaises(RuntimeError):
            self.load(Path("relative.txt"))
        with self.assertRaises(RuntimeError):
            self.load(self.root / ".." / "other")

    def test_no_credential_content_in_errors(self):
        self.password.chmod(0o644)
        with self.assertRaises(RuntimeError) as err:
            self.load()
        self.assertNotIn(self.fixture, str(err.exception))
        self.assertNotIn(str(self.password), str(err.exception))

    def test_smoke_reader_does_not_inline_a_credential_or_send_mail(self):
        code = SOURCE.read_text(encoding="utf-8")
        self.assertIn("_read_private_pilot_password(PASSWORD)", code)
        self.assertNotIn("PASSWORD.read_text()", code)
        self.assertIn("os.O_NOFOLLOW", code)
        self.assertIn("os.fstat", code)
        self.assertNotIn("send_email(", code)
        self.assertNotIn("smtp.", code)


if __name__ == "__main__":
    unittest.main()
