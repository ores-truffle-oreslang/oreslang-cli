"""Host-only integration tests for guarded, atomic Homebrew formula publication.

No native compiler, Homebrew installation, or artifact provenance is claimed.
"""
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

GENERATOR = Path(__file__).resolve().parents[1] / "packaging" / "homebrew" / "generate-formula.sh"
ARM_SHA = "a" * 64
INTEL_SHA = "b" * 64


class HomebrewAtomicOutput(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="atto-brew-3506-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def invoke(self, destination, tag="v1.2.3", arm=ARM_SHA, intel=INTEL_SHA):
        return subprocess.run(
            ["bash", str(GENERATOR), tag, arm, intel, str(destination)],
            check=False, capture_output=True, text=True,
        )

    def assert_no_temp_files(self, parent):
        self.assertEqual(list(parent.glob(".oreslang-formula.*")), [])

    def test_invalid_metadata_never_overwrites_existing_release(self):
        destination = self.root / "published.rb"
        marker = b"existing-approved-formula\n"
        destination.write_bytes(marker)
        for tag, sha in [("v1.2.3;echo unsafe", ARM_SHA),
                         ("v1.2.3", "not-a-digest"),
                         ("v1.2.3", "g" * 64)]:
            with self.subTest(tag=tag, sha=sha):
                result = self.invoke(destination, tag=tag, arm=sha)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(destination.read_bytes(), marker)
                self.assert_no_temp_files(self.root)

    def test_symlink_and_hardlink_destinations_preserve_external_sentinel(self):
        sentinel = self.root / "trusted.rb"
        marker = b"trusted-content-keep\n"
        sentinel.write_bytes(marker)
        destination = self.root / "linked.rb"
        try:
            destination.symlink_to(sentinel)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        result = self.invoke(destination)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(destination.is_symlink())
        self.assertEqual(sentinel.read_bytes(), marker)
        self.assert_no_temp_files(self.root)

        destination.unlink()
        try:
            os.link(sentinel, destination)
        except OSError:
            self.skipTest("hardlinks unavailable")
        result = self.invoke(destination)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_bytes(), marker)
        self.assertEqual(destination.read_bytes(), marker)
        self.assert_no_temp_files(self.root)

    def test_existing_directory_is_not_a_formula_file(self):
        destination = self.root / "existing-directory"
        destination.mkdir()
        self.assertNotEqual(self.invoke(destination).returncode, 0)
        self.assertTrue(destination.is_dir())
        self.assertEqual(list(destination.iterdir()), [])
        self.assert_no_temp_files(self.root)

    def test_successful_unicode_and_dash_paths_are_deterministic_and_atomic(self):
        for name in ("Formula.rb", "-dash-name.rb"):
            with self.subTest(name=name):
                destination = self.root / "日本語 folder" / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"previous-approved-formula\n")
                first = self.invoke(destination)
                self.assertEqual(first.returncode, 0, first.stderr)
                contents = destination.read_bytes()
                self.assertIn(b'version "1.2.3"', contents)
                self.assertIn(ARM_SHA.encode(), contents)
                self.assertIn(INTEL_SHA.encode(), contents)
                self.assertIn(b'bin.install "atto", "oreslang", "oreslang-compiler"', contents)
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o644)
                self.assert_no_temp_files(destination.parent)

                again = self.invoke(destination)
                self.assertEqual(again.returncode, 0, again.stderr)
                self.assertEqual(destination.read_bytes(), contents)
                self.assert_no_temp_files(destination.parent)


if __name__ == "__main__":
    unittest.main()
