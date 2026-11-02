"""Executable negative fixtures for the inline, no-checkout release publisher."""
import io
import pathlib
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

REPO = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = (REPO / ".github/workflows/release.yml").read_text()
LINES = WORKFLOW.splitlines()
START = next(i for i, line in enumerate(LINES) if line.strip() == 'python3 - "$PWD/dist" <<\'PY\'')
END = next(i for i in range(START + 1, len(LINES)) if LINES[i].strip() == "PY")
SCRIPT = "\n".join(line[10:] for line in LINES[START + 1:END]) + "\n"
TARS = ("oreslang-linux-x86_64.tar.gz", "oreslang-macos-x86_64.tar.gz", "oreslang-macos-aarch64.tar.gz")
ZIP = "oreslang-windows-x86_64.zip"


def make_tar(path, entries):
    with tarfile.open(path, "w:gz") as tar:
        for name, payload, kind in entries:
            member = tarfile.TarInfo(name)
            if kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = "oreslang"
                tar.addfile(member)
            else:
                member.size = len(payload)
                tar.addfile(member, io.BytesIO(payload))


def make_zip(path, entries):
    with zipfile.ZipFile(path, "w") as zipped:
        for name, payload, kind in entries:
            member = zipfile.ZipInfo(name)
            if kind == "symlink":
                member.create_system = 3
                member.external_attr = (stat.S_IFLNK | 0o777) << 16
            zipped.writestr(member, payload)


class ReleaseArchiveValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        for name in TARS:
            make_tar(self.root / name, [("atto", b"binary", "file"), ("oreslang", b"binary", "file")])
        make_zip(self.root / ZIP, [("atto.exe", b"binary", "file"), ("oreslang.exe", b"binary", "file")])

    def verify(self, should_pass):
        proc = subprocess.run([sys.executable, "-c", SCRIPT, str(self.root)], capture_output=True, text=True)
        self.assertEqual(proc.returncode == 0, should_pass, proc.stderr)

    def test_valid_archives(self):
        self.verify(True)

    def test_tar_symlink_rejected(self):
        make_tar(self.root / TARS[0], [("atto", b"binary", "file"), ("oreslang", b"", "symlink")])
        self.verify(False)

    def test_tar_duplicate_rejected(self):
        make_tar(self.root / TARS[0], [("atto", b"binary", "file"), ("atto", b"binary", "file"), ("oreslang", b"binary", "file")])
        self.verify(False)

    def test_tar_extra_member_rejected(self):
        make_tar(self.root / TARS[0], [("atto", b"binary", "file"), ("oreslang", b"binary", "file"), ("extra", b"binary", "file")])
        self.verify(False)

    def test_tar_empty_binary_rejected(self):
        make_tar(self.root / TARS[0], [("atto", b"", "file"), ("oreslang", b"binary", "file")])
        self.verify(False)

    def test_zip_symlink_rejected(self):
        make_zip(self.root / ZIP, [("atto.exe", b"binary", "file"), ("oreslang.exe", b"oreslang.exe", "symlink")])
        self.verify(False)

    def test_zip_duplicate_rejected(self):
        make_zip(self.root / ZIP, [("atto.exe", b"binary", "file"), ("atto.exe", b"binary", "file"), ("oreslang.exe", b"binary", "file")])
        self.verify(False)

    def test_zip_extra_member_rejected(self):
        make_zip(self.root / ZIP, [("atto.exe", b"binary", "file"), ("oreslang.exe", b"binary", "file"), ("extra", b"binary", "file")])
        self.verify(False)

    def test_zip_empty_binary_rejected(self):
        make_zip(self.root / ZIP, [("atto.exe", b"", "file"), ("oreslang.exe", b"binary", "file")])
        self.verify(False)


if __name__ == "__main__":
    unittest.main()
