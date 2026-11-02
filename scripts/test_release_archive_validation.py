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


def synthetic_executable(archive):
    # Minimal binary headers for format/CPU admission, not runnable programs.
    header = bytearray(256)
    if archive == TARS[0]:
        header[:4] = b"\x7fELF"
        header[4:6] = b"\x02\x01"
        header[18:20] = (62).to_bytes(2, "little")
    elif archive in TARS[1:]:
        header[:4] = b"\xcf\xfa\xed\xfe"
        cpu = 0x01000007 if archive == TARS[1] else 0x0100000c
        header[4:8] = cpu.to_bytes(4, "little")
    elif archive == ZIP:
        header[:2] = b"MZ"
        header[0x3c:0x40] = (128).to_bytes(4, "little")
        header[128:132] = b"PE\x00\x00"
        header[132:134] = (0x8664).to_bytes(2, "little")
    else:
        raise ValueError(archive)
    return bytes(header)


def make_tar(path, entries):
    with tarfile.open(path, "w:gz") as tar:
        for name, payload, kind in entries:
            member = tarfile.TarInfo(name)
            if kind == "file" and payload == b"binary":
                payload = synthetic_executable(path.name)
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
            if kind == "file" and payload == b"binary":
                payload = synthetic_executable(path.name)
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

    def test_linux_wrong_machine_rejected(self):
        wrong = bytearray(synthetic_executable(TARS[0]))
        wrong[18:20] = (183).to_bytes(2, "little")  # AArch64, not x86_64
        make_tar(self.root / TARS[0], [("atto", bytes(wrong), "file"), ("oreslang", b"binary", "file")])
        self.verify(False)

    def test_macos_intel_wrong_machine_rejected(self):
        wrong = synthetic_executable(TARS[2])  # arm64 Mach-O in x86_64 archive
        make_tar(self.root / TARS[1], [("atto", wrong, "file"), ("oreslang", b"binary", "file")])
        self.verify(False)

    def test_macos_arm_wrong_machine_rejected(self):
        wrong = synthetic_executable(TARS[1])  # x86_64 Mach-O in arm64 archive
        make_tar(self.root / TARS[2], [("atto", wrong, "file"), ("oreslang", b"binary", "file")])
        self.verify(False)

    def test_windows_wrong_machine_rejected(self):
        wrong = bytearray(synthetic_executable(ZIP))
        wrong[132:134] = (0xAA64).to_bytes(2, "little")  # ARM64, not AMD64
        make_zip(self.root / ZIP, [("atto.exe", bytes(wrong), "file"), ("oreslang.exe", b"binary", "file")])
        self.verify(False)

    def test_wrong_format_even_with_expected_member_names_rejected(self):
        make_tar(self.root / TARS[0], [("atto", synthetic_executable(TARS[1]), "file"), ("oreslang", b"binary", "file")])
        self.verify(False)


if __name__ == "__main__":
    unittest.main()
