"""Source-free release verifier regression for both Linux executable aliases.

Validate real release workflow's inline archive verifier, not a compiled guest
binary. Every mutation gets an independent pristine positive restoration.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, make_tar, synthetic_executable,
)


class Wave2141LinuxELFTypes(unittest.TestCase):
    setUp = ReleaseArchiveValidation.setUp
    verify = ReleaseArchiveValidation.verify

    def _publish(self, binaries):
        make_tar(self.root / TARS[0], [
            (alias, data, "file") for alias, data in binaries.items()
        ])

    def test_independent_non_executable_elf_types_never_publish(self):
        original = synthetic_executable(TARS[0])
        for bad_type in (1, 4):  # ET_REL object, ET_CORE core dump
            for alias in ("atto", "oreslang"):
                with self.subTest(file_type=bad_type, binary=alias):
                    self.verify(True)
                    forged = bytearray(original)
                    forged[16:18] = bad_type.to_bytes(2, "little")
                    binaries = {"atto": original, "oreslang": original}
                    binaries[alias] = bytes(forged)
                    self._publish(binaries)
                    self.verify(False)
                    self._publish({"atto": original, "oreslang": original})
                    self.verify(True)

    def test_et_exec_remains_accepted_for_both_linux_aliases(self):
        original = synthetic_executable(TARS[0])
        executable = bytearray(original)
        executable[16:18] = (2).to_bytes(2, "little")
        for alias in ("atto", "oreslang"):
            with self.subTest(binary=alias):
                binaries = {"atto": original, "oreslang": original}
                binaries[alias] = bytes(executable)
                self._publish(binaries)
                self.verify(True)
        self._publish({"atto": bytes(executable), "oreslang": bytes(executable)})
        self.verify(True)


if __name__ == "__main__":
    unittest.main()
