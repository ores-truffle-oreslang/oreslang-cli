"""Exact release publisher rejects executable-name spoofing on all targets.

Real source-owned inline archive verifier, synthetic binary headers only.
No compiled or runnable native guest payload is claimed.
"""
import unittest
from test_release_archive_validation import (
    ReleaseArchiveValidation, TARS, ZIP, make_tar, make_zip,
)

class ExecutableMemberNameAdmission(unittest.TestCase):
    setUp=ReleaseArchiveValidation.setUp
    verify=ReleaseArchiveValidation.verify

    def test_tar_alias_names_must_be_exact_in_all_three_targets(self):
        originals=("atto","oreslang")
        for target in TARS:
            for index in (0,1):
                name=originals[index]
                for forged in ("./"+name, "bin/"+name, name.upper()):
                    with self.subTest(target=target,alias=name,forged=forged):
                        members=[(n,b"binary","file") for n in originals]
                        members[index]=(forged,b"binary","file")
                        make_tar(self.root/target,members)
                        self.verify(False)
                        make_tar(self.root/target,[
                            (n,b"binary","file") for n in originals
                        ])
                        self.verify(True)

    def test_windows_executable_members_reject_case_path_and_extension_aliases(self):
        originals=("atto.exe","oreslang.exe")
        for index in (0,1):
            name=originals[index]
            for forged in ("./"+name, "bin/"+name, name.upper(), name+".bak"):
                with self.subTest(alias=name,forged=forged):
                    members=[(n,b"binary","file") for n in originals]
                    members[index]=(forged,b"binary","file")
                    make_zip(self.root/ZIP,members)
                    self.verify(False)
                    make_zip(self.root/ZIP,[
                        (n,b"binary","file") for n in originals
                    ])
                    self.verify(True)

if __name__=="__main__":
    unittest.main()
