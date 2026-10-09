#!/usr/bin/env python3
"""Small controls for the update source-pin/full-capture boundary."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).with_name("refresh-update-fixtures.py")
SPEC = importlib.util.spec_from_file_location("update_fixture", PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ProvenanceTests(unittest.TestCase):
    def test_source_pin_and_full_capture_remain_independent_and_fail_closed(self):
        valid = {"Version": MODULE.COREKIT_VERSION}
        MODULE.check_build_identity(MODULE.ORACLE_GO, valid)
        for version, module in [
            ("go1.26.9", valid),
            (MODULE.ORACLE_GO, {"Version": "v0.0.0"}),
            (MODULE.ORACLE_GO, dict(valid, Replace={})),
            (MODULE.ORACLE_GO, dict(valid, Replace={"Dir": "/untrusted"})),
        ]:
            with self.subTest(version=version, module=module):
                with self.assertRaises(RuntimeError):
                    MODULE.check_build_identity(version, module)
        files = ["go.mod", "production.go", "go.sum"]
        self.assertEqual(MODULE.source_pin_files(files), ["production.go"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in files:
                (root / name).write_bytes(name.encode())
            with patch.object(MODULE, "ROOT", root):
                full = MODULE.digest(files)
                pin = MODULE.digest(MODULE.source_pin_files(files))
                for name in ["go.mod", "go.sum"]:
                    (root / name).write_bytes(b"changed build manifest")
                    self.assertNotEqual(MODULE.digest(files), full)
                    self.assertEqual(MODULE.digest(MODULE.source_pin_files(files)), pin)
                    (root / name).write_bytes(name.encode())
                (root / "production.go").write_bytes(b"changed production behavior")
                self.assertNotEqual(MODULE.digest(files), full)
                self.assertNotEqual(MODULE.digest(MODULE.source_pin_files(files)), pin)


if __name__ == "__main__":
    unittest.main()
