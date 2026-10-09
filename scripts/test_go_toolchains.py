#!/usr/bin/env python3
"""Check patched product builds without changing the historical oracle compiler."""

import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]


class GoToolchainTests(unittest.TestCase):
    def test_product_and_oracle_compilers_are_separate(self):
        env = os.environ.copy()
        for name in ("GOTOOLCHAIN", "GO_TOOLCHAIN", "BUILD_GO_TOOLCHAIN", "MAKEFLAGS", "MFLAGS"):
            env.pop(name, None)
        result = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "Makefile", "-f", "-",
             "check-toolchain-selection"],
            input=(".PHONY: check-toolchain-selection\n"
                   "check-toolchain-selection:\n"
                   "\t@$(GO) env GOVERSION\n"
                   "\t@GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) env GOVERSION\n"),
            cwd=ROOT, env=env, text=True, capture_output=True, timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["go1.26.9", "go1.26.6"])
        self.assertIn("\ntoolchain go1.26.9\n", (ROOT / "go.mod").read_text())


if __name__ == "__main__":
    unittest.main()
