#!/usr/bin/env python3
"""One wiring regression; process mocks are not production recovery evidence."""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import run_go_tests


class BootstrapCheck(unittest.TestCase):
    def test_bootstrap_and_all_vault_callers(self):
        argv = ["cargo", "+stable", "--", "go", "test", "./...", "-race"]
        for binary in ["/external rust build/debug/symvault",
                       "C:\\cargo target\\debug\\symvault.exe"]:
            artifact = json.dumps({"reason": "compiler-artifact",
                                   "target": {"name": "symvault", "kind": ["bin"]},
                                   "executable": binary})
            with patch.dict(os.environ, {"CARGO_TARGET_DIR": "external rust build"}, clear=True), \
                    patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, artifact)) as build, \
                    patch.object(subprocess, "call", return_value=17) as go:
                self.assertEqual(run_go_tests.main(argv), 17)
                self.assertEqual(build.call_args.args[0],
                                 ["cargo", "+stable", "build", "-p", "symvault-cli", "--bin",
                                  "symvault", "--locked", "--message-format=json"])
                self.assertEqual(build.call_args.kwargs["encoding"], "utf-8")
                self.assertEqual(go.call_args.args[0], argv[3:])
                self.assertEqual(go.call_args.kwargs["env"]["SYMVAULT_RUST_BINARY"], binary)
                self.assertEqual(go.call_args.kwargs["env"]["CARGO_TARGET_DIR"], "external rust build")
                self.assertNotIn("SYMVAULT_RUST_BINARY", os.environ)
        with patch.dict(os.environ, {"SYMVAULT_RUST_BINARY": "/explicit caller binary"}, clear=True), \
                patch.object(subprocess, "run") as build, \
                patch.object(subprocess, "call", return_value=19) as go:
            self.assertEqual(run_go_tests.main(argv), 19)
            build.assert_not_called()
            self.assertEqual(go.call_args.kwargs["env"]["SYMVAULT_RUST_BINARY"], "/explicit caller binary")
        for code, output in [(23, "build failed"), (0, ""), (0, "invalid json")]:
            with patch.dict(os.environ, {}, clear=True), \
                    patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], code, output)), \
                    patch.object(subprocess, "call") as go, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(run_go_tests.main(argv), code or 1)
                go.assert_not_called()
        root = Path(__file__).resolve().parent.parent
        for target in ["test", "test-fast", "test-race", "test-coverage", "test-coverage-html",
                       "test-core", "test-core-coverage", "test-vault", "test-bench", "cover", "test-ci"]:
            command = subprocess.check_output(["make", "-n", target], cwd=root, text=True)
            self.assertIn("python3 scripts/run_go_tests.py cargo -- go test ", command, target)
        for target in ["test-config", "test-crypto"]:
            command = subprocess.check_output(["make", "-n", target], cwd=root, text=True)
            self.assertNotIn("run_go_tests.py", command, target)


if __name__ == "__main__":
    unittest.main()
