"""Negative controls for the live device-list acceptance runner."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("device_list", Path(__file__).with_name("device_list_differential.py"))
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RunnerTests(unittest.TestCase):
    def test_changed_stdout_exit_and_error_stream_are_rejected(self):
        baseline = subprocess.CompletedProcess([], 0, b"ok\n", b"")
        for code, stdout, stderr in [(0, b"wrong\n", b""), (1, b"ok\n", b""), (0, b"ok\n", b"leak")]:
            with self.assertRaises(AssertionError):
                runner.compare(baseline, subprocess.CompletedProcess([], code, stdout, stderr))

    def test_failure_reaches_caller(self):
        with tempfile.TemporaryDirectory() as cwd:
            with self.assertRaises(RuntimeError):
                runner.checked([sys.executable, "-c", "raise SystemExit(7)"], cwd, os.environ.copy())

    def test_negative_comparator_rejects_success_leaks_and_silent_failure(self):
        baseline = subprocess.CompletedProcess([], 1, b"", b"error")
        for code, stdout, stderr in [(0, b"", b"error"), (1, b"leak", b"error"), (1, b"", b"")]:
            with self.assertRaises(AssertionError):
                runner.compare(baseline, subprocess.CompletedProcess([], code, stdout, stderr), negative=True)

    def test_manifest_detects_empty_directory_creation(self):
        with tempfile.TemporaryDirectory() as cwd:
            root = Path(cwd)
            before = runner.manifest(root)
            (root / "unexpected").mkdir()
            self.assertNotEqual(runner.manifest(root), before)

    def test_existing_report_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as cwd:
            report = Path(cwd) / "existing.json"
            report.write_bytes(b"retained evidence")
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("device_list_differential.py")), "--report", str(report)], capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report.read_bytes(), b"retained evidence")

    @unittest.skipIf(os.name == "nt", "POSIX process group regression; native Windows remains required")
    def test_timeout_kills_descendant_holding_pipe(self):
        # Parent exits while its descendant still owns stdout/stderr. The runner
        # must time out, kill the group, drain the pipes, and propagate timeout.
        code = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])"
        with tempfile.TemporaryDirectory() as cwd:
            with self.assertRaises(subprocess.TimeoutExpired):
                runner.run([sys.executable, "-c", code], cwd, os.environ.copy(), timeout=0.5)


if __name__ == "__main__":
    unittest.main()
