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
            result = subprocess.run([sys.executable, str(Path(__file__).with_name("device_list_differential.py")), "--supervised", "--report", str(report)], capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"report already exists", result.stderr)
            self.assertEqual(report.read_bytes(), b"retained evidence")

    @unittest.skipIf(os.name == "nt", "POSIX process group regression; native Windows remains required")
    def test_timeout_kills_descendant_holding_pipe(self):
        # Parent exits while its descendant still owns stdout/stderr. The runner
        # must time out, kill the group, drain the pipes, and propagate timeout.
        code = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])"
        with tempfile.TemporaryDirectory() as cwd:
            with self.assertRaises(subprocess.TimeoutExpired):
                runner.run([sys.executable, "-c", code], cwd, os.environ.copy(), timeout=0.5)

    def test_yaml_is_compared_by_value_not_by_encoder_style(self):
        go = b"count: 2\ndevices:\n    - name: 'laptop<&>\xe2\x80\xa8'\n      added_at: \"2026-09-14T12:34:56+02:00\"\n    - name: second\nunmanaged_recipients:\n    - extra-key\n"
        rust = b"count: 2\ndevices:\n- name: 'laptop<&>\xe2\x80\xa8    '\n  added_at: 2026-09-14T12:34:56+02:00\n- name: second\nunmanaged_recipients:\n- extra-key\n"
        runner.compare_yaml(go, rust)
        self.assertEqual(runner.mini_yaml("count: 0\ndevices: []\n"), {"count": 0, "devices": []})
        with self.assertRaises(AssertionError):
            runner.compare_yaml(go, rust.replace(b"second", b"third"))
        with self.assertRaises(AssertionError):
            runner.compare_yaml(go, b"   \n")

    def test_yaml_comparison_is_type_strict(self):
        runner.compare_yaml(b"flag: true\ncount: 1\n", b"flag: true\ncount: 1\n")
        for left, right in ((b"flag: true\n", b"flag: 1\n"), (b"count: 1\n", b"count: 1.0\n"), (b"flag: false\n", b"flag: 0\n"),
                            (b"v: 1\n", b"v: '1'\n")):
            with self.assertRaisesRegex(AssertionError, "YAML values differ: \\$\\.", msg=(left, right)):
                runner.compare_yaml(left, right)
            with self.assertRaises(AssertionError):
                runner.compare_yaml(right, left)

    def test_report_validation_rejects_every_tampering(self):
        def row(seed, mode):
            negative = seed == "malformed"
            side = {"exit": 1 if negative else 0, "stdout_b64": b"" if negative else b"ok\n", "stderr_b64": b"boom" if negative else b""}
            side = {k: (v if k == "exit" else __import__("base64").b64encode(v).decode()) for k, v in side.items()}
            native = {"TimedOut": False, "Signal": "", "FilesBefore": [1], "Files": [1]}
            return {"id": f"{seed}/{mode}", "success": True, "negative": negative, "go": dict(side), "rust": dict(side),
                    "native": {"go": {"TimedOut": False, "Signal": "", "files_unchanged": True}, "rust": native}}
        report = {"head": "abc", "success": True, "mutation_rejected": True,
                  "cases": [row(seed, mode) for seed in runner.SEED_NAMES for mode, _ in runner.VARIANTS]}
        runner.validate_report(report, "abc")
        import copy
        for mutate in [lambda r: r.update(head="other"), lambda r: r.update(mutation_rejected=False),
                       lambda r: r["cases"].pop(), lambda r: r["cases"][0].update(success=False),
                       lambda r: r["cases"][0]["rust"].update(exit=2),
                       lambda r: r["cases"][0]["native"]["rust"].update(Files=[2]),
                       lambda r: r["cases"][-1]["go"].update(stdout_b64="b29wcw==")]:
            changed = copy.deepcopy(report)
            mutate(changed)
            with self.subTest(mutation=mutate), self.assertRaises((AssertionError, KeyError)):
                runner.validate_report(changed, "abc")


if __name__ == "__main__":
    unittest.main()
