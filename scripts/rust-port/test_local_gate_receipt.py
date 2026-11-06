#!/usr/bin/env python3
"""Tests of receipt() in local-gate-receipt.sh (sourced by local-gate.sh).

`area_complete` must be true only for a clean, unnarrowed run that executed
exactly the expected target list and exited 0.
LOCAL_GATE_RECEIPT_LIB=<path> runs the cases against a mutated copy (guard-revert
controls).
"""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIB = Path(os.environ.get("LOCAL_GATE_RECEIPT_LIB", HERE / "local-gate-receipt.sh"))
TARGETS = ["alpha", "beta", "gamma"]


def log_text(ran=None, expected=None, partial="false"):
    ran = TARGETS if ran is None else ran
    expected = TARGETS if expected is None else expected
    lines = [f"area-expected: lane=macos {' '.join(expected)}", f"area-partial: {partial}",
             f"area-targets: lane=macos {' '.join(ran)}"]
    lines += [f"area-target: {t} exit=0 secs=1" for t in ran]
    return "\n".join(lines) + "\n"


class Receipt(unittest.TestCase):
    def receipt(self, text, *, dirty="false", exit_code="0", target="macos-area"):
        with tempfile.TemporaryDirectory(prefix="ga-fu-") as d:
            log = Path(d) / "run.log"
            log.write_text(text)
            receipts = Path(d) / "receipts.jsonl"
            script = (f'. "{LIB}"\nsha=0123abcd dirty={dirty} receipts="{receipts}"\n'
                      f'receipt {target} {exit_code} 2026-01-01T00:00:00Z "{log}"\n')
            result = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = receipts.read_text().splitlines()
            self.assertEqual(len(lines), 1)
            return json.loads(lines[0])

    def test_clean_complete_run(self):
        row = self.receipt(log_text())
        self.assertIs(row["area_complete"], True)
        self.assertIs(row["dirty"], False)
        self.assertIs(row["partial"], False)
        self.assertEqual(row["area_expected"], "alpha beta gamma")
        self.assertEqual(row["area_targets"], "alpha:0,beta:0,gamma:0")

    def test_dirty_run_is_never_complete(self):
        row = self.receipt(log_text(), dirty="true")
        self.assertIs(row["dirty"], True)
        self.assertIs(row["area_complete"], False)
        # everything else about it still reads as a full run
        self.assertEqual(row["area_targets"], "alpha:0,beta:0,gamma:0")
        self.assertIs(row["partial"], False)

    def test_failed_partial_short_and_extra_runs_are_not_complete(self):
        self.assertIs(self.receipt(log_text(), exit_code="1")["area_complete"], False)
        narrowed = self.receipt(log_text(ran=["alpha"], partial="true"))
        self.assertIs(narrowed["area_complete"], False)
        self.assertIs(narrowed["partial"], True)
        self.assertIs(self.receipt(log_text(ran=["alpha", "beta"]))["area_complete"], False)
        self.assertIs(self.receipt(log_text(ran=TARGETS + ["delta"]))["area_complete"], False)
        self.assertIs(self.receipt(log_text(ran=["gamma", "beta", "alpha"]))["area_complete"], False)

    def test_log_without_area_lines_is_not_complete(self):
        row = self.receipt("make: all green\n", target="macos")
        self.assertIs(row["area_complete"], False)
        self.assertEqual(row["area_expected"], "")
        self.assertIs(row["partial"], False)


if __name__ == "__main__":
    unittest.main()
