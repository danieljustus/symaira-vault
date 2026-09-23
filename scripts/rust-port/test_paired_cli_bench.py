#!/usr/bin/env python3
"""Focused self-checks for paired_cli_bench.py; no Rust/Go build required."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

MODULE_PATH = Path(__file__).with_name("paired_cli_bench.py")
SPEC = importlib.util.spec_from_file_location("paired_cli_bench", MODULE_PATH)
assert SPEC and SPEC.loader
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


class PairedCliBenchTests(unittest.TestCase):
    def test_nearest_rank_percentile(self) -> None:
        self.assertEqual(bench.percentile([8, 1, 7, 2, 6, 3, 5, 4], 95), 8)
        self.assertEqual(bench.percentile(list(range(1, 21)), 95), 19)

    def test_rss_parsers_normalize_to_bytes(self) -> None:
        linux, linux_method = bench.parse_rss_bytes(
            "Maximum resident set size (kbytes): 2048\n", "Linux"
        )
        bsd, bsd_method = bench.parse_rss_bytes("  2097152 maximum resident set size\n", "Darwin")
        self.assertEqual((linux, linux_method), (2_097_152, "/usr/bin/time -v"))
        self.assertEqual((bsd, bsd_method), (2_097_152, "/usr/bin/time -l"))
        self.assertEqual(bench.parse_rss_bytes("", "Windows"), (None, None))

    @unittest.skipIf(os.name == "nt", "self-check uses executable shebang scripts")
    def test_disposable_paired_run_emits_metrics_without_command_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="paired-cli-self-check-") as temp_name:
            root = Path(temp_name)
            binaries = {}
            for side, version in (("go", "symvault v0.22.1"), ("rust", "symvault dev")):
                path = root / side
                path.write_text(
                    "#!/usr/bin/env python3\n"
                    "import os, pathlib, sys\n"
                    f"VERSION = {version!r}\n"
                    "args = sys.argv[1:]\n"
                    "if args == ['version']:\n"
                    "    print(VERSION)\n"
                    "elif args and args[0] == 'init':\n"
                    "    pathlib.Path(os.environ['SYMVAULT_VAULT']).mkdir(parents=True, exist_ok=True)\n"
                    "elif args and args[0] == 'add':\n"
                    "    p = pathlib.Path(os.environ['SYMVAULT_VAULT']) / (args[1] + '.fixture')\n"
                    "    p.write_text('synthetic-command-output-marker')\n"
                    "elif args and args[0] == 'get':\n"
                    "    print('synthetic-command-output-marker')\n"
                    "else:\n"
                    "    raise SystemExit(2)\n",
                    encoding="utf-8",
                )
                path.chmod(0o755)
                binaries[side] = path

            report = bench.build_report(
                binaries["go"], binaries["rust"], runs=2, warmups=0, entries=1, include_rss=False
            )
            serialized = json.dumps(report)
            self.assertEqual(report["fixture"], {"entries": 1, "synthetic": True, "vault_copies": 2})
            self.assertEqual(report["measurements"]["go"]["read_p95_ms"] > 0, True)
            self.assertIn("value_gate_claim", report)
            self.assertNotIn("synthetic-command-output-marker", serialized)
            self.assertNotIn("value-bench-", serialized)


if __name__ == "__main__":
    unittest.main()
