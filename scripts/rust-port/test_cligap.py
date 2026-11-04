#!/usr/bin/env python3
"""Selftests of cligap.py (the Python port of the retired Go cligap tool's unit tests)."""
import json
from pathlib import Path
import stat
import tempfile
import unittest

import cligap

ROOT_HELP = """Symaira Vault

Usage: symvault [OPTIONS] [COMMAND]

Commands:
  get       Read an entry
  config    Configuration
  help      Print help
  completion  Shell completion

Options:
      --vault <VAULT>  Vault path
  -h, --help           Print help
"""
CONFIG_HELP = """Usage: symvault config [OPTIONS] [COMMAND]

Commands:
  get  Read a key

Options:
      --json  JSON output; also mentions --not-a-flag in prose
"""


class CligapTests(unittest.TestCase):
    def test_flag_names_come_from_the_option_section_only(self):
        self.assertEqual(cligap.flag_names(CONFIG_HELP), {"json", "not-a-flag"})
        self.assertEqual(cligap.flag_names("Usage: x --prose-only\n\nOptions:\n  --real <V>\nCommands:\n  --not-here\n"), {"real"})

    def test_subcommands_skip_help_and_completion(self):
        self.assertEqual(cligap.subcommands(ROOT_HELP), ["get", "config"])
        self.assertEqual(cligap.subcommands("Essentials:\n  add  Add\nVault:\n  list  List\nOptions:\n  --x\n"), ["add", "list"])

    def test_alias_path(self):
        self.assertEqual(cligap.alias_path("symvault config get", "show"), "symvault config show")

    def test_report_for_a_fake_binary(self):
        with tempfile.TemporaryDirectory() as raw:
            raw = Path(raw)
            fake = raw / "symvault"
            fake.write_text("#!/bin/sh\ncase \"$*\" in\n"
                            "  '--help') cat <<'EOF'\n" + ROOT_HELP + "EOF\n;;\n"
                            "  'config --help') cat <<'EOF'\n" + CONFIG_HELP + "EOF\n;;\n"
                            "  'get --help') printf 'Usage: symvault get\\n\\nOptions:\\n      --json\\n' ;;\n"
                            "  'config get --help') printf 'Usage: symvault config get\\n' ;;\n"
                            "  *) echo 'error: unrecognized subcommand' >&2; exit 2 ;;\nesac\n")
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            tree = raw / "tree.json"
            tree.write_text(json.dumps({"oracle": {"commit": "abc", "release": "v0"}, "commands": [
                {"path": "symvault", "local_flags": []},
                {"path": "symvault get", "aliases": ["show"], "local_flags": [{"name": "json"}, {"name": "help"}, {"name": "raw"}]},
                {"path": "symvault config get", "local_flags": []},
                {"path": "symvault gone", "local_flags": []}]}))
            out = raw / "report.json"
            cligap.main(["--binary", str(fake), "--tree", str(tree), "--output", str(out)])
            report = json.loads(out.read_text())
        self.assertEqual(report["oracle_paths"], 3)
        self.assertEqual([g["path"] for g in report["missing_paths"]], ["symvault gone"])
        self.assertEqual([(g["path"], g["detail"]) for g in report["flag_gaps"]], [("symvault get", "--raw")])
        self.assertEqual([(g["path"], g["detail"]) for g in report["alias_gaps"]], [("symvault get", "show")])
        self.assertEqual(report["rust_only_paths"], ["symvault config"])  # reachable but absent from the frozen tree
        self.assertEqual(report["rust_paths"], 4)  # symvault, get, config, config get


if __name__ == "__main__":
    unittest.main()
