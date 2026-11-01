#!/usr/bin/env python3
"""Mutation controls for gen_config_schema.py.

Each case copies the generator, the non-test Go files of internal/config and
the checked-in table to a scratch directory outside the repository, mutates the
copy and runs the copied generator: a field the generator can model must reach
the table (wherever its tag sits, in whichever file its struct lives), a field
it cannot model must stop it with a message naming the field, never vanish.
"""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path("scripts/rust-port/gen_config_schema.py")
TABLE = Path("crates/symvault-cli/src/config_schema.rs")
ANCHOR = '\tPort                int               `yaml:"port,omitempty"`\n'


class GenConfigSchemaMutations(unittest.TestCase):
    def setUp(self):
        self.scratch = Path(tempfile.mkdtemp(prefix="gen-config-schema."))
        self.addCleanup(shutil.rmtree, self.scratch, ignore_errors=True)
        for relative in (SCRIPT, TABLE):
            (self.scratch / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / relative, self.scratch / relative)
        config = self.scratch / "internal/config"
        config.mkdir(parents=True)
        for path in (ROOT / "internal/config").glob("*.go"):
            if not path.name.endswith("_test.go"):
                shutil.copy(path, config / path.name)

    def mutate(self, name, old, new):
        path = self.scratch / "internal/config" / name
        text = path.read_text()
        self.assertEqual(text.count(old), 1, f"{name} must hold the mutation anchor once")
        path.write_text(text.replace(old, new))

    def run_generator(self, *args):
        return subprocess.run(
            [sys.executable, "-B", str(self.scratch / SCRIPT), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def table(self):
        return (self.scratch / TABLE).read_text()

    def test_pristine_copy_matches_the_checked_in_table(self):
        result = self.run_generator("--check")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_yaml_tag_behind_another_tag_is_read(self):
        self.mutate("schema.go", ANCHOR, ANCHOR + '\tExtra string `json:"extra" yaml:"extra_key"`\n')
        self.assertNotEqual(self.run_generator("--check").returncode, 0, "the table must be stale")
        self.assertEqual(self.run_generator().returncode, 0)
        self.assertIn('("extra_key", "string")', self.table())

    def test_untagged_flow_and_skipped_fields(self):
        self.mutate(
            "schema.go",
            ANCHOR,
            ANCHOR
            + '\tNoTag string\n\tHidden string `yaml:"-"`\n\tprivate string\n\tFlowy []string `yaml:",flow"`\n',
        )
        self.assertEqual(self.run_generator().returncode, 0)
        table = self.table()
        self.assertIn('("notag", "string")', table)
        self.assertIn('("flowy", "[]string")', table)
        self.assertNotIn('("hidden"', table)
        self.assertNotIn('("private"', table)

    def test_struct_in_another_file_is_scanned(self):
        self.mutate("config.go", "type Config struct {\n", 'type Config struct {\n\tZed ZStruct `yaml:"zed"`\n')
        (self.scratch / "internal/config/zz.go").write_text(
            'package config\n\ntype ZStruct struct {\n\tK string `yaml:"k"`\n}\n'
        )
        self.assertEqual(self.run_generator().returncode, 0)
        table = self.table()
        self.assertIn('("ZStruct", &[', table)
        self.assertIn('("k", "string")', table)

    def assert_loud(self, field, message):
        self.mutate("schema.go", ANCHOR, ANCHOR + field)
        for args in ((), ("--check",)):
            result = self.run_generator(*args)
            self.assertNotEqual(result.returncode, 0, f"{args}: {result.stdout}")
            self.assertIn(message, result.stderr)
            self.assertNotIn("is stale", result.stderr, "an error, not a drift report")

    def test_inline_flag_is_an_error(self):
        self.assert_loud('\tWeird string `yaml:"w,inline"`\n', "yaml tag flag 'inline'")

    def test_multi_name_field_is_an_error(self):
        self.assert_loud('\tOdd, Pair string `yaml:"odd"`\n', "multi-name exported field")

    def test_unmodeled_type_is_an_error(self):
        self.assert_loud('\tRatio float64 `yaml:"ratio"`\n', "field type 'float64' is not decoded")

    def test_legacy_raw_tag_is_an_error(self):
        self.assert_loud("\tRaw string `rawkey,omitempty`\n", "legacy raw struct tag")

    def test_unparseable_line_is_an_error(self):
        self.assert_loud("\tBroken = 3\n", "cannot parse field line")

    def test_embedded_exported_type_is_an_error(self):
        self.assert_loud("\tAuditConfig\n", "embedded exported field")

    def test_duplicate_yaml_key_is_an_error(self):
        self.assert_loud('\tDup string `yaml:"port"`\n', "duplicate yaml key 'port'")

    def test_unmarshaler_on_a_reached_type_is_an_error(self):
        for method in ("UnmarshalYAML(value *yaml.Node) error", "UnmarshalText(text []byte) error"):
            with self.subTest(method=method):
                self.setUp()
                path = self.scratch / "internal/config/schema.go"
                path.write_text(path.read_text() + f"\nfunc (c *MCPConfig) {method} {{ return nil }}\n")
                for args in ((), ("--check",)):
                    result = self.run_generator(*args)
                    self.assertNotEqual(result.returncode, 0, f"{args}: {result.stdout}")
                    self.assertIn("MCPConfig.Unmarshal", result.stderr)

    def test_anonymous_struct_field_is_an_error(self):
        self.mutate("schema.go", ANCHOR, ANCHOR + '\tNested struct {\n\t\tInner string `yaml:"inner"`\n\t}\n')
        result = self.run_generator()
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
