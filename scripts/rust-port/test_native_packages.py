"""Check native-package smoke images have the init prerequisite."""

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "native_packages", Path(__file__).with_name("native_packages.py")
)
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class NativePackageSmokeTests(unittest.TestCase):
    def test_each_package_installs_git_before_init(self):
        for suffix, image in (('deb', 'ubuntu:24.04'), ('rpm', 'fedora:44'), ('apk', 'alpine:3.23')):
            with self.subTest(suffix=suffix), patch.object(runner.subprocess, "run") as run:
                runner.smoke(Path(__file__).with_suffix(f".{suffix}"), "amd64")
                command = run.call_args.args[0]
                self.assertEqual(command[5], image)
                self.assertIn(f"dst=/tmp/symvault.{suffix},readonly", command[4])
                self.assertIn("git", command[-1].split("symvault init")[0])
                self.assertIn(f"/tmp/symvault.{suffix}", command[-1])
                self.assertTrue(run.call_args.kwargs["check"])


if __name__ == "__main__":
    unittest.main()
