#!/usr/bin/env python3
"""Release/runner support policy regression checks for issue #1550."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(os.environ.get("SYMVAULT_PLATFORM_TEST_ROOT", Path(__file__).resolve().parents[1]))


class SupportedPlatformsTests(unittest.TestCase):
    def test_workflows_do_not_select_unsupported_platforms(self):
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            doc = yaml.safe_load(path.read_text())
            for name, job in doc["jobs"].items():
                selection = str([job.get("runs-on"), job.get("strategy", {}).get("matrix")])
                for unsupported in ["windows", "macos-13", "macos-15-intel", "x86_64-apple-darwin"]:
                    self.assertNotIn(unsupported, selection.lower(), (path.name, name))

    def test_release_targets_and_publishers(self):
        config = yaml.safe_load((ROOT / ".goreleaser.yml").read_text())
        self.assertNotIn("scoops", config)
        targets = {(os_name, arch) for build in config["builds"]
                   for os_name in build["goos"] for arch in build["goarch"]}
        self.assertEqual(targets, {("darwin", "arm64"), ("linux", "amd64"),
                                  ("linux", "arm64"), ("freebsd", "amd64"),
                                  ("freebsd", "arm64")})
        release = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertNotIn("darwin_amd64", release)
        self.assertNotIn("SCOOP", release)
        self.assertIn("darwin_arm64.tar.gz", release)

    def test_homebrew_renders_without_an_intel_mac_checksum(self):
        # Deliberately synthetic checksums, testing rendering only, not downloads.
        with tempfile.TemporaryDirectory() as tmp:
            sums = Path(tmp) / "checksums.txt"
            sums.write_text("".join("0" * 64 + f"  symaira-vault_0.0.0_{target}.tar.gz\n"
                                    for target in ["darwin_arm64", "linux_amd64", "linux_arm64"]))
            formula = subprocess.check_output(["bash", str(ROOT / "scripts/homebrew-formula.sh"),
                                               "0.0.0", str(sums)], text=True)
        self.assertNotIn("darwin_amd64", formula)
        self.assertIn("depends_on arch: :arm64", formula)
        self.assertIn("linux_amd64", formula)
        self.assertIn("linux_arm64", formula)


if __name__ == "__main__":
    unittest.main(verbosity=2)
