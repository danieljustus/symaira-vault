#!/usr/bin/env python3
"""Structural and selector checks for the consolidated HTTP-family macOS job.

Run from the repository root:  python3 -B scripts/test_ci_macos_satellites.py
Needs PyYAML (CI installs a pinned copy into a throwaway venv).

What is proven here:
- the selector is fail-closed and covers every input the family compiles/executes;
- every macOS command that the eight original workflows executed at the pinned
  baseline commit still runs, verbatim and in order, in the consolidated job;
- the eight original workflows keep their ubuntu/windows legs and lost only the
  macOS legs and the macOS-only assert step;
- the consolidated job's env, toolchain pins, checkout and artifact names match
  the baseline.
"""
import importlib.util
import json
import os
import re
import sys
import tomllib
import unittest

import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BASELINE_PATH = os.path.join(ROOT, "scripts", "ci_macos_satellites_baseline.json")
SELECTOR_PATH = os.path.join(ROOT, "scripts", "ci_macos_satellites.py")
CONSOLIDATED_PATH = os.path.join(ROOT, ".github", "workflows", "rust-http-macos.yml")
PINNED_BASE = "895b1fe70103b2bb5c712bc02bb1c616eac1fc2a"
ORDER = ["head", "origin", "oauth", "deadline", "timeout", "write", "framing", "tls"]
FILES = {
    "head": "rust-http-head.yml",
    "origin": "rust-http-origin.yml",
    "oauth": "rust-http-oauth.yml",
    "deadline": "rust-http-read-deadlines.yml",
    "timeout": "rust-http-timeouts.yml",
    "write": "rust-http-write.yml",
    "framing": "rust-http-framing.yml",
    "tls": "rust-http-tls.yml",
}
ASSERT_NAME = "Assert actual native macOS arm64"
SHARED_PROLOGUE_NAMES = {
    ASSERT_NAME, "Checkout code", "Checkout retained Go oracle and candidate",
    "Set up pinned Go", "Set up pinned Python", "Install pinned Rust",
}


def load_selector():
    spec = importlib.util.spec_from_file_location("ci_macos_satellites", SELECTOR_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
        return fh.read()


def live_pull_request_paths(text):
    """Extract `on.pull_request.paths` items without relying on YAML for this check."""
    lines = text.splitlines()
    paths, in_pr, in_paths = [], False, False
    for line in lines:
        if re.match(r"^  pull_request:\s*$", line):
            in_pr = True
            continue
        if in_pr and re.match(r"^  \S", line):
            in_pr = False
        if in_pr and re.match(r"^    paths:\s*$", line):
            in_paths = True
            continue
        if in_paths:
            m = re.match(r"^      - ['\"]?([^'\"]+)['\"]?\s*$", line)
            if m:
                paths.append(m.group(1))
            else:
                break
    return paths


def mac_run_text(text):
    return text.replace("${{ matrix.os }}", "macos-latest")


class SelectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sel = load_selector()

    def chosen(self, changed):
        decisions = self.sel.select("pull_request", changed)
        return sorted(k for k, v in decisions.items() if v)

    def test_glob_semantics(self):
        rx = self.sel.glob_to_regex
        self.assertTrue(rx("scripts/rust-port/http_oauth*").match("scripts/rust-port/http_oauth_contract.py"))
        self.assertFalse(rx("scripts/rust-port/http_oauth*").match("scripts/rust-port/http_oauth/x.py"))
        self.assertTrue(rx("crates/**").match("crates/symvault-crypto/src/lib.rs"))
        self.assertTrue(rx("Cargo.lock").match("Cargo.lock"))
        self.assertFalse(rx("Cargo.lock").match("Cargo.lock.bak"))
        self.assertFalse(rx("crates/symvault-cli/**").match("crates/symvault-clix/a.rs"))
        for bad in ["docs/[ab].md", "!docs/**", "docs/{a,b}.md"]:
            with self.assertRaises(ValueError):
                rx(bad)

    def test_docs_and_unrelated_paths_select_nothing(self):
        self.assertEqual(self.chosen(["docs/rust-port/README.md", "README.md"]), [])
        self.assertEqual(self.chosen(["editors/x/src/app.ts"]), [])
        self.assertEqual(self.chosen([]), [])

    def test_shared_rust_inputs_select_the_whole_family(self):
        everything = sorted(ORDER)
        for changed in (
            ["Cargo.lock"],
            ["Cargo.toml"],
            ["rust-toolchain.toml"],
            ["crates/symvault-crypto/src/lib.rs"],
            ["crates/symvault-sync/src/lib.rs"],
            ["crates/symvault-gojson/src/lib.rs"],
            ["third_party/argon2/src/lib.c"],
        ):
            with self.subTest(changed=changed):
                self.assertEqual(self.chosen(changed), everything)

    def test_satellite_specific_inputs_select_only_their_satellites(self):
        self.assertEqual(self.chosen(["docs/adr/0025-live-tls-and-client-identity-proof.md"]), ["tls"])
        self.assertEqual(self.chosen(["scripts/rust-port/http_tls_contract.py"]), ["tls", "write"])
        self.assertEqual(self.chosen([".github/workflows/rust-http-framing.yml"]), ["framing"])

    def test_non_pull_request_events_select_everything(self):
        for event in ("workflow_dispatch", "push", "schedule", "unknown"):
            with self.subTest(event=event):
                decisions = self.sel.select(event, None)
                self.assertTrue(all(decisions[k] for k in ORDER))

    def test_truncated_or_missing_diff_is_refused(self):
        with self.assertRaises(ValueError):
            self.sel.select("pull_request", None)
        with self.assertRaises(ValueError):
            self.sel.select("pull_request", ["docs/x.md"] * self.sel.MAX_CHANGED_FILES)

    def test_pinned_baseline_patterns_are_covered(self):
        with open(BASELINE_PATH, encoding="utf-8") as fh:
            baseline = json.load(fh)
        self.assertEqual(baseline["source_commit"], PINNED_BASE)
        for key in ORDER:
            covered = set(self.sel.patterns_for(key))
            for pattern in baseline["satellites"][key]["pull_request_paths"]:
                self.assertIn(pattern, covered, (key, pattern))
            for shared in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "crates/**", "third_party/**"]:
                self.assertIn(shared, covered, (key, shared))

    def test_live_workflow_paths_are_covered_by_selector(self):
        for key in ORDER:
            live = live_pull_request_paths(read(f".github/workflows/{FILES[key]}"))
            self.assertTrue(live, FILES[key])
            covered = set(self.sel.patterns_for(key))
            for pattern in live:
                self.assertIn(pattern, covered, (key, pattern))

    def test_crate_closure_is_covered_by_shared_inputs(self):
        # Every workspace crate the family links against must be selected by crates/**;
        # every path dependency outside crates/ must be covered explicitly.
        crate_dirs = {}
        for manifest in sorted(os.listdir(os.path.join(ROOT, "crates"))):
            path = os.path.join(ROOT, "crates", manifest, "Cargo.toml")
            if os.path.isfile(path):
                with open(path, "rb") as fh:
                    data = tomllib.load(fh)
                crate_dirs[data["package"]["name"]] = data
        self.assertIn("symvault-crypto", crate_dirs)
        for name, data in crate_dirs.items():
            for section in ("dependencies", "build-dependencies", "dev-dependencies"):
                for dep in data.get(section, {}).values():
                    if isinstance(dep, dict) and "path" in dep:
                        target = os.path.normpath(os.path.join(ROOT, "crates", name, dep["path"]))
                        rel = os.path.relpath(target, ROOT).replace(os.sep, "/")
                        if rel.startswith("crates/"):
                            continue
                        self.assertTrue(any(self.sel.glob_to_regex(p).match(rel + "/x")
                                            for p in self.sel.SHARED_INPUTS), (name, rel))

    def test_crypto_sync_gojson_are_selected_for_every_satellite(self):
        # Regression for the original path lists, which omitted these crates.
        for key in ORDER:
            for changed in (["crates/symvault-crypto/src/lib.rs"], ["crates/symvault-sync/src/lib.rs"],
                            ["crates/symvault-gojson/src/lib.rs"]):
                self.assertIn(key, self.chosen(changed))


class LiveWorkflowTests(unittest.TestCase):
    def test_satellites_keep_only_ubuntu_and_windows_legs(self):
        for key in ORDER:
            text = read(f".github/workflows/{FILES[key]}")
            doc = yaml.safe_load(text)
            job = list(doc["jobs"].values())[0]
            self.assertEqual(job["strategy"]["matrix"]["os"], ["ubuntu-latest", "windows-latest"], key)
            self.assertEqual(job["runs-on"], "${{ matrix.os }}", key)
            self.assertNotIn("macos", text.replace("# macOS runs in rust-http-macos.yml", ""), key)
            self.assertNotIn("xcode-27", text, key)

    def test_live_run_commands_are_exactly_the_baseline_minus_macos_assert(self):
        with open(BASELINE_PATH, encoding="utf-8") as fh:
            baseline = json.load(fh)
        for key in ORDER:
            doc = yaml.safe_load(read(f".github/workflows/{FILES[key]}"))
            job = list(doc["jobs"].values())[0]
            live = [s["run"] for s in job["steps"] if s.get("run")]
            expected = [r for r in baseline["satellites"][key]["all_run_strings"]
                        if "test \"$RUNNER_OS\" = macOS" not in r]
            self.assertEqual(live, expected, key)


class ConsolidatedWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(BASELINE_PATH, encoding="utf-8") as fh:
            cls.baseline = json.load(fh)
        with open(CONSOLIDATED_PATH, encoding="utf-8") as fh:
            cls.doc = yaml.safe_load(fh)
        on = cls.doc.get(True, cls.doc.get("on"))
        cls.on = on
        cls.jobs = cls.doc["jobs"]
        cls.mac = cls.jobs["macos-http"]
        cls.steps = cls.mac["steps"]

    def test_triggers_and_permissions(self):
        self.assertEqual(sorted(self.on.keys()), ["pull_request", "workflow_dispatch"])
        self.assertEqual(self.on["pull_request"]["branches"], ["main"])
        self.assertEqual(self.doc["permissions"], {"contents": "read"})
        self.assertEqual(self.doc["concurrency"]["cancel-in-progress"], True)

    def test_macos_job_shape_matches_baseline(self):
        self.assertEqual(self.mac["runs-on"], "xcode-27")
        self.assertEqual(self.mac["needs"], "select")
        self.assertEqual(self.mac["env"], self.baseline["job_env"])
        self.assertEqual(self.mac["defaults"], {"run": {"shell": "bash"}})
        self.assertIn("needs.select.result != 'success'", self.mac["if"])
        self.assertIn("needs.select.outputs.any != 'false'", self.mac["if"])
        self.assertIn("!cancelled()", self.mac["if"])

    def test_selector_job_outputs_every_satellite_and_fails_closed(self):
        select = self.jobs["select"]
        self.assertEqual(sorted(select["outputs"].keys()), sorted(["any"] + ORDER))
        step = [s for s in select["steps"] if s.get("id") == "select"][0]
        self.assertIn("selecting all satellites", step["run"])
        self.assertIn("ci_macos_satellites.py select", step["run"])

    def test_prologue_is_identical_to_baseline(self):
        by_name = {s.get("name"): s for s in self.steps}
        assert_step = by_name[ASSERT_NAME]
        self.assertEqual(mac_run_text(assert_step["run"]), mac_run_text(
            self._baseline_run(ORDER[0], ASSERT_NAME)))
        install = by_name["Install pinned Rust"]
        self.assertEqual(install["run"], self._baseline_run(ORDER[0], "Install pinned Rust"))
        self.assertEqual(by_name["Set up pinned Go"]["with"]["go-version"], "1.26.6")
        self.assertEqual(by_name["Checkout code"]["with"], {"fetch-depth": 0, "persist-credentials": False})

    def _baseline_run(self, key, name):
        for step in self.baseline["satellites"][key]["steps"]:
            if step["name"] == name:
                return step["run"]
        raise KeyError((key, name))

    def test_every_baseline_macos_command_runs_in_order_under_its_selector(self):
        for key in ORDER:
            with self.subTest(satellite=key):
                base_steps = [s for s in self.baseline["satellites"][key]["steps"]
                              if s["name"] not in SHARED_PROLOGUE_NAMES]
                expected_runs = [mac_run_text(s["run"]) for s in base_steps if s.get("run")]
                gate = f"needs.select.outputs.{key} != 'false'"
                gated = [s for s in self.steps
                         if gate in str(s.get("if", "")) and "reset worktree" not in str(s.get("name"))]
                actual_runs = [mac_run_text(s["run"]) for s in gated if s.get("run")]
                self.assertEqual(actual_runs, expected_runs)

    def test_artifacts_match_baseline_uploads(self):
        for key in ORDER:
            base_uploads = [s for s in self.baseline["satellites"][key]["steps"]
                            if (s.get("uses") or "").startswith("actions/upload-artifact")]
            gate = f"needs.select.outputs.{key} != 'false'"
            new_uploads = [s for s in self.steps
                           if (s.get("uses") or "").startswith("actions/upload-artifact")
                           and gate in str(s.get("if", ""))]
            self.assertEqual(len(base_uploads), 1, key)
            self.assertEqual(len(new_uploads), 1, key)
            base_with = {k: mac_run_text(v) if isinstance(v, str) else v
                         for k, v in base_uploads[0]["with"].items()}
            self.assertEqual(new_uploads[0]["with"], base_with, key)

    def test_steps_are_gated_and_chained(self):
        seen_ids = set()
        for step in self.steps:
            name = step.get("name", "")
            if name in SHARED_PROLOGUE_NAMES or name == "Shared prologue complete":
                continue
            cond = str(step.get("if", ""))
            self.assertIn("!cancelled()", cond, name)
            self.assertIn("needs.select.outputs.", cond, name)
            if step.get("id"):
                seen_ids.add(step["id"])
            if "steps.prologue.outcome == 'success'" not in cond and "reset worktree" not in name \
                    and not (step.get("uses") or "").startswith("actions/upload-artifact"):
                # Chained: each non-first step needs its predecessor to succeed.
                self.assertRegex(cond, r"steps\.[A-Za-z0-9_-]+\.outcome == 'success'", name)

    def test_no_unresolved_matrix_references(self):
        for step in self.steps:
            run = step.get("run") or ""
            self.assertNotIn("matrix.os", run)


if __name__ == "__main__":
    unittest.main(verbosity=2)
