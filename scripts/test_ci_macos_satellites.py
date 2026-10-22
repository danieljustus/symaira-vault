#!/usr/bin/env python3
"""Structural and selector checks for the consolidated PR macOS satellite jobs.

Run from the repository root:  python3 -B scripts/test_ci_macos_satellites.py
Needs PyYAML (CI installs a pinned copy into a throwaway venv).

Covers two consolidations:
- rust-http-macos.yml: the eight HTTP-family satellites (group "http").
- rust-macos-satellites.yml: the remaining PR-triggered macOS satellites in the
  groups "mcp", "broker" and "rest". Pairing and TUI keep their own macOS jobs.

What is proven here:
- the selector is fail-closed and covers every input the family compiles/executes;
- every macOS command that the original workflows executed at the pinned baseline
  commit still runs, verbatim and in order, with the same effective environment,
  shell, artifact definitions and gating;
- the original workflows changed only their os matrix line (sha256 of the
  reverted file equals the pinned original), so their ubuntu/windows legs and
  their macOS legs for push, schedule and workflow_dispatch are untouched;
- mutations of the consolidated workflows (dropped command, changed env, dropped
  gate, dropped reset or artifact, extra keys) make the checks fail.
"""
import copy
import hashlib
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
GROUP_PATH = os.path.join(ROOT, ".github", "workflows", "rust-macos-satellites.yml")
PINNED_BASE = "861ad93813e3ee43c4ec989f45940d14b05b6eaf"
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
NEW_FILES = {
    "mcp_process": "rust-mcp-process.yml",
    "mcp_http_process": "rust-mcp-http-process.yml",
    "mcp_http_shutdown": "mcp-http-shutdown.yml",
    "broker_connect": "rust-broker-connect.yml",
    "broker_egress": "rust-broker-egress.yml",
    "audit": "rust-audit.yml",
    "api_transport": "rust-api-transport.yml",
    "cli_artifacts": "rust-cli-artifacts.yml",
    "intake_cli": "rust-intake-cli.yml",
    "serve_cli": "rust-serve-cli.yml",
    "kdf_policy": "kdf-resource-policy.yml",
    "vault_read_policy": "vault-read-resource-policy.yml",
    "store_observations": "rust-store-observations.yml",
    "sync_observations": "rust-sync-observations.yml",
}
GROUP_NAMES = ["mcp", "broker", "rest"]
ASSERT_NAME = "Assert actual native macOS arm64"
RUST_INSTALL = ("rustup toolchain install 1.98.0 --profile minimal "
                "--component rustfmt --component clippy")
RESET_MARKERS = ["git worktree prune", "git checkout --quiet -- .", "git clean -fd --quiet",
                 "test -z \"$(git status --porcelain=v1 --untracked-files=normal)\""]
ALLOWED_STEP_KEYS = {"name", "id", "if", "uses", "with", "run", "env", "shell"}
EXCLUDED_CONDITIONS = {"runner.os == 'Linux'", "runner.os == 'Windows'"}
STEP_OK_CONDITIONS = {"always()", "!cancelled()", "!cancelled() && runner.os == 'macOS'",
                      "runner.os == 'macOS'", "matrix.os == 'macos-latest'"}


def load_selector(path=SELECTOR_PATH):
    spec = importlib.util.spec_from_file_location("ci_macos_satellites", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
        return fh.read()


def load_baseline():
    with open(BASELINE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


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


def strip_expr(cond):
    c = str(cond or "").strip()
    if c.startswith("${{") and c.endswith("}}"):
        c = c[3:-2].strip()
    return c


def is_prologue(step):
    uses = step.get("uses") or ""
    return (step.get("name") == ASSERT_NAME or uses.startswith("actions/checkout")
            or uses.startswith("actions/setup-go") or (step.get("name") or "").startswith("Install pinned Rust"))


def mac_applicable_indexes(steps):
    return [i for i, s in enumerate(steps) if strip_expr(s.get("if")) not in EXCLUDED_CONDITIONS]


def chain_expectation(step):
    """Return 'chained', 'explicit' or raise for an original step's condition."""
    c = strip_expr(step.get("if"))
    if c in ("", ) or c == "runner.os == 'macOS'" or c == "matrix.os == 'macos-latest'":
        return "chained"
    if c in ("always()", "!cancelled()", "!cancelled() && runner.os == 'macOS'"):
        return "explicit"
    raise ValueError(f"unexpected original condition: {c!r}")


# ---------------------------------------------------------------------------
# Structural validation of a consolidated group job (shared with mutation tests)
# ---------------------------------------------------------------------------

def validate_group(doc, group, bl):
    errs = []
    g = bl["groups"][group]
    job = doc.get("jobs", {}).get(g["job_id"])
    if job is None:
        return [f"missing job {g['job_id']}"]
    job_env = {k: str(v) for k, v in (job.get("env") or {}).items()}
    if job.get("runs-on") != "xcode-27":
        errs.append("runs-on")
    if job.get("needs") != "select":
        errs.append("needs")
    cond = str(job.get("if", ""))
    for frag in ["!cancelled()", "needs.select.result != 'success'",
                 f"needs.select.outputs.group_{group} != 'false'"]:
        if frag not in cond:
            errs.append(f"job if lacks {frag}")
    if job.get("timeout-minutes") != g["timeout_minutes"]:
        errs.append("timeout-minutes")
    if (job.get("env") or {}) != g["job_env"]:
        errs.append("job env differs from intersection")
    if job.get("defaults") != {"run": {"shell": "bash"}}:
        errs.append("defaults")
    steps = job.get("steps", [])
    if len(steps) < 5:
        return errs + ["too few steps"]
    head = [s.get("name") for s in steps[:5]]
    if head != [ASSERT_NAME, "Checkout code", "Set up pinned Go", "Install pinned Rust", "Shared prologue complete"]:
        errs.append(f"prologue names {head}")
    first_raw = bl["satellites"][g["satellites"][0]]["steps"]
    if mac_run_text(steps[0].get("run", "")) != mac_run_text(first_raw[0]["run"]):
        errs.append("assert command differs from baseline")
    if steps[1].get("with") != {"fetch-depth": 0, "persist-credentials": False}:
        errs.append("checkout with")
    if steps[2].get("with") != {"go-version": "1.26.10"}:
        errs.append("go version")
    if (steps[3].get("run") or "").strip() != RUST_INSTALL:
        errs.append("rust install command")
    if steps[4].get("id") != "prologue":
        errs.append("prologue id")
    if steps[0].get("if") is not None:
        errs.append("assert step must not be gated by matrix")
    actual_ids = [s.get("id") for s in steps if s.get("id")]
    if len(actual_ids) != len(set(actual_ids)):
        errs.append("duplicate step ids")
    for s in steps:
        if set(s.keys()) - {"name", "id", "if", "uses", "with", "run", "env", "shell"}:
            errs.append(f"unexpected keys in step {s.get('name')}: {sorted(set(s) - ALLOWED_STEP_KEYS)}")
        if "matrix." in (s.get("run") or ""):
            errs.append(f"matrix reference in run of {s.get('name')}")
    positions = []
    for sat in g["satellites"]:
        errs += validate_block(steps, sat, bl, positions, job_env)
    if positions != sorted(positions):
        errs.append("satellite blocks out of order")
    return errs


def validate_block(steps, sat, bl, positions, job_env):
    errs = []
    s = bl["satellites"][sat]
    raw = s["steps"]
    expected = [raw[i] for i in s["mac_step_indexes"] if not is_prologue(raw[i])]
    id_re = re.compile(re.escape(sat) + r"-\d+")
    pos = [i for i, st in enumerate(steps) if id_re.fullmatch(str(st.get("id", "")))]
    if not pos:
        return [f"{sat}: no steps"]
    if pos != list(range(pos[0], pos[0] + len(pos))):
        errs.append(f"{sat}: steps not contiguous")
    actual = [steps[i] for i in pos]
    positions.append(pos[0])
    if len(actual) != len(expected):
        return errs + [f"{sat}: {len(actual)} steps, baseline expects {len(expected)}"]
    gate = f"needs.select.outputs.{sat} != 'false'"
    prev = "prologue"
    for n, (exp, act) in enumerate(zip(expected, actual), start=1):
        label = f"{sat}[{n}] {exp.get('name')!r}"
        if act.get("id") != f"{sat}-{n}":
            errs.append(f"{label}: id {act.get('id')!r}")
        if not str(act.get("name", "")).startswith(f"[{s['label']}] "):
            errs.append(f"{label}: name {act.get('name')!r}")
        if "run" in exp:
            if act.get("run") != mac_run_text(exp["run"]):
                errs.append(f"{label}: run command differs from baseline")
        if exp.get("uses"):
            if act.get("uses") != exp["uses"]:
                errs.append(f"{label}: uses differs")
            if mac_run_text_json(act.get("with")) != mac_run_text_json(exp.get("with")):
                errs.append(f"{label}: with differs")
        if act.get("shell") != exp.get("shell"):
            errs.append(f"{label}: shell differs")
        eff_exp = {k: str(v) for k, v in {**s["job_env"], **(exp.get("env") or {})}.items()}
        eff_act = {k: str(v) for k, v in {**job_env, **(act.get("env") or {})}.items()}
        if eff_exp != eff_act:
            errs.append(f"{label}: effective env differs {eff_exp} != {eff_act}")
        cond = str(act.get("if", ""))
        if "!cancelled()" not in cond or gate not in cond:
            errs.append(f"{label}: gate missing ({cond[:80]})")
        kind = chain_expectation(exp)
        if kind == "chained":
            want = f"steps.{prev}.outcome == 'success'"
            if want not in cond:
                errs.append(f"{label}: chain on {prev} missing")
        else:
            if "outcome == 'success'" in cond:
                errs.append(f"{label}: explicit step must not chain")
        extra = strip_expr(exp.get("if"))
        if extra == "runner.os == 'macOS'" or extra == "!cancelled() && runner.os == 'macOS'":
            if "runner.os == 'macOS'" not in cond:
                errs.append(f"{label}: macOS condition dropped")
        prev = act.get("id")
    reset = steps[pos[-1] + 1] if pos[-1] + 1 < len(steps) else {}
    if reset.get("id") != f"reset-{sat}":
        errs.append(f"{sat}: reset step missing after block")
    else:
        if gate not in str(reset.get("if", "")) or "!cancelled()" not in str(reset.get("if", "")):
            errs.append(f"{sat}: reset not gated")
        for marker in RESET_MARKERS:
            if marker not in str(reset.get("run", "")):
                errs.append(f"{sat}: reset lacks {marker!r}")
    return errs


def bl_group_of(bl, sat):
    return bl["satellites"][sat]["group"]


def mac_run_text_json(value):
    return json.dumps(value, sort_keys=True).replace("${{ matrix.os }}", "macos-latest")


def validate_select_job(doc, bl):
    errs = []
    select = doc["jobs"].get("select")
    if select is None:
        return ["missing select job"]
    keys = set(select.get("outputs", {}))
    want = set(NEW_FILES) | {f"group_{g}" for g in GROUP_NAMES}
    if keys != want:
        errs.append(f"select outputs {sorted(keys ^ want)}")
    text = yaml.safe_dump(select)
    for k in sorted(want):
        if k not in text:
            errs.append(f"select has no {k}")
    return errs


def validate_consolidated_http(doc, bl):
    """Checks for rust-http-macos.yml: the original HTTP job shape, now gated by group_http."""
    errs = []
    job = doc["jobs"]["macos-http"]
    if "needs.select.outputs.group_http != 'false'" not in job["if"]:
        errs.append("http job gate")
    if "needs.select.outputs.any" in job["if"]:
        errs.append("http job still gated by any")
    outputs = sorted(doc["jobs"]["select"]["outputs"].keys())
    if outputs != sorted(["group_http"] + ORDER):
        errs.append(f"http select outputs {outputs}")
    return errs


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class SelectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sel = load_selector()

    def chosen(self, changed, keys=None):
        """Sorted satellite keys selected by `changed` (default: the HTTP family)."""
        decisions = self.sel.select("pull_request", changed)
        keys = ORDER if keys is None else keys
        return sorted(k for k in keys if decisions[k])

    def groups(self, changed):
        decisions = self.sel.select("pull_request", changed)
        return sorted(g for g in self.sel.GROUPS if decisions["group_" + g])

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
        self.assertEqual(self.chosen(["docs/rust-port/README.md", "README.md"], self.sel.ALL_KEYS), [])
        self.assertEqual(self.chosen(["editors/x/src/app.ts"], self.sel.ALL_KEYS), [])
        self.assertEqual(self.chosen([], self.sel.ALL_KEYS), [])
        self.assertEqual(self.groups(["docs/rust-port/README.md"]), [])

    def test_shared_rust_inputs_select_the_whole_http_family(self):
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
                self.assertTrue(all(decisions[k] for k in self.sel.OUTPUT_KEYS))
                self.assertTrue(all(decisions["group_" + g] for g in self.sel.GROUPS))

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
        for key in NEW_FILES:
            covered = set(self.sel.patterns_for(key))
            for pattern in baseline["satellites"][key]["pull_request_paths"]:
                self.assertIn(pattern, covered, (key, pattern))
            for infra in self.sel.GROUP_WORKFLOW_INPUTS:
                self.assertIn(infra, covered, (key, infra))

    def test_live_workflow_paths_are_covered_by_selector(self):
        for key in ORDER:
            live = live_pull_request_paths(read(f".github/workflows/{FILES[key]}"))
            self.assertTrue(live, FILES[key])
            covered = set(self.sel.patterns_for(key))
            for pattern in live:
                self.assertIn(pattern, covered, (key, pattern))
        for key, file in NEW_FILES.items():
            live = live_pull_request_paths(read(f".github/workflows/{file}"))
            self.assertTrue(live, file)
            covered = set(self.sel.patterns_for(key))
            for pattern in live:
                self.assertIn(pattern, covered, (key, pattern))

    def test_crate_closure_is_covered_by_shared_inputs(self):
        # Every workspace crate the HTTP family links against must be selected by crates/**;
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

    def test_crypto_sync_gojson_are_selected_for_every_http_satellite(self):
        # Regression for the original path lists, which omitted these crates.
        for key in ORDER:
            for changed in (["crates/symvault-crypto/src/lib.rs"], ["crates/symvault-sync/src/lib.rs"],
                            ["crates/symvault-gojson/src/lib.rs"]):
                self.assertIn(key, self.chosen(changed))

    def test_group_selection_by_change(self):
        self.assertEqual(self.groups([".github/workflows/rust-macos-satellites.yml"]), ["broker", "mcp", "rest"])
        self.assertEqual(self.groups(["Cargo.lock"]), ["broker", "http", "mcp", "rest"])
        self.assertEqual(self.groups([".github/workflows/rust-audit.yml"]), ["rest"])
        self.assertEqual(self.groups([".github/workflows/mcp-http-shutdown.yml"]), ["mcp"])
        self.assertEqual(self.groups([".github/workflows/rust-broker-egress.yml"]), ["broker"])
        # internal/config/config.go is on the original path lists of kdf and cli-artifacts only
        self.assertEqual(self.groups(["internal/config/config.go"]), ["rest"])
        self.assertEqual(self.chosen(["internal/config/config.go"], self.sel.ALL_KEYS),
                         ["cli_artifacts", "kdf_policy"])

    def test_group_members_select_exactly_their_satellite(self):
        self.assertEqual(self.chosen([".github/workflows/mcp-http-shutdown.yml"], self.sel.ALL_KEYS),
                         ["mcp_http_shutdown"])
        self.assertEqual(self.chosen([".github/workflows/rust-audit.yml"], self.sel.ALL_KEYS), ["audit"])

    def test_group_membership_matches_baseline(self):
        bl = load_baseline()
        for group, meta in bl["groups"].items():
            if group == "http":
                continue
            self.assertEqual(self.sel.GROUPS[group], meta["satellites"], group)
        for key in NEW_FILES:
            owners = [g for g, m in bl["groups"].items() if key in m["satellites"]]
            self.assertEqual(owners, [bl["satellites"][key]["group"]], key)

    def test_group_pattern_drop_is_detected(self):
        real = self.sel

        class Dropped:
            """Selector stub whose audit satellite lost one original path."""
            def patterns_for(self, key):
                pats = real.patterns_for(key)
                if key == "audit":
                    pats = [p for p in pats if p != "Cargo.lock"]
                return pats

        bl = load_baseline()
        stub = Dropped()
        missing = [p for p in bl["satellites"]["audit"]["pull_request_paths"]
                   if p not in stub.patterns_for("audit")]
        self.assertEqual(missing, ["Cargo.lock"])


class LiveWorkflowTests(unittest.TestCase):
    def test_satellites_keep_only_ubuntu_and_windows_legs_on_pull_request(self):
        for key in ORDER:
            text = read(f".github/workflows/{FILES[key]}")
            doc = yaml.safe_load(text)
            job = list(doc["jobs"].values())[0]
            self.assertEqual(job["strategy"]["matrix"]["os"], [
                "ubuntu-latest", "windows-latest"], key)
            self.assertEqual(job["runs-on"], "${{ matrix.os }}", key)
            self.assertNotIn("macos", text.replace("# macOS runs in rust-http-macos.yml", ""), key)
            self.assertNotIn("xcode-27", text, key)

    def test_live_run_commands_are_exactly_the_baseline_minus_macos_assert(self):
        baseline = load_baseline()
        for key in ORDER:
            doc = yaml.safe_load(read(f".github/workflows/{FILES[key]}"))
            job = list(doc["jobs"].values())[0]
            live = [s["run"] for s in job["steps"] if s.get("run")]
            expected = [r for r in baseline["satellites"][key]["all_run_strings"]
                        if "test \"$RUNNER_OS\" = macOS" not in r]
            self.assertEqual(live, expected, key)

    def test_new_originals_changed_only_their_matrix_line(self):
        bl = load_baseline()
        old, new = bl["matrix_line_original"], bl["matrix_line_consolidated"]
        for key, file in NEW_FILES.items():
            with self.subTest(file=file):
                text = read(f".github/workflows/{file}")
                self.assertEqual(text.count(new), 1)
                reverted = text.replace(new, old, 1)
                self.assertEqual(hashlib.sha256(reverted.encode("utf-8")).hexdigest(),
                                 bl["satellites"][key]["file_sha256"])

    def test_new_originals_steps_are_unchanged_and_keep_macos_off_pull_request(self):
        bl = load_baseline()
        for key, file in NEW_FILES.items():
            with self.subTest(file=file):
                doc = yaml.safe_load(read(f".github/workflows/{file}"))
                job = list(doc["jobs"].values())[0]
                self.assertEqual(job["steps"], bl["satellites"][key]["steps"])
                self.assertEqual(job["runs-on"], "${{ matrix.os == 'macos-latest' && 'xcode-27' || matrix.os }}")
                expr = doc["jobs"][list(doc["jobs"].keys())[0]]["strategy"]["matrix"]["os"]
                self.assertIn("github.event_name == 'pull_request'", expr)
                self.assertIn('fromJSON(\'["ubuntu-latest","macos-latest","windows-latest"]\')', expr)
                self.assertIn('fromJSON(\'["ubuntu-latest","windows-latest"]\')', expr)

    def test_original_macos_only_steps_are_classified_as_expected(self):
        bl = load_baseline()
        for key in NEW_FILES:
            raw = bl["satellites"][key]["steps"]
            self.assertEqual(bl["satellites"][key]["mac_step_indexes"], mac_applicable_indexes(raw), key)
            for i, s in enumerate(raw):
                c = strip_expr(s.get("if"))
                if i in bl["satellites"][key]["mac_step_indexes"]:
                    self.assertTrue(c == "" or c in STEP_OK_CONDITIONS, (key, c))


class ConsolidatedHttpWorkflowTests(unittest.TestCase):
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
        self.assertIn("needs.select.outputs.group_http != 'false'", self.mac["if"])
        self.assertIn("!cancelled()", self.mac["if"])

    def test_selector_job_outputs_every_http_satellite_and_fails_closed(self):
        self.assertEqual(validate_consolidated_http(self.doc, self.baseline), [])
        select = self.jobs["select"]
        step = [s for s in select["steps"] if s.get("id") == "select"][0]
        self.assertIn("selecting all satellites", step["run"])
        self.assertIn("ci_macos_satellites.py select", step["run"])
        self.assertIn("for k in group_http head origin", step["run"])

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
                              if s["name"] not in {ASSERT_NAME, "Checkout code", "Set up pinned Go",
                                                   "Set up pinned Python", "Install pinned Rust",
                                                   "Checkout retained Go oracle and candidate",
                                                   "Checkout retained oracle and candidate",
                                                   "Shared prologue complete"}
                              and not is_prologue(s)]
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
        for step in self.steps:
            name = step.get("name", "")
            if name in {ASSERT_NAME, "Checkout code", "Set up pinned Go", "Set up pinned Python",
                        "Install pinned Rust", "Checkout retained Go oracle and candidate",
                        "Checkout retained oracle and candidate", "Shared prologue complete"}:
                continue
            cond = str(step.get("if", ""))
            self.assertIn("!cancelled()", cond, name)
            self.assertIn("needs.select.outputs.", cond, name)
            if "steps.prologue.outcome == 'success'" not in cond and "reset worktree" not in name \
                    and not (step.get("uses") or "").startswith("actions/upload-artifact"):
                self.assertRegex(cond, r"steps\.[A-Za-z0-9_-]+\.outcome == 'success'", name)

    def test_no_unresolved_matrix_references(self):
        for step in self.steps:
            run = step.get("run") or ""
            self.assertNotIn("matrix.os", run)


class ConsolidatedGroupWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bl = load_baseline()
        with open(GROUP_PATH, encoding="utf-8") as fh:
            cls.doc = yaml.safe_load(fh)
        cls.on = cls.doc.get(True, cls.doc.get("on"))

    def test_triggers_permissions_and_concurrency(self):
        self.assertEqual(sorted(self.on.keys()), ["pull_request", "workflow_dispatch"])
        self.assertEqual(self.on["pull_request"]["branches"], ["main"])
        self.assertEqual(self.doc["permissions"], {"contents": "read"})
        self.assertEqual(self.doc["concurrency"]["group"], "${{ github.workflow }}-${{ github.ref }}")
        self.assertEqual(self.doc["concurrency"]["cancel-in-progress"], True)

    def test_select_job_outputs_every_satellite_and_group(self):
        self.assertEqual(validate_select_job(self.doc, self.bl), [])

    def test_select_job_fallback_lists_every_output(self):
        select = self.doc["jobs"]["select"]
        step = [s for s in select["steps"] if s.get("id") == "select"][0]
        for key in list(NEW_FILES) + [f"group_{g}" for g in GROUP_NAMES]:
            self.assertIn(key, step["run"])

    def test_each_group_job_is_valid_against_baseline(self):
        for group in GROUP_NAMES:
            with self.subTest(group=group):
                self.assertEqual(validate_group(self.doc, group, self.bl), [])

    def test_group_membership_covers_each_new_satellite_once(self):
        members = [k for g in GROUP_NAMES for k in self.bl["groups"][g]["satellites"]]
        self.assertEqual(sorted(members), sorted(NEW_FILES))

    def test_group_job_env_is_the_intersection_of_member_envs(self):
        for group in GROUP_NAMES:
            members = self.bl["groups"][group]["satellites"]
            envs = [self.bl["satellites"][k]["job_env"] for k in members]
            inter = {k: v for k, v in envs[0].items() if all(e.get(k) == v for e in envs[1:])}
            self.assertEqual(self.bl["groups"][group]["job_env"], inter, group)
            self.assertEqual(self.doc["jobs"][self.bl["groups"][group]["job_id"]].get("env") or {}, inter)


class GroupMutationTests(unittest.TestCase):
    """Each mutation of a valid group job must be rejected by validate_group."""

    @classmethod
    def setUpClass(cls):
        cls.bl = load_baseline()
        with open(GROUP_PATH, encoding="utf-8") as fh:
            cls.base_doc = yaml.safe_load(fh)

    def mutate(self, group, fn):
        doc = copy.deepcopy(self.base_doc)
        job = doc["jobs"][self.bl["groups"][group]["job_id"]]
        fn(job)
        return validate_group(doc, group, self.bl)

    @staticmethod
    def index_by_id(job, step_id):
        hits = [i for i, s in enumerate(job["steps"]) if s.get("id") == step_id]
        assert len(hits) == 1, step_id
        return hits[0]

    @staticmethod
    def upload_index(job, sat):
        hits = [i for i, s in enumerate(job["steps"])
                if (s.get("uses") or "").startswith("actions/upload-artifact")
                and f"needs.select.outputs.{sat} " in str(s.get("if", ""))]
        assert len(hits) == 1, sat
        return hits[0]

    def test_baseline_document_is_valid(self):
        for group in GROUP_NAMES:
            self.assertEqual(validate_group(self.base_doc, group, self.bl), [])

    def test_dropped_command_is_rejected(self):
        def fn(job):
            del job["steps"][self.index_by_id(job, "audit-2")]
        self.assertTrue(self.mutate("rest", fn))

    def test_altered_command_is_rejected(self):
        def fn(job):
            i = self.index_by_id(job, "mcp_process-3")
            job["steps"][i]["run"] = job["steps"][i]["run"].replace(
                "make mcp-ordered-fixtures-check", "make mcp-ordered-fixtures-check-x")
        self.assertTrue(self.mutate("mcp", fn))

    def test_dropped_step_env_override_is_rejected(self):
        def fn(job):
            # mcp_process-5 carries GOTOOLCHAIN=go1.26.6 from the original step
            i = self.index_by_id(job, "mcp_process-5")
            self.assertEqual(job["steps"][i]["env"]["GOTOOLCHAIN"], "go1.26.6")
            job["steps"][i]["env"].pop("GOTOOLCHAIN")
        self.assertTrue(self.mutate("mcp", fn))

    def test_removed_gate_is_rejected(self):
        def fn(job):
            i = self.index_by_id(job, "kdf_policy-1")
            job["steps"][i]["if"] = job["steps"][i]["if"].replace("!cancelled() && ", "")
        self.assertTrue(self.mutate("rest", fn))

    def test_gate_pointing_at_another_satellite_is_rejected(self):
        def fn(job):
            i = self.index_by_id(job, "store_observations-1")
            job["steps"][i]["if"] = job["steps"][i]["if"].replace(
                "needs.select.outputs.store_observations", "needs.select.outputs.sync_observations")
        self.assertTrue(self.mutate("rest", fn))

    def test_dropped_reset_is_rejected(self):
        def fn(job):
            del job["steps"][self.index_by_id(job, "reset-vault_read_policy")]
        self.assertTrue(self.mutate("rest", fn))

    def test_dropped_upload_is_rejected(self):
        def fn(job):
            del job["steps"][self.upload_index(job, "store_observations")]
        self.assertTrue(self.mutate("rest", fn))

    def test_explicit_upload_made_chained_is_rejected(self):
        def fn(job):
            i = self.upload_index(job, "cli_artifacts")
            job["steps"][i]["if"] = job["steps"][i]["if"].replace(
                " }}", " && steps.cli_artifacts-1.outcome == 'success' }}")
        self.assertTrue(self.mutate("rest", fn))

    def test_extra_key_is_rejected(self):
        def fn(job):
            job["steps"][self.index_by_id(job, "audit-1")]["continue-on-error"] = True
        self.assertTrue(self.mutate("rest", fn))

    def test_job_env_drift_is_rejected(self):
        def fn(job):
            job["env"]["RUST_TEST_THREADS"] = "1"
        self.assertTrue(self.mutate("broker", fn))

    def test_wrong_timeout_is_rejected(self):
        def fn(job):
            job["timeout-minutes"] = 360
        self.assertTrue(self.mutate("mcp", fn))

    def test_missing_macos_condition_is_rejected(self):
        def fn(job):
            # cli_artifacts' "Install native macOS shells" step is gated by runner.os == 'macOS'
            i = [k for k, s in enumerate(job["steps"]) if s.get("id") == "cli_artifacts-2"][0]
            self.assertIn("runner.os == 'macOS'", job["steps"][i]["if"])
            job["steps"][i]["if"] = job["steps"][i]["if"].replace(" && runner.os == 'macOS'", "")
        self.assertTrue(self.mutate("rest", fn))

    def test_group_job_without_select_gate_is_rejected(self):
        def fn(job):
            job["if"] = "${{ always() }}"
        self.assertTrue(self.mutate("broker", fn))


class SelectorOutputTests(unittest.TestCase):
    def test_write_output_lists_every_key_and_any(self):
        import tempfile
        sel = load_selector()
        decisions = sel.select("pull_request", ["Cargo.lock"])
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            path = fh.name
        try:
            sel.write_output("pull_request", decisions, path)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        finally:
            os.unlink(path)
        lines = dict(line.split("=", 1) for line in text.strip().splitlines())
        self.assertEqual(set(lines), {"any"} | set(sel.OUTPUT_KEYS))
        self.assertEqual(lines["group_http"], "true")
        self.assertEqual(lines["group_mcp"], "true")


if __name__ == "__main__":
    unittest.main(verbosity=2)
