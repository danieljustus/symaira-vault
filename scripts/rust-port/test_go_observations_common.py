#!/usr/bin/env python3
"""Selftests of go_observations_common: replay is strict, never a skip."""
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import go_observations_common as obs


class ObservationStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patch = mock.patch.object(obs, "OBS_DIR", Path(self.tmp.name))
        patch.start()
        self.addCleanup(patch.stop)
        self.addCleanup(self.tmp.cleanup)

    def save(self, observations=None, **kwargs):
        return obs.save("demo", observations if observations is not None else {"go": [1, 2]},
                        oracle_commit="abc", version="go1.26.10", args=["demo"], **kwargs)

    def test_round_trip_and_stable_bytes(self):
        first = self.save().read_bytes()
        self.assertEqual(obs.load("demo", oracle_commit="abc")["observations"], {"go": [1, 2]})
        self.assertEqual(self.save().read_bytes(), first)

    def test_missing_observation_is_a_failure(self):
        with self.assertRaises(obs.MissingObservation):
            obs.load("demo")

    def test_foreign_observation_is_a_failure(self):
        target = self.save()
        with self.assertRaises(obs.MissingObservation):
            obs.load("demo", oracle_commit="other")
        with self.assertRaises(obs.MissingObservation):
            obs.load("demo", goos="windows")
        document = json.loads(target.read_bytes())
        document["contract"] = "elsewhere"
        target.write_text(json.dumps(document))
        with self.assertRaises(obs.MissingObservation):
            obs.load("demo")
        target.write_text("{")
        with self.assertRaises(obs.MissingObservation):
            obs.load("demo")

    def test_material_is_minted_once(self):
        self.save(material={"seed": "one"})
        self.save(material={"seed": "two"})
        self.assertEqual(obs.load("demo")["material"], {"seed": "one"})

    def test_compare_names_the_first_difference(self):
        recorded = {"go": [{"case": "a", "exit": 0}]}
        obs.compare(recorded, copy.deepcopy(recorded), "demo")
        mutated = copy.deepcopy(recorded)
        mutated["go"][0]["exit"] = 1
        with self.assertRaisesRegex(AssertionError, r"\$\.go\[0\]\.exit"):
            obs.compare(recorded, mutated, "demo")

    def test_go_json_reduction_keeps_finished_tests_only(self):
        text = "\n".join(json.dumps(row) for row in [
            {"Action": "run", "Package": "p", "Test": "TestA"},
            {"Action": "output", "Package": "p", "Test": "TestA", "Output": "x"},
            {"Action": "pass", "Package": "p", "Test": "TestA", "Elapsed": 0.3},
            {"Action": "pass", "Package": "p", "Elapsed": 1.0}])
        self.assertEqual(obs.reduce_go_json(text), [{"Action": "pass", "Package": "p"},
                                                   {"Action": "pass", "Package": "p", "Test": "TestA"}])
        self.assertEqual(obs.reduce_go_text("=== RUN T\n--- PASS: TestA (0.31s)\n    --- FAIL: TestB/sub (0.0s)\n"),
                         ["--- FAIL: TestB/sub (0.00s)", "--- PASS: TestA (0.00s)"])


class OraclePinTests(unittest.TestCase):
    """The helper-driven captures are keyed to a fixed oracle commit, not to "the last *.go commit"."""

    def test_pin_is_a_fixed_full_commit(self):
        self.assertRegex(obs.ORACLE_COMMIT, r"^[0-9a-f]{40}$")
        source = Path(obs.__file__).read_text()
        self.assertNotIn('"log", "-1", "--format=%H"', source, "the oracle must not follow the last *.go commit")

    def test_capture_requires_the_go_sources_of_the_pin(self):
        with mock.patch.object(obs.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
            with self.assertRaisesRegex(SystemExit, "differ from the pinned oracle"):
                obs.tree_oracle_commit()
        with mock.patch.object(obs.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
            self.assertEqual(obs.tree_oracle_commit(), obs.ORACLE_COMMIT)

    def test_replay_never_asks_git_for_the_oracle(self):
        # data-safety replay used to ask git for the last *.go commit; replay uses the constant
        text = (Path(obs.__file__).parent / "data_safety_contract.py").read_text()
        replay = text.split("    else:\n        try:\n            recorded")[1].split("    try:\n        run_seed")[0]
        self.assertIn("oracle_commit=observations.ORACLE_COMMIT", replay)
        self.assertNotIn("tree_oracle_commit", replay)


class AttestationTests(unittest.TestCase):
    """verify-attestation is strict about labels, history and the pin; missing means failure."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patch = mock.patch.object(obs, "ATTEST_DIR", Path(self.tmp.name))
        patch.start()
        self.addCleanup(patch.stop)
        self.head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=obs.ROOT, capture_output=True, text=True, check=True).stdout.strip()
        self.good = {"schema": 1, "name": "audit-differential", "goos": obs.host_goos(), "goarch": "x", "go_version": "go1.26.6",
                     "direction": "x", "oracle_commit": obs.ORACLE_COMMIT, "rust_commit": self.head,
                     "rust_artifacts_sha256": {"rust-output.jsonl": "a" * 64},
                     "go_verdict": {"command": ["go"], "exit_code": 0, "output_sha256": "b" * 64, "accepted": True}}

    def write(self, **changes):
        document = copy.deepcopy(self.good)
        document.update(changes)
        obs.attestation_path(document["name"]).write_text(json.dumps(document))
        return document

    def test_accepts_a_well_formed_attestation(self):
        self.write()
        self.assertEqual(obs.check_attestation("audit-differential")["rust_commit"], self.head)

    def test_missing_is_a_failure(self):
        with self.assertRaises(obs.MissingObservation):
            obs.check_attestation("audit-differential")

    def test_labels_must_be_the_expected_ones(self):
        for labels in ({"other": "a" * 64}, {"rust-output.jsonl": "a" * 64, "extra": "a" * 64}, {}):
            self.write(rust_artifacts_sha256=labels)
            with self.assertRaises(obs.MissingObservation, msg=labels):
                obs.check_attestation("audit-differential")

    def test_rust_commit_must_be_an_ancestor_of_head(self):
        self.write(rust_commit="1" * 40)
        with self.assertRaisesRegex(obs.MissingObservation, "not an ancestor"):
            obs.check_attestation("audit-differential")

    def test_oracle_must_be_the_pin_and_verdict_accepting(self):
        self.write(oracle_commit="2" * 40)
        with self.assertRaises(obs.MissingObservation):
            obs.check_attestation("audit-differential")
        self.write(go_verdict={"command": ["go"], "exit_code": 1, "output_sha256": "b" * 64, "accepted": False})
        with self.assertRaises(obs.MissingObservation):
            obs.check_attestation("audit-differential")

    def test_ci_run_attestation_needs_its_fields_and_unchanged_sources(self):
        paths = ["scripts/rust-port/go_observations_common.py"]
        ci = {"schema": 1, "name": "native-keyring-interop", "goos": obs.host_goos(), "source": "ci-run", "direction": "x",
              "run_url": "https://github.com/danieljustus/symaira-vault/actions/runs/1", "job_id": 2, "commit": "3" * 40,
              "source_paths": paths, "source_digest": obs.sources_digest(paths), "oracle_commit": obs.ORACLE_COMMIT}
        target = obs.attestation_path("native-keyring-interop")
        target.write_text(json.dumps(ci))
        self.assertEqual(obs.check_attestation("native-keyring-interop")["job_id"], 2)
        for field, value in (("run_url", "https://example.com/run"), ("job_id", "2"), ("commit", "xyz"), ("source_paths", []),
                             ("source_digest", "0" * 64)):
            target.write_text(json.dumps({**ci, field: value}))
            with self.assertRaises(obs.MissingObservation, msg=field):
                obs.check_attestation("native-keyring-interop")
        target.write_text(json.dumps({k: v for k, v in ci.items() if k != "run_url"}))
        with self.assertRaises(obs.MissingObservation):
            obs.check_attestation("native-keyring-interop")

    def test_accepted_gap_is_printed_not_silent(self):
        with mock.patch.dict(obs.ACCEPTED_GAPS, {("audit-differential", obs.host_goos()): "no runner"}):
            self.assertEqual(obs.main(["verify-attestation", "audit-differential"]), 0)
        with self.assertRaises(SystemExit):
            obs.main(["verify-attestation", "audit-differential"])


class OperatorPathTests(unittest.TestCase):
    """Committed evidence never carries the capture host's paths."""

    def test_pack_tree_tokenizes_and_unpack_restores(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp, "seed")
            (source / "vault").mkdir(parents=True)
            (source / "vault" / "config.yaml").write_text(f"vaultDir: {source}/vault\nname: x\n")
            packed = obs.pack_tree(source)
            text = base64.b64decode(packed["vault/config.yaml"]).decode()
            self.assertEqual(text, "vaultDir: @TREE_ROOT@/vault\nname: x\n")
            target = Path(tmp, "elsewhere")
            obs.unpack_tree(packed, target)
            self.assertEqual((target / "vault" / "config.yaml").read_text(), f"vaultDir: {target}/vault\nname: x\n")

    def test_pack_tree_refuses_an_operator_path_it_cannot_tokenize(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "note").write_text("see /Users/someone/vault\n")
            with self.assertRaisesRegex(ValueError, "operator paths"):
                obs.pack_tree(tmp)

    def test_save_refuses_paths_even_when_base64_packed(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(obs, "OBS_DIR", Path(tmp)):
            hidden = base64.b64encode(b"vaultDir: /var/folders/7v/abc/T/x").decode()
            with self.assertRaises(ValueError):
                obs.save("demo", {"go": [hidden]}, oracle_commit="abc", version="v", args=[])
            with self.assertRaises(ValueError):
                obs.save("demo", {"go": ["/tmp/symvault-api-capture-89da60wj/x"]}, oracle_commit="abc", version="v", args=[])

    def test_portable_command_hides_the_checkout(self):
        self.assertEqual(obs.portable(f"sh {obs.ROOT}/a.sh {obs.ROOT}"), "sh <repo>/a.sh <repo>")

    def test_committed_evidence_has_no_operator_paths(self):
        roots = [obs.OBS_DIR, obs.ROOT / "docs" / "rust-port" / "evidence"]
        scanned, hits = 0, {}
        for root in roots:
            for file in sorted(root.rglob("*")):
                if file.is_file():
                    scanned += 1
                    found = obs.operator_paths(file.read_bytes())
                    if found:
                        hits[str(obs.rel(file))] = found
        self.assertGreater(scanned, 40, "the scan found no evidence to look at")
        self.assertEqual(hits, {})


if __name__ == "__main__":
    unittest.main()
