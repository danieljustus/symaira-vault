#!/usr/bin/env python3
"""Negative controls for the Go-free native closeout records (no Go, no keyring, no cargo)."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import go_observations_common as obs
import native_closeout as closeout


def policy_document(fixture_bytes, **changes):
    observations = {"oracle_pin": closeout.POLICY_ORACLE_COMMIT, "oracle_release": "unreleased", "check_exit": 0,
                    "committed_fixture": closeout.POLICY_FIXTURE,
                    "native_fixture_sha256": hashlib.sha256(fixture_bytes).hexdigest(), "native_matches_committed": True}
    observations.update(changes)
    return {"schema": obs.SCHEMA, "contract": closeout.POLICY_OBSERVATION, "oracle_commit": "a" * 40, "go_version": "go1.26.6",
            "goos": obs.host_goos(), "goarch": "arm64", "args": [], "observations": observations}


class PolicyReplay(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repo"
        (self.root / "testdata/port/core").mkdir(parents=True)
        self.fixture = b'{"policy":"contract"}\n'
        (self.root / closeout.POLICY_FIXTURE).write_bytes(self.fixture)
        self.obs_dir = Path(self.tmp.name) / "obs"
        self.obs_dir.mkdir()
        patcher = patch.object(obs, "OBS_DIR", self.obs_dir)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, document):
        obs.path(closeout.POLICY_OBSERVATION).write_text(json.dumps(document))

    def test_matching_observation_returns_the_committed_fixture(self):
        self.write(policy_document(self.fixture))
        report = {}
        self.assertEqual(closeout.replay_policy(self.root, report), self.root / closeout.POLICY_FIXTURE)
        self.assertIs(report["policy_fixture_matches_committed"], True)

    def test_mutated_committed_fixture_is_rejected(self):
        self.write(policy_document(self.fixture))
        (self.root / closeout.POLICY_FIXTURE).write_bytes(self.fixture + b" ")
        with self.assertRaisesRegex(SystemExit, "no longer has the bytes native Go regeneration produced"):
            closeout.replay_policy(self.root, {})

    def test_mutated_or_non_accepting_observation_is_rejected(self):
        for change in [{"native_matches_committed": False}, {"check_exit": 1}, {"oracle_pin": "deadbee"},
                       {"committed_fixture": "elsewhere.json"}, {"native_fixture_sha256": "0" * 64}]:
            with self.subTest(change=change):
                self.write(policy_document(self.fixture, **change))
                with self.assertRaises(SystemExit):
                    closeout.replay_policy(self.root, {})

    def test_missing_or_foreign_observation_is_a_failure_never_a_skip(self):
        with self.assertRaises(obs.MissingObservation):
            closeout.replay_policy(self.root, {})
        foreign = policy_document(self.fixture)
        foreign["goos"] = "plan9"
        self.write(foreign)
        with self.assertRaises(obs.MissingObservation):
            closeout.replay_policy(self.root, {})


class KeyringAttestation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = patch.object(obs, "ATTEST_DIR", Path(self.tmp.name))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.good = {"schema": obs.SCHEMA, "name": closeout.KEYRING_ATTESTATION, "goos": obs.host_goos(), "go_version": "go1.26.6",
                     "oracle_commit": obs.ORACLE_COMMIT, "rust_commit": obs.git_output("rev-parse", "HEAD"),
                     "rust_artifacts_sha256": {"rust-native-keyring-test": "c" * 64},
                     "go_verdict": {"command": ["x"], "exit_code": 0, "output_sha256": "d" * 64, "accepted": True}}

    def write(self, document):
        obs.attestation_path(closeout.KEYRING_ATTESTATION).write_text(json.dumps(document))

    def test_accepting_attestation_verifies(self):
        self.write(self.good)
        self.assertEqual(obs.check_attestation(closeout.KEYRING_ATTESTATION)["go_version"], "go1.26.6")

    def test_mutated_attestation_is_rejected(self):
        def mutate(path, value):
            document = copy.deepcopy(self.good)
            target = document
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            return document
        for path, value in [(["go_verdict", "accepted"], False), (["go_verdict", "exit_code"], 1), (["goos"], "plan9"),
                            (["oracle_commit"], "zz"), (["oracle_commit"], "a" * 40), (["rust_commit"], ""),
                            (["rust_commit"], "b" * 40), (["rust_artifacts_sha256"], {}),
                            (["name"], "other"), (["schema"], 2)]:
            with self.subTest(path=path):
                self.write(mutate(path, value))
                with self.assertRaises(obs.MissingObservation):
                    obs.check_attestation(closeout.KEYRING_ATTESTATION)

    def test_missing_attestation_is_a_failure_never_a_skip(self):
        with self.assertRaises(obs.MissingObservation):
            obs.check_attestation(closeout.KEYRING_ATTESTATION)


if __name__ == "__main__":
    unittest.main()
