#!/usr/bin/env python3
"""Selftests of go_observations_common: replay is strict, never a skip."""
import copy
import json
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
