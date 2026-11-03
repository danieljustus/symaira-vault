#!/usr/bin/env python3
"""Pins the local-area target list of each lane.

local-gate-area.sh reads the expected list from `make local-area-list`, so a
target deleted from the Makefile would silently shrink both the run and its
expectation. These lists are written out here instead: dropping, adding or
renaming a target fails this test until the list below (and the lane's
documented count in docs/rust-port/local-first.md) is changed on purpose.
"""
import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

COMMON = """
api-templates-differential api-transport-contract area-check-selftest broker-connect-contract
broker-egress-contract cfg-overrides-fixtures-check cli-artifacts-contract config-profile-differential
config-session-differential device-list-differential device-session-differential git-offline-differential
git-winner-differential http-framing-contract http-head-contract http-oauth-contract http-origin-contract
http-process-contract http-slow-peer-contract http-timeout-contract http-tls-contract http-write-contract
intake-cli-contract kdf-resource-policy-contract mcp-call-differential mcp-clipboard-signals-differential
mcp-execute-api-policy-differential mcp-http-replay-contract mcp-http-shutdown-contract mcp-http-token-contract mcp-init-differential
mcp-list-differential mcp-named-tests mcp-oauth-contract mcp-process-contract mcp-stdio-differential pairing-differential
pairing-oracle-contract read-resource-policy-contract rust-007-differential serve-cli-contract
signal-process-contract store-live-contract store-observations-contract store004-isolation-check
sync-observations-contract toolhash-process-contract tui-named-tests update-fixtures-check
worktree-prune-check
""".split()
LANE_ONLY = {"macos": "tui-harness-check", "linux": "tui-contract"}
PINNED = {lane: sorted(COMMON + [extra]) for lane, extra in LANE_ONLY.items()}


def area_list(lane):
    env = {k: v for k, v in os.environ.items() if k not in ("MAKEFLAGS", "MFLAGS", "MAKELEVEL")}
    out = subprocess.run(["make", "--no-print-directory", "-s", "-C", str(ROOT), "local-area-list",
                          f"LOCAL_AREA_LANE={lane}"], env=env, capture_output=True, text=True, check=True).stdout
    return out.split()


class AreaLists(unittest.TestCase):
    def test_pinned_counts(self):
        self.assertEqual({lane: len(names) for lane, names in PINNED.items()}, {"macos": 51, "linux": 51})
        for names in PINNED.values():
            self.assertEqual(len(names), len(set(names)))

    def test_each_lane_runs_exactly_the_pinned_targets(self):
        for lane, pinned in PINNED.items():
            actual = area_list(lane)
            self.assertEqual(len(actual), len(set(actual)), f"{lane}: a target is listed twice")
            self.assertEqual(sorted(actual), pinned,
                             f"{lane}: make local-area-list differs from the pinned list; "
                             f"missing={sorted(set(pinned) - set(actual))} extra={sorted(set(actual) - set(pinned))}")

    def test_lane_only_targets_stay_lane_only(self):
        self.assertIn("tui-harness-check", area_list("macos"))
        self.assertNotIn("tui-contract", area_list("macos"))
        self.assertIn("tui-contract", area_list("linux"))
        self.assertNotIn("tui-harness-check", area_list("linux"))


if __name__ == "__main__":
    unittest.main()
