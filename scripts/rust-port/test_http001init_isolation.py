#!/usr/bin/env python3
"""Replay of the HTTP fixture Make entrypoint's keyring-isolation probe (macOS only).

The probe once built the historical generator against an instrumented go-keyring copy and proved that the Make entrypoint
selected the memory keyring before Go package init (four init-time OS-keyring helper calls without the isolation, none
with it). That needs the archived Go tree (tag `legacy/go-oracle`) and is not repeated here; its verdicts are the committed
`http001init-isolation` observation. This replay loads the observation under its pinned oracle (a missing or foreign one
fails), requires the recorded verdict fields to be exactly the probe's, and authenticates the HTTP initialize fixture
bytes through the independent anchor manifest.
"""
import subprocess
import sys

from mcp_oracle import HISTORICAL
from mcp_process_contract import ROOT, load_go_observations, provenance
from mcp_fixture_contract import fixture_anchor, generator_paths

OBSERVATION = "http001init-isolation"
VERDICT_FIELDS = {"control_helper_calls", "control_exit", "safe_backends", "safe_helper_calls", "unsafe_exit_nonzero",
                  "unsafe_helper_calls", "unsafe_backends"}
FIXTURE = "testdata/port/mcp/http-initialize.json"


def history_checks():
    """The committed HTTP initialize fixture is the immutable historical byte string."""
    fixture_anchor(ROOT, generator_paths())
    fixture_anchor(ROOT, [FIXTURE])


def main():
    if sys.platform != "darwin":
        print("SKIP: absolute-keychain-helper instrumentation is macOS-specific")
        return 0
    document = load_go_observations(OBSERVATION, {}, oracle=HISTORICAL)
    history_checks()
    assert set(document["data"]) == VERDICT_FIELDS, ("recorded probe verdict fields differ from the probe's", sorted(document["data"]))
    print("PASS (replay): HTTP initialize fixture bytes anchored by the independent manifest; recorded Go probe observation "
          + provenance(document)["path"] + " loaded under its pinned oracle (verdict values were asserted at capture).")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, subprocess.SubprocessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
