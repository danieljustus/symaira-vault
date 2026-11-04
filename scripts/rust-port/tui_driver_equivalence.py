#!/usr/bin/env python3
"""Driver equivalence evidence: the Python driver reproduced the Go helper's Rust-side rows.

  tui_driver_equivalence.py check [EVIDENCE]     replay (no Go, no run)

The committed evidence (docs/rust-port/evidence/tui-driver-equivalence.<goos>.json) was proven once, on a
Go capture host: the Rust binary driven by the former Go fixture helper on the recorded seeds, and the same
binary driven by tui_driver.py, produced identical rows. The proof cannot be repeated in this tree (the Go
helper and its capture mode are gone; tag `legacy/go-oracle` holds them).

`check` fails when the committed evidence is missing for this OS, is not an identical verdict, or
no longer describes the driver, the snapshot tool or the recorded observation in the tree.
"""
from pathlib import Path
import json
import sys

import go_observations_common as obs
import tui_contract as tui

SNAPSHOT_SOURCE = tui.ROOT/'crates/symvault-store/examples/tui-snapshot.rs'


def evidence_path(goos=None):
    return tui.ROOT/'docs/rust-port/evidence'/f'tui-driver-equivalence.{goos or obs.host_goos()}.json'


def check(path):
    if not path.is_file():
        raise AssertionError(f'missing driver equivalence evidence {obs.rel(path)} (recorded once on a Go capture host; see tag legacy/go-oracle)')
    document = json.loads(path.read_bytes())
    assert document.get('contract') == 'tui-driver-equivalence' and document.get('identical') is True, 'not an identical verdict'
    assert document['cases'] == len(tui.CASES) and document['snapshots_compared'] > 0, 'evidence compared nothing'
    observation = obs.path(tui.OBS_NAME)
    assert observation.is_file(), f'missing recorded Go observation {obs.rel(observation)}'
    for key, current in [('python_driver_source_sha256', tui.digest(tui.DRIVER)),
                         ('snapshot_tool_source_sha256', tui.digest(SNAPSHOT_SOURCE)),
                         ('observation_sha256', tui.digest(observation))]:
        assert document.get(key) == current, f'{key}: the evidence describes a different {key.split("_")[0]}'
    print(f"equivalence evidence ok: {document['cases']} cases, {document['snapshots_compared']} store snapshots "
          f"({obs.rel(path)})")


def main():
    if sys.argv[1:2] != ['check']:
        sys.exit(__doc__)
    check(Path(sys.argv[2]) if len(sys.argv) > 2 else evidence_path())


if __name__ == '__main__':
    try:
        main()
    except AssertionError as error:
        sys.exit(f'FAIL: {error}')
