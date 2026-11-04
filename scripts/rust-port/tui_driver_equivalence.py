#!/usr/bin/env python3
"""Driver equivalence evidence: the Python driver reproduces the Go helper's Rust-side rows.

  tui_driver_equivalence.py REFERENCE NATIVE_RECEIPT [--evidence PATH]     prove and record
  tui_driver_equivalence.py check EVIDENCE                                 replay (no Go, no run)

REFERENCE is written by `tui_contract.py --capture-go --reference-rust-out`: the Rust binary driven
by the former Go fixture helper on the recorded seeds. NATIVE_RECEIPT is the receipt of the Go-free
replay, in which the same Rust binary is driven by tui_driver.py. Every deterministic field of every
Rust case row (store snapshots before and after, configuration readback, exit class, console mode
restoration, editor observations, decisions) must be identical; a difference is a failure.

`check` fails when the committed evidence is missing for this OS, is not an identical verdict, or
no longer describes the driver, the snapshot tool or the recorded observation in the tree: changing
any of them needs the equivalence proven again (a Go capture host).
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

import go_observations_common as obs
import tui_contract as tui


def compare(reference, receipt):
    assert reference['rust_executable_sha256'] == receipt['rust_executable_sha256'], \
        'the two drivers must drive the same Rust binary'
    new_rows = [tui.normalize_row(row) for row in receipt['rust']]
    old_rows = reference['rows']
    assert [r['case'] for r in old_rows] == [r['case'] for r in new_rows] == tui.CASES, 'case set differs'
    fields = 0
    for old, new in zip(old_rows, new_rows):
        found = obs.first_difference(old, new, old['case'])
        assert found is None, f'Python driver differs from the Go helper on the same Rust binary: {found}'
        fields += len(old)
    return {'cases': len(old_rows), 'compared_fields': fields,
            'snapshots_compared': sum(len(r.get('before', [])) + len(r.get('after', [])) for r in old_rows)}


SNAPSHOT_SOURCE = tui.ROOT/'crates/symvault-store/examples/tui-snapshot.rs'


def evidence_path(goos=None):
    return tui.ROOT/'docs/rust-port/evidence'/f'tui-driver-equivalence.{goos or obs.host_goos()}.json'


def check(path):
    if not path.is_file():
        raise AssertionError(f'missing driver equivalence evidence {obs.rel(path)}: prove it on a Go capture host')
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
    if sys.argv[1:2] == ['check']:
        check(Path(sys.argv[2]) if len(sys.argv) > 2 else evidence_path())
        return
    parser = argparse.ArgumentParser()
    parser.add_argument('reference', type=Path)
    parser.add_argument('receipt', type=Path)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    reference = json.loads(args.reference.read_bytes())
    receipt = json.loads(args.receipt.read_bytes())
    assert 'failure' not in receipt and all(row['passed'] is True for row in receipt['rust']), 'the replay did not pass every case'
    summary = compare(reference, receipt)
    if args.evidence:
        document = {'schema': 1, 'contract': 'tui-driver-equivalence', 'platform': reference['platform'],
                    'rust_executable_sha256': reference['rust_executable_sha256'],
                    'reference_driver': reference['reference_driver'],
                    'reference_sha256': hashlib.sha256(args.reference.read_bytes()).hexdigest(),
                    'python_driver_source_sha256': tui.digest(tui.DRIVER),
                    'snapshot_tool': 'symvault-store example tui-snapshot',
                    'snapshot_tool_source_sha256': tui.digest(SNAPSHOT_SOURCE),
                    'observation_sha256': tui.digest(obs.path(tui.OBS_NAME)), **summary, 'identical': True}
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_bytes(obs.canonical(document).encode())
    print(f"PASS: Python driver == Go helper on {summary['cases']} cases ({summary['snapshots_compared']} store snapshots)")


if __name__ == '__main__':
    try:
        main()
    except AssertionError as error:
        sys.exit(f'FAIL: {error}')
