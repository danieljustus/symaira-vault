#!/usr/bin/env python3
"""Committed observation of the Go -race tests behind `make mcp-http-shutdown-contract`.

The target used to run two live `go test -race -json` commands against the Go oracle sources and check that a
fixed list of tests passed (gate_area_check go-json). Those tests observe Go; once Go is removed the only thing
left to check is their recorded verdict. `--capture-go` (Go required) runs both commands once and records the
normalised event stream (Action, Package, Test of every pass/fail/skip event; no output, time or elapsed);
`--replay OUT.jsonl` (Go-free) rewrites it as the go-test JSON lines gate_area_check reads, byte-identically
for every replay.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mcp_process_contract import ROOT, go_version_of, load_go_observations, provenance, save_go_observations  # noqa: E402

CONTRACT = 'mcp-http-shutdown-go-tests'
NORMALIZATION = ['go test -json events reduced to Action/Package/Test of the pass, fail and skip events; output, time and elapsed dropped '
                 '(nothing compares them); events sorted so the recording is independent of test scheduling']
SELECTED = ('TestApprovalCancellation|TestApprovalUninterruptible|^TestAuthorize|TestScopeCheckHook|'
            'TestHandleGet_OutsideScope|TestHandleDelete_OutsideScope|TestHandleGetMetadata_OutsideScope')
COMMANDS = [
    ['-race', '-json', './internal/mcp/serverbootstrap', './internal/secureui', './internal/approval', './internal/policy', '-count=1'],
    ['-race', '-json', './internal/mcp/server', '-count=1', '-run', SELECTED],
]
ACTIONS = {'pass', 'fail', 'skip'}


def run_go(arguments):
    env = dict(os.environ, GOWORK='off', TZ='UTC', SYMVAULT_TEST_KEYRING='memory')
    result = subprocess.run(['go', 'test', *arguments], cwd=ROOT, env=env, capture_output=True, text=True, timeout=1500)
    events = []
    for line in result.stdout.splitlines():
        if line.startswith('{'):
            row = json.loads(line)
            if row.get('Action') in ACTIONS:
                events.append({k: row[k] for k in ('Action', 'Package', 'Test') if k in row})
    if result.returncode and not any(e['Action'] == 'fail' for e in events):
        raise SystemExit(f'go test {arguments[:3]} failed ({result.returncode}) without a failing event: {result.stderr[-1500:]}')
    return events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--capture-go', action='store_true', help='run the Go tests and write the committed observation (Go required)')
    mode.add_argument('--replay', type=Path, metavar='OUT.jsonl', help='write the recorded events as go test -json lines (Go-free)')
    args = parser.parse_args()
    if args.capture_go:
        events = [event for arguments in COMMANDS for event in run_go(arguments)]
        assert not any(e['Action'] == 'fail' for e in events), 'a Go -race test failed; refusing to record a failing oracle'
        events.sort(key=lambda e: (e['Package'], e.get('Test', ''), e['Action']))
        path = save_go_observations(CONTRACT, dict(commands=COMMANDS, events=events), {}, NORMALIZATION, go_version_of())
        print(f'CAPTURED: {len(events)} Go -race events -> {path}')
        return
    document = load_go_observations(CONTRACT, {})
    lines = [json.dumps(event, sort_keys=True) for event in document['data']['events']]
    args.replay.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f'REPLAYED: {len(lines)} recorded Go -race events from {provenance(document)["path"]}')


if __name__ == '__main__':
    main()
