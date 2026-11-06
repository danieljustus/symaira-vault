#!/usr/bin/env python3
"""Replay of the committed Go -race observation behind `make mcp-http-shutdown-contract`.

The target used to run two live Go race-detector test commands (JSON event output) against the Go oracle sources and
check that a fixed list of tests passed (gate_area_check go-json). Those tests observe Go; the only thing left to check is their recorded
verdict. The normalised event stream (Action, Package, Test of every pass/fail/skip event; no output, time or elapsed;
events sorted so the recording is independent of test scheduling) was recorded once from the archived Go tree (tag
`legacy/go-oracle`); there is no capture mode here. `--replay OUT.jsonl` rewrites it as the go-test JSON lines
gate_area_check reads, byte-identically for every replay.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mcp_process_contract import load_go_observations, provenance  # noqa: E402

CONTRACT = 'mcp-http-shutdown-go-tests'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--replay', type=Path, metavar='OUT.jsonl', required=True,
                        help='write the recorded events as Go test JSON event lines')
    args = parser.parse_args()
    document = load_go_observations(CONTRACT, {})
    lines = [json.dumps(event, sort_keys=True) for event in document['data']['events']]
    args.replay.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f'REPLAYED: {len(lines)} recorded Go -race events from {provenance(document)["path"]}')


if __name__ == '__main__':
    main()
