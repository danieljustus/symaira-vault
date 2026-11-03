#!/usr/bin/env python3
"""Go-recorded timestamp fixtures: acceptance and display.

Runs scripts/rust-port/go_timestamp_oracle.go.txt (Go 1.26.6, time.Parse RFC3339
via encoding/json into *time.Time) over the raw JSON timestamp values and
records, per value, whether Go accepts it and what Go prints for it in the
token/agent tables (Format("2006-01-02 15:04")) plus whether it is After the
zero time. Outputs (both under crates/symvault-store/tests/fixtures/):

  go_timestamp_cases.json          [[raw, accepts], ...]
  go_timestamp_display_cases.json  [[raw, display, after_zero], ...]  accepted non-null raws only

Modes (exactly one is required):
  --generate  re-record and overwrite both fixtures (the only writing mode)
  --check     re-record in memory and compare byte-for-byte; never writes

The oracle runs under three process time zones that must agree: Go's Format
uses the parsed offset, so the output may not depend on TZ.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / 'scripts/rust-port/go_timestamp_oracle.go.txt'
FIXTURES = ROOT / 'crates/symvault-store/tests/fixtures'
CASES = FIXTURES / 'go_timestamp_cases.json'
DISPLAY = FIXTURES / 'go_timestamp_display_cases.json'
TOOLCHAIN = os.environ.get('GO_TOOLCHAIN', 'go1.26.6')
ZONES = ('UTC', 'America/New_York', 'Pacific/Kiritimati')

# Display-relevant values added to the acceptance sweep (kept at the end so the
# original 953 stay in place): zero-time boundaries, one-digit hours with and
# without an offset, non-canonical fractions/offsets, extreme years.
EXTRA = [
    '"0001-01-01T00:00:00Z"', '"0001-01-01T00:00:00.5Z"', '"0001-01-01T01:00:00+01:00"',
    '"0001-01-01T00:00:00+00:01"', '"0000-12-31T23:59:59Z"', '"0000-01-01T00:00:00Z"',
    '"0001-01-01T0:00:00Z"', '"0001-01-01T00:00:00-00:01"',
    '"2026-01-01T0:00:00Z"', '"2026-01-01T9:05:07Z"', '"2026-01-01T9:05:07-07:00"',
    '"2026-01-01T9:05:07+05:30"', '"2026-01-01T23:59:59-24:00"', '"2026-01-01T00:00:00+24:00"',
    '"2026-01-01T00:00:00+24:60"', '"2026-01-01T9:05:07,123+00:60"', '"2026-12-31T23:59:59.999999999Z"',
    '"2026-01-01T5:7:09Z"', '"2026-02-29T00:00:00Z"', '"2028-02-29T9:00:00Z"',
    '"9999-12-31T23:59:59-24:00"', '"9999-12-31T23:59:59+24:00"', '"0000-01-01T00:00:00+24:00"',
    '"2026-06-15T09:30:00+02:00"', '"2026-06-15T09:30:00-02:30"', '"2026-06-15T9:30:00.000000001+14:00"',
]

# `agent token list` drops expired tokens at load, so its EXPIRES AT column can
# only be exercised with instants in the future. These far-future (year 2999)
# values keep that coverage independent of the clock: every wall-clock shape
# the Go parser accepts (one-digit hours, `,`/`.` fractions, offsets up to
# +-24:60) across a few dates.
FUTURE_DATES = ['2999-01-01', '2999-02-28', '2999-06-15', '2999-12-31']
FUTURE_TIMES = [
    'T0:00:00Z', 'T1:00:00Z', 'T9:05:07Z', 'T09:05:07Z', 'T12:34:56Z', 'T23:59:59Z',
    'T9:05:07-07:00', 'T9:05:07+05:30', 'T9:05:07+14:00', 'T12:00:00-00:01', 'T0:00:00-12:30',
    'T23:59:59-24:00', 'T00:00:00+24:00', 'T00:00:00+24:60', 'T9:05:07,123+00:60',
    'T23:59:59.999999999Z', 'T00:00:00,5Z', 'T0:00:00.5+14:00', 'T10:20:30+00:00', 'T5:7:09Z',
]
EXTRA += [f'"{date}{time}"' for date in FUTURE_DATES for time in FUTURE_TIMES]


def record(raws, zone, work):
    source = work / 'oracle.go'
    source.write_bytes(ORACLE.read_bytes())
    cases = work / 'cases.json'
    cases.write_text(json.dumps(raws), encoding='utf-8')
    env = dict(os.environ, TZ=zone, CGO_ENABLED='0', GOWORK='off', GOTOOLCHAIN=TOOLCHAIN)
    done = subprocess.run(['go', 'run', str(source), str(cases)], cwd=work, env=env, capture_output=True, text=True, timeout=300)
    if done.returncode:
        raise SystemExit(f'go oracle failed under TZ={zone}: {done.stderr}')
    rows = json.loads(done.stdout)
    assert [row['raw'] for row in rows] == raws
    return rows


def build():
    raws = [raw for raw, _ in json.loads(CASES.read_text(encoding='utf-8'))]
    raws += [raw for raw in EXTRA if raw not in raws]
    assert len(set(raws)) == len(raws)
    with tempfile.TemporaryDirectory(prefix='symvault-go-timestamps-', dir=os.environ.get('TMPDIR')) as tmp:
        recorded = [record(raws, zone, Path(tmp)) for zone in ZONES]
    for zone, rows in zip(ZONES[1:], recorded[1:]):
        assert rows == recorded[0], f'Go output depends on TZ={zone}'
    rows = recorded[0]
    assert all(row['go'] in {'accept', 'reject', 'syntax'} for row in rows)
    cases = [[row['raw'], row['go'] == 'accept'] for row in rows]
    display = [[row['raw'], row['display'], row['after_zero']] for row in rows if row['has_time']]
    assert all(text for _, text, _ in display)
    render = lambda items: '[\n' + ',\n'.join(json.dumps(item) for item in items) + '\n]\n'
    return render(cases), render(display), len(cases), len(display)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--generate', action='store_true', help='re-record and overwrite the fixtures')
    mode.add_argument('--check', action='store_true', help='re-record in memory and compare; never writes')
    args = parser.parse_args()
    if shutil.which('go') is None:
        raise SystemExit('go is required')
    cases, display, n_cases, n_display = build()
    if args.generate:
        CASES.write_text(cases, encoding='utf-8')
        DISPLAY.write_text(display, encoding='utf-8')
        print(f'recorded {n_cases} acceptance cases and {n_display} display cases')
        return
    stale = [path.name for path, text in ((CASES, cases), (DISPLAY, display)) if not path.exists() or path.read_text(encoding='utf-8') != text]
    if stale:
        raise SystemExit(f'STALE: {", ".join(stale)} differ from the Go oracle (run the Go oracle archive recipe (docs/rust-port/go-oracle-archive.md))')
    print(f'PASS: {n_cases} acceptance and {n_display} display cases match Go {TOOLCHAIN} under TZ {", ".join(ZONES)}')


if __name__ == '__main__':
    main()
