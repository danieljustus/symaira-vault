#!/usr/bin/env python3
"""Go-recorded MCP tools/call authorization matrix (MCP-002/MCP-003), replay only.

The corrected Go oracle was built out of tree once, one disposable vault per agent
profile (22 profiles, same set as mcp_process_contract.py) was seeded and the JSON-RPC
response of a minimal `tools/call` was recorded for every registered tool plus one
unknown name, with no token, with a token scope excluding the tool and with a token
scope naming exactly the tool. Arguments are inert (`{}`), so no tool reaches a
clipboard, autotype, payment, Perplexity, network or child process.

The matrix is recorded per host GOOS (the capability decisions depend on the
platform: Touch ID, clipboard and autotype backends, secure-input UI):

  testdata/port/mcp/authz-matrix.json          darwin
  testdata/port/mcp/authz-matrix-linux.json    linux

  --check      replay, no Go: the host's frozen fixture must be the bytes the Go
               capture accepted (scripts/rust-port/fixtures/go-observations/
               mcp-authz-matrix.<goos>.json), its oracle pin must resolve in git
               with the recorded source digest; a host without a recorded fixture
               is a failure, never a skip

There is no generate/capture mode in this tree: the matrix is regenerated from tag
`legacy/go-oracle` (docs/rust-port/go-oracle-archive.md).
"""
import argparse
import hashlib
import json
import platform
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import go_observations_common as observations

ROOT = Path(__file__).resolve().parents[2]
# The pinned corrected oracle the matrix was recorded from (see scripts/rust-port/mcp_oracle.py).
ORDERED = '24acdb08fcc7021262717aa803d72eb8d151c66a'
CONTRACT = 'mcp-anomaly-ordered-v1'
MODULE_FILES = ("go.mod", "go.sum")
FIXTURES = {
    'darwin': ROOT / 'testdata/port/mcp/authz-matrix.json',
    'linux': ROOT / 'testdata/port/mcp/authz-matrix-linux.json',
}
PROBE = ROOT / 'scripts/rust-port/mcp_authz_probe.go.txt'
SEED = ROOT / 'scripts/rust-port/mcp_process_seed.go.txt'
CATALOG = ROOT / 'testdata/port/mcp/tool-list.json'
UNKNOWN_TOOL = 'mcp_authz_unknown_tool'
TOKEN_MODES = ['none', 'excluding', 'including']
# Successful results that are random or depend on the whole prior audit trail
# (timestamps, earlier denials) cannot be frozen byte for byte. Their frozen
# value is the mask below; the replay applies the identical mask to Rust.
MASKS = {
    'generate_password': ('random_password', lambda text: {'masked': 'random_password', 'length': len(undo_mcp_sanitizer(text))}),
    # normalize() already turned the JSON array text into {'json_text': [...]}.
    'symaira_audit_self': ('audit_rows', lambda text: {'masked': 'audit_rows', 'json_array': isinstance(text, dict) and isinstance(text.get('json_text'), list)}),
}


def undo_mcp_sanitizer(text):
    """Inverts the only rewrites the MCP output sanitizer can apply to a
    generated password (internal/mcp/server/render.go sanitizeBytes, mirrored by
    crates/symvault-mcp/src/render.rs): `</name...>` -> `</ name... >` and
    `-->` -> `-- >`. The password charset has neither a space nor a control or
    non-ASCII character, so every space comes from the sanitizer and the original
    length is recoverable exactly. Without this, about 1 password in 8,700
    (`-->` or `</x...>` among 16 characters of an 82-character alphabet) is
    longer than 16 and the masked length differs between two otherwise identical
    observations. Any other space or character stays in the measured text, so a
    wrong-length password is still a visible difference."""
    if not isinstance(text, str):
        return text
    return re.sub(r'</ ([^ >]+) >', r'</\1>', text).replace('-- >', '-->')


def host_goos():
    """Go spelling of the host OS; an unrecorded host fails visibly."""
    goos = {'Darwin': 'darwin', 'Linux': 'linux'}.get(platform.system())
    if goos not in FIXTURES:
        raise SystemExit(f'MCP authz matrix has no fixture for host OS {platform.system()!r}; recorded: {sorted(FIXTURES)}')
    return goos


def fixture_path(goos):
    return FIXTURES[goos]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def normalize(value, home):
    """Rewrites only the disposable HOME prefix, nested JSON text (compared as
    JSON, as the process contract does) and the host's Touch ID capability
    (macOS hardware vs Linux CI)."""
    if isinstance(value, str):
        value = value.replace(str(home), '__HOME__')
        try:
            nested = json.loads(value)
        except ValueError:
            return value
        if isinstance(nested, (dict, list)):
            return {'json_text': normalize(nested, home)}
        return value
    if isinstance(value, list):
        return [normalize(v, home) for v in value]
    if isinstance(value, dict):
        return {k: ('<host-dependent>' if k == 'touchIDAvailable' else normalize(v, home)) for k, v in value.items()}
    return value


def mask(tool, response):
    """Mask only an isError=false text result of the two documented tools."""
    result = response.get('result') if isinstance(response, dict) else None
    if tool in MASKS and result and not result.get('isError') and result.get('content'):
        content = dict(result['content'][0])
        content['text'] = MASKS[tool][1](content['text'])
        return dict(response, result=dict(result, content=[content]))
    return response


def differing_rows(first, second, limit=600):
    """The rows two observations of one profile disagree on, as readable text,
    so a nondeterminism failure names the tool, the token mode and both values
    instead of only the tool/mode pair."""
    return [{'tool': a['tool'], 'token': a['token'],
             'first': json.dumps(a['response'], ensure_ascii=False)[:limit],
             'second': json.dumps(b['response'], ensure_ascii=False)[:limit]}
            for a, b in zip(first, second) if a != b]


def git(args):
    done = subprocess.run(['git', *args], cwd=ROOT, capture_output=True)
    assert done.returncode == 0, (args[:2], done.stderr.decode(errors='replace')[-500:])
    return done.stdout


def frozen_source_digest(commit):
    """The oracle source digest recomputed from git blobs (no checkout, no Go): same algorithm as inventory()."""
    names = sorted(p for p in git(['ls-tree', '-r', '--name-only', commit]).decode().splitlines()
                   if p in MODULE_FILES or p.endswith('.go') and not p.endswith('_test.go'))
    digest = hashlib.sha256()
    for name in names:
        digest.update(name.encode() + b'\0' + git(['show', f'{commit}:{name}']) + b'\0')
    return digest.hexdigest(), len(names)


def replay_check(goos, fixture_file):
    """Replay: the frozen per-OS fixture is the recorded Go observation. It must be the bytes the Go capture
    accepted, its oracle pin must resolve in git with the recorded source digest, and the probes must be unchanged."""
    if not fixture_file.is_file():
        raise SystemExit(f'MCP authz matrix fixture missing for {goos}: {fixture_file.relative_to(ROOT)}; the matrix cannot be regenerated in this tree (tag legacy/go-oracle holds the generator)')
    recorded = observations.load('mcp-authz-matrix', oracle_commit=ORDERED)['observations']
    assert recorded['fixture'] == str(fixture_file.relative_to(ROOT)), 'recorded Go observation covers another fixture'
    if sha256(fixture_file) != recorded['fixture_sha256']:
        raise SystemExit(f'MCP authz matrix fixture changed for {goos}: it is not the bytes the Go oracle produced')
    fixture = json.loads(fixture_file.read_text(encoding='utf-8'))
    oracle = fixture['oracle']
    assert oracle['commit_sha'] == ORDERED and oracle['reference_contract'] == CONTRACT, 'fixture oracle pin drifted'
    digest, count = frozen_source_digest(ORDERED)
    assert digest == oracle['source_digest'] == recorded['source_digest'], 'oracle source digest differs from git blobs'
    assert oracle['source_files'].endswith(f'({count} files)'), ('oracle source file count', oracle['source_files'], count)
    assert sha256(PROBE) == oracle['probe_sha256'] == recorded['probe_sha256'], 'authz probe changed'
    assert sha256(SEED) == oracle['seed_sha256'] == recorded['seed_sha256'], 'authz seed changed'
    assert len(fixture['cases']) == recorded['cases'] == len(fixture['profiles']) * len(fixture['tools']) * len(TOKEN_MODES)
    return fixture


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true', help='replay: verify the frozen fixture against the recorded Go observation (no Go)')
    args = parser.parse_args()
    goos = host_goos()
    fixture_file = fixture_path(goos)
    fixture = replay_check(goos, fixture_file)
    print(f"PASS MCP authz matrix oracle ({goos}): {len(fixture['profiles'])} profiles x {len(fixture['tools'])} tools x "
          f"{len(TOKEN_MODES)} token modes = {len(fixture['cases'])} cases")


if __name__ == '__main__':
    main()
