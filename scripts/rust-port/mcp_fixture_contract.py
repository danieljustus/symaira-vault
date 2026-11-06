#!/usr/bin/env python3
"""Replay of the committed Go lane captures of the MCP fixtures, checked against the frozen fixture bytes.

The historical, corrected (approval-lifetime-v1) and product-source lanes of the fixture generators were executed once
against the archived Go tree (tag `legacy/go-oracle`) and recorded into
scripts/rust-port/fixtures/go-observations/mcp-ordered-fixtures.<goos>.json. This script starts no Go toolchain and
creates no git worktree. It verifies the independent input anchor (historical-inputs.json) over every fixture and every
generator source that is still held in the tree, the reviewed approval-lifetime delta, the recorded step verdicts and
every recorded capture: historical captures equal the anchored bytes, corrected and product-source captures equal the
historical fixtures in every response/state/case field (oracle identity only may differ) and carry the pinned commit.
What is no longer re-derived: the byte identity of the generator sources that lived in the Go
package and command trees (deleted with the Go tree; their digests stay in the anchor), the source and generator digests
of the overlaid oracle trees and the compiler adapter (recorded verdicts only); see docs/adr/0036-go-removal.md.
"""
import argparse
import gzip
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile

from mcp_oracle import CONTRACT, HISTORICAL, ORDERED, inventory
from mcp_process_contract import load_go_observations, provenance

OBSERVATION = 'mcp-ordered-fixtures'
NORMALIZATION = ['the recording is the byte content each Go lane produced for every fixture (historical lane: its sha256, asserted equal to '
                 'the anchored historical bytes at capture; corrected and product-source lanes: gzip+base64 of the exact bytes) plus the '
                 'verdict rows of the Go steps (exit status, executed generator tests); no per-run value is recorded',
                 'Go compiler identity/paths, generator binary hashes and temp directories are not recorded: they are properties of the capture '
                 'machine, not of the fixtures']

ROOT = Path(__file__).resolve().parents[2]
PRODUCT_SOURCE = '58d978bb53a1dc6257b3a0e3154f7bd29fdd3fd9'
FIXTURE_BASE = '2b596f916bf736250b7fd3bb4d39f5f89fb20aa2'
ANCHOR = ROOT/'scripts/rust-port/fixtures/mcp-anomaly/historical-inputs.json'
ANCHOR_SHA256 = '678531bead3d9bc4a8d754ce7996b8cd29f94d8a4dbb8ef91cef71577296394d'
ARCHIVE = 'scripts/rust-port/fixtures/mcp-anomaly/historical/'
# The anchored inputs whose original bytes were relocated below ARCHIVE as `<path>.txt` (Go sources and the frozen
# fixtures they generated); every other anchored input that is still held lives at its own path.
ARCHIVED_COUNT = 12
# Explicit inventory: do not derive acceptance counts from whatever ran.
CASES = {
    'CopyClipboard': ('COPY_CLIPBOARD', 'copy-clipboard.json', 16),
    'ExecuteAPIHTTPS': ('EXECUTE_API_HTTPS', 'execute-api-https.json', 3),
    'ExecuteAPIPolicy': ('EXECUTE_API_POLICY', 'execute-api-policy.json', 9),
    'ExecuteAPIRequest': ('EXECUTE_API_REQUEST', 'execute-api-request.json', 15),
    'ExecuteWithSecret': ('EXECUTE_WITH_SECRET', 'execute-with-secret.json', 13),
    'Prompts': ('PROMPTS', 'prompts.json', 25),
    'SecureInput': ('SECURE_INPUT', 'secure-input.json', 11),
    'List': ('LIST', 'tool-list.json', 11),
    'AuditSelf': ('AUDIT_SELF', 'tools-audit-self.json', 15),
    'AuthStatus': ('AUTH_STATUS', 'tools-auth-status.json', 2),
    'Call': ('CALL', 'tools-call-initialized.json', 1),
    'DeleteEntry': ('DELETE_ENTRY', 'tools-delete-entry.json', 7),
    'GeneratePassword': ('GENERATE_PASSWORD', 'tools-generate-password.json', 4),
    'GenerateTemplate': ('GENERATE_TEMPLATE', 'tools-generate-template.json', 8),
    'GenerateTOTP': ('GENERATE_TOTP', 'tools-generate-totp.json', 4),
    'GetValue': ('GET_VALUE', 'tools-get-value.json', 8),
    'ListEntries': ('LIST_ENTRIES', 'tools-list-entries.json', 3),
    'RateLimit': ('RATE_LIMIT', 'tools-rate-limit.json', 4),
    'SanitizeOutput': ('SANITIZE_OUTPUT', 'tools-sanitize-output.json', 7),
    'SearchFetch': ('SEARCH_FETCH', 'tools-search-fetch.json', 13),
    'SecretUnseal': ('SECRET_UNSEAL', 'tools-secret-unseal.json', 6),
    'SetEntry': ('SET_ENTRY', 'tools-set-entry.json', 11),
    'SymairaSearch': ('SYMAIRA_SEARCH', 'tools-symaira-search.json', 7),
    'WriteApproval': ('WRITE_APPROVAL', 'write-tty-approval.json', 14),
}
FIXTURES = {'testdata/port/mcp/'+name: count for _,name,count in CASES.values()}
FIXTURES.update({'testdata/port/mcp/tools-call.json':4, 'testdata/port/mcp/http-initialize.json':27})
IDENTITY_KEYS = {'commit', 'commit_sha', 'source_hash', 'source_digest', 'generator_hash', 'generator_digest'}
APPROVAL_SOURCE = 'scripts/rust-port/fixtures/mcp-anomaly/approval-lifetime-v1.go.txt'
# Independently reviewed source admission, NOT compiler/native provenance.
APPROVAL_SHA256 = '91e62899d00eecb039d93bc4630c762b213d49798fbf9ae82c8a595d2a036562'
APPROVAL_FIXTURE = 'testdata/port/mcp/write-tty-approval.json'


def compare_fixture(old, new, count, expected_commit=ORDERED):
    # JSON numeric equality must not accept bool/int or int/float substitution.
    def compare(a, b, path=''):
        if type(a) is not type(b):
            raise ValueError('fixture type drift: '+path)
        if isinstance(a, dict):
            if a.keys() != b.keys():
                raise ValueError('fixture key drift: '+path)
            for key in a:
                if (path == '/oracle' and key in IDENTITY_KEYS) or (not path and key == 'generator_digest'):
                    continue
                compare(a[key], b[key], path+'/'+key)
        elif isinstance(a, list):
            if len(a) != len(b):
                raise ValueError('fixture length drift: '+path)
            for i,(left,right) in enumerate(zip(a,b,strict=True)):
                compare(left,right,path+'/'+str(i))
        elif a != b:
            raise ValueError('fixture value drift: '+path)
    if len(old['cases']) != count or len(new['cases']) != count:
        raise ValueError('fixture case inventory drift')
    if expected_commit not in (HISTORICAL, ORDERED, PRODUCT_SOURCE) or new['oracle']['commit_sha'] != expected_commit:
        raise ValueError('captured fixture is not bound to its lane oracle')
    compare(old, new)


def confined_file(root, name):
    if not isinstance(name,str) or '\\' in name:
        raise ValueError('invalid fixture input path')
    parts=PurePosixPath(name)
    if parts.is_absolute() or '..' in parts.parts or parts.as_posix()!=name:
        raise ValueError('invalid fixture input path')
    root=root.resolve()
    path=root
    for component in parts.parts:
        path=path/component
        if path.is_symlink():
            raise ValueError('symlink fixture input')
    if not path.resolve().is_relative_to(root) or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('fixture input must be a contained regular file')
    return path


def fixture_anchor(root, names):
    raw=confined_file(ANCHOR.parent,ANCHOR.name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != ANCHOR_SHA256:
        raise ValueError('independent historical input anchor drift')
    manifest=json.loads(raw)
    if manifest['source_commit'] != FIXTURE_BASE:
        raise ValueError('historical input identity drift')
    # Validate membership and file types for ALL inputs before opening ANY.
    for name in names:
        if not isinstance(name,str) or name not in manifest['files']:
            raise ValueError('unanchored fixture input path')
        historical_file(root,name)
    for name in names:
        if hashlib.sha256(historical_file(root,name).read_bytes()).hexdigest() != manifest['files'][name]:
            raise ValueError('historical fixture/generator anchor drift: '+name)


def archived_inputs():
    root = (ROOT/ARCHIVE).resolve()
    names = {p.relative_to(root).as_posix()[:-len('.txt')] for p in root.rglob('*.txt') if p.is_file()}
    if len(names) != ARCHIVED_COUNT:
        raise ValueError('archived historical input inventory drift: %d' % len(names))
    return names


def historical_file(root, name):
    # Explicit relocated originals, not an automatic fallback on checksum error.
    # The unchanged independent anchor still authenticates every byte.
    return confined_file(root, ARCHIVE+name+'.txt' if name in archived_inputs() else name)


def held(root, name):
    try:
        historical_file(root, name)
    except (OSError, ValueError):
        return False
    return True


def generator_paths():
    """Anchored generator inputs whose bytes are still held in the tree (the rest left with the Go tree)."""
    fixture_anchor(ROOT, ())
    return sorted(name for name in set(json.loads(ANCHOR.read_bytes())['files']) - set(FIXTURES) if held(ROOT, name))


def approval_generator_source(root):
    """Admit only the reviewed approval-lifetime-v1 generator: pinned digest, and the lifetime close is present once."""
    data = confined_file(root, APPROVAL_SOURCE).read_bytes()
    if hashlib.sha256(data).hexdigest() != APPROVAL_SHA256:
        raise ValueError('unreviewed approval generator source')
    anchor = b'\tlogger.SetSyncMode(true)\n\tsrv.auditLog = logger'
    addition = (b'\tdefer func() {\n'
                b'\t\tif err := logger.Close(); err != nil {\n'
                b'\t\t\tt.Errorf("close fixture audit logger: %v", err)\n'
                b'\t\t}\n\t}()\n')
    if data.count(addition+anchor) != 1:
        raise ValueError('approval generator lacks the reviewed lifetime correction')
    return data


def candidate_fixture_payloads():
    # Product captures may bind patched dependencies; historical bytes may not.
    # Their separate provenance gates check those metadata changes. No response,
    # state, request, count or JSON type may drift from the historical contract.
    for name, count in FIXTURES.items():
        old=json.loads(historical_file(ROOT,name).read_bytes())
        new=json.loads(confined_file(ROOT,name).read_bytes())
        new['oracle']=dict(old['oracle'],commit_sha=ORDERED)
        compare_fixture(old,new,count)


LANES = [('historical', HISTORICAL), ('corrected', ORDERED), ('product-source', PRODUCT_SOURCE)]
STEP_KEYS = ('name', 'exit', 'timed_out', 'passed', 'executed_tests')


def replay_capture(lane, entry, name):
    """The bytes a lane produced for one fixture, verified against their recorded digest (and, for the unchanged
    historical lane, against the anchored bytes)."""
    if 'gzip_base64' in entry:
        captured = gzip.decompress(base64.b64decode(entry['gzip_base64']))
        if hashlib.sha256(captured).hexdigest() != entry['sha256']:
            raise ValueError('recorded Go capture is corrupt: '+name)
        return captured
    if lane != 'historical' or name == APPROVAL_FIXTURE:
        raise ValueError('capture bytes missing: %s %s' % (lane, name))
    captured = historical_file(ROOT, name).read_bytes()
    if hashlib.sha256(captured).hexdigest() != entry['sha256']:
        raise ValueError('recorded historical Go capture differs from the anchored bytes: '+name)
    return captured


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    destinations = parser.add_mutually_exclusive_group(required=True)
    destinations.add_argument('--output', type=Path, help='new evidence directory, never overwrites a prior run')
    destinations.add_argument('--output-root', type=Path, help='parent for a fresh retained run directory')
    parser.add_argument('--generator', choices=['tools-call', 'http-initialize', 'execute-with-secret'],
                        help='replay only the fixtures of one ordinary generator')
    parser.add_argument('--approval-generator', choices=['original', 'approval-lifetime-v1'], default='original',
                        help='the recorded corrected-generator executions on both sources; not historical replay')
    args = parser.parse_args()
    if sys.flags.optimize:
        parser.error('unoptimized Python is required')
    contract_args = dict(approval_generator=args.approval_generator, generator=args.generator)
    if args.approval_generator != 'original' and args.generator:
        parser.error('corrected approval execution requires the full two-lane fixture gate')
    fixture_anchor(ROOT, FIXTURES)
    generators = generator_paths()
    fixture_anchor(ROOT, [*FIXTURES, *generators])
    if args.approval_generator != 'original':
        approval_generator_source(ROOT)  # reject changed/unreviewed bytes
    candidate_fixture_payloads()
    # Source admission first; a missing/mismatching observation is a failure before any output.
    recorded = load_go_observations(OBSERVATION, contract_args)
    if args.output_root:
        args.output_root.mkdir(parents=True, exist_ok=True)
        output = Path(tempfile.mkdtemp(prefix='run-', dir=args.output_root)).resolve()
    else:
        output = args.output.resolve()
        output.mkdir(parents=True, exist_ok=False)
    def candidate_inputs():
        files = {name: hashlib.sha256(historical_file(ROOT, name).read_bytes()).hexdigest() for name in [*FIXTURES, *generators]}
        files.update(inventory(ROOT, [*([APPROVAL_SOURCE] if args.approval_generator != 'original' else []),
                                      'scripts/rust-port/mcp_oracle.py', 'scripts/rust-port/mcp_fixture_contract.py',
                                      ANCHOR.relative_to(ROOT).as_posix()]))
        return files
    receipt = {'contract': CONTRACT, 'historical_oracle': HISTORICAL, 'corrected_oracle': ORDERED,
               'product_source': PRODUCT_SOURCE, 'fixture_anchor': FIXTURE_BASE,
               'candidate_inputs': candidate_inputs(),
               'anchored_generators_held': generators,
               'approval_generator': args.approval_generator, 'native_os': sys.platform, 'passed': False, 'lanes': [],
               'go_observations': provenance(recorded), 'compiler': recorded['data']['compiler']}
    selected = {name: count for name, count in FIXTURES.items()
                if not args.generator or Path(name).stem == args.generator}
    try:
        for lane, commit in LANES:
            execution = lane if args.approval_generator == 'original' else lane+'-'+args.approval_generator
            lane_out = output/execution
            lane_out.mkdir()
            row = {'lane': execution, 'source_commit': commit, 'passed': False, 'replayed_from_go_observations': True}
            if lane == 'product-source':
                receipt['product_source_replay'] = row
            else:
                receipt['lanes'].append(row)
            row['steps'] = recorded['data']['lanes'][execution]['steps']
            if not all(step['passed'] and not step['timed_out'] and step['exit'] == 0 for step in row['steps']):
                raise ValueError('recorded Go step failed: '+execution)
            lane_captures = recorded['data']['lanes'][execution]['captures']
            if set(lane_captures) != set(FIXTURES):
                raise ValueError('recorded capture inventory drift: '+execution)
            for name, count in selected.items():
                captured = replay_capture(lane, lane_captures[name], name)
                (lane_out/Path(name).name).write_bytes(captured)
                old = json.loads(historical_file(ROOT, name).read_bytes())
                regenerated = args.approval_generator != 'original' and name == APPROVAL_FIXTURE
                if lane == 'historical' and not regenerated:
                    if captured != historical_file(ROOT, name).read_bytes():
                        raise ValueError('historical fixture changed: '+name)
                else:
                    compare_fixture(old, json.loads(captured), count, commit)
            row.update(passed=True, fixtures=len(selected), cases=sum(selected.values()),
                       captures=inventory(lane_out, [Path(p).name for p in selected]))
        if not args.generator:
            # The product captures bind patched module inputs separately from both immutable lanes; the recorded
            # product-source verdict (the three ordinary generator tests under CHECK) is replayed.
            product = {'passed': False, 'steps': recorded['data']['product_replay']['steps'],
                       'replayed_from_go_observations': True}
            receipt['product_replay'] = product
            if not product['steps'] or not all(step['passed'] and step['exit'] == 0 for step in product['steps']):
                raise ValueError('recorded Go product replay failed')
            product['passed'] = True
        if receipt['candidate_inputs'] != candidate_inputs():
            raise ValueError('candidate inputs changed during fixture acceptance')
        receipt['passed'] = True
    finally:
        (output/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    mode = 'historical replay' if args.approval_generator == 'original' else 'recorded approval-lifetime-v1 generator executions'
    print(f'PASS {mode} and {CONTRACT}: {len(selected)} fixtures, {sum(selected.values())} cases per lane; {output}/receipt.json')


if __name__ == '__main__':
    main()
