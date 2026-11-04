#!/usr/bin/env python3
"""TOOLHASH-001 process-level contract: actual Go and Rust binaries.

Prebuilt binaries are passed in (the caller owns compilation):

  --go-cli    Go symvault built from this checkout
  --go-seed   Go `scripts/rust-port/cmd/toolhashseed` built from this checkout
  --rust      Rust symvault

Checks, each against disposable HOME/vault roots only:

  1. `agent token new` and `agent token rotate` by BOTH CLIs stamp the registry
     hash recorded by Go in testdata/port/mcp/tool-registry-hash.json.
  2. Over HTTP, every token (Go-issued current/legacy/stale, Go-CLI-issued,
     Rust-CLI-issued) gets byte-identical tools/call outcomes from the Go and
     Rust servers (status line and body; only Date is excluded), a stale token
     is refused with the drift text, a legacy empty hash and a current hash are
     accepted, and the refusal sits after scope denial and before entry policy.
  3. Rust-issued tokens are accepted by the Go server (rollback direction) and
     Go-issued tokens by the Rust server.
  4. MCP-003: the audit rows each server appends for those calls (tool calls,
     `tool_denied`, `tool_registry_drift`) are identical field for field, in
     field order, between Go and Rust once the random ids are masked: `sess_id`
     (32 hex, one per agent server) and `req_id` (16 hex, one per call) must be
     present, well formed and, for `sess_id`, constant; `token_id` is the
     registry's deterministic id and is compared exactly. `--drop-audit-ids`
     deletes those three fields from the Rust rows before comparing; the
     comparison must then fail (negative control).
"""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mcp_process_contract import (load_go_observations, native_goos, pack_tree, provenance, save_go_observations,  # noqa: E402
                                  unpack_tree)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = 'toolhash-process'
# The Go side is built from the checkout (no pinned oracle worktree): this is the integrated base whose Go sources were
# captured. Capture refuses to run when any Go source differs from it.
GO_SOURCE_COMMIT = 'c069d3f2b17d704525cedc1bd42840cc6a3e9896'
PORT = 28112  # fixed so the served bytes are identical in capture and replay
NORMALIZATION = ['fixed loopback port', 'seed vault, the Go-issued and the Rust-issued CLI tokens (and the shared vault holding them) pinned in the file',
                 'prompt-injection data fence nonce (DATA_<16 hex>) and the audit ids (sess_id/req_id) already masked by the driver',
                 'Rust-issued token minted by the Rust CLI at first capture (needs --rust once); re-captures reuse the pinned shared vault']
FIXTURE = ROOT / 'testdata/port/mcp/tool-registry-hash.json'
PASSPHRASE = 'correct horse battery staple'
DRIFT_TEXT = ("tool registry has changed since this token was issued \u2014 "
              "re-issue the token with 'symvault agent token new fixture'")


def git(*arguments):
    return subprocess.run(['git', *arguments], cwd=ROOT, capture_output=True, text=True, check=True).stdout


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def isolated(home):
    env = {k: v for k, v in os.environ.items() if k in {'PATH', 'TMPDIR', 'LANG', 'LC_ALL', 'LC_CTYPE'}}
    env.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home / 'config'),
               XDG_DATA_HOME=str(home / 'data'), XDG_CACHE_HOME=str(home / 'cache'),
               SYMVAULT_VAULT=str(home / 'vault'), SYMVAULT_TEST_KEYRING='memory',
               SYMVAULT_SECUREUI='none', SYMVAULT_PASSPHRASE=PASSPHRASE,
               SYMVAULT_ALLOW_ENV_PASSPHRASE='1', SYMVAULT_NO_ENV_WARNING='1',
               SYMVAULT_NO_NOTIFY='1', CI='1', NO_COLOR='1', TZ='UTC')
    return env


def run(args, home, check=True):
    result = subprocess.run([str(a) for a in args], cwd=home, env=isolated(home),
                            capture_output=True, timeout=120)
    if check and result.returncode:
        raise RuntimeError(f'{args} failed ({result.returncode}): {result.stderr.decode(errors="replace")[-1500:]}')
    return result


def fresh_home(base, name, vault=None):
    home = base / name
    home.mkdir()
    for directory in ('config', 'data', 'cache'):
        (home / directory).mkdir()
    if vault:
        shutil.copytree(vault, home / 'vault')
    return home


def registry_tokens(home):
    return json.loads((home / 'vault/mcp-tokens.json').read_text())['tokens']


def raw_token(stdout):
    for line in stdout.decode().splitlines():
        if line.startswith('Raw token (copy now'):
            return line.split(': ', 1)[1].strip()
    raise AssertionError('no raw token in CLI output: ' + stdout.decode())


def http(port, token, body, agent='fixture'):
    data = (f'POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n'
            f'Authorization: Bearer {token}\r\nX-Symaira-Agent: {agent}\r\n'
            f'Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n'
            f'Content-Length: {len(body)}\r\n\r\n').encode() + body
    with socket.create_connection(('127.0.0.1', port), timeout=15) as connection:
        connection.sendall(data)
        raw = bytearray()
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            raw += chunk
    head, _, payload = bytes(raw).partition(b'\r\n\r\n')
    lines = head.decode('latin1').split('\r\n')
    # The prompt-injection data fence carries a per-call random nonce (both
    # binaries); it is the only intentionally non-deterministic byte run.
    return lines[0], re.sub(r'DATA_[0-9a-f]{16}', 'DATA_<nonce>', payload.decode('utf-8'))


def serve(binary, home, port):
    process = subprocess.Popen([str(binary), '--quiet', 'mcp', '--bind', '127.0.0.1', '--port', str(port)],
                               cwd=home, env=isolated(home), stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.stdin.write(b'y\n')
    process.stdin.close()
    deadline = time.monotonic() + 30
    while True:
        assert process.poll() is None, 'server exited before listening: ' + process.stderr.read().decode()
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                return process
        except OSError:
            assert time.monotonic() < deadline, 'server never listened'
            time.sleep(.05)


STALE_SCOPED = 'go_stale_scoped_health'
# (scenario, tool, arguments, tokens that call it). The 14 HTTP outcomes of the
# receipt are exactly these pairs; gate_area_check.py imports this table.
SCENARIOS = [
    ('search', 'symaira_search', {'intent': 'auth', 'return': 'names'},
     ['go_current', 'go_legacy_empty', 'go_stale', 'go_cli_issued', 'rust_cli_issued', STALE_SCOPED]),
    # entry-policy ordering: public/ is allowed, private/ is not
    ('policy-allowed-path', 'get_entry_metadata', {'path': 'public/fixture'}, ['go_current', 'go_stale']),
    ('policy-denied-path', 'get_entry_metadata', {'path': 'private/x'}, ['go_current', 'go_stale']),
    ('out-of-scope-tool', 'symaira_search', {'intent': 'auth'}, [STALE_SCOPED]),
    ('health', 'health', {}, ['go_current', 'go_stale', 'rust_cli_issued']),
]
EXPECTED_AUDIT_ROWS = 8


AUDIT_LOG = 'vault/audit-fixture.log'
MASKED = ('ts', 'hmac', 'kid')


def audit_rows(home):
    path = home / AUDIT_LOG
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def mask_audit(rows, drop_ids=False):
    """Rows as ordered key/value lists with the random ids masked."""
    masked = []
    sessions = set()
    for row in rows:
        if row.get('action', '').startswith('anomaly_'):
            # Both servers run the anomaly detector (off-hours, time-of-day
            # dependent, so the rows are skipped from the field-for-field
            # comparison). Each logs with context.Background(): sess_id only,
            # no req_id/token_id. Rust ported it for PLATFORM-002 / ADR 0034
            # item 29; anomaly_dispatch.rs and mcp_anomaly_process.rs pin the rows.
            assert 'req_id' not in row and 'token_id' not in row, row
            continue
        out = []
        for key, value in row.items():
            if key in MASKED:
                continue
            if key == 'sess_id':
                assert re.fullmatch(r'[0-9a-f]{32}', value), ('sess_id', row)
                sessions.add(value)
                if drop_ids:
                    continue
                value = '<sess>'
            elif key == 'req_id':
                assert re.fullmatch(r'[0-9a-f]{16}', value), ('req_id', row)
                if drop_ids:
                    continue
                value = '<req>'
            elif key == 'token_id' and drop_ids:
                continue
            out.append([key, value])
        keys = [k for k, _ in out]
        if not drop_ids:
            assert 'sess_id' in keys and 'req_id' in keys, ('ids missing', row)
        masked.append(out)
    if not drop_ids:
        assert len(sessions) <= 1, ('one session per agent server', sessions)
    return masked


def call(name, arguments, ident):
    return json.dumps({'jsonrpc': '2.0', 'id': ident, 'method': 'tools/call',
                       'params': {'name': name, 'arguments': arguments}}).encode()


def run_server(binary, base, label, shared_vault, tokens):
    """Serve the shared vault copy with one binary; return its HTTP outcomes and raw audit rows."""
    results = {}
    home = fresh_home(base, f'serve-{label}', shared_vault)
    process = serve(binary, home, PORT)
    try:
        init = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
            'protocolVersion': '2025-11-25', 'clientInfo': {'name': 'p', 'version': '1'},
            'capabilities': {}}}).encode()
        for name, tool, arguments, who in SCENARIOS:
            for token_name in who:
                token = tokens[token_name]
                http(PORT, token, init)
                status, body = http(PORT, token, call(tool, arguments, 2))
                assert token not in body
                results[(name, token_name)] = (status, body)
    finally:
        # SIGTERM lets Go's buffered audit logger flush before exit.
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=15)
    rows = audit_rows(home)
    time.sleep(.3)
    return results, rows


def check_issuance(binary, impl, base, seed_vault, recorded):
    home = fresh_home(base, f'issue-{impl}', seed_vault)
    new = run([binary, 'agent', 'token', 'new', 'fixture', '--tools', '*', '--label', f'{impl}-new'], home)
    raw = raw_token(new.stdout)
    hashes = {t['label']: t.get('tool_registry_hash', '') for t in registry_tokens(home).values()}
    assert hashes[f'{impl}-new'] == recorded, (impl, 'agent token new', hashes)
    run([binary, 'agent', 'token', 'rotate', 'fixture', '--tools', '*', '--label', f'{impl}-rotated'], home)
    hashes = {t['label']: t.get('tool_registry_hash', '') for t in registry_tokens(home).values()
              if not t.get('revoked')}
    assert hashes == {f'{impl}-rotated': recorded}, (impl, 'agent token rotate', hashes)
    return raw, {'new': recorded, 'rotate': recorded}


def check_outcomes(results, impl):
    """The per-implementation semantic controls of the 14 HTTP outcomes (unchanged assertions)."""
    def body(scenario, token_name):
        return json.loads(results[(scenario, token_name)][1])['result']

    for token_name in ('go_current', 'go_legacy_empty', 'go_cli_issued', 'rust_cli_issued'):
        result = body('search', token_name)
        assert not result['isError'], (impl, token_name, result)
    stale = body('search', 'go_stale')
    assert stale['isError'] and stale['content'][0]['text'] == DRIFT_TEXT, (impl, stale)
    scoped = body('out-of-scope-tool', STALE_SCOPED)
    assert scoped['isError'] and 'tool registry has changed' not in scoped['content'][0]['text'], (impl, scoped)
    allowed = body('policy-allowed-path', 'go_current')
    assert not allowed['isError'], (impl, allowed)
    # Control: with a current token the entry policy itself denies the
    # path (a JSON-RPC error); the stale token must hit drift first.
    denied_current = json.loads(results[('policy-denied-path', 'go_current')][1])
    assert 'error' in denied_current and 'result' not in denied_current, (impl, denied_current)
    assert 'tool registry has changed' not in json.dumps(denied_current)
    denied_stale = body('policy-denied-path', 'go_stale')
    assert denied_stale['content'][0]['text'] == DRIFT_TEXT, (impl, 'drift must precede entry policy', denied_stale)
    assert body('health', 'rust_cli_issued')['isError'] is False
    assert body('health', 'go_stale')['content'][0]['text'] == DRIFT_TEXT


def capture(args):
    """Go half only (the prebuilt Go CLI and seed): write the committed Go observations."""
    assert args.go_cli and args.go_seed, '--capture-go needs --go-cli and --go-seed'
    changed = git('diff', '--name-only', GO_SOURCE_COMMIT, '--', '*.go', 'go.mod', 'go.sum').split()
    assert not changed, ('Go sources differ from the pinned capture base', changed[:5])
    go_cli, go_seed = args.go_cli.resolve(), args.go_seed.resolve()
    recorded = json.loads(FIXTURE.read_text())['registry']['hash']
    prior = None if args.reseed else load_go_observations(CONTRACT, oracle=GO_SOURCE_COMMIT, required=False)
    if prior is None and not args.reseed:
        # Encrypted seed vaults and the minted tokens are OS independent: a first capture on another OS reuses them.
        for other in ('darwin', 'linux'):
            if other != native_goos():
                prior = load_go_observations(CONTRACT, oracle=GO_SOURCE_COMMIT, required=False, goos=other)
                if prior is not None:
                    break
    prior = prior['data'] if prior else None
    with tempfile.TemporaryDirectory(prefix='symvault-toolhash-') as raw:
        base = Path(raw)
        seed_home = fresh_home(base, 'seed')
        if prior:
            unpack_tree(prior['seed_tree'], seed_home / 'vault')
            tokens = dict(prior['tokens'])
        else:
            tokens = json.loads(run([go_seed, '--root', seed_home / 'vault'], seed_home).stdout)
        _, issue = check_issuance(go_cli, 'go', base, seed_home / 'vault', recorded)
        if prior:
            shared = fresh_home(base, 'shared')
            unpack_tree(prior['shared_tree'], shared / 'vault')
        else:
            assert args.rust, 'the first capture needs --rust once, to mint the Rust-issued token the Go server must accept'
            shared = fresh_home(base, 'shared', seed_home / 'vault')
            for impl, binary in (('go', go_cli), ('rust', args.rust.resolve())):
                out = run([binary, 'agent', 'token', 'new', 'fixture', '--tools', '*', '--label', f'serve-{impl}'], shared)
                tokens[f'{impl}_cli_issued'] = raw_token(out.stdout)
        results, rows = run_server(go_cli, base, 'go', shared / 'vault', tokens)
        check_outcomes(results, 'go')
        audit = mask_audit(rows)
        actions = {dict(row)['action'] for row in audit}
        assert {'tool_denied', 'tool_registry_drift'} <= actions, ('Go audit lacks denials', actions)
        assert any(dict(row).get('token_id') for row in audit), 'Go rows carry token ids'
        assert len(audit) == EXPECTED_AUDIT_ROWS, len(audit)
        data = dict(info=dict(go_binary_sha256=sha256(go_cli), seed_binary_sha256=sha256(go_seed)), recorded_go_hash=recorded,
                    tokens=tokens, seed_tree=pack_tree(seed_home / 'vault'), shared_tree=pack_tree(shared / 'vault'),
                    issue=issue, http=[[name, token_name, list(outcome)] for (name, token_name), outcome in sorted(results.items())],
                    audit=audit)
        toolchain = subprocess.run(['go', 'version', str(go_cli)], capture_output=True, text=True, check=True).stdout.split(':')[-1].strip()
        path = save_go_observations(CONTRACT, data, {}, NORMALIZATION, toolchain, oracle=GO_SOURCE_COMMIT)
    print(f'CAPTURED: {len(results)} Go HTTP outcomes and {len(audit)} audit rows -> {path}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--go-cli', type=Path, help='with --capture-go: Go symvault built from this checkout')
    parser.add_argument('--go-seed', type=Path, help='with --capture-go: Go toolhashseed built from this checkout')
    parser.add_argument('--rust', type=Path)
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--allow-dirty-for-development', action='store_true')
    parser.add_argument('--drop-audit-ids', action='store_true',
                        help='negative control: strip the ids from the Rust audit rows')
    parser.add_argument('--capture-go', action='store_true', help='record the Go half (Go required) instead of replaying it')
    parser.add_argument('--reseed', action='store_true', help='with --capture-go: regenerate the pinned seed vault and tokens')
    args = parser.parse_args()
    if args.capture_go:
        return capture(args)
    assert args.rust, '--rust is required in replay mode'
    # The binaries run with cwd set to a scratch HOME: a relative path (the
    # Makefile passes target/... when CARGO_TARGET_DIR is relative) must not
    # be resolved against that cwd.
    rust = args.rust.resolve()
    document = load_go_observations(CONTRACT, {}, oracle=GO_SOURCE_COMMIT)
    go_recorded = document['data']
    recorded = json.loads(FIXTURE.read_text())['registry']['hash']
    assert go_recorded['recorded_go_hash'] == recorded, 'Go observations were recorded against another registry hash'
    parser_clean = not git('status', '--porcelain=v1').strip()
    assert parser_clean or args.allow_dirty_for_development, 'a clean worktree is required (--allow-dirty-for-development)'
    receipt = {'passed': False, 'candidate_commit': git('rev-parse', 'HEAD').strip(), 'candidate_worktree_clean': parser_clean,
               'native_os': platform.system(), 'architecture': platform.machine(),
               'driver_sha256': sha256(Path(__file__)), 'go_binary_sha256': go_recorded['info']['go_binary_sha256'],
               'seed_binary_sha256': go_recorded['info']['seed_binary_sha256'], 'rust_binary_sha256': sha256(rust),
               'recorded_go_hash': recorded, 'issue': {}, 'http': [], 'go_observations': provenance(document)}
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-toolhash-') as raw:
            base = Path(raw)
            seed_home = fresh_home(base, 'seed')
            unpack_tree(go_recorded['seed_tree'], seed_home / 'vault')
            tokens = dict(go_recorded['tokens'])
            # (1) CLI issuance: Go recorded, Rust live, on throwaway copies of the vault.
            receipt['issue']['go'] = go_recorded['issue']
            _, receipt['issue']['rust'] = check_issuance(rust, 'rust', base, seed_home / 'vault', recorded)
            # (2) the shared vault (Go- and Rust-issued tokens) is served by Rust now and was served by Go at capture.
            shared = fresh_home(base, 'shared')
            unpack_tree(go_recorded['shared_tree'], shared / 'vault')
            rust_results, rust_rows = run_server(rust, base, 'rust', shared / 'vault', tokens)
            go_results = {(name, token_name): tuple(outcome) for name, token_name, outcome in go_recorded['http']}
            failures = []
            for key in sorted(go_results):
                name, token_name = key
                go, rust_outcome = go_results[key], rust_results[key]
                receipt['http'].append({'scenario': name, 'token': token_name, 'go': go, 'rust': rust_outcome})
                if go != rust_outcome:
                    failures.append((name, token_name, go, rust_outcome))
            assert not failures, f'Go/Rust differences: {json.dumps(failures, indent=1)}'
            assert set(go_results) == set(rust_results), 'same outcome inventory'

            go_audit = [[list(pair) for pair in row] for row in go_recorded['audit']]
            rust_audit = mask_audit(rust_rows, drop_ids=args.drop_audit_ids)
            receipt['audit'] = {'go': go_audit, 'rust': rust_audit}
            assert go_audit == rust_audit, (
                'Go/Rust audit rows differ:\n' + json.dumps({'go': go_audit, 'rust': rust_audit}, indent=1))
            for impl, results in (('go', go_results), ('rust', rust_results)):
                check_outcomes(results, impl)

        receipt['candidate_worktree_clean_at_end'] = not git('status', '--porcelain=v1').strip()
        assert receipt['candidate_worktree_clean_at_end'] or args.allow_dirty_for_development, 'worktree changed during the run'
        assert sha256(rust) == receipt['rust_binary_sha256'], 'Rust binary changed during the run'
        receipt['passed'] = True
    finally:
        if args.receipt:
            args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'PASS: {len(receipt["audit"]["go"])} audit rows identical (ids masked); '
          f'{len(receipt["http"])} Go/Rust HTTP outcomes identical; CLI issuance hash {recorded[:12]} for both binaries '
          f'(Go side replayed from {receipt["go_observations"]["path"]})')


if __name__ == '__main__':
    sys.exit(main())
