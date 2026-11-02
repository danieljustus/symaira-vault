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
"""
import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'testdata/port/mcp/tool-registry-hash.json'
PASSPHRASE = 'correct horse battery staple'
DRIFT_TEXT = ("tool registry has changed since this token was issued \u2014 "
              "re-issue the token with 'symvault agent token new fixture'")


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


def call(name, arguments, ident):
    return json.dumps({'jsonrpc': '2.0', 'id': ident, 'method': 'tools/call',
                       'params': {'name': name, 'arguments': arguments}}).encode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--go-cli', type=Path, required=True)
    parser.add_argument('--go-seed', type=Path, required=True)
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    recorded = json.loads(FIXTURE.read_text())['registry']['hash']
    receipt = {'recorded_go_hash': recorded, 'issue': {}, 'http': []}

    with tempfile.TemporaryDirectory(prefix='symvault-toolhash-') as raw:
        base = Path(raw)
        seed_home = fresh_home(base, 'seed')
        tokens = json.loads(run([args.go_seed, '--root', seed_home / 'vault'], seed_home).stdout)

        # (1) CLI issuance by both binaries, on throwaway copies of the vault.
        issued = {}
        for impl, binary in (('go', args.go_cli), ('rust', args.rust)):
            home = fresh_home(base, f'issue-{impl}', seed_home / 'vault')
            new = run([binary, 'agent', 'token', 'new', 'fixture', '--tools', '*', '--label', f'{impl}-new'], home)
            issued[f'{impl}_cli_issued'] = raw_token(new.stdout)
            hashes = {t['label']: t.get('tool_registry_hash', '') for t in registry_tokens(home).values()}
            assert hashes[f'{impl}-new'] == recorded, (impl, 'agent token new', hashes)
            run([binary, 'agent', 'token', 'rotate', 'fixture', '--tools', '*', '--label', f'{impl}-rotated'], home)
            hashes = {t['label']: t.get('tool_registry_hash', '') for t in registry_tokens(home).values()
                      if not t.get('revoked')}
            assert hashes == {f'{impl}-rotated': recorded}, (impl, 'agent token rotate', hashes)
            receipt['issue'][impl] = {'new': recorded, 'rotate': recorded}

        # Tokens issued by the CLIs go into one shared vault copy served by both.
        shared = fresh_home(base, 'shared', seed_home / 'vault')
        for impl, binary in (('go', args.go_cli), ('rust', args.rust)):
            out = run([binary, 'agent', 'token', 'new', 'fixture', '--tools', '*', '--label', f'serve-{impl}'], shared)
            tokens[f'{impl}_cli_issued'] = raw_token(out.stdout)
        # (the rotate above revoked nothing here: rotate ran on the throwaway copies)

        stale_scoped = 'go_stale_scoped_health'
        scenarios = [
            ('search', 'symaira_search', {'intent': 'auth', 'return': 'names'},
             ['go_current', 'go_legacy_empty', 'go_stale', 'go_cli_issued', 'rust_cli_issued', stale_scoped]),
            # entry-policy ordering: public/ is allowed, private/ is not
            ('policy-allowed-path', 'get_entry_metadata', {'path': 'public/fixture'}, ['go_current', 'go_stale']),
            ('policy-denied-path', 'get_entry_metadata', {'path': 'private/x'}, ['go_current', 'go_stale']),
            ('out-of-scope-tool', 'symaira_search', {'intent': 'auth'}, [stale_scoped]),
            ('health', 'health', {}, ['go_current', 'go_stale', 'rust_cli_issued']),
        ]
        results = {}
        with socket.socket() as selection:
            selection.bind(('127.0.0.1', 0))
            port = selection.getsockname()[1]
        for impl, binary in (('go', args.go_cli), ('rust', args.rust)):
            home = fresh_home(base, f'serve-{impl}', shared / 'vault')
            process = serve(binary, home, port)
            try:
                init = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                    'protocolVersion': '2025-11-25', 'clientInfo': {'name': 'p', 'version': '1'},
                    'capabilities': {}}}).encode()
                for name, tool, arguments, who in scenarios:
                    for token_name in who:
                        token = tokens[token_name]
                        http(port, token, init)
                        status, body = http(port, token, call(tool, arguments, 2))
                        assert token not in body
                        results[(impl, name, token_name)] = (status, body)
            finally:
                process.kill()
                process.wait(timeout=15)
            time.sleep(.3)

        failures = []
        for key in sorted(k for k in results if k[0] == 'go'):
            _, name, token_name = key
            go, rust = results[key], results[('rust', name, token_name)]
            receipt['http'].append({'scenario': name, 'token': token_name, 'go': go, 'rust': rust})
            if go != rust:
                failures.append((name, token_name, go, rust))
        assert not failures, f'Go/Rust differences: {json.dumps(failures, indent=1)}'

        def body(impl, scenario, token_name):
            frame = json.loads(results[(impl, scenario, token_name)][1])
            return frame['result']

        for impl in ('go', 'rust'):
            for token_name in ('go_current', 'go_legacy_empty', 'go_cli_issued', 'rust_cli_issued'):
                result = body(impl, 'search', token_name)
                assert not result['isError'], (impl, token_name, result)
            stale = body(impl, 'search', 'go_stale')
            assert stale['isError'] and stale['content'][0]['text'] == DRIFT_TEXT, (impl, stale)
            scoped = body(impl, 'out-of-scope-tool', stale_scoped)
            assert scoped['isError'] and 'tool registry has changed' not in scoped['content'][0]['text'], (impl, scoped)
            allowed = body(impl, 'policy-allowed-path', 'go_current')
            assert not allowed['isError'], (impl, allowed)
            # Control: with a current token the entry policy itself denies the
            # path (a JSON-RPC error); the stale token must hit drift first.
            denied_current = json.loads(results[(impl, 'policy-denied-path', 'go_current')][1])
            assert 'error' in denied_current and 'result' not in denied_current, (impl, denied_current)
            assert 'tool registry has changed' not in json.dumps(denied_current)
            denied_stale = body(impl, 'policy-denied-path', 'go_stale')
            assert denied_stale['content'][0]['text'] == DRIFT_TEXT, (impl, 'drift must precede entry policy', denied_stale)
            assert body(impl, 'health', 'rust_cli_issued')['isError'] is False
            assert body(impl, 'health', 'go_stale')['content'][0]['text'] == DRIFT_TEXT

    if args.receipt:
        args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'PASS: {len(receipt["http"])} Go/Rust HTTP outcomes identical; CLI issuance hash {recorded[:12]} for both binaries')


if __name__ == '__main__':
    sys.exit(main())
