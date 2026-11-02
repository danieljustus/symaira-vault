#!/usr/bin/env python3
"""Actual Go/Rust bearer-token state, clock and storage matrix over the real HTTP CLIs.

Section A seeds one registry covering expiry boundaries (relative to the run
clock, past and future), revocation, retention, agent binding, tool scopes,
stale tool-registry stamps and malformed bearer forms.  Section B starts both
CLIs against file-level registry states (missing, legacy, malformed, typed
errors) and compares the startup outcome, served responses and resulting token
files, with kill and SIGINT disposal.  Section C changes the registry while the
servers run (live expiry, out-of-band add/revoke/corrupt) and records latency;
Section C2 writes duplicate-key and invalid-UTF-8 documents while the servers
run (rejected documents must leave the last good state in place).  Section D revokes in the file with no intervening request, waits past Go's 2 s
poll, corrupts or deletes the file and requires both to answer 401.
Every expectation is hand-written; Go and Rust are each held to it.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
from http_oauth_contract import PASSPHRASE, PROBE
from http_process_contract import SECRET, ProcessCapture, request
from http_replay_contract import HEALTH, INIT, PING, TOOLS, exchange, transcript
from mcp_process_contract import ORACLE, ROOT, checked, inventory, isolated, oracle_build_timeout, remove_worktree, vault_snapshot

STEPS = [('init', INIT), ('health', HEALTH), ('list', TOOLS), ('ping', PING)]
LEGACY_TOKEN = 'public-legacy-token'


def iso(delta):
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=delta)).strftime('%Y-%m-%dT%H:%M:%SZ')


def entry(name, **fields):
    raw = 'public-token-' + name
    result = dict(id='tok-' + name, label=name, hash=hashlib.sha256(raw.encode()).hexdigest(), prefix=raw[:4], allowed_tools=['*'],
                  agent_name='fixture', created_at=iso(-3600), revoked=False)
    result.update(fields)
    return raw, result


def registry(specs):
    raws, tokens = {}, {}
    for name, fields in specs.items():
        raws[name], record = entry(name, **fields)
        tokens[record['id']] = record
    return raws, json.dumps(dict(version=2, tokens=tokens), indent=2) + '\n'


# name -> (fields, agent header, expected auth status, expected health denial)
TOKENS = {
    'never': ({}, 'fixture', 200, False), 'future1h': (dict(expires_at='@3600'), 'fixture', 200, False),
    'far': (dict(expires_at='9999-12-31T23:59:59Z'), 'fixture', 200, False),
    'offset': (dict(expires_at='2999-01-01T00:00:00+02:00'), 'fixture', 200, False),
    'fraction': (dict(expires_at='2999-01-01T00:00:00.123456789Z'), 'fixture', 200, False),
    'past1s': (dict(expires_at='@-1'), 'fixture', 401, None), 'past1h': (dict(expires_at='@-3600'), 'fixture', 401, None),
    'past-year': (dict(expires_at='2000-01-01T00:00:00Z'), 'fixture', 401, None),
    'revoked': (dict(revoked=True, revoked_at='@-60'), 'fixture', 401, None),
    'revoked-expired': (dict(revoked=True, revoked_at='@-60', expires_at='@-60'), 'fixture', 401, None),
    'revoked-old': (dict(revoked=True, revoked_at='@-2678400'), 'fixture', 401, None),
    'revoked-no-at': (dict(revoked=True), 'fixture', 401, None),
    'agentless': (dict(agent_name=''), 'fixture', 200, False), 'ghost': (dict(agent_name='ghost'), 'ghost', 403, None),
    'other': (dict(agent_name='other'), 'other', 200, False), 'bound-mismatch': (dict(agent_name='other'), 'fixture', 403, None),
    'tools-empty': (dict(allowed_tools=[]), 'fixture', 200, True), 'tools-null': (dict(allowed_tools=None), 'fixture', 200, True),
    'tools-star': (dict(allowed_tools=['*']), 'fixture', 200, False), 'tools-health': (dict(allowed_tools=['health']), 'fixture', 200, False),
    'tools-upper': (dict(allowed_tools=['HEALTH']), 'fixture', 200, True), 'tools-space': (dict(allowed_tools=[' health']), 'fixture', 200, True),
    'tools-star-plus': (dict(allowed_tools=['*', 'health']), 'fixture', 200, False), 'tools-unknown': (dict(allowed_tools=['nope']), 'fixture', 200, True),
    'stale-hash': (dict(tool_registry_hash='stale'), 'fixture', 200, True),
    # Go's json.Unmarshal binds struct fields case-insensitively (Unicode simple folding): a mis-cased
    # revoked/expiry key must take effect in both implementations, never be ignored as an unknown field.
    'upper-revoked': (dict(REVOKED=True), 'fixture', 401, None), 'mixed-revoked-at': (dict(Revoked=True, Revoked_At='@-60'), 'fixture', 401, None),
    'upper-expires': (dict(EXPIRES_AT='@-3600'), 'fixture', 401, None), 'long-s-expires': (dict(**{'expire\u017f_at': '@-3600'}), 'fixture', 401, None),
    'upper-allowed-tools': (dict(ALLOWED_TOOLS=['health']), 'fixture', 200, False), 'upper-agent': (dict(AGENT_NAME='other'), 'fixture', 403, None),
    'upper-unrevokes': (dict(revoked=True, REVOKED=False), 'fixture', 200, False),
    'last-used': (dict(last_used_at='@-10'), 'fixture', 200, False),
    'refresh-fields': (dict(refresh_token_hash='ab' * 32, refresh_expires_at='@3600'), 'fixture', 200, False),
    'extra-field': (dict(zzz='extra'), 'fixture', 200, False), 'label-empty': (dict(label=''), 'fixture', 200, False),
}


def resolve(fields):
    return {key: iso(int(value[1:])) if isinstance(value, str) and value.startswith('@') else value for key, value in fields.items()}


def token_registry():
    return registry({name: resolve(spec[0]) for name, spec in TOKENS.items()})


def token_cases(port, raws):
    cases = []
    for name, (_, agent, _, _) in TOKENS.items():
        for label, body in STEPS:
            cases.append((f'{name}:{label}', request('/mcp', port, {}, body=body, auth=raws[name], agent=agent)))
    base = raws['never']
    for label, header in [('lower', 'bearer ' + base), ('double-space', 'Bearer  ' + base), ('trailing-space', 'Bearer ' + base + ' '),
                          ('upper-token', 'Bearer ' + base.upper()), ('basic', 'Basic ' + base), ('no-space', 'Bearer' + base),
                          ('empty', 'Bearer '), ('tab', 'Bearer\t' + base), ('token-only', base)]:
        data = request('/mcp', port, {}, body=PING, auth=None).replace(b'Content-Length', f'Authorization: {header}\r\nContent-Length'.encode(), 1)
        cases.append(('bearer:' + label, data))
    cases.append(('bearer:query-token', request('/mcp?access_token=' + base, port, {}, body=PING, auth=None)))
    for index in range(25):
        cases.append((f'failure-{index}', request('/mcp', port, {}, body=PING, auth=f'public-wrong-{index}')))
    cases.append(('after-failures', request('/mcp', port, {}, body=PING, auth=base)))
    return cases


class Process:
    """One real CLI with bounded output capture and Go-compatible cleartext confirmation."""
    def __init__(self, binary, home, port):
        self.child = subprocess.Popen([str(binary), '--quiet', 'mcp', '--bind', '127.0.0.1', '--port', str(port)], cwd=home, env=isolated(home),
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.capture = ProcessCapture(self.child)
        self.child.stdin.write(b'y\n')
        self.child.stdin.close()
        self.child.stdin = None
        deadline, self.state = time.monotonic() + 30, 'timeout'
        while time.monotonic() < deadline:
            if self.child.poll() is not None:
                self.state = 'exited'
                break
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2):
                    self.state = 'listening'
                    break
            except OSError:
                time.sleep(.05)
        if self.state == 'listening':
            time.sleep(.5)   # a listener that dies immediately after accept is an exit, not service
            if self.child.poll() is not None:
                self.state = 'exited'
        assert self.state != 'timeout', 'native CLI neither listened nor exited'

    def close(self, graceful=False):
        disposal = 'exited' if self.child.poll() is not None else 'killed'
        if self.child.poll() is None:
            if graceful and os.name != 'nt':
                self.child.send_signal(signal.SIGINT)
                disposal = 'graceful'
                try:
                    self.child.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    self.child.kill()
                    disposal = 'graceful-timeout-killed'
            else:
                self.child.kill()
        self.child.wait(timeout=15)
        stdout, stderr, complete = self.capture.finish()
        assert complete, 'owned output readers finished'
        return dict(disposal=disposal, exit=self.child.returncode, stdout=stdout, stderr=stderr)


def token_files(vault):
    """Structure of the token files, never a raw token or random id/hash."""
    result = {}
    for path in sorted(vault.glob('mcp-token*')):
        if path.is_dir():
            result[path.name] = 'directory'
            continue
        if path.name != 'mcp-tokens.json':
            result[path.name] = 'present'
            continue
        try:
            document = json.loads(path.read_text(encoding='utf-8'))
            result[path.name] = dict(version=document.get('version'), entries=sorted(
                (e.get('label', ''), e.get('agent_name', ''), json.dumps(e.get('allowed_tools')), bool(e.get('revoked')), 'expires_at' in e, 'last_used_at' in e,
                 'revoked_at' in e, e.get('tool_registry_hash', ''), len(str(e.get('hash', ''))), len(str(e.get('prefix', ''))))
                for e in (document.get('tokens') or {}).values() if e))
        except (ValueError, AttributeError, TypeError):
            result[path.name] = 'unparseable'
    return result


def raw_files(vault):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(vault.glob('mcp-token*')) if path.is_file()}


def prepare(base, name, seed_vault, mutate):
    home = base / name
    if home.exists():
        shutil.rmtree(home)
    home.mkdir(parents=True)
    shutil.copytree(seed_vault, home / 'vault')
    mutate(home / 'vault')
    return home


def observe_cases(binary, home, port, raws, result):
    process = Process(binary, home, port)
    try:
        assert process.state == 'listening'
        for name, data in token_cases(port, raws):
            row = dict(case=name, request_sha256=hashlib.sha256(data).hexdigest(), request_base64=base64.b64encode(data).decode())
            result['rows'].append(row)
            row.update(exchange(port, data))
            assert not any(value.encode() in base64.b64decode(row['raw_base64']) for value in list(raws.values()) + [SECRET, PASSPHRASE]), 'token in response'
    finally:
        result['process'] = {k: (v if k in {'disposal', 'exit'} else base64.b64encode(v).decode()) for k, v in process.close().items()}
        for value in list(raws.values()) + [SECRET, PASSPHRASE, LEGACY_TOKEN]:
            assert value.encode() not in base64.b64decode(result['process']['stdout']) + base64.b64decode(result['process']['stderr']), 'token in process output'


def check_token_rows(go_rows, rust_rows):
    assert [r['case'] for r in go_rows] == [r['case'] for r in rust_rows]
    different = []
    for left, right in zip(go_rows, rust_rows, strict=True):
        name = left['case']
        assert left['request_sha256'] == right['request_sha256'], name
        assert transcript(left) == transcript(right), (name, 'undeclared token-state difference', left['responses'], right['responses'])
        if ':' in name and name.split(':')[0] in TOKENS:
            token, step = name.split(':')
            _, _, status, denied = TOKENS[token]
            code = left['responses'][0]['code']
            assert code == (status if step != 'health' or status != 200 else 200), (name, code, status)
            if step == 'health' and status == 200:
                body = json.loads(base64.b64decode(left['responses'][0]['body_base64']))
                text = json.dumps(body)
                assert denied == bool(body['result'].get('isError')), (name, 'scope/drift denial', text[:200])
                if token == 'stale-hash':
                    assert 'tool registry has changed since this token was issued' in text
        elif name.startswith('bearer:') or name.startswith('failure-'):
            # Trailing optional whitespace is trimmed from a field value; every other form is a different credential.
            expected = 200 if name == 'bearer:trailing-space' else 401
            assert left['responses'][0]['code'] == expected, (name, 'malformed or unknown bearer is unauthorized')
        elif name == 'after-failures':
            assert left['responses'][0]['code'] == 200, 'no failure lockout after 25 bad bearers'
    return different


def duplicate_documents(body):
    """Go-decoder duplicate-key and encoding documents, built around the real `never` entry.

    Go's encoding/json decodes every occurrence of a repeated key into the same field and returns the first
    type error it saw, so a bad earlier value fails the whole document even when a later one is fine; a
    repeated root `tokens` object is decoded into the same map (ids merge, a repeated id replaces the entry,
    `null` resets the map); invalid UTF-8 inside a string is replaced by U+FFFD instead of rejected.
    name -> (document bytes, startup state, code of the `never` token when served)."""
    never = {k: v for k, v in json.loads(body)['tokens']['tok-never'].items() if k != 'revoked'}
    head = json.dumps(never)[:-1]

    def entry_with(extra, **overrides):
        return (json.dumps({**never, **overrides})[:-1] if overrides else head) + extra + '}'

    def doc(tokens_text, prefix='"version":2,'):
        return ('{%s"tokens":%s}' % (prefix, tokens_text)).encode()

    def one(extra, **overrides):
        return doc('{"tok-never":%s}' % entry_with(extra, **overrides))

    ok, bad = ('listening', 200), ('exited', None)
    other = '{"tok-other":{"id":"tok-other","hash":"%s"}}' % ('ab' * 32)
    never_entry = entry_with(',"revoked":false')
    revoked_entry = entry_with(',"revoked":true')
    return {
        'dup-control': (one(',"revoked":false'), *ok),
        'dup-revoked-typeerr-then-false': (one(',"revoked":"yes","revoked":false'), *bad),
        'dup-revoked-false-then-typeerr': (one(',"revoked":false,"revoked":"yes"'), *bad),
        'dup-revoked-typeerr-folded-then-false': (one(',"REVOKED":"yes","revoked":false'), *bad),
        'dup-revoked-true-then-null': (one(',"revoked":true,"REVOKED":null'), *('listening', 401)),
        'dup-expires-typeerr-then-null': (one(',"expires_at":"tomorrow","expires_at":null'), *bad),
        'dup-expires-valid-then-null': (one(',"expires_at":"2000-01-01T00:00:00Z","EXPIRES_AT":null'), *ok),
        'dup-allowed-tools-typeerr-then-valid': (one(',"allowed_tools":[5],"allowed_tools":["*"]'), *bad),
        'dup-hash-typeerr-then-valid': (doc('{"tok-never":{"hash":5,%s}}' % json.dumps(never)[1:]), *bad),
        'dup-version-typeerr-then-int': (doc('{"tok-never":%s}' % never_entry, '"version":"a","version":2,'), *bad),
        'dup-version-int-then-typeerr': (doc('{"tok-never":%s}' % never_entry, '"version":2,"version":"a",'), *bad),
        'dup-root-tokens-typeerr-first': (doc('{"tok-bad":{"revoked":"yes"}},"tokens":{"tok-never":%s}' % never_entry), *bad),
        'dup-root-tokens-notobject-first': (doc('[],"tokens":{"tok-never":%s}' % never_entry), *bad),
        'dup-id-entry-typeerr-first': (doc('{"tok-never":"x","tok-never":%s}' % never_entry), *bad),
        'dup-id-entry-nested-typeerr-first': (doc('{"tok-never":%s,"tok-never":%s}' % (entry_with(',"revoked":"yes"'), never_entry)), *bad),
        'dup-unknown-member-typeerr-ignored': (one(',"zzz":"x","zzz":5'), *ok),
        'dup-root-tokens-merge': (doc('{"tok-never":%s},"tokens":%s' % (never_entry, other)), *ok),
        'dup-root-tokens-merge-reverse': (doc('%s,"tokens":{"tok-never":%s}' % (other, never_entry)), *ok),
        'dup-root-tokens-id-replaced-revoked': (doc('{"tok-never":%s},"tokens":{"tok-never":%s}' % (never_entry, revoked_entry)), *('listening', 401)),
        'dup-root-tokens-id-replaced-valid': (doc('{"tok-never":%s},"tokens":{"tok-never":%s}' % (revoked_entry, never_entry)), *ok),
        'dup-root-tokens-null-resets': (doc('{"tok-never":%s},"tokens":null' % never_entry), *('listening', 401)),
        'dup-root-tokens-null-then-map': (doc('null,"tokens":{"tok-never":%s}' % never_entry), *ok),
        'utf8-invalid-label': (one(',"label":"a@@"').replace(b'@@', b'\xff\xe2\x82'), *ok),
        'utf8-invalid-revoked-key-padding': (one(',"revoked":true,"zz@@":"x"').replace(b'@@', b'\xff'), *('listening', 401)),
        'utf8-invalid-outside-string': (one(',"revoked":false') + b'\xff', *bad),
    }


# --- Section B: file-level and startup states ---------------------------------------------------------
def startup_scenarios(raws, body):
    def put(text):
        return lambda vault: (vault / 'mcp-tokens.json').write_text(text, encoding='utf-8')

    def remove(vault):
        (vault / 'mcp-tokens.json').unlink()

    def legacy(vault):
        remove(vault)
        (vault / 'mcp-token').write_text(LEGACY_TOKEN + '\n')

    def legacy_and_registry(vault):
        put(body)(vault)
        (vault / 'mcp-token').write_text(LEGACY_TOKEN + '\n')

    def directory(vault):
        remove(vault)
        (vault / 'mcp-tokens.json').mkdir()

    def put_bytes(data):
        return lambda vault: (vault / 'mcp-tokens.json').write_bytes(data)

    expiry = json.loads(body)['tokens']['tok-future1h']['expires_at']
    assert expiry in body, 'registry anchor for the malformed-expiry controls'
    # name, mutate, graceful, expected state, expected first-call code (for the never token) / None
    return [
        ('registry-valid', put(body), False, 'listening', 200), ('registry-valid-sigint', put(body), True, 'listening', 200),
        ('registry-missing', remove, False, 'listening', 401), ('registry-missing-sigint', remove, True, 'listening', 401),
        ('legacy-only', legacy, False, 'listening', 401), ('legacy-only-sigint', legacy, True, 'listening', 401),
        ('legacy-plus-registry', legacy_and_registry, False, 'listening', 200),
        ('registry-empty-file', put(''), False, 'exited', None), ('registry-invalid-json', put('{not json'), False, 'exited', None),
        ('registry-no-tokens', put('{"version":2}'), False, 'listening', 401), ('registry-tokens-null', put('{"version":2,"tokens":null}'), False, 'listening', 401),
        ('registry-tokens-empty', put('{"version":2,"tokens":{}}'), False, 'listening', 401), ('registry-array', put('[]'), False, 'exited', None),
        ('registry-bad-expiry', put(body.replace(expiry, 'tomorrow')), False, 'exited', None),
        ('registry-null-expiry', put(body.replace('"expires_at": "%s"' % expiry, '"expires_at": null')), False, 'listening', 200),
        ('registry-version-1', put(body.replace('"version": 2', '"version": 1')), False, 'listening', 200),
        ('registry-version-string', put(body.replace('"version": 2', '"version": "x"')), False, 'exited', None),
        ('registry-trailing-garbage', put(body + 'garbage'), False, 'exited', None), ('registry-bom', put('\ufeff' + body), False, 'exited', None),
        ('registry-directory', directory, False, 'exited', None),
        ('registry-entry-null', put('{"version":2,"tokens":{"a":null}}'), False, 'listening', 401),
        ('registry-entry-string', put('{"version":2,"tokens":{"a":"x"}}'), False, 'exited', None),
        ('registry-hash-number', put('{"version":2,"tokens":{"a":{"hash":5}}}'), False, 'exited', None),
        ('registry-entry-minimal', put('{"version":2,"tokens":{"a":{"hash":"ab","id":"a"}}}'), False, 'listening', 401),
    ] + [(name, put_bytes(data), False, state, first) for name, (data, state, first) in duplicate_documents(body).items()]


def startup_calls(port, raws):
    return [('scoped-init', request('/mcp', port, {}, body=INIT, auth=raws['never'])), ('expired', request('/mcp', port, {}, body=PING, auth=raws['past1s'])),
            ('legacy-ping', request('/mcp', port, {}, body=PING, auth=LEGACY_TOKEN)),
            ('legacy-other-agent-health', request('/mcp', port, {}, body=HEALTH, auth=LEGACY_TOKEN, agent='other')),
            ('legacy-no-agent', request('/mcp', port, {}, body=PING, auth=LEGACY_TOKEN, agent=None))]


def observe_startup(binary, base, seed_vault, port, scenario, raws):
    name, mutate, graceful, _, _ = scenario
    home = prepare(base, name, seed_vault, mutate)
    before = token_files(home / 'vault')
    process = Process(binary, home, port)
    responses = []
    if process.state == 'listening':
        for label, data in startup_calls(port, raws):
            responses.append(dict(case=label, **exchange(port, data)))
    done = process.close(graceful)
    stderr = done['stderr'].decode('utf-8', 'replace')
    for value in list(raws.values()) + [LEGACY_TOKEN]:
        assert value not in stderr and value.encode() not in done['stdout'], 'token in process output'
    return dict(state=process.state, exit=done['exit'], disposal=done['disposal'], before=before, after=token_files(home / 'vault'),
                responses=responses, stderr_has_legacy_warning='legacy MCP token migrated' in stderr, stderr_utf8=stderr)


def check_startup(scenario, go, rust):
    name, _, graceful, state, first = scenario
    for side, observed in (('go', go), ('rust', rust)):
        assert observed['state'] == state, (name, side, 'startup state', observed['state'])
        if state == 'exited':
            assert observed['exit'] == 1, (name, side, 'fatal registry exit status')
    assert go['before'] == rust['before']
    assert go['exit'] == rust['exit'] and go['disposal'] == rust['disposal'], (name, 'exit/disposal', go['exit'], rust['exit'])
    assert go['after'] == rust['after'], (name, 'resulting token files', go['after'], rust['after'])
    assert go['stderr_has_legacy_warning'] == rust['stderr_has_legacy_warning'], (name, 'legacy migration warning')
    assert [transcript(r) for r in go['responses']] == [transcript(r) for r in rust['responses']], (name, 'served responses')
    if first is not None:
        assert go['responses'][0]['responses'][0]['code'] == first, (name, 'first call status')
    if name.startswith('legacy-only') or name.startswith('registry-missing'):
        entries = go['after']['mcp-tokens.json']['entries']
        assert len(entries) == 1 and entries[0][0] == 'legacy (auto-migrated, unscoped)' and entries[0][1] == 'legacy' and 'mcp-token' not in go['after'], (name, entries)
    if name.startswith('legacy'):
        codes = [r['responses'][0]['code'] if r['responses'] else None for r in go['responses']]
        if name == 'legacy-only' or name == 'legacy-only-sigint':
            assert codes == [401, 401, 200, 200, 403], (name, codes)


# --- Section C: dynamic clock and out-of-band changes ----------------------------------------------------
def code_of(port, raw, agent='fixture'):
    row = exchange(port, request('/mcp', port, {}, body=PING, auth=raw, agent=agent))
    return row['responses'][0]['code']


def wait_for(port, raw, wanted, limit=8.0):
    started = time.monotonic()
    while time.monotonic() - started < limit:
        if code_of(port, raw) == wanted:
            return time.monotonic() - started
        time.sleep(.05)
    raise AssertionError(('status never reached', wanted))


def observe_dynamic(binary, base, seed_vault, port, raws, body):
    result = {}
    live_expiry = iso(8)
    live_raw, live_entry = entry('live', expires_at=live_expiry)
    added_raw, added_entry = entry('added')
    document = json.loads(body)
    document['tokens'][live_entry['id']] = live_entry
    home = prepare(base, 'dynamic', seed_vault, lambda vault: (vault / 'mcp-tokens.json').write_text(json.dumps(document, indent=2) + '\n'))
    registry_path = home / 'vault' / 'mcp-tokens.json'
    process = Process(binary, home, port)
    try:
        assert process.state == 'listening'
        result['live_before_expiry'] = code_of(port, live_raw)
        wait_for(port, live_raw, 401, 12)
        result['live_expiry_epoch'] = datetime.datetime.strptime(live_expiry, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()
        result['live_detected_epoch'] = time.time()
        document['tokens'][added_entry['id']] = added_entry
        registry_path.write_text(json.dumps(document, indent=2) + '\n')
        result['added_before'] = None
        result['added_latency'] = wait_for(port, added_raw, 200)
        document['tokens'][added_entry['id']]['revoked'] = True
        document['tokens'][added_entry['id']]['revoked_at'] = iso(0)
        registry_path.write_text(json.dumps(document, indent=2) + '\n')
        result['revoke_latency'] = wait_for(port, added_raw, 401)
        registry_path.write_text('{corrupt')
        time.sleep(3.2)
        result['after_corruption'] = code_of(port, raws['never'])
        registry_path.write_text(json.dumps(document, indent=2) + '\n')
        result['recovered_latency'] = wait_for(port, raws['never'], 200)
    finally:
        process.close()
    return result


def observe_stale_revocation(binary, base, seed_vault, port, raws, body, mode):
    """Revoke in the file, send NO request (the only registry read is the startup load), wait past Go's 2 s poll,
    then corrupt or delete the file and finally request the revoked token.  Go's watcher reloaded the revocation
    and keeps it after the failed reload; a cache refreshed only by requests would still serve the old entry."""
    home = prepare(base, 'stale-' + mode, seed_vault, lambda vault: (vault / 'mcp-tokens.json').write_text(body))
    registry_path = home / 'vault' / 'mcp-tokens.json'
    process = Process(binary, home, port)
    try:
        assert process.state == 'listening'
        document = json.loads(body)
        document['tokens']['tok-never']['revoked'] = True
        document['tokens']['tok-never']['revoked_at'] = iso(0)
        registry_path.write_text(json.dumps(document, indent=2) + '\n')
        time.sleep(3.5)
        if mode == 'corrupt':
            registry_path.write_text('{corrupt')
        else:
            registry_path.unlink()
        time.sleep(2.5)
        return dict(mode=mode, revoked_token_status=code_of(port, raws['never']), other_token_status=code_of(port, raws['future1h']))
    finally:
        process.close()


def check_stale_revocation(go, rust):
    for left, right in zip(go, rust, strict=True):
        for side, observed in (('go', left), ('rust', right)):
            assert observed['revoked_token_status'] == 401, (side, observed['mode'], 'revoked token must stay revoked after a failed reload')
            assert observed['other_token_status'] == 200, (side, observed['mode'], 'unrevoked tokens keep the last good registry')


def observe_duplicate_reload(binary, base, seed_vault, port, raws, body):
    """Live reload of duplicate-key and encoding documents.  Every write is followed by either a wait for the
    expected status or, for a document Go rejects, a wait past Go's 2 s poll proving the last good state stays."""
    docs = duplicate_documents(body)
    registry_path = None
    codes = []
    home = prepare(base, 'dup-reload', seed_vault, lambda vault: (vault / 'mcp-tokens.json').write_text(body, encoding='utf-8'))
    registry_path = home / 'vault' / 'mcp-tokens.json'
    revoked_document = json.loads(body)
    revoked_document['tokens']['tok-never']['revoked'] = True
    revoked_bytes = (json.dumps(revoked_document, indent=2) + '\n').encode()
    process = Process(binary, home, port)
    try:
        assert process.state == 'listening'

        def accepted(label, data, expected):
            registry_path.write_bytes(data)
            wait_for(port, raws['never'], expected)
            codes.append((label, code_of(port, raws['never'])))

        def rejected(label, data, expected):
            registry_path.write_bytes(data)
            time.sleep(3.5)
            codes.append((label, code_of(port, raws['never'])))
            assert codes[-1][1] == expected, (label, 'last good state must stay', codes[-1])

        accepted('baseline', body.encode(), 200)
        accepted('revoked', revoked_bytes, 401)
        # a revoked token is un-revoked only by a document Go accepts
        rejected('revoked-typeerr-then-false', docs['dup-revoked-typeerr-then-false'][0], 401)
        rejected('root-tokens-typeerr-first', docs['dup-root-tokens-typeerr-first'][0], 401)
        rejected('version-typeerr-first', docs['dup-version-typeerr-then-int'][0], 401)
        rejected('id-entry-typeerr-first', docs['dup-id-entry-typeerr-first'][0], 401)
        rejected('expires-typeerr-then-null', docs['dup-expires-typeerr-then-null'][0], 401)
        accepted('root-tokens-merge', docs['dup-root-tokens-merge'][0], 200)
        accepted('revoked-again', revoked_bytes, 401)
        accepted('invalid-utf8-label', docs['utf8-invalid-label'][0], 200)
        accepted('revoked-third', revoked_bytes, 401)
        accepted('root-tokens-id-replaced-valid', docs['dup-root-tokens-id-replaced-valid'][0], 200)
        accepted('root-tokens-id-replaced-revoked', docs['dup-root-tokens-id-replaced-revoked'][0], 401)
    finally:
        process.close()
    return codes


def check_duplicate_reload(go, rust):
    assert go == rust, ('duplicate-key reload sequence differs', go, rust)
    assert len(go) == 13, len(go)


def check_dynamic(go, rust):
    for side, observed in (('go', go), ('rust', rust)):
        assert observed['live_before_expiry'] == 200, (side, 'token live before its deadline')
        assert 0.0 <= observed['live_detected_epoch'] - observed['live_expiry_epoch'] < 3.0, (side, 'actual elapsed expiry', observed['live_detected_epoch'] - observed['live_expiry_epoch'])
        assert observed['added_latency'] <= 4.5 and observed['revoke_latency'] <= 4.5 and observed['recovered_latency'] <= 4.5, (side, 'registry change took effect within the poll bound')
    # Go keeps its last good in-memory registry after a failed reload; Rust must do the same (it re-reads per request and
    # polls in the background, so the only declared timing difference is that registry edits take effect immediately
    # rather than within Go's 2 s poll).
    assert go['after_corruption'] == 200 and rust['after_corruption'] == 200, (go['after_corruption'], rust['after_corruption'], 'last-good registry after a corrupt reload')


def candidate_paths():
    return sorted(p for p in checked(['git', 'ls-files', '--cached', '--others', '--exclude-standard']).decode().splitlines()
                  if p.startswith(('crates/', 'third_party/', 'testdata/', 'scripts/rust-port/', 'internal/mcp/apitemplates/builtin/'))
                  or p in {'Cargo.toml', 'Cargo.lock', '.gitattributes'})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--allow-dirty-for-development', action='store_true')
    args = parser.parse_args()
    clean = not checked(['git', 'status', '--porcelain=v1']).strip()
    assert clean or args.allow_dirty_for_development
    rust = args.rust.resolve()
    paths = candidate_paths()
    receipt = dict(passed=False, candidate_commit=checked(['git', 'rev-parse', 'HEAD']).decode().strip(), candidate_worktree_clean=clean,
                   candidate_sources=inventory(paths, ROOT), native_os=platform.system(), architecture=platform.machine(), oracle_commit=ORACLE,
                   rust_binary_sha256=hashlib.sha256(rust.read_bytes()).hexdigest(), driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   go=dict(rows=[]), rust=dict(rows=[]), startup=[], dynamic={})
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-http-token-') as raw:
            base, tree = Path(raw), Path(raw) / 'oracle'
            checked(['git', 'worktree', 'add', '--detach', tree, ORACLE])
            try:
                files = checked(['git', 'ls-tree', '-r', '--name-only', ORACLE]).decode().splitlines()
                sources = sorted(p for p in files if p in {'go.mod', 'go.sum'} or p.endswith('.go') and not p.endswith('_test.go'))
                embedded = sorted(p for p in files if p.startswith('internal/mcp/apitemplates/builtin/'))
                assert len(embedded) == 17
                receipt.update(oracle_sources=inventory(sources, tree), oracle_embedded=inventory(embedded, tree), seed_probe_sha256=hashlib.sha256(PROBE.read_bytes()).hexdigest())
                helper = tree / 'scripts/rust-port/cmd/httptokenseed'
                helper.mkdir()
                (helper / 'main.go').write_bytes(PROBE.read_bytes())
                suffix = '.exe' if os.name == 'nt' else ''
                go, seed = base / ('go-cli' + suffix), base / ('go-seed' + suffix)
                checked(['go', 'build', '-trimpath', '-buildvcs=false', '-o', go, '.'], tree, timeout=oracle_build_timeout())
                checked(['go', 'build', '-trimpath', '-buildvcs=false', '-o', seed, './scripts/rust-port/cmd/httptokenseed'], tree, timeout=oracle_build_timeout())
                receipt.update(go_binary_sha256=hashlib.sha256(go.read_bytes()).hexdigest(), seed_binary_sha256=hashlib.sha256(seed.read_bytes()).hexdigest())
                seed_home = base / 'seed'
                seed_home.mkdir()
                json.loads(checked([seed, '--root', seed_home / 'vault'], seed_home, isolated(seed_home)))
                snapshot = vault_snapshot(seed_home / 'vault')
                receipt['fixture_snapshot'] = snapshot
                raws, body = token_registry()
                with socket.socket() as selection:
                    selection.bind(('127.0.0.1', 0))
                    port = selection.getsockname()[1]
                receipt['port'] = port
                # A: the shared token-state matrix
                for implementation, binary in [('go', go), ('rust', rust)]:
                    home = prepare(base, implementation, seed_home / 'vault', lambda vault: (vault / 'mcp-tokens.json').write_text(body, encoding='utf-8'))
                    observe_cases(binary, home, port, raws, receipt[implementation])
                check_token_rows(receipt['go']['rows'], receipt['rust']['rows'])
                receipt['token_cases'] = len(receipt['go']['rows'])
                # B: startup / storage states
                for scenario in startup_scenarios(raws, body):
                    pair = [observe_startup(binary, base, seed_home / 'vault', port, scenario, raws) for binary in (go, rust)]
                    check_startup(scenario, *pair)
                    receipt['startup'].append(dict(case=scenario[0], go=pair[0], rust=pair[1]))
                # C: dynamic clock / out-of-band changes
                dynamic = [observe_dynamic(binary, base, seed_home / 'vault', port, raws, body) for binary in (go, rust)]
                check_dynamic(*dynamic)
                receipt['dynamic'] = dict(go=dynamic[0], rust=dynamic[1])
                # C2: duplicate-key / invalid-UTF-8 documents written while running
                reload_codes = [observe_duplicate_reload(binary, base, seed_home / 'vault', port, raws, body) for binary in (go, rust)]
                check_duplicate_reload(*reload_codes)
                receipt['duplicate_reload'] = dict(go=reload_codes[0], rust=reload_codes[1])
                # D: revoke -> no request -> wait > poll -> corrupt / delete -> request (cache must not outlive the revocation)
                stale = {impl: [observe_stale_revocation(binary, base, seed_home / 'vault', port, raws, body, mode) for mode in ('corrupt', 'delete')]
                         for impl, binary in (('go', go), ('rust', rust))}
                check_stale_revocation(stale['go'], stale['rust'])
                receipt['stale_revocation'] = stale
                assert inventory(paths, ROOT) == receipt['candidate_sources'] and candidate_paths() == paths, 'candidate changed during observations'
                assert hashlib.sha256(rust.read_bytes()).hexdigest() == receipt['rust_binary_sha256']
                receipt['candidate_worktree_clean_at_end'] = not checked(['git', 'status', '--porcelain=v1']).strip()
                assert receipt['candidate_worktree_clean_at_end'] or args.allow_dirty_for_development
                receipt['passed'] = True
            finally:
                remove_worktree(lambda: checked(['git', 'worktree', 'remove', '--force', tree]), 'oracle worktree')
    finally:
        args.receipt.write_text(json.dumps(receipt, indent=2, default=str) + '\n', encoding='utf-8')
    print(f"PASS: {receipt['token_cases']} token-state cases, {len(receipt['startup'])} startup/storage scenarios and 1 dynamic clock/out-of-band scenario and "
          f"{len(receipt['duplicate_reload']['go'])} duplicate-key reload steps and "
          f"{len(receipt['stale_revocation']['go'])} stale-revocation scenarios per implementation on {platform.system()}")


if __name__ == '__main__':
    main()
