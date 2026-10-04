#!/usr/bin/env python3
"""Real native OAuth browser/PKCE/rotation/persistence semantic controls.

Opaque IDs, tokens, creation times and consent DOM are asserted explicitly.
This supplements the strict Date-only HTTP corpus; it does not normalize it.
Only disposable public fixture secrets are present in retained observations.
"""
import argparse
import base64
from datetime import datetime
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlencode, urlsplit

sys.dont_write_bytecode = True
from http_process_contract import ProcessCapture, SECRET, exchange, request
from mcp_process_contract import ORACLE, ROOT, checked, inventory, isolated, vault_snapshot

PROBE = ROOT / 'scripts/rust-port/http_oauth_seed.go.txt'
PASSPHRASE = 'correct horse battery staple'
VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip('=')
REDIRECT = 'http://127.0.0.1:48175/public-callback'
OTHER_REDIRECT = 'http://127.0.0.1:48176/other-callback'
STATE = 'public state & + / = <tag>'
HEX32 = re.compile(r'[0-9a-f]{32}')
HEX64 = re.compile(r'[0-9a-f]{64}')


class ConsentForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.hidden = {}
        self.passwords = []
        self.buttons = []

    def handle_starttag(self, tag, attributes):
        fields = dict(attributes)
        if tag == 'form':
            self.forms.append(fields)
        if tag == 'input' and fields.get('type') == 'hidden':
            name = fields['name']
            assert name not in self.hidden, 'duplicate consent binding'
            self.hidden[name] = fields.get('value', '')
        if tag == 'input' and fields.get('type') == 'password':
            self.passwords.append(fields)
        if tag == 'button':
            self.buttons.append(fields)


def status(response):
    return int(response['status_line'].split()[1])


def headers(response, **expected):
    actual = response['headers_without_date']
    fields = [('connection', 'close')]
    if any(name == 'transfer-encoding' for name, _ in actual):
        fields.append(('transfer-encoding', 'chunked'))
    else:
        fields.append(('content-length', str(len(base64.b64decode(response['body_base64'])))))
    fields += [(name.replace('_', '-'), value) for name, value in expected.items()]
    assert actual == sorted(fields), 'complete semantic-control header multiset'


def error_response(response, error, description=None):
    assert status(response) == 400
    expected = {'error': error}
    if description is not None:
        expected['error_description'] = description
    assert json.loads(response['body_utf8']) == expected
    assert response['body_utf8'] == json.dumps(expected, sort_keys=True, separators=(',', ':')) + '\n'
    headers(response, content_type='application/json')


def consent(response, implementation, client, redirect, state=STATE, challenge=CHALLENGE, wrong=False):
    assert status(response) == 200
    headers(response, content_type='text/html; charset=utf-8',
            **({'cache_control': 'no-store'} if implementation == 'rust' else {}))
    assert '<html' in response['body_utf8'].lower()
    form = ConsentForm()
    form.feed(response['body_utf8'])
    assert len(form.forms) == 1 and form.forms[0]['method'].upper() == 'POST'
    assert form.forms[0]['action'] == '/mcp/oauth/authorize/confirm'
    assert len(form.passwords) == 1 and form.passwords[0]['name'] == 'passphrase'
    assert form.passwords[0].get('value', '') == ''
    assert client in response['body_utf8'] and redirect in response['body_utf8']
    if implementation == 'go':
        assert form.hidden == dict(client_id=client, redirect_uri=redirect, state=state,
                                   code_challenge=challenge, code_challenge_method='S256')
        if wrong:
            assert 'Incorrect passphrase. Please try again.' in response['body_utf8']
    else:
        assert set(form.hidden) == {'flow_id'} and HEX64.fullmatch(form.hidden['flow_id'])
        assert 'Agent: oauth' in response['body_utf8']
        assert {(b.get('name'), b.get('value')) for b in form.buttons} == {('decision', 'approve'), ('decision', 'deny')}
        if wrong:
            assert 'Incorrect passphrase.' in response['body_utf8']
    return form.hidden


def redirect_code(response, redirect, state, previous):
    assert response['status_line'] == 'HTTP/1.1 302 Found' and response['body_utf8'] == ''
    locations = [v for k, v in response['headers'] if k == 'location']
    assert len(locations) == 1
    parsed, expected = urlsplit(locations[0]), urlsplit(redirect)
    assert (parsed.scheme, parsed.netloc, parsed.path, parsed.fragment) == (expected.scheme, expected.netloc, expected.path, '')
    parameters = parse_qs(parsed.query, keep_blank_values=True)
    assert set(parameters) == {'code', 'state'} and parameters['state'] == [state]
    code, = parameters['code']
    assert HEX32.fullmatch(code) and code not in previous
    previous.add(code)
    headers(response, location=locations[0])
    return code


def token_record(root, access, refresh):
    raw = (root / 'mcp-tokens.json').read_bytes()
    assert access.encode() not in raw and refresh.encode() not in raw, 'raw token stored on disk'
    registry = json.loads(raw)
    assert registry['version'] == 2
    records = [record for record in registry['tokens'].values()
               if record['hash'] == hashlib.sha256(access.encode()).hexdigest()]
    assert len(records) == 1
    record, = records
    assert record['refresh_token_hash'] == hashlib.sha256(refresh.encode()).hexdigest()
    assert record['prefix'] == access[:4] and record['agent_name'] == 'oauth'
    assert record['allowed_tools'] == ['*'] and not record.get('revoked', False)
    assert record['label'].startswith('oauth-')
    assert re.fullmatch(r'tok-\d{8}-[0-9a-f]{8}', record['id'])
    return record, registry


def token_pair(response, root, known, client=None, access_ttl=86400, refresh_ttl=2592000):
    assert status(response) == 200
    headers(response, content_type='application/json')
    payload = json.loads(response['body_utf8'])
    assert set(payload) == {'access_token', 'refresh_token', 'token_type', 'expires_in'}
    assert payload['token_type'] == 'Bearer'
    assert type(payload['expires_in']) is int and max(1, access_ttl - 30) <= payload['expires_in'] <= access_ttl
    access, refresh = payload['access_token'], payload['refresh_token']
    assert HEX64.fullmatch(access) and HEX64.fullmatch(refresh)
    assert access != refresh and access not in known and refresh not in known
    known.extend([access, refresh])
    record, registry = token_record(root, access, refresh)
    if client is not None:
        assert record['label'] == 'oauth-' + client[:8]
        created = datetime.fromisoformat(record['created_at'])
        assert abs((datetime.fromisoformat(record['expires_at']) - created).total_seconds() - access_ttl) < .01
        assert abs((datetime.fromisoformat(record['refresh_expires_at']) - created).total_seconds() - refresh_ttl) < .01
    return access, refresh, record, registry


class Server:
    def __init__(self, binary, home, port, process_records, known):
        self.known, self.record = known, {}
        process_records.append(self.record)
        self.child = subprocess.Popen([str(binary), '--quiet', 'mcp', '--bind', '127.0.0.1', '--port', str(port)],
                                      cwd=home, env=isolated(home), stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.capture = ProcessCapture(self.child)
        self.child.stdin.write(b'y\n')
        self.child.stdin.close()
        self.child.stdin = None
        try:
            deadline = time.monotonic() + 30
            while True:
                assert self.child.poll() is None, 'native OAuth CLI exited before listening'
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    assert time.monotonic() < deadline, 'native OAuth CLI never listened'
                    time.sleep(.05)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.child.poll() is None:
            self.child.kill()
        self.child.wait(timeout=15)
        stdout, stderr, complete = self.capture.finish()
        self.record.update(stdout_base64=base64.b64encode(stdout).decode(), stderr_base64=base64.b64encode(stderr).decode(),
                           exit=self.child.returncode, output_capture_complete=complete,
                           output_capture_errors=self.capture.errors, forced_cleanup_not_graceful_evidence=True)
        assert complete
        assert not any(value.encode() in stdout + stderr for value in [SECRET, PASSPHRASE, 'public-wrong-passphrase'] + self.known), 'secret/token in process output'


def observe(implementation, binary, home, port, seeded_tokens, result):
    known = list(seeded_tokens.values())
    codes = set()
    rows, root = result['rows'], home / 'vault'

    def send(name, path, method='POST', body=b'', access=None, agent=None, form=None, semantic=None):
        fields = []
        if form is not None:
            body = urlencode(form).encode()
            fields = [('Content-Type', 'application/x-www-form-urlencoded')]
        data = request(path, port, {}, method=method, body=body, auth=access, agent=agent, headers=fields)
        row = {'case': name, 'semantic_control': semantic, 'request_base64': base64.b64encode(data).decode(),
               'request_sha256': hashlib.sha256(data).hexdigest(), 'response': {},
               'observed_at_start': time.time()}
        rows.append(row)
        row['response'].update(exchange(port, data, row['response']))
        row['observed_at_end'] = time.time()
        assert SECRET not in row['response']['body_utf8'] and PASSPHRASE not in row['response']['body_utf8']
        assert not any(value in row['response']['body_utf8'] for value in known), 'previous token leaked in response'
        return row['response']

    def authorize(name, client, redirect=REDIRECT):
        query = urlencode(dict(response_type='code', client_id=client, redirect_uri=redirect,
                               code_challenge=CHALLENGE, code_challenge_method='S256', state=STATE))
        response = send(name, '/mcp/oauth/authorize?' + query, method='GET', semantic='bound-browser-consent')
        return consent(response, implementation, client, redirect)

    def approve(name, form, redirect=REDIRECT, state=STATE):
        response = send(name, '/mcp/oauth/authorize/confirm', form=dict(form, passphrase=PASSPHRASE, decision='approve'),
                        semantic='fresh-single-use-code')
        return redirect_code(response, redirect, state, codes)

    def grant(name, code, verifier=VERIFIER, good=True, client=None):
        response = send(name, '/mcp/oauth/token', form=dict(grant_type='authorization_code', code=code, code_verifier=verifier),
                        semantic='fresh-scoped-token-pair' if good else None)
        if good:
            return token_pair(response, root, known, client)
        error_response(response, 'invalid_grant')

    def rpc(name, token, payload, expected_status=200, agent='oauth'):
        response = send(name, '/mcp', access=token, agent=agent, body=json.dumps(payload, separators=(',', ':')).encode())
        assert status(response) == expected_status
        if expected_status == 200:
            frame = json.loads(response['body_utf8'])
            assert 'result' in frame and not frame['result'].get('isError'), 'actual authorized MCP handler did not succeed'
            if payload['method'] == 'tools/call':
                assert json.loads(frame['result']['content'][0]['text']) == dict(server='Symaira Vault MCP', status='healthy', transport='http', version='1.0.0')

    initialize = dict(jsonrpc='2.0', id=1, method='initialize', params=dict(protocolVersion='2025-11-25',
                      clientInfo=dict(name='public-oauth-fixture', version='1'), capabilities={}))
    health = dict(jsonrpc='2.0', id=2, method='tools/call', params=dict(name='health', arguments={}))
    server = Server(binary, home, port, result['processes'], known)
    try:
        clients = []
        for name, redirect in [('register-primary', REDIRECT), ('register-secondary', OTHER_REDIRECT)]:
            response = send(name, '/oauth/register', body=json.dumps(dict(redirect_uris=[redirect])).encode(), semantic='fresh-persisted-client')
            assert status(response) == 201
            headers(response, content_type='application/json')
            client = json.loads(response['body_utf8'])
            assert set(client) == {'client_id', 'client_id_issued_at', 'client_secret_expires_at', 'token_endpoint_auth_method',
                                   'grant_types', 'response_types', 'redirect_uris'}
            assert HEX32.fullmatch(client['client_id']) and client['client_id'] not in clients
            clients.append(client['client_id'])
            assert client == dict(client_id=clients[-1], client_id_issued_at=client['client_id_issued_at'], client_secret_expires_at=0,
                                  token_endpoint_auth_method='none', grant_types=['authorization_code', 'refresh_token'], response_types=['code'], redirect_uris=[redirect])
            row = rows[-1]
            assert row['observed_at_start'] - 1 <= client['client_id_issued_at'] <= row['observed_at_end'] + 1
            persisted = json.loads((root / 'mcp-oauth-clients.json').read_bytes())
            assert persisted['version'] == 1 and persisted['clients'][clients[-1]]['client_id'] == clients[-1]
            assert persisted['clients'][clients[-1]]['redirect_uris'] == [redirect]
            result['client_snapshots'].append(persisted)
        primary, secondary = clients
        form = authorize('authorize-primary', primary)
        before = (root / 'mcp-tokens.json').read_bytes()
        wrong = send('consent-wrong-passphrase', '/mcp/oauth/authorize/confirm', form=dict(form, passphrase='public-wrong-passphrase', decision='approve'), semantic='bound-browser-consent')
        retried = consent(wrong, implementation, primary, REDIRECT, wrong=True)
        assert retried == form and (root / 'mcp-tokens.json').read_bytes() == before
        code = approve('consent-approved', form)
        access, refresh, original, registry = grant('code-exchange', code, client=primary)
        result['token_snapshots'].append(registry)
        grant('code-replay', code, good=False)
        rpc('issued-token-initialize', access, initialize)
        rpc('issued-token-health', access, health)
        rpc('issued-token-other-agent-denied', access, health, 403, 'other')
        rotated = send('refresh-rotate', '/mcp/oauth/token', form=dict(grant_type='refresh_token', refresh_token=refresh), semantic='fresh-scoped-token-pair')
        next_access, next_refresh, next_record, registry = token_pair(rotated, root, known)
        assert registry['tokens'][original['id']]['revoked']
        assert next_record['label'] == original['label'] and next_record['agent_name'] == original['agent_name']
        for field in ['expires_at', 'refresh_expires_at']:
            assert abs((datetime.fromisoformat(next_record[field]) - datetime.fromisoformat(original[field])).total_seconds()) < .01
        result['token_snapshots'].append(registry)
        rpc('old-access-after-rotation-denied', access, health, 401)
        replay = send('refresh-replay', '/mcp/oauth/token', form=dict(grant_type='refresh_token', refresh_token=refresh))
        error_response(replay, 'invalid_grant', 'invalid or expired refresh token')
        rpc('rotated-token-initialize', next_access, initialize)
        rpc('rotated-token-health', next_access, health)
        bad_form = authorize('authorize-bad-verifier', primary)
        bad_code = approve('consent-bad-verifier', bad_form)
        before = (root / 'mcp-tokens.json').read_bytes()
        grant('wrong-pkce', bad_code, verifier='public-wrong-verifier', good=False)
        grant('failed-pkce-code-replay', bad_code, good=False)
        assert (root / 'mcp-tokens.json').read_bytes() == before, 'failed PKCE minted a token'
        replay = send('consent-replay', '/mcp/oauth/authorize/confirm', form=dict(form, passphrase=PASSPHRASE, decision='approve'), semantic='single-use-browser-confirmation')
        if implementation == 'go':
            redirect_code(replay, REDIRECT, STATE, codes)
        else:
            error_response(replay, 'invalid_request')
        tamper = authorize('authorize-tamper', primary)
        tampered = dict(tamper, passphrase=PASSPHRASE, decision='approve', client_id=secondary,
                        redirect_uri=OTHER_REDIRECT, state='public-tampered-state', code_challenge='public-tampered-challenge', code_challenge_method='plain')
        response = send('consent-metadata-tamper', '/mcp/oauth/authorize/confirm', form=tampered, semantic='server-bound-consent-metadata')
        if implementation == 'go':
            tamper_code = redirect_code(response, OTHER_REDIRECT, 'public-tampered-state', codes)
        else:
            tamper_code = redirect_code(response, REDIRECT, STATE, codes)
        grant('tampered-consent-original-pkce', tamper_code, good=implementation == 'rust', client=primary)
        rows[-1]['semantic_control'] = 'server-bound-consent-pkce'
        denied_form = authorize('authorize-denial', primary)
        before = (root / 'mcp-tokens.json').read_bytes()
        denied = send('browser-denied', '/mcp/oauth/authorize/confirm', form=dict(denied_form, decision='deny'), semantic='server-side-consent-denial')
        if implementation == 'go':
            consent(denied, implementation, primary, REDIRECT)
            assert 'Passphrase is required.' in denied['body_utf8']
        else:
            assert status(denied) == 302 and denied['body_utf8'] == ''
            location, = [v for k, v in denied['headers'] if k == 'location']
            assert location == REDIRECT + '?' + urlencode(dict(error='access_denied', state=STATE))
            headers(denied, location=location)
        assert (root / 'mcp-tokens.json').read_bytes() == before, 'denial minted tokens'
        pending = authorize('authorize-before-restart', primary)
        pending_code = approve('consent-before-restart', pending)
        result['state_before_restart'] = vault_snapshot(root)
        server.close()
        assert vault_snapshot(root) == result['state_before_restart']
        server = Server(binary, home, port, result['processes'], known)
        grant('unpersisted-code-after-restart', pending_code, good=False)
        authorize('persisted-client-after-restart', primary)
        rpc('persisted-token-initialize', next_access, initialize)
        rpc('persisted-token-health', next_access, health)
        response = send('persisted-refresh-rotate', '/mcp/oauth/token', form=dict(grant_type='refresh_token', refresh_token=next_refresh), semantic='fresh-scoped-token-pair')
        final_access, final_refresh, final_record, registry = token_pair(response, root, known)
        assert registry['tokens'][next_record['id']]['revoked']
        result['token_snapshots'].append(registry)
        rpc('persisted-old-access-denied', next_access, health, 401)
        rpc('persisted-rotated-token-initialize', final_access, initialize)
        rpc('persisted-rotated-token-health', final_access, health)
        assert final_record['label'] == original['label']
        result.update(codes=sorted(codes), token_sha256=[hashlib.sha256(t.encode()).hexdigest() for t in known],
                      final_snapshot=vault_snapshot(root))
    finally:
        server.close()


def observe_ttl(implementation, binary, home, port, seeded_tokens, result):
    """Observe actual configured expiration and renewal, using real elapsed time."""
    known = list(seeded_tokens.values())
    root, rows = home / 'vault', result['ttl_rows']
    server = Server(binary, home, port, result['processes'], known)

    def send(name, path, method='POST', body=b'', form=None, access=None, semantic=None):
        fields = []
        if form is not None:
            body = urlencode(form).encode()
            fields.append(('Content-Type', 'application/x-www-form-urlencoded'))
        data = request(path, port, {}, method=method, body=body, auth=access, agent='oauth' if access else None, headers=fields)
        row = dict(case=name, semantic_control=semantic, request_sha256=hashlib.sha256(data).hexdigest(),
                   request_base64=base64.b64encode(data).decode(), response={})
        rows.append(row)
        row['response'].update(exchange(port, data, row['response']))
        assert not any(value in row['response']['body_utf8'] for value in [SECRET, PASSPHRASE] + known)
        return row['response']

    initialize = dict(jsonrpc='2.0', id=1, method='initialize', params=dict(protocolVersion='2025-11-25',
                      clientInfo=dict(name='public-oauth-fixture', version='1'), capabilities={}))
    health = dict(jsonrpc='2.0', id=2, method='tools/call', params=dict(name='health', arguments={}))
    try:
        response = send('ttl-register', '/oauth/register', body=json.dumps(dict(redirect_uris=[REDIRECT])).encode(), semantic='fresh-persisted-client')
        assert status(response) == 201
        headers(response, content_type='application/json')
        client = json.loads(response['body_utf8'])['client_id']
        assert HEX32.fullmatch(client)
        query = urlencode(dict(response_type='code', client_id=client, redirect_uri=REDIRECT, state=STATE,
                               code_challenge=CHALLENGE, code_challenge_method='S256'))
        response = send('ttl-authorize', '/mcp/oauth/authorize?' + query, method='GET', semantic='bound-browser-consent')
        form = consent(response, implementation, client, REDIRECT)
        response = send('ttl-consent', '/mcp/oauth/authorize/confirm', form=dict(form, passphrase=PASSPHRASE, decision='approve'), semantic='fresh-single-use-code')
        code = redirect_code(response, REDIRECT, STATE, set())
        response = send('ttl-code-exchange', '/mcp/oauth/token', form=dict(grant_type='authorization_code', code=code, code_verifier=VERIFIER), semantic='configured-positive-token-ttls')
        access, refresh, record, registry = token_pair(response, root, known, client, 2, 60)
        result['ttl_token_snapshots'].append(registry)
        for name, payload in [('ttl-token-initialize', initialize), ('ttl-token-health', health)]:
            response = send(name, '/mcp', access=access, body=json.dumps(payload, separators=(',', ':')).encode())
            assert status(response) == 200 and 'result' in json.loads(response['body_utf8'])
            assert not json.loads(response['body_utf8'])['result'].get('isError')
            if payload['method'] == 'tools/call':
                assert json.loads(json.loads(response['body_utf8'])['result']['content'][0]['text'])['status'] == 'healthy'
        expiry = datetime.fromisoformat(record['expires_at']).timestamp()
        waiting = time.monotonic()
        while time.time() <= expiry + .05:
            assert time.monotonic() - waiting < 5, 'configured two-second token did not reach real expiry'
            time.sleep(.02)
        response = send('ttl-expired-access-denied', '/mcp', access=access, body=json.dumps(health, separators=(',', ':')).encode())
        assert status(response) == 401
        response = send('ttl-refresh-after-access-expiry', '/mcp/oauth/token', form=dict(grant_type='refresh_token', refresh_token=refresh), semantic='bounded-refresh-after-access-expiry')
        if implementation == 'go':
            error_response(response, 'invalid_grant', 'invalid or expired refresh token')
            renewed = access
        else:
            renewed, new_refresh, new_record, registry = token_pair(response, root, known, access_ttl=2, refresh_ttl=60)
            created = datetime.fromisoformat(new_record['created_at'])
            assert abs((datetime.fromisoformat(new_record['expires_at']) - created).total_seconds() - 2) < .01
            assert datetime.fromisoformat(new_record['refresh_expires_at']) == datetime.fromisoformat(record['refresh_expires_at'])
            assert registry['tokens'][record['id']]['revoked']
            result['ttl_token_snapshots'].append(registry)
        for name, payload in [('ttl-renewed-token-initialize', initialize), ('ttl-renewed-token-health', health)]:
            response = send(name, '/mcp', access=renewed, body=json.dumps(payload, separators=(',', ':')).encode(), semantic='bounded-refreshed-runtime-control')
            assert status(response) == (401 if implementation == 'go' else 200)
            if implementation == 'rust':
                frame = json.loads(response['body_utf8'])
                assert 'result' in frame and not frame['result'].get('isError')
                if payload['method'] == 'tools/call':
                    assert json.loads(frame['result']['content'][0]['text'])['status'] == 'healthy'
        response = send('ttl-old-access-still-denied', '/mcp', access=access, body=json.dumps(health, separators=(',', ':')).encode())
        assert status(response) == 401
        result['ttl_final_snapshot'] = vault_snapshot(root)
    finally:
        server.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--allow-dirty-for-development', action='store_true')
    args = parser.parse_args()
    clean = not checked(['git', 'status', '--porcelain=v1']).strip()
    assert clean or args.allow_dirty_for_development
    rust = args.rust.resolve()
    paths = sorted(p for p in checked(['git', 'ls-files', '--cached', '--others', '--exclude-standard']).decode().splitlines()
                   if p.startswith(('crates/', 'third_party/', 'testdata/', 'internal/mcp/apitemplates/builtin/', 'scripts/rust-port/'))
                   or p in {'Cargo.toml', 'Cargo.lock', '.gitattributes', '.github/workflows/rust-http-oauth.yml'})
    result = dict(passed=False, candidate_commit=checked(['git', 'rev-parse', 'HEAD']).decode().strip(), candidate_worktree_clean=clean,
                  candidate_source_files=paths, candidate_source_digest=inventory(paths, ROOT), oracle_commit=ORACLE,
                  native_os=platform.system(), architecture=platform.machine(), rust_binary_sha256=hashlib.sha256(rust.read_bytes()).hexdigest(),
                  driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), seed_probe_sha256=hashlib.sha256(PROBE.read_bytes()).hexdigest(),
                  go=dict(rows=[], ttl_rows=[], processes=[], client_snapshots=[], token_snapshots=[], ttl_token_snapshots=[]),
                  rust=dict(rows=[], ttl_rows=[], processes=[], client_snapshots=[], token_snapshots=[], ttl_token_snapshots=[]), differences=[], semantic_controls=[])
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-http-oauth-') as raw:
            base = Path(raw)
            tree = base / 'oracle'
            checked(['git', 'worktree', 'add', '--detach', tree, ORACLE])
            try:
                files = checked(['git', 'ls-tree', '-r', '--name-only', ORACLE]).decode().splitlines()
                sources = sorted(p for p in files if p in {'go.mod', 'go.sum'} or p.endswith('.go') and not p.endswith('_test.go'))
                embedded = sorted(p for p in files if p.startswith('internal/mcp/apitemplates/builtin/'))
                assert len(embedded) == 17
                result.update(oracle_source_files=sources, oracle_source_digest=inventory(sources, tree),
                              oracle_embedded_files=embedded, oracle_embedded_digest=inventory(embedded, tree))
                helper = tree / 'scripts/rust-port/cmd/httpoauthseed'
                helper.mkdir()
                (helper / 'main.go').write_bytes(PROBE.read_bytes())
                suffix = '.exe' if os.name == 'nt' else ''
                go, seed = base / ('go-cli' + suffix), base / ('go-seed' + suffix)
                checked(['go', 'build', '-trimpath', '-buildvcs=false', '-o', go, '.'], tree)
                checked(['go', 'build', '-trimpath', '-buildvcs=false', '-o', seed, './scripts/rust-port/cmd/httpoauthseed'], tree)
                result.update(go_binary_sha256=hashlib.sha256(go.read_bytes()).hexdigest(), seed_binary_sha256=hashlib.sha256(seed.read_bytes()).hexdigest())
                seed_home = base / 'seed'
                seed_home.mkdir()
                tokens = json.loads(checked([seed, '--root', seed_home / 'vault'], seed_home, isolated(seed_home)))
                snapshot = vault_snapshot(seed_home / 'vault')
                result['fixture_snapshot'] = snapshot
                with socket.socket() as selection:
                    selection.bind(('127.0.0.1', 0))
                    port = selection.getsockname()[1]
                result['port'] = port
                for implementation, binary in [('go', go), ('rust', rust)]:
                    home = base / implementation
                    home.mkdir()
                    shutil.copytree(seed_home / 'vault', home / 'vault')
                    assert vault_snapshot(home / 'vault') == snapshot
                    observe(implementation, binary, home, port, tokens, result[implementation])
                ttl_seed = base / 'ttl-seed'
                ttl_seed.mkdir()
                ttl_tokens = json.loads(checked([seed, '--root', ttl_seed / 'vault', '--access-ttl', '2s', '--refresh-ttl', '1m'], ttl_seed, isolated(ttl_seed)))
                ttl_snapshot = vault_snapshot(ttl_seed / 'vault')
                result['ttl_fixture_snapshot'] = ttl_snapshot
                for implementation, binary in [('go', go), ('rust', rust)]:
                    home = base / (implementation + '-ttl')
                    home.mkdir()
                    shutil.copytree(ttl_seed / 'vault', home / 'vault')
                    assert vault_snapshot(home / 'vault') == ttl_snapshot
                    observe_ttl(implementation, binary, home, port, ttl_tokens, result[implementation])
                for implementation in ['go', 'rust']:
                    assert len(result[implementation]['rows']) == 35 and len(result[implementation]['ttl_rows']) == 11
                    assert len(result[implementation]['processes']) == 3 and all(p['output_capture_complete'] for p in result[implementation]['processes'])
                assert set(result['go']['codes']).isdisjoint(result['rust']['codes']), 'independent real code entropy'
                assert set(result['go']['token_sha256'][len(tokens):]).isdisjoint(result['rust']['token_sha256'][len(tokens):]), 'independent real token entropy'
                assert set(result['go']['client_snapshots'][-1]['clients']).isdisjoint(result['rust']['client_snapshots'][-1]['clients']), 'independent real client entropy'
                left = result['go']['rows'] + result['go']['ttl_rows']
                right = result['rust']['rows'] + result['rust']['ttl_rows']
                for a, b in zip(left, right, strict=True):
                    assert a['case'] == b['case'] and a['semantic_control'] == b['semantic_control']
                    if a['semantic_control'] is not None:
                        result['semantic_controls'].append(dict(case=a['case'], decision=a['semantic_control']))
                    elif any(a['response'][k] != b['response'][k] for k in ['status_line', 'headers_without_date', 'body_base64', 'wire_body_base64']):
                        result['differences'].append(dict(case=a['case'], go=a['response'], rust=b['response']))
                assert not result['differences'], 'unexpected actual OAuth HTTP difference retained'
                assert inventory(paths, ROOT) == result['candidate_source_digest']
                assert checked(['git', 'rev-parse', 'HEAD']).decode().strip() == result['candidate_commit']
                assert hashlib.sha256(rust.read_bytes()).hexdigest() == result['rust_binary_sha256']
                result['candidate_worktree_clean_at_end'] = not checked(['git', 'status', '--porcelain=v1']).strip()
                assert result['candidate_worktree_clean_at_end'] or args.allow_dirty_for_development
                result['passed'] = True
            finally:
                checked(['git', 'worktree', 'remove', '--force', tree])
    finally:
        args.receipt.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(f"PASS: {len(result['go']['rows']) + len(result['go']['ttl_rows'])} actual OAuth HTTP cases per implementation and three owned process lifetimes on {platform.system()}")


if __name__ == '__main__':
    main()
