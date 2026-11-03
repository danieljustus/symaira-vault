#!/usr/bin/env python3
"""Actual native HEAD responses and a HEAD/GET keep-alive boundary."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import sys
import tempfile
import time
from urllib.parse import urlencode

sys.dont_write_bytecode = True
from http_oauth_contract import CHALLENGE, HEX32, PASSPHRASE, PROBE, REDIRECT, STATE, Server, consent, headers
from http_process_contract import SECRET, request
from mcp_process_contract import (ORACLE, ROOT, add_capture_arguments, capture_arguments_ok, checked, go_capture_session,
                                  inventory, isolated, load_go_observations, pinned_seed, provenance, replay_seed,
                                  save_go_observations, scrub_parts, vault_snapshot)

CONTRACT='http-head'
PORT=28102  # fixed so request bytes (Host header) are identical in capture and replay
NORMALIZATION=['fixed loopback port','seed vault and tokens pinned in the file','Date header, log timestamps, peer ports',
               'per-run OAuth entropy (client id, issued-at, consent flow) replaced by same-length placeholders; the 13 compared rows and the pipeline stay byte-exact']
ENTROPY_PARTS=('registration','client_id','client_snapshot','authorization_heads','browser_control')


def parse_response(raw):
    head, body = raw.split(b'\r\n\r\n', 1)
    lines = head.decode('latin1').split('\r\n')
    fields = [(k.lower(), v.strip()) for k, v in (line.split(':', 1) for line in lines[1:])]
    return dict(status_line=lines[0], headers=fields, headers_without_date=sorted((k,v) for k,v in fields if k!='date'),
                body_base64=base64.b64encode(body).decode(), raw_base64=base64.b64encode(raw).decode())


def exchange(port, data, retained, timeout=5):
    raw = bytearray()
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=timeout) as stream:
            stream.sendall(data)
            while True:
                part = stream.recv(4096)
                if not part:
                    break
                raw += part
                assert len(raw) < 1024*1024
        return parse_response(raw)
    finally:
        retained['raw_base64'] = base64.b64encode(raw).decode()


def pipeline(port, tokens, retained):
    head = request('/.well-known/oauth-protected-resource', port, tokens, method='HEAD', auth=None, agent=None)
    head = head.replace(b'Connection: close\r\n', b'Connection: keep-alive\r\n', 1)
    get = request('/.well-known/oauth-protected-resource', port, tokens, method='GET', auth=None, agent=None)
    data = head + get
    retained.update(request_sha256=hashlib.sha256(data).hexdigest(), request_base64=base64.b64encode(data).decode(), responses=[])
    observed = bytearray()
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=5) as stream:
            stream.sendall(data)
            with stream.makefile('rb') as reader:
                for is_head in [True, False]:
                    raw = bytearray()
                    for _ in range(64):
                        line = reader.readline(8192)
                        observed += line
                        raw += line
                        assert line and line.endswith(b'\r\n'), 'complete pipeline response header'
                        if line == b'\r\n':
                            break
                    else:
                        raise AssertionError('pipeline header bound')
                    fields = parse_response(raw)['headers']
                    length, = [v for k, v in fields if k == 'content-length']
                    if not is_head:
                        body = reader.read(int(length))
                        observed += body
                        raw += body
                        assert len(body) == int(length), 'complete subsequent GET body'
                    retained['responses'].append(parse_response(raw))
                extra = reader.read()
                observed += extra
                assert not extra, 'HEAD body bytes leaked into later exchange'
    finally:
        retained['raw_base64'] = base64.b64encode(observed).decode()
    assert len(retained['responses']) == 2
    assert all(r['status_line'] == 'HTTP/1.1 200 OK' for r in retained['responses'])
    assert not base64.b64decode(retained['responses'][0]['body_base64'])
    assert json.loads(base64.b64decode(retained['responses'][1]['body_base64']))['resource'].endswith('/mcp')


def observe(binary, home, port, tokens, result):
    known = [SECRET, PASSPHRASE] + list(tokens.values())
    server = Server(binary, home, port, result['processes'], list(tokens.values()))
    try:
        cases = [
            ('resource-head', '/.well-known/oauth-protected-resource', None, None, ()),
            ('resource-query-head', '/.well-known/oauth-protected-resource?public=fixture', None, None, ()),
            ('authorization-discovery-head', '/.well-known/oauth-authorization-server', None, None, ()),
            ('unknown-head', '/public-missing', None, None, ()),
            ('unknown-foreign-origin-head', '/public-missing', None, None, [('Origin','https://foreign.example')]),
            ('mcp-authenticated-head', '/mcp', 'full', 'fixture', ()),
            ('mcp-missing-bearer-head', '/mcp', None, 'fixture', ()),
            ('mcp-invalid-bearer-head', '/mcp', 'public-invalid-token', 'fixture', ()),
            ('mcp-missing-agent-head', '/mcp', 'full', None, ()),
            ('mcp-foreign-origin-head', '/mcp', None, None, [('Origin','https://foreign.example')]),
            ('register-head', '/oauth/register', None, None, ()),
            ('authorize-invalid-head', '/mcp/oauth/authorize', None, None, ()),
            ('token-head', '/mcp/oauth/token', None, None, ()),
        ]
        for name, path, auth, agent, fields in cases:
            data = request(path, port, tokens, method='HEAD', auth=auth, agent=agent, headers=fields)
            row = dict(case=name, request_sha256=hashlib.sha256(data).hexdigest(),
                       request_base64=base64.b64encode(data).decode(), response={})
            result['rows'].append(row)
            row['response'].update(exchange(port, data, row['response']))
        pipeline(port, tokens, result['pipeline'])
        # HEAD inspection must leave the bounded browser-ticket store
        # available for a real subsequent browser authorization GET.
        data = request('/oauth/register', port, {}, body=json.dumps(dict(redirect_uris=[REDIRECT])).encode(), auth=None, agent=None)
        result['registration'] = dict(request_base64=base64.b64encode(data).decode(), observed_at_start=time.time())
        result['registration'].update(exchange(port, data, result['registration']))
        result['registration']['observed_at_end'] = time.time()
        response = result['registration']
        assert response['status_line'] == 'HTTP/1.1 201 Created'
        metadata = json.loads(base64.b64decode(response['body_base64']))
        client = metadata['client_id']
        assert HEX32.fullmatch(client)
        assert metadata == dict(client_id=client, client_id_issued_at=metadata['client_id_issued_at'],
                                client_secret_expires_at=0, token_endpoint_auth_method='none',
                                grant_types=['authorization_code', 'refresh_token'], response_types=['code'],
                                redirect_uris=[REDIRECT])
        assert response['observed_at_start']-1 <= metadata['client_id_issued_at'] <= response['observed_at_end']+1
        headers(response, content_type='application/json')
        result['client_id'] = client
        persisted = json.loads((home/'vault'/'mcp-oauth-clients.json').read_bytes())
        assert persisted['version'] == 1 and persisted['clients'][client]['redirect_uris'] == [REDIRECT]
        result['client_snapshot'] = persisted
        unchanged_tokens = (home/'vault'/'mcp-tokens.json').read_bytes()
        query = urlencode(dict(response_type='code',client_id=client,redirect_uri=REDIRECT,state=STATE,
                               code_challenge=CHALLENGE,code_challenge_method='S256'))
        for index in range(512):
            data = request('/mcp/oauth/authorize?'+query,port,{},method='HEAD',auth=None,agent=None)
            row = dict(index=index, request_sha256=hashlib.sha256(data).hexdigest(),
                       request_base64=base64.b64encode(data).decode(), response={})
            result['authorization_heads'].append(row)
            row['response'].update(exchange(port,data,row['response']))
            assert row['response']['status_line']=='HTTP/1.1 200 OK'
            assert not base64.b64decode(row['response']['body_base64'])
            expected=[('connection','close'),('content-type','text/html; charset=utf-8')]
            if result['implementation']=='rust':expected.append(('cache-control','no-store'))
            assert row['response']['headers_without_date']==sorted(expected), 'complete consent HEAD header multiset'
        data=request('/mcp/oauth/authorize?'+query,port,{},method='GET',auth=None,agent=None)
        assert (home/'vault'/'mcp-tokens.json').read_bytes()==unchanged_tokens, 'HEAD must not issue tokens'
        result['browser_control']=dict(request_base64=base64.b64encode(data).decode())
        result['browser_control'].update(exchange(port,data,result['browser_control']))
        response=result['browser_control']
        body=base64.b64decode(response['body_base64'])
        transfers=[v for k,v in response['headers'] if k=='transfer-encoding']
        response['wire_body_base64']=response['body_base64']
        if transfers:
            assert transfers==['chunked']
            entity=bytearray()
            while True:
                line,body=body.split(b'\r\n',1)
                length=int(line,16)
                if length==0:
                    assert body==b'\r\n'
                    break
                assert body[length:length+2]==b'\r\n'
                entity+=body[:length];body=body[length+2:]
            body=bytes(entity)
            response['body_base64']=base64.b64encode(body).decode()
        response['body_utf8']=body.decode('utf-8')
        consent(response,result['implementation'],client,REDIRECT)
        assert (home/'vault'/'mcp-tokens.json').read_bytes()==unchanged_tokens, 'browser GET must await consent'
        responses = [r['response'] for r in result['rows'] + result['authorization_heads']]
        responses += result['pipeline']['responses'] + [result['registration'], result['browser_control']]
        assert all(not any(value.encode() in base64.b64decode(r['raw_base64']) for value in known) for r in responses), 'secret/token in unrelated response'
    finally:
        server.close()


def capture(args):
    """Go half only: build the oracle, observe it, write the committed observations."""
    with go_capture_session(CONTRACT, args, {'seed': ('httpheadseed', PROBE.read_bytes())}) as session:
        base = session['base']
        tokens = pinned_seed(session, 'main', base / 'seed',
                             lambda home: json.loads(checked([session['helpers']['seed'], '--root', home / 'vault'], home, isolated(home))))
        snapshot = vault_snapshot(base / 'seed/vault')
        result = dict(implementation='go', rows=[], processes=[], pipeline={}, authorization_heads=[])
        home = base / 'go'
        home.mkdir()
        shutil.copytree(base / 'seed/vault', home / 'vault')
        assert vault_snapshot(home / 'vault') == snapshot
        observe(session['go'], home, PORT, tokens, result)
        for row in result['authorization_heads']:
            row['request_base64'] = ''  # 512 near-identical requests; only the status/header multiset is compared
        scrub_parts(result, ENTROPY_PARTS)
        data = dict(info=dict(session['info'], seed_probe_sha256=hashlib.sha256(PROBE.read_bytes()).hexdigest()),
                    port=PORT, fixture_snapshot=snapshot, seeds=session['seeds'], go=result)
        path = save_go_observations(CONTRACT, data, {}, NORMALIZATION, session['go_version'])
    print(f'CAPTURED: {len(result["rows"])} Go HEAD responses -> {path}')


def main():
    parser = argparse.ArgumentParser()
    add_capture_arguments(parser, rust_required=False)
    parser.add_argument('--allow-dirty-for-development', action='store_true')
    args = parser.parse_args()
    if capture_arguments_ok(args):
        return capture(args)
    document = load_go_observations(CONTRACT, {})
    recorded = document['data']
    clean = not checked(['git','status','--porcelain=v1']).strip()
    assert clean or args.allow_dirty_for_development
    rust = args.rust.resolve()
    paths = sorted(p for p in checked(['git','ls-files','--cached','--others','--exclude-standard']).decode().splitlines()
                   if p.startswith(('crates/','third_party/','testdata/','scripts/rust-port/','internal/mcp/apitemplates/builtin/'))
                   or p in {'Cargo.toml','Cargo.lock','.gitattributes','.github/workflows/rust-http-head.yml'})
    receipt = dict(passed=False, candidate_commit=checked(['git','rev-parse','HEAD']).decode().strip(),
                   candidate_worktree_clean=clean, candidate_sources=inventory(paths,ROOT), native_os=platform.system(),
                   architecture=platform.machine(), rust_binary_sha256=hashlib.sha256(rust.read_bytes()).hexdigest(), oracle_commit=ORACLE,
                   go=recorded['go'],
                   rust=dict(implementation='rust', rows=[], processes=[], pipeline={}, authorization_heads=[]), differences=[],
                   go_observations=provenance(document), port=recorded['port'], fixture_snapshot=recorded['fixture_snapshot'],
                   **recorded['info'])
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-http-head-') as raw:
            base = Path(raw)
            seed_home = base/'seed'
            tokens = replay_seed(recorded, 'main', seed_home)
            snapshot = vault_snapshot(seed_home/'vault')
            assert snapshot == receipt['fixture_snapshot'], 'recorded seed vault bytes changed'
            home=base/'rust';home.mkdir();shutil.copytree(seed_home/'vault',home/'vault')
            assert vault_snapshot(home/'vault')==snapshot
            observe(rust,home,receipt['port'],tokens,receipt['rust'])
            for a,b in zip(receipt['go']['rows'],receipt['rust']['rows'],strict=True):
                assert a['case']==b['case'] and a['request_sha256']==b['request_sha256']
                assert not base64.b64decode(a['response']['body_base64']) and not base64.b64decode(b['response']['body_base64']), 'HEAD response must not carry entity bytes'
                if any(a['response'][k]!=b['response'][k] for k in ['status_line','headers_without_date','body_base64']):
                    receipt['differences'].append(dict(case=a['case'],go=a['response'],rust=b['response']))
            assert len(receipt['go']['rows'])==len(receipt['rust']['rows'])==13
            assert all(len(receipt[k]['authorization_heads'])==512 for k in ['go','rust'])
            assert receipt['go']['client_id'] != receipt['rust']['client_id'], 'independent actual issuer entropy'
            assert receipt['go']['pipeline']['request_sha256']==receipt['rust']['pipeline']['request_sha256']
            for a,b in zip(receipt['go']['pipeline']['responses'],receipt['rust']['pipeline']['responses'],strict=True):
                assert all(a[k]==b[k] for k in ['status_line','headers_without_date','body_base64'])
            assert not receipt['differences']
            assert inventory(paths,ROOT)==receipt['candidate_sources']
            assert checked(['git','rev-parse','HEAD']).decode().strip()==receipt['candidate_commit']
            assert hashlib.sha256(rust.read_bytes()).hexdigest()==receipt['rust_binary_sha256']
            receipt['candidate_worktree_clean_at_end']=not checked(['git','status','--porcelain=v1']).strip()
            assert receipt['candidate_worktree_clean_at_end'] or args.allow_dirty_for_development
            receipt['passed']=True
    finally:
        args.receipt.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print(f"PASS: 13 HEAD responses, one HEAD/GET pipeline and 512 authorization HEADs with a real browser recovery per implementation on {platform.system()} (Go side replayed from {receipt['go_observations']['path']})")


if __name__=='__main__':
    main()
