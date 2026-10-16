#!/usr/bin/env python3
"""Actual native HTTP Host/Origin validation, including real authenticated calls."""
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

sys.dont_write_bytecode = True
from http_head_contract import exchange
from http_oauth_contract import PASSPHRASE, PROBE, Server
from http_process_contract import SECRET, request
from mcp_process_contract import ORACLE, ROOT, checked, inventory, isolated, vault_snapshot


ORIGINS = [
    ('missing', None), ('empty', ''), ('null', 'null'),
    ('bind', 'http://127.0.0.1:{port}'), ('bind-https', 'https://127.0.0.1:{port}'),
    ('bind-other-port', 'http://127.0.0.1:49179'), ('bind-no-port', 'http://127.0.0.1'),
    ('localhost', 'http://localhost:{port}'), ('localhost-uppercase', 'https://LOCALHOST:{port}'),
    ('scheme-uppercase', 'HTTP://localhost:{port}'),
    ('ipv4-loopback-range', 'http://127.2.3.4:49179'), ('ipv6', 'http://[::1]:{port}'),
    ('ipv6-other-port', 'https://[::1]:49179'), ('ipv6-no-port', 'http://[::1]'),
    ('mapped-loopback', 'http://[::ffff:127.0.0.1]:{port}'),
    ('ipv4-private', 'http://192.168.1.1:{port}'), ('ipv6-private', 'http://[fd00::1]:{port}'),
    ('foreign', 'https://foreign.example'), ('localhost-suffix', 'http://localhost.foreign.example'),
    ('localhost-dot', 'http://localhost.'), ('foreign-userinfo', 'http://localhost@foreign.example'),
    ('loopback-userinfo', 'http://foreign.example@localhost'),
    ('loopback-path', 'http://localhost/path'), ('loopback-query', 'http://localhost?public=fixture'),
    ('loopback-fragment', 'http://localhost#public'), ('ftp', 'ftp://localhost:{port}'),
    ('ipv6-suffix', 'http://[::1]public'), ('ipv6-nonnumeric-port', 'http://[::1]:public'),
    ('ipv6-empty-port', 'http://[::1]:'), ('ipv6-zero-port', 'http://[::1]:0'),
    ('ipv6-overflow-port', 'http://[::1]:65536'), ('bracketed-ipv4', 'http://[127.0.0.1]:{port}'),
    ('ipv6-signed-port', 'http://[::1]:+80'), ('ipv6-negative-port', 'http://[::1]:-1'),
    ('ipv6-missing-bracket', 'http://[::1'), ('unbracketed-ipv6', 'http://::1'),
    ('localhost-empty-port', 'http://localhost:'), ('localhost-zero-port', 'http://localhost:0'),
    ('localhost-overflow-port', 'http://localhost:65536'), ('localhost-nonnumeric-port', 'http://localhost:public'),
    ('localhost-signed-port', 'http://localhost:+80'), ('localhost-negative-port', 'http://localhost:-1'),
    ('localhost-percent', 'http://local%68ost'), ('invalid-percent', 'http://%'),
    ('localhost-backslash', 'http://localhost\\public'), ('multiple-origins', 'http://localhost http://127.0.0.1'),
    ('origin-whitespace', ' \thttp://localhost:{port}\t '),
]

HOSTS = [
    ('bind', '127.0.0.1:{port}'), ('localhost', 'localhost:{port}'),
    ('localhost-uppercase', 'LOCALHOST:{port}'), ('ipv4-loopback-range', '127.2.3.4:49179'),
    ('ipv6', '[::1]:{port}'), ('ipv6-no-port', '[::1]'),
    ('mapped-loopback', '[::ffff:127.0.0.1]:{port}'),
    ('foreign', 'foreign.example'), ('private', '192.168.1.1'),
    ('ipv6-suffix', '[::1]public'), ('ipv6-nonnumeric-port', '[::1]:public'),
    ('ipv6-empty-port', '[::1]:'), ('ipv6-zero-port', '[::1]:0'),
    ('ipv6-overflow-port', '[::1]:65536'), ('bracketed-ipv4', '[127.0.0.1]:{port}'),
    ('ipv6-signed-port', '[::1]:+80'), ('ipv6-negative-port', '[::1]:-1'),
    ('localhost-empty-port', 'localhost:'), ('localhost-zero-port', 'localhost:0'),
    ('localhost-overflow-port', 'localhost:65536'), ('localhost-nonnumeric-port', 'localhost:public'),
    ('localhost-signed-port', 'localhost:+80'), ('localhost-negative-port', 'localhost:-1'),
]

RUST_ALLOWED_ORIGINS = {
    'missing', 'empty', 'bind', 'bind-https', 'bind-other-port', 'bind-no-port',
    'localhost', 'localhost-uppercase', 'scheme-uppercase', 'ipv4-loopback-range',
    'ipv6', 'ipv6-other-port', 'ipv6-no-port', 'mapped-loopback', 'origin-whitespace',
}
GO_ALLOWED_ORIGINS = RUST_ALLOWED_ORIGINS | {
    'loopback-userinfo', 'loopback-path', 'loopback-query', 'loopback-fragment', 'ftp',
    'ipv6-empty-port', 'ipv6-zero-port', 'ipv6-overflow-port',
    'localhost-empty-port', 'localhost-zero-port', 'localhost-overflow-port',
}
RUST_ALLOWED_HOSTS = {
    'bind', 'localhost', 'localhost-uppercase', 'ipv4-loopback-range',
    'ipv6', 'ipv6-no-port', 'mapped-loopback',
}


def expected_cases(implementation):
    result = {}
    for name, _ in ORIGINS:
        allowed = name in (GO_ALLOWED_ORIGINS if implementation=='go' else RUST_ALLOWED_ORIGINS)
        for suffix, status in [('authenticated',200), ('unauthenticated',401), ('oauth',400)]:
            result['origin-'+name+'-'+suffix] = status if allowed else 403
    for name, _ in HOSTS:
        allowed = implementation=='go' or name in RUST_ALLOWED_HOSTS
        for suffix, status in [('authenticated',200), ('unauthenticated',401)]:
            result['host-'+name+'-'+suffix] = status if allowed else 403
    for name in ['foreign','private']:
        for suffix, status in [('authenticated',200), ('unauthenticated',401)]:
            result['host-origin-'+name+'-'+suffix] = status if implementation=='go' else 403
    result['recovery-ping'] = 200
    return result


def assert_validation_response(response, status):
    reason, body, mime = {
        200: ('OK', b'{"jsonrpc":"2.0","id":2,"result":{}}\n', 'application/json'),
        401: ('Unauthorized', b'unauthorized\n', 'text/plain; charset=utf-8'),
        400: ('Bad Request', b'{"error":"invalid_redirect_uri"}\n', 'application/json'),
        403: ('Forbidden', b'{"error":{"message":"invalid Origin header","code":-32600},"jsonrpc":"2.0"}\n', 'application/json'),
    }[status]
    assert response['status_line']==f'HTTP/1.1 {status} {reason}', 'actual boundary status'
    assert base64.b64decode(response['body_base64'])==body, 'complete boundary response entity'
    expected = [('connection','close'), ('content-length',str(len(body))), ('content-type',mime)]
    if status==401:
        expected.append(('x-content-type-options','nosniff'))
    assert response['headers_without_date']==sorted(expected), 'complete boundary header multiset'


def validate_framing(response):
    body = base64.b64decode(response['body_base64'])
    lengths = [value for name, value in response['headers'] if name == 'content-length']
    transfers = [value for name, value in response['headers'] if name == 'transfer-encoding']
    assert not transfers, 'small boundary responses must not use chunked framing'
    if lengths:
        assert len(lengths) == 1 and int(lengths[0]) == len(body), 'complete declared response entity'
    else:
        assert ('connection', 'close') in response['headers'], 'EOF-framed parser rejection must close'


def observe(binary, home, port, tokens, result):
    known = [SECRET, PASSPHRASE] + list(tokens.values())
    server = Server(binary, home, port, result['processes'], list(tokens.values()))
    ping = b'{"jsonrpc":"2.0","id":2,"method":"ping"}'
    initialize = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"public-origin-fixture","version":"1"},"capabilities":{}}}'

    def send(name, path, body, fields=(), auth='full', agent='fixture', method='POST'):
        data = request(path, port, tokens, body=body, headers=fields, auth=auth, agent=agent, method=method)
        if any(key.lower()=='host' for key,_ in fields):
            data=data.replace(f'Host: 127.0.0.1:{port}\r\n'.encode(), b'', 1)
        assert sum(line.lower().startswith(b'host:') for line in data.split(b'\r\n\r\n',1)[0].split(b'\r\n'))==1, 'one actual Host override'
        row = dict(case=name, request_sha256=hashlib.sha256(data).hexdigest(),
                   request_base64=base64.b64encode(data).decode(), response={})
        result['rows'].append(row)
        response = row['response']
        response.update(exchange(port, data, response))
        validate_framing(response)
        assert not any(value.encode() in base64.b64decode(response['raw_base64']) for value in known), 'secret/token in boundary response'
        return response

    try:
        response = send('initialize', '/mcp', initialize)
        assert response['status_line'] == 'HTTP/1.1 200 OK'
        assert 'result' in json.loads(base64.b64decode(response['body_base64']))
        for name, origin in ORIGINS:
            fields = [] if origin is None else [('Origin', origin.format(port=port))]
            send('origin-'+name+'-authenticated', '/mcp', ping, fields)
            send('origin-'+name+'-unauthenticated', '/mcp', ping, fields, auth=None)
            send('origin-'+name+'-oauth', '/oauth/register', b'{}', fields, auth=None, agent=None)
        for name, host in HOSTS:
            fields = [('Host', host.format(port=port))]
            send('host-'+name+'-authenticated', '/mcp', ping, fields)
            send('host-'+name+'-unauthenticated', '/mcp', ping, fields, auth=None)
        for name, host in [('foreign','foreign.example'), ('private','192.168.1.1')]:
            fields=[('Host',host),('Origin','https://'+host)]
            send('host-origin-'+name+'-authenticated', '/mcp', ping, fields)
            send('host-origin-'+name+'-unauthenticated', '/mcp', ping, fields, auth=None)
        for name, origin in [('foreign', 'https://foreign.example'), ('malformed', 'http://%'), ('loopback-path', 'http://localhost/path')]:
            for route, method in [('/.well-known/oauth-protected-resource', 'GET'), ('/.well-known/oauth-authorization-server', 'GET'), ('/public-missing', 'GET')]:
                response = send('public-'+name+'-'+route, route, b'', [('Origin', origin)], auth=None, agent=None, method=method)
                assert int(response['status_line'].split()[1]) == (404 if route=='/public-missing' else 200)
        send('recovery-ping', '/mcp', ping)
    finally:
        server.close()


def declared_difference(name, left, right):
    go, rust = expected_cases('go'), expected_cases('rust')
    if name not in go or go[name]==rust[name]:
        return None
    assert_validation_response(left,go[name])
    assert_validation_response(right,rust[name])
    if name.startswith('origin-') and any(name=='origin-'+key+'-'+suffix for key in ['loopback-userinfo','loopback-path','loopback-query','loopback-fragment','ftp'] for suffix in ['authenticated','unauthenticated','oauth']):
        return 'serialized-http-origin-required'
    if any(name==prefix+key+'-'+suffix for prefix in ['host-','host-origin-'] for key in ['foreign','private'] for suffix in ['authenticated','unauthenticated']):
        return 'loopback-host-required'
    return 'valid-loopback-authority-required'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rust', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--allow-dirty-for-development', action='store_true')
    args = parser.parse_args()
    clean = not checked(['git','status','--porcelain=v1']).strip()
    assert clean or args.allow_dirty_for_development
    rust = args.rust.resolve()
    paths = sorted(p for p in checked(['git','ls-files','--cached','--others','--exclude-standard']).decode().splitlines()
                   if p.startswith(('crates/','third_party/','testdata/','scripts/rust-port/','internal/mcp/apitemplates/builtin/'))
                   or p in {'Cargo.toml','Cargo.lock','.gitattributes','.github/workflows/rust-http-origin.yml'})
    receipt = dict(passed=False, candidate_commit=checked(['git','rev-parse','HEAD']).decode().strip(),
                   candidate_worktree_clean=clean, candidate_sources=inventory(paths,ROOT), native_os=platform.system(),
                   architecture=platform.machine(), rust_binary_sha256=hashlib.sha256(rust.read_bytes()).hexdigest(), oracle_commit=ORACLE,
                   go=dict(rows=[], processes=[]), rust=dict(rows=[], processes=[]), differences=[], declared_differences=[])
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-http-origin-') as raw:
            base, tree = Path(raw), Path(raw)/'oracle'
            checked(['git','worktree','add','--detach',tree,ORACLE])
            try:
                files = checked(['git','ls-tree','-r','--name-only',ORACLE]).decode().splitlines()
                sources = sorted(p for p in files if p in {'go.mod','go.sum'} or p.endswith('.go') and not p.endswith('_test.go'))
                embedded = sorted(p for p in files if p.startswith('internal/mcp/apitemplates/builtin/'))
                assert len(embedded)==17
                receipt.update(oracle_sources=inventory(sources,tree), oracle_embedded=inventory(embedded,tree), seed_probe_sha256=hashlib.sha256(PROBE.read_bytes()).hexdigest())
                helper = tree/'scripts/rust-port/cmd/httporiginseed'
                helper.mkdir()
                (helper/'main.go').write_bytes(PROBE.read_bytes())
                suffix = '.exe' if os.name=='nt' else ''
                go,seed = base/('go-cli'+suffix),base/('go-seed'+suffix)
                checked(['go','build','-trimpath','-buildvcs=false','-o',go,'.'],tree)
                checked(['go','build','-trimpath','-buildvcs=false','-o',seed,'./scripts/rust-port/cmd/httporiginseed'],tree)
                receipt.update(go_binary_sha256=hashlib.sha256(go.read_bytes()).hexdigest(),seed_binary_sha256=hashlib.sha256(seed.read_bytes()).hexdigest())
                seed_home=base/'seed';seed_home.mkdir()
                tokens=json.loads(checked([seed,'--root',seed_home/'vault'],seed_home,isolated(seed_home)))
                snapshot=vault_snapshot(seed_home/'vault');receipt['fixture_snapshot']=snapshot
                with socket.socket() as selection:
                    selection.bind(('127.0.0.1',0));port=selection.getsockname()[1]
                receipt['port']=port
                for implementation,binary in [('go',go),('rust',rust)]:
                    home=base/implementation;home.mkdir();shutil.copytree(seed_home/'vault',home/'vault')
                    assert vault_snapshot(home/'vault')==snapshot
                    observe(binary,home,port,tokens,receipt[implementation])
                for implementation in ['go','rust']:
                    expected=expected_cases(implementation)
                    for row in receipt[implementation]['rows']:
                        if row['case'] in expected:
                            assert_validation_response(row['response'],expected[row['case']])
                for a,b in zip(receipt['go']['rows'],receipt['rust']['rows'],strict=True):
                    assert a['case']==b['case'] and a['request_sha256']==b['request_sha256']
                    left,right=a['response'],b['response']
                    if any(left[k]!=right[k] for k in ['status_line','headers_without_date','body_base64']):
                        difference=dict(case=a['case'],go=left,rust=right)
                        declared=declared_difference(a['case'],left,right)
                        if declared:
                            receipt['declared_differences'].append(dict(difference,decision=declared))
                        else:
                            receipt['differences'].append(difference)
                expected_count=2+3*len(ORIGINS)+2*len(HOSTS)+9+4
                assert len(receipt['go']['rows'])==len(receipt['rust']['rows'])==expected_count
                assert len(receipt['declared_differences'])==69
                assert {d['decision'] for d in receipt['declared_differences']}=={
                    'serialized-http-origin-required','loopback-host-required','valid-loopback-authority-required'}
                assert inventory(paths,ROOT)==receipt['candidate_sources']
                assert checked(['git','rev-parse','HEAD']).decode().strip()==receipt['candidate_commit']
                assert hashlib.sha256(rust.read_bytes()).hexdigest()==receipt['rust_binary_sha256']
                receipt['candidate_worktree_clean_at_end']=not checked(['git','status','--porcelain=v1']).strip()
                assert receipt['candidate_worktree_clean_at_end'] or args.allow_dirty_for_development
                assert not receipt['differences'], 'actual undeclared Host/Origin differences retained'
                receipt['passed']=True
            finally:
                checked(['git','worktree','remove','--force',tree])
    finally:
        args.receipt.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print(f"PASS: {expected_count} actual Host/Origin responses per implementation on {platform.system()}")


if __name__=='__main__':
    main()
