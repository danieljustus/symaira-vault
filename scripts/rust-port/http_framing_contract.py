#!/usr/bin/env python3
"""Actual native request framing and bounded chunked-body process contracts."""
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
from http_head_contract import parse_response
from http_oauth_contract import PASSPHRASE, PROBE, Server
from http_process_contract import SECRET, request
from mcp_process_contract import ORACLE, ROOT, checked, inventory, isolated, vault_snapshot

PING=b'{"jsonrpc":"2.0","id":2,"method":"ping"}'
INITIALIZE=b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"public-framing-fixture","version":"1"},"capabilities":{}}}'
PING_BODY=b'{"jsonrpc":"2.0","id":2,"result":{}}\n'
JSON_ERROR=b'{"error":{"message":"invalid JSON","code":-32700},"jsonrpc":"2.0"}\n'
PLAIN_ERROR=b'bad request\n'


def policy(name):
    if name.startswith('chunked-sensitive-trailer-'):
        return 200,PING_BODY,400,PLAIN_ERROR,'security-metadata-stays-in-headers'
    if name in {'chunked-invalid-size','chunked-signed-size','chunked-negative-size','chunked-size-overflow'}:
        return 400,JSON_ERROR,400,PLAIN_ERROR,'framing-validation-before-dispatch'
    if name in {'chunked-missing-body-crlf','chunked-truncated','chunked-missing-final-chunk','chunked-partial-final-header','chunked-missing-trailer-terminator'}:
        return 200,PING_BODY,400,PLAIN_ERROR,'complete-chunk-frame-required'
    if name=='chunked-length-ambiguity':
        return 200,PING_BODY,400,PLAIN_ERROR,'one-request-length-required'
    if name=='chunked-http10':
        return 400,JSON_ERROR,400,PLAIN_ERROR,'chunked-requires-http11'
    return None


def assert_response(response,status,body,version='HTTP/1.1'):
    reason={200:'OK',400:'Bad Request',413:'Request Entity Too Large'}[status]
    assert response['status_line']==f'{version} {status} {reason}', 'actual framing-control status'
    assert base64.b64decode(response['body_base64'])==body, 'complete framing-control entity'
    mime='text/plain; charset=utf-8' if body==PLAIN_ERROR else 'application/json'
    fields=[('content-length',str(len(body))),('content-type',mime)]
    if version=='HTTP/1.1':fields.append(('connection','close'))
    if mime.startswith('text/plain'):fields.append(('x-content-type-options','nosniff'))
    assert response['headers_without_date']==sorted(fields), 'complete framing-control header multiset'


def chunked(port,tokens,body,headers=(),keep_length=False,version='HTTP/1.1'):
    data=request('/mcp',port,tokens,body=b'',headers=[('Transfer-Encoding','chunked')]+list(headers))
    if not keep_length:
        data=data.replace(b'Content-Length: 0\r\n',b'',1)
    data=data.replace(b'HTTP/1.1\r\n',version.encode()+b'\r\n',1)
    return data+body


def encoded(body,extension=b''):
    return format(len(body),'x').encode()+extension+b'\r\n'+body+b'\r\n0\r\n\r\n'


def cases(port,tokens):
    exact=b' '*(1024*1024-len(PING))+PING
    return [
        ('initialize',request('/mcp',port,tokens,body=INITIALIZE)),
        ('length-ping',request('/mcp',port,tokens,body=PING)),
        ('length-http10-ping',request('/mcp',port,tokens,body=PING).replace(b'HTTP/1.1\r\n',b'HTTP/1.0\r\n',1)),
        ('length-http10-invalid-json',request('/mcp',port,tokens,body=b'{').replace(b'HTTP/1.1\r\n',b'HTTP/1.0\r\n',1)),
        ('chunked-ping',chunked(port,tokens,encoded(PING))),
        ('chunked-bytewise',chunked(port,tokens,b''.join(encoded(bytes([byte]))[:-5] for byte in PING)+b'0\r\n\r\n')),
        ('chunked-uppercase-hex',chunked(port,tokens,format(len(PING),'X').encode()+b'\r\n'+PING+b'\r\n0\r\n\r\n')),
        ('chunked-extension',chunked(port,tokens,encoded(PING,b';public=fixture'))),
        ('chunked-quoted-extension',chunked(port,tokens,encoded(PING,b';public="fixture value"'))),
        ('chunked-empty-extension',chunked(port,tokens,encoded(PING,b';'))),
        ('chunked-trailer',chunked(port,tokens,encoded(PING)[:-2]+b'X-Public-Test: fixture\r\n\r\n')),
        ('chunked-declared-trailer',chunked(port,tokens,encoded(PING)[:-2]+b'X-Public-Test: fixture\r\n\r\n',[('Trailer','X-Public-Test')])),
        *[('chunked-sensitive-trailer-'+name.lower(),chunked(port,tokens,encoded(PING)[:-2]+name.encode()+b': public-invalid-fixture\r\n\r\n'))
          for name in ['Host','Authorization','Origin','X-Symaira-Agent','Content-Length','Transfer-Encoding','X-Enroll-Proof']],
        ('chunked-invalid-size',chunked(port,tokens,b'xx\r\n'+PING+b'\r\n0\r\n\r\n')),
        ('chunked-signed-size',chunked(port,tokens,b'+25\r\n'+PING+b'\r\n0\r\n\r\n')),
        ('chunked-negative-size',chunked(port,tokens,b'-1\r\n'+PING+b'\r\n0\r\n\r\n')),
        ('chunked-size-overflow',chunked(port,tokens,b'10000000000000000\r\n')),
        ('chunked-missing-body-crlf',chunked(port,tokens,format(len(PING),'x').encode()+b'\r\n'+PING+b'XX0\r\n\r\n')),
        ('chunked-truncated',chunked(port,tokens,format(len(PING)+1,'x').encode()+b'\r\n'+PING)),
        ('chunked-missing-final-chunk',chunked(port,tokens,encoded(PING)[:-5])),
        ('chunked-partial-final-header',chunked(port,tokens,encoded(PING)[:-5]+b'0\r')),
        ('chunked-missing-trailer-terminator',chunked(port,tokens,encoded(PING)[:-2])),
        ('chunked-length-ambiguity',chunked(port,tokens,encoded(PING),keep_length=True)),
        ('chunked-http10',chunked(port,tokens,encoded(PING),version='HTTP/1.0')),
        ('chunked-exact-limit',chunked(port,tokens,encoded(exact))),
        ('chunked-over-limit',chunked(port,tokens,encoded(b' '+exact))),
        ('recovery-ping',request('/mcp',port,tokens,body=PING)),
    ]


def exchange(port,data,retained):
    raw=bytearray()
    try:
        with socket.create_connection(('127.0.0.1',port),timeout=15) as stream:
            try:
                stream.sendall(data)
                stream.shutdown(socket.SHUT_WR)
            except (ConnectionResetError,ConnectionAbortedError,BrokenPipeError):
                retained['send_reset']=True
            while True:
                try:
                    part=stream.recv(65536)
                except (ConnectionResetError,ConnectionAbortedError):
                    retained['receive_reset']=True
                    break
                if not part:
                    break
                raw+=part
                assert len(raw)<8*1024*1024
        response=parse_response(raw)
        lengths=[v for k,v in response['headers'] if k=='content-length']
        transfers=[v for k,v in response['headers'] if k=='transfer-encoding']
        assert not transfers, 'small framing responses must not be chunked'
        if lengths:
            assert len(lengths)==1 and int(lengths[0])==len(base64.b64decode(response['body_base64']))
        else:
            assert ('connection','close') in response['headers']
        return response
    finally:
        retained['raw_base64']=base64.b64encode(raw).decode()


def pipeline(port,tokens,retained):
    first=chunked(port,tokens,encoded(PING),[('Trailer','X-Public-Test')])
    first=first[:-2]+b'X-Public-Test: fixture\r\n\r\n'
    first=first.replace(b'Connection: close\r\n',b'Connection: keep-alive\r\n',1)
    second=request('/.well-known/oauth-protected-resource',port,tokens,method='GET',auth=None,agent=None)
    data=first+second
    retained.update(request_sha256=hashlib.sha256(data).hexdigest(),request_base64=base64.b64encode(data).decode(),responses=[])
    observed=bytearray()
    try:
        with socket.create_connection(('127.0.0.1',port),timeout=5) as stream:
            stream.sendall(data)
            with stream.makefile('rb') as reader:
                for _ in range(2):
                    raw=bytearray()
                    for _ in range(64):
                        line=reader.readline(8192)
                        observed+=line;raw+=line
                        assert line and line.endswith(b'\r\n'), 'complete chunk/GET pipeline header'
                        if line==b'\r\n':break
                    else:
                        raise AssertionError('pipeline header bound')
                    fields=parse_response(raw)['headers']
                    length,=[v for k,v in fields if k=='content-length']
                    body=reader.read(int(length))
                    observed+=body;raw+=body
                    assert len(body)==int(length), 'complete chunk/GET pipeline entity'
                    retained['responses'].append(parse_response(raw))
                extra=reader.read()
                observed+=extra
                assert not extra, 'unexpected bytes after framed pipeline'
    finally:
        retained['raw_base64']=base64.b64encode(observed).decode()
    assert len(retained['responses'])==2 and all(r['status_line']=='HTTP/1.1 200 OK' for r in retained['responses'])
    assert base64.b64decode(retained['responses'][0]['body_base64'])==PING_BODY
    assert json.loads(base64.b64decode(retained['responses'][1]['body_base64']))['resource'].endswith('/mcp')


def observe(binary,home,port,tokens,result):
    known=[SECRET,PASSPHRASE]+list(tokens.values())
    server=Server(binary,home,port,result['processes'],list(tokens.values()))
    try:
        for name,data in cases(port,tokens):
            row=dict(case=name,request_sha256=hashlib.sha256(data).hexdigest(),request_base64=base64.b64encode(data).decode(),response={})
            result['rows'].append(row)
            response=row['response']
            response.update(exchange(port,data,response))
            assert not any(value.encode() in base64.b64decode(response['raw_base64']) for value in known), 'secret/token in response'
            if name in ['initialize','length-ping','recovery-ping']:
                assert response['status_line']=='HTTP/1.1 200 OK'
                assert 'result' in json.loads(base64.b64decode(response['body_base64']))
        pipeline(port,tokens,result['pipeline'])
        assert not any(value.encode() in base64.b64decode(result['pipeline']['raw_base64']) for value in known)
    finally:
        server.close()


def declared_difference(name,left,right):
    decision=policy(name)
    if decision is None:return None
    go_status,go_body,rust_status,rust_body,label=decision
    version='HTTP/1.0' if name=='chunked-http10' else 'HTTP/1.1'
    assert_response(left,go_status,go_body,version)
    assert_response(right,rust_status,rust_body,version)
    return label


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
                   or p in {'Cargo.toml','Cargo.lock','.gitattributes','.github/workflows/rust-http-framing.yml'})
    receipt = dict(passed=False, candidate_commit=checked(['git','rev-parse','HEAD']).decode().strip(),
                   candidate_worktree_clean=clean, candidate_sources=inventory(paths,ROOT), native_os=platform.system(),
                   architecture=platform.machine(), rust_binary_sha256=hashlib.sha256(rust.read_bytes()).hexdigest(), oracle_commit=ORACLE,
                   go=dict(rows=[], processes=[], pipeline={}), rust=dict(rows=[], processes=[], pipeline={}), differences=[], declared_differences=[])
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-http-framing-') as raw:
            base, tree = Path(raw), Path(raw)/'oracle'
            checked(['git','worktree','add','--detach',tree,ORACLE])
            try:
                files = checked(['git','ls-tree','-r','--name-only',ORACLE]).decode().splitlines()
                sources = sorted(p for p in files if p in {'go.mod','go.sum'} or p.endswith('.go') and not p.endswith('_test.go'))
                embedded = sorted(p for p in files if p.startswith('internal/mcp/apitemplates/builtin/'))
                assert len(embedded)==17
                receipt.update(oracle_sources=inventory(sources,tree), oracle_embedded=inventory(embedded,tree), seed_probe_sha256=hashlib.sha256(PROBE.read_bytes()).hexdigest())
                helper = tree/'scripts/rust-port/cmd/httpframingseed'
                helper.mkdir()
                (helper/'main.go').write_bytes(PROBE.read_bytes())
                suffix = '.exe' if os.name=='nt' else ''
                go,seed = base/('go-cli'+suffix),base/('go-seed'+suffix)
                checked(['go','build','-trimpath','-buildvcs=false','-o',go,'.'],tree)
                checked(['go','build','-trimpath','-buildvcs=false','-o',seed,'./scripts/rust-port/cmd/httpframingseed'],tree)
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
                    for row in receipt[implementation]['rows']:
                        name,response=row['case'],row['response']
                        decision=policy(name)
                        if decision:
                            status,body=decision[:2] if implementation=='go' else decision[2:4]
                            assert_response(response,status,body,'HTTP/1.0' if name=='chunked-http10' else 'HTTP/1.1')
                        elif name=='chunked-over-limit':
                            assert_response(response,413,b'{"error":{"message":"request body too large","code":-32700},"jsonrpc":"2.0"}\n')
                        elif name=='length-http10-invalid-json':
                            assert_response(response,400,JSON_ERROR,'HTTP/1.0')
                        elif name!='initialize':
                            assert_response(response,200,PING_BODY,'HTTP/1.0' if name=='length-http10-ping' else 'HTTP/1.1')
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
                expected_count=len(cases(receipt['port'],{}))
                assert len(receipt['go']['rows'])==len(receipt['rust']['rows'])==expected_count
                assert len(receipt['declared_differences'])==18
                assert receipt['go']['pipeline']['request_sha256']==receipt['rust']['pipeline']['request_sha256']
                for a,b in zip(receipt['go']['pipeline']['responses'],receipt['rust']['pipeline']['responses'],strict=True):
                    assert all(a[k]==b[k] for k in ['status_line','headers_without_date','body_base64'])
                assert inventory(paths,ROOT)==receipt['candidate_sources']
                assert checked(['git','rev-parse','HEAD']).decode().strip()==receipt['candidate_commit']
                assert hashlib.sha256(rust.read_bytes()).hexdigest()==receipt['rust_binary_sha256']
                receipt['candidate_worktree_clean_at_end']=not checked(['git','status','--porcelain=v1']).strip()
                assert receipt['candidate_worktree_clean_at_end'] or args.allow_dirty_for_development
                assert not receipt['differences'], 'actual undeclared HTTP framing differences retained'
                receipt['passed']=True
            finally:
                checked(['git','worktree','remove','--force',tree])
    finally:
        args.receipt.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print(f"PASS: {expected_count} actual framing responses per implementation on {platform.system()}")


if __name__=='__main__':
    main()
