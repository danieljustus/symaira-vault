#!/usr/bin/env python3
"""Actual Go/Rust HTTP CLI responses; only Date is excluded from comparison."""
import argparse
import base64
import hashlib
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
import threading
import time
from urllib.parse import urlencode

sys.dont_write_bytecode = True
from mcp_process_contract import ORACLE, checked, isolated, inventory, vault_snapshot

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT/'scripts/rust-port/http_process_seed.go.txt'
SECRET = 'public-http-secret-729c'


class ProcessCapture:
    """Drain both real pipes throughout the request corpus, with bounded storage."""
    def __init__(self, process):
        self.buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        self.errors = []
        self.workers = []
        for name, pipe in [('stdout', process.stdout), ('stderr', process.stderr)]:
            def drain(name=name, pipe=pipe):
                try:
                    while True:
                        data = os.read(pipe.fileno(), 4096)
                        if not data:
                            break
                        remaining = 1024*1024-len(self.buffers[name])
                        self.buffers[name] += data[:max(0,remaining)]
                        if len(data)>remaining:
                            self.errors.append(name+' exceeds the 1 MiB fixture capture bound')
                            process.kill()
                except Exception as error:
                    self.errors.append(name+': '+type(error).__name__)
                finally:
                    pipe.close()
            worker = threading.Thread(target=drain)
            worker.start()
            self.workers.append(worker)

    def finish(self):
        for worker in self.workers:
            worker.join(timeout=5)
        complete = not self.errors and all(not worker.is_alive() for worker in self.workers)
        return bytes(self.buffers['stdout']), bytes(self.buffers['stderr']), complete


def request(path, port, tokens, method='POST', body=b'', auth='full', agent='fixture', headers=()):
    fields = [('Host',f'127.0.0.1:{port}'),('Connection','close')]
    if auth is not None:
        fields.append(('Authorization','Bearer '+tokens.get(auth,auth)))
    if agent is not None:
        fields.append(('X-Symaira-Agent',agent))
    fields += list(headers)
    if not any(k.lower()=='content-type' for k,v in fields):
        fields.append(('Content-Type','application/json'))
    if not any(k.lower()=='accept' for k,v in fields):
        fields.append(('Accept','application/json, text/event-stream'))
    fields.append(('Content-Length',str(len(body))))
    return (f'{method} {path} HTTP/1.1\r\n'+''.join(f'{k}: {v}\r\n' for k,v in fields)+'\r\n').encode()+body


def exchange(port, data, retained):
    result = bytearray()
    send_reset = False
    with socket.create_connection(('127.0.0.1',port),timeout=15) as connection:
        try:
            try:
                connection.sendall(data)
            except (ConnectionResetError, BrokenPipeError):
                send_reset = True
            while True:
                try:
                    chunk = connection.recv(65536)
                except ConnectionResetError:
                    break
                if not chunk:
                    break
                result += chunk
                assert len(result)<8*1024*1024
        finally:
            # Also preserve actual partial bytes when recv times out or fails.
            retained['raw_base64']=base64.b64encode(result).decode()
            retained['send_reset']=send_reset
    return parse_response(bytes(result), send_reset)


def parse_response(raw, send_reset=False):
    head,body = raw.split(b'\r\n\r\n',1)
    lines = head.decode('latin1').split('\r\n')
    fields = [tuple(line.split(':',1)) for line in lines[1:]]
    fields = [(name.lower(),value.strip()) for name,value in fields]
    wire_body = body
    lengths = [value for name,value in fields if name=='content-length']
    transfers = [value for name,value in fields if name=='transfer-encoding']
    if transfers:
        assert not lengths and transfers==['chunked'], 'unambiguous actual chunk framing'
        chunks = bytearray()
        while True:
            line,body=body.split(b'\r\n',1)
            length=int(line,16)
            if length==0:
                assert body==b'\r\n', 'complete final chunk, no hidden trailers'
                break
            assert len(body)>=length+2 and body[length:length+2]==b'\r\n'
            chunks+=body[:length]
            body=body[length+2:]
        body=bytes(chunks)
    else:
        assert len(lengths)==1 and int(lengths[0])==len(body), 'complete HTTP framing'
    return {'status_line':lines[0],'headers':fields,'headers_without_date':sorted((k,v) for k,v in fields if k!='date'),
            'body_base64':base64.b64encode(body).decode(),'body_utf8':body.decode('utf-8'),
            'raw_base64':base64.b64encode(raw).decode(),'wire_body_base64':base64.b64encode(wire_body).decode(),
            'send_reset':send_reset}


def cases(port,tokens):
    initialize = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"public-fixture","version":"1"},"capabilities":{}}}'
    ping = b'{"jsonrpc":"2.0","id":2,"method":"ping"}'
    health = b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"health","arguments":{}}}'
    tools = b'{"jsonrpc":"2.0","id":4,"method":"tools/list"}'
    metadata = b'{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_entry_metadata","arguments":{"path":"public/fixture"}}}'
    challenge = urlencode({'response_type':'code','client_id':'public-unknown-client',
        'redirect_uri':'http://127.0.0.1:48175/public-callback','code_challenge':'public-pkce-challenge',
        'code_challenge_method':'S256'})
    result = [
        ('resource-discovery',request('/.well-known/oauth-protected-resource',port,tokens,method='GET',auth=None,agent=None)),
        ('authorization-discovery',request('/.well-known/oauth-authorization-server',port,tokens,method='GET',auth=None,agent=None)),
        ('unknown-route',request('/public-missing',port,tokens,method='GET',auth=None,agent=None)),
        ('unknown-route-foreign-origin',request('/public-missing',port,tokens,method='GET',auth=None,agent=None,headers=[('Origin','https://foreign.example')])),
        ('unknown-route-authenticated',request('/public-missing',port,tokens,body=ping)),
        ('resource-discovery-wrong-method',request('/.well-known/oauth-protected-resource',port,tokens,auth=None,agent=None)),
        ('authorization-discovery-wrong-method',request('/.well-known/oauth-authorization-server',port,tokens,auth=None,agent=None)),
        ('missing-bearer',request('/mcp',port,tokens,body=initialize,auth=None)),
        ('invalid-bearer',request('/mcp',port,tokens,body=initialize,auth='public-invalid-http-token')),
        ('expired-bearer',request('/mcp',port,tokens,body=initialize,auth='expired')),
        ('revoked-bearer',request('/mcp',port,tokens,body=initialize,auth='revoked')),
        ('missing-agent',request('/mcp',port,tokens,body=initialize,agent=None)),
        ('mismatched-agent',request('/mcp',port,tokens,body=initialize,agent='other')),
        ('foreign-origin-before-auth',request('/mcp',port,tokens,body=initialize,auth=None,headers=[('Origin','https://foreign.example')])),
        ('loopback-origin',request('/mcp',port,tokens,body=initialize,headers=[('Origin',f'http://127.0.0.1:{port}')])),
        ('mcp-initialize',request('/mcp',port,tokens,body=initialize)),
        ('mcp-ping',request('/mcp',port,tokens,body=ping)),
        ('mcp-query-ping',request('/mcp?public=fixture',port,tokens,body=ping)),
        ('mcp-scoped-before-initialize',request('/mcp',port,tokens,body=health,auth='health')),
        ('mcp-notification',request('/mcp',port,tokens,body=b'{"jsonrpc":"2.0","method":"notifications/initialized"}')),
        ('mcp-sse-get',request('/mcp',port,tokens,method='GET',headers=[('Accept','text/event-stream')])),
        ('mcp-content-type',request('/mcp',port,tokens,body=ping,headers=[('Content-Type','text/plain')])),
        ('mcp-accept-denied',request('/mcp',port,tokens,body=ping,headers=[('Accept','text/html')])),
        ('mcp-accept-missing',request('/mcp',port,tokens,body=ping,headers=[('Accept','')])),
        ('mcp-unsupported-version',request('/mcp',port,tokens,body=ping,headers=[('MCP-Protocol-Version','2099-01-01')])),
        ('mcp-invalid-json',request('/mcp',port,tokens,body=b'{')),
        ('mcp-body-exact-limit',request('/mcp',port,tokens,body=b' '*(1024*1024-len(ping))+ping)),
        ('mcp-body-over-limit',request('/mcp',port,tokens,body=b' '*(1024*1024+1-len(ping))+ping)),
        ('mcp-two-json-objects',request('/mcp',port,tokens,body=ping+b' '+ping)),
        ('mcp-invalid-utf8',request('/mcp',port,tokens,body=b'{"jsonrpc":"2.0","id":2,"method":"ping","extra":"\xff"}')),
        ('mcp-repeated-accept',request('/mcp',port,tokens,body=ping,headers=[('Accept','application/json'),('Accept','text/event-stream')])),
        ('health-token-initialize',request('/mcp',port,tokens,body=initialize,auth='health')),
        ('health-token-call',request('/mcp',port,tokens,body=health,auth='health')),
        ('health-token-list',request('/mcp',port,tokens,body=tools,auth='health')),
        ('metadata-token-initialize',request('/mcp',port,tokens,body=initialize,auth='metadata')),
        ('metadata-token-permitted-call',request('/mcp',port,tokens,body=metadata,auth='metadata')),
        ('metadata-token-health-denied',request('/mcp',port,tokens,body=health,auth='metadata')),
        ('metadata-token-list',request('/mcp',port,tokens,body=tools,auth='metadata')),
        ('full-token-list-after-scoped',request('/mcp',port,tokens,body=tools)),
        ('oauth-register-content-type',request('/oauth/register',port,tokens,body=b'{}',auth=None,agent=None,headers=[('Content-Type','text/plain')])),
        ('oauth-register-no-redirect',request('/oauth/register',port,tokens,body=b'{}',auth=None,agent=None)),
        ('oauth-register-foreign-redirect',request('/oauth/register',port,tokens,body=b'{"redirect_uris":["https://foreign.example/callback"]}',auth=None,agent=None)),
        ('oauth-authorize-invalid',request('/mcp/oauth/authorize',port,tokens,method='GET',auth=None,agent=None)),
        ('oauth-authorize-unsupported-pkce',request('/mcp/oauth/authorize?'+challenge.replace('S256','plain'),port,tokens,method='GET',auth=None,agent=None)),
        ('oauth-authorize-unknown-client',request('/mcp/oauth/authorize?'+challenge,port,tokens,method='GET',auth=None,agent=None)),
        ('oauth-register-wrong-method',request('/oauth/register',port,tokens,method='GET',auth=None,agent=None)),
        ('oauth-foreign-origin',request('/oauth/register',port,tokens,body=b'{}',auth=None,agent=None,headers=[('Origin','https://foreign.example')])),
        ('oauth-token-invalid-grant',request('/mcp/oauth/token',port,tokens,body=b'grant_type=public_invalid',auth=None,agent=None,headers=[('Content-Type','application/x-www-form-urlencoded')])),
        ('oauth-token-missing-refresh',request('/mcp/oauth/token',port,tokens,body=b'grant_type=refresh_token',auth=None,agent=None,headers=[('Content-Type','application/x-www-form-urlencoded')])),
        ('oauth-token-invalid-refresh',request('/mcp/oauth/token',port,tokens,body=b'grant_type=refresh_token&refresh_token=public-invalid-refresh',auth=None,agent=None,headers=[('Content-Type','application/x-www-form-urlencoded')])),
    ]
    return result


def declared_difference(name, left, right):
    if name=='metadata-token-permitted-call':
        bodies=[base64.b64decode(response['body_base64']) for response in [left,right]]
        ids=[]
        for response,body in zip([left,right],bodies,strict=True):
            assert response['status_line']=='HTTP/1.1 200 OK'
            frame=json.loads(body)
            metadata=json.loads(frame['result']['content'][0]['text'])
            assert not frame['result']['isError'] and metadata['has_value']
            marker=re.fullmatch(r'<!-- DATA_([0-9a-f]{16}) label=usage_hint --><!-- /DATA_\1 -->',metadata['usage_hint'])
            assert marker, 'complete paired fresh metadata marker'
            ids.append(marker[1].encode())
            assert body.count(ids[-1])==2
        assert ids[0]!=ids[1], 'independent native marker generation'
        assert bodies[0].replace(ids[0],ids[1])==bodies[1], 'every non-random body byte must agree'
        assert left['headers_without_date']==right['headers_without_date'], 'complete metadata-control header multiset'
        return 'metadata-fresh-marker-semantic-control'
    decisions = {
        'mcp-scoped-before-initialize': ('token-session-isolation',200,
            b'{"jsonrpc":"2.0","id":3,"result":{"content":[{"text":"{\\"server\\":\\"Symaira Vault MCP\\",\\"status\\":\\"healthy\\",\\"transport\\":\\"http\\",\\"version\\":\\"1.0.0\\"}","type":"text"}],"isError":false}}\n',
            200,b'{"error":{"message":"Server not initialized","code":-32000},"jsonrpc":"2.0","id":3}\n','application/json'),
        'mcp-two-json-objects': ('complete-json-body-required',200,
            b'{"jsonrpc":"2.0","id":2,"result":{}}\n',400,
            b'{"error":{"message":"invalid JSON","code":-32700},"jsonrpc":"2.0"}\n','application/json'),
        'mcp-invalid-utf8': ('valid-utf8-required',200,
            b'{"jsonrpc":"2.0","id":2,"result":{}}\n',400,b'bad request\n','text/plain; charset=utf-8'),
    }
    if name not in decisions:
        return None
    decision,go_status,go_body,rust_status,rust_body,rust_mime=decisions[name]
    for observed,status,body,mime in [(left,go_status,go_body,'application/json'),(right,rust_status,rust_body,rust_mime)]:
        reason={200:'OK',400:'Bad Request'}[status]
        assert observed['status_line']==f'HTTP/1.1 {status} {reason}'
        assert base64.b64decode(observed['body_base64'])==body, 'complete declared error envelope'
        headers=[('connection','close'),('content-length',str(len(body))),('content-type',mime)]
        if mime.startswith('text/plain'):
            headers.append(('x-content-type-options','nosniff'))
        assert observed['headers_without_date']==sorted(headers), 'complete declared header multiset'
    return decision


def startup_denials(binary,home,port,tokens,observations):
    for name,data in [('eof',b''),('no',b'n\n'),('blank',b'\n'),('not-affirmative',b'approve\n'),('unterminated-yes',b'y')]:
        child=subprocess.Popen([str(binary),'--quiet','mcp','--bind','127.0.0.1','--port',str(port)],
            cwd=home,env=isolated(home),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        row={'case':name,'input_base64':base64.b64encode(data).decode(),'listener_opened':False}
        observations.append(row)
        child.stdin.write(data);child.stdin.close();child.stdin=None
        try:
            deadline=time.monotonic()+15
            while child.poll() is None:
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1):
                        row['listener_opened']=True
                        break
                except OSError:
                    assert time.monotonic()<deadline, 'unconfirmed native process did not exit'
                    time.sleep(.02)
        finally:
            if child.poll() is None:child.kill()
            stdout,stderr=child.communicate(timeout=15)
            row.update(exit=child.returncode,stdout_base64=base64.b64encode(stdout).decode(),stderr_utf8=stderr.decode('utf-8'))
        assert row['exit']==1 and not row['listener_opened'] and not stdout, 'confirmation must precede listener creation'
        assert b'insecure bind' in stderr and not any(value.encode() in stderr for value in [SECRET]+list(tokens.values()))


def stalled_response_class(row, implementation):
    assert implementation in {'go','rust'}, 'known timeout implementation'
    bounds={'idle-before-request':(4,8),'incomplete-request-body':(9,15)}
    assert row['case'] in bounds, 'known stalled-client case'
    minimum,maximum=bounds[row['case']]
    elapsed=row['elapsed_seconds']
    assert type(elapsed) in {int,float} and minimum<=elapsed<maximum, 'actual bounded transport closure'
    received=base64.b64decode(row['received_base64'],validate=True)
    if not received:
        return 'silent-eof'
    assert implementation=='go' and row['case']=='incomplete-request-body', 'unexpected stalled-client response'
    # Go's equal default read/write deadlines can race after header acquisition.
    # Preserve and validate the complete measured error, never normalize it away.
    response=parse_response(received)
    body=b'{"error":{"message":"invalid JSON","code":-32700},"jsonrpc":"2.0"}\n'
    assert response['status_line']=='HTTP/1.1 400 Bad Request', 'timeout parse-error status'
    assert base64.b64decode(response['body_base64'])==body, 'timeout parse-error body'
    assert response['headers_without_date']==sorted([
        ('connection','close'),('content-length',str(len(body))),('content-type','application/json')
    ]), 'complete timeout parse-error headers'
    dates=[value for name,value in response['headers'] if name=='date']
    assert len(dates)==1 and re.fullmatch(r'[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT',dates[0]), 'one HTTP Date'
    return 'complete-invalid-json-400'


def validate_stalled_observations(receipt):
    for implementation in ['go','rust']:
        rows=receipt[implementation+'_stalled_clients']
        assert [row['case'] for row in rows]==['idle-before-request','incomplete-request-body'], 'exact stalled-case inventory'
        for row in rows:
            assert row['passed'] is True and row['peer_eof'] is True, 'executed successful EOF assertion'
            assert row['response_class']==stalled_response_class(row,implementation), 'derived timeout response class'
    for left,right in zip(receipt['go_stalled_clients'],receipt['rust_stalled_clients'],strict=True):
        assert re.fullmatch(r'[0-9a-f]{64}',left['request_sha256']) and left['request_sha256']==right['request_sha256'], 'same complete stalled request'


def stalled_connections(port,tokens,observations,implementation):
    incomplete=request('/mcp',port,tokens,body=b' '*64)[:-63]
    for name,data in [('idle-before-request',b''),('incomplete-request-body',incomplete)]:
        row={'case':name,'request_sha256':hashlib.sha256(data).hexdigest(),'received_base64':'','peer_eof':False,'passed':False}
        observations.append(row)
        with socket.create_connection(('127.0.0.1',port),timeout=15) as connection:
            started=time.monotonic()
            received=bytearray()
            try:
                connection.sendall(data)
                while True:
                    part=connection.recv(4096)
                    if not part:
                        row['peer_eof']=True
                        break
                    received+=part
                    row['received_base64']=base64.b64encode(received).decode()
                    assert len(received)<65536
            finally:
                row['received_base64']=base64.b64encode(received).decode()
                row['elapsed_seconds']=time.monotonic()-started
        assert row['peer_eof'] is True, 'actual peer EOF, not socket timeout/reset'
        row['response_class']=stalled_response_class(row,implementation)
        row['passed']=True


def observe(binary,home,port,tokens,rows,process_record,transport_rows,implementation):
    process = subprocess.Popen([str(binary),'--quiet','mcp','--bind','127.0.0.1','--port',str(port)],
        cwd=home,env=isolated(home),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    capture = ProcessCapture(process)
    # The actual Go CLI requires explicit consent for configured cleartext.
    # Only disposable, public fixture credentials are served over loopback.
    process.stdin.write(b'y\n')
    process.stdin.close()
    process.stdin = None
    try:
        deadline = time.monotonic()+30
        while True:
            assert process.poll() is None, 'native CLI exited before serving'
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.2):
                    break
            except OSError:
                assert time.monotonic()<deadline,'native CLI never listened'
                time.sleep(.05)
        for name,data in cases(port,tokens):
            row = {'case':name,'request_sha256':hashlib.sha256(data).hexdigest()}
            rows.append(row)
            row['response'] = {}
            row['response'].update(exchange(port,data,row['response']))
            assert SECRET not in row['response']['body_utf8']
            assert not any(token in row['response']['body_utf8'] for token in tokens.values())
        stalled_connections(port,tokens,transport_rows,implementation)
        data=request('/mcp',port,tokens,body=b'{"jsonrpc":"2.0","id":6,"method":"ping"}')
        row={'case':'mcp-ping-after-stalled-clients','request_sha256':hashlib.sha256(data).hexdigest(),'response':{}}
        rows.append(row)
        row['response'].update(exchange(port,data,row['response']))
        assert json.loads(row['response']['body_utf8'])=={'jsonrpc':'2.0','id':6,'result':{}}, 'listener still usable after actual timeouts'
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=15)
        stdout,stderr,complete = capture.finish()
        process_record.update(stdout_base64=base64.b64encode(stdout).decode(),stderr_utf8=stderr.decode('utf-8'),
                              forced_cleanup_not_graceful_evidence=True,exit=process.returncode,
                              output_capture_complete=complete,output_capture_errors=capture.errors)
        assert complete, 'owned stdout/stderr readers did not finish complete bounded capture'
        assert not any(value.encode() in stdout+stderr for value in [SECRET]+list(tokens.values())), 'credential in process output'
    return process_record


def candidate_paths():
    return sorted(p for p in checked(['git','ls-files','--cached','--others','--exclude-standard']).decode().splitlines()
        if p.startswith(('crates/','third_party/','testdata/','internal/mcp/apitemplates/builtin/'))
        or p in {'Cargo.toml','Cargo.lock','.gitattributes','.github/workflows/rust-mcp-http-process.yml',
            'scripts/rust-port/http_process_contract.py','scripts/rust-port/http_process_seed.go.txt',
            'scripts/rust-port/mcp_process_contract.py','scripts/rust-port/test_http_process_contract.py'})


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--allow-dirty-for-development',action='store_true')
    args=parser.parse_args()
    clean=not checked(['git','status','--porcelain=v1']).strip()
    assert clean or args.allow_dirty_for_development
    rust=args.rust.resolve()
    paths=candidate_paths()
    receipt={'passed':False,'candidate_commit':checked(['git','rev-parse','HEAD']).decode().strip(),
        'candidate_worktree_clean':clean,'native_os':platform.system(),'architecture':platform.machine(),
        'candidate_source_files':paths,'candidate_source_digest':inventory(paths,ROOT),
        'oracle_commit':ORACLE,'rust_binary_sha256':hashlib.sha256(rust.read_bytes()).hexdigest(),
        'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'seed_probe_sha256':hashlib.sha256(PROBE.read_bytes()).hexdigest(),'go':[],'rust':[],
        'go_startup_denials':[],'rust_startup_denials':[],'go_stalled_clients':[],'rust_stalled_clients':[],
        'differences':[],'declared_differences':[]}
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-http-process-') as raw:
            base=Path(raw);tree=base/'oracle'
            checked(['git','worktree','add','--detach',tree,ORACLE])
            try:
                files=checked(['git','ls-tree','-r','--name-only',ORACLE]).decode().splitlines()
                sources=sorted(p for p in files if p in {'go.mod','go.sum'} or p.endswith('.go') and not p.endswith('_test.go'))
                embedded=sorted(p for p in files if p.startswith('internal/mcp/apitemplates/builtin/'))
                assert len(embedded)==17
                receipt.update(oracle_source_files=sources,oracle_source_digest=inventory(sources,tree),
                    oracle_embedded_files=embedded,oracle_embedded_digest=inventory(embedded,tree))
                helper=tree/'scripts/rust-port/cmd/httpprocessseed';helper.mkdir()
                (helper/'main.go').write_bytes(PROBE.read_bytes())
                suffix='.exe' if os.name=='nt' else ''
                go,seed=base/('go-cli'+suffix),base/('go-seed'+suffix)
                checked(['go','build','-trimpath','-buildvcs=false','-o',go,'.'],tree)
                checked(['go','build','-trimpath','-buildvcs=false','-o',seed,'./scripts/rust-port/cmd/httpprocessseed'],tree)
                receipt.update(go_binary_sha256=hashlib.sha256(go.read_bytes()).hexdigest(),seed_binary_sha256=hashlib.sha256(seed.read_bytes()).hexdigest())
                seed_home=base/'seed';seed_home.mkdir()
                tokens=json.loads(checked([seed,'--root',seed_home/'vault'],cwd=seed_home,env=isolated(seed_home)))
                snapshot=vault_snapshot(seed_home/'vault');receipt['fixture_snapshot']=snapshot
                with socket.socket() as selection:
                    selection.bind(('127.0.0.1',0));port=selection.getsockname()[1]
                receipt['port']=port
                for implementation,binary in [('go',go),('rust',rust)]:
                    home=base/implementation;home.mkdir();shutil.copytree(seed_home/'vault',home/'vault')
                    assert vault_snapshot(home/'vault')==snapshot
                    receipt[implementation+'_process']={}
                    startup_denials(binary,home,port,tokens,receipt[implementation+'_startup_denials'])
                    observe(binary,home,port,tokens,receipt[implementation],receipt[implementation+'_process'],receipt[implementation+'_stalled_clients'],implementation)
                validate_stalled_observations(receipt)
                for a,b in zip(receipt['go'],receipt['rust'],strict=True):
                    assert a['case']==b['case'] and a['request_sha256']==b['request_sha256']
                    left,right=a['response'],b['response']
                    if any(left[k]!=right[k] for k in ['status_line','headers_without_date','body_base64','wire_body_base64']):
                        difference={'case':a['case'],'go':left,'rust':right}
                        declared=declared_difference(a['case'],left,right)
                        if declared:receipt['declared_differences'].append(dict(difference,decision=declared))
                        else:receipt['differences'].append(difference)
                expected={'mcp-initialize':200,'mcp-ping':200,'mcp-body-exact-limit':200,'mcp-body-over-limit':413,
                    'health-token-call':200,'metadata-token-permitted-call':200,'metadata-token-health-denied':200,
                    'mcp-invalid-json':400,'mcp-repeated-accept':200}
                for implementation in ['go','rust']:
                    responses={r['case']:r['response'] for r in receipt[implementation]}
                    for name,status in expected.items():
                        assert int(responses[name]['status_line'].split()[1])==status, (implementation,name,'positive/negative control')
                    for name in ['mcp-initialize','mcp-ping','health-token-call','metadata-token-permitted-call']:
                        frame=json.loads(responses[name]['body_utf8'])
                        assert 'result' in frame and not frame['result'].get('isError'), 'real successful handler control'
                    denied=json.loads(responses['metadata-token-health-denied']['body_utf8'])
                    assert 'error' in denied or denied['result']['isError'], 'scoped token must deny unauthorized tool'
                assert len(receipt['declared_differences'])==4
                assert receipt['go_startup_denials']==receipt['rust_startup_denials'], 'complete native startup failure bytes'
                assert candidate_paths()==paths and inventory(paths,ROOT)==receipt['candidate_source_digest'], 'candidate changed during actual observations'
                assert checked(['git','rev-parse','HEAD']).decode().strip()==receipt['candidate_commit']
                assert hashlib.sha256(rust.read_bytes()).hexdigest()==receipt['rust_binary_sha256'], 'candidate executable changed'
                if not args.allow_dirty_for_development:
                    assert not checked(['git','status','--porcelain=v1']).strip(), 'candidate became dirty'
                assert not receipt['differences'],'actual HTTP differences retained'
                receipt['passed']=True
            finally:
                checked(['git','worktree','remove','--force',tree])
    finally:
        args.receipt.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print(f"PASS: {len(receipt['go'])} actual Go/Rust HTTP CLI transcripts and five startup denials on {platform.system()}")


if __name__=='__main__':
    main()
