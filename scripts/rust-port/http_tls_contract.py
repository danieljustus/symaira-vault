#!/usr/bin/env python3
"""Actual verified TLS/mTLS CLI exchanges and progressing encrypted records."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
from http_framing_contract import INITIALIZE, JSON_ERROR, PING, PING_BODY, assert_response
from http_head_contract import parse_response
from http_origin_contract import assert_validation_response
from http_oauth_contract import PASSPHRASE, PROBE
from http_process_contract import ProcessCapture, SECRET, request
from mcp_process_contract import ORACLE, ROOT, checked, inventory, isolated, vault_snapshot

IDENTITY = ROOT/'scripts/rust-port/http_tls_identity.go.txt'
FIELDS = ['status_line','headers_without_date','body_base64']


def encoded(data):
    return base64.b64encode(data).decode()


def context(identities,version,client=None,ca='server-ca'):
    result = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    result.minimum_version = result.maximum_version = version
    result.check_hostname = True
    result.verify_mode = ssl.CERT_REQUIRED
    result.load_verify_locations(cafile=identities/(ca+'.pem'))
    if client:
        result.load_cert_chain(identities/(client+'.pem'),identities/(client+'.key'))
    return result


class NativeServer:
    def __init__(self,binary,home,port,identities,mtls,records,known):
        self.known,self.record = known,{}
        records.append(self.record)
        command=[str(binary),'--quiet','mcp','--bind','127.0.0.1','--port',str(port),
                 '--tls-cert',str(identities/'server.pem'),'--tls-key',str(identities/'server.key')]
        if mtls:command += ['--tls-ca',str(identities/'client-ca.pem')]
        self.child=subprocess.Popen(command,cwd=home,env=isolated(home),stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.capture=ProcessCapture(self.child)
        try:
            deadline=time.monotonic()+30
            while True:
                assert self.child.poll() is None,'native TLS CLI exited before listening'
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                except OSError:
                    assert time.monotonic()<deadline,'native TLS CLI never listened'
                    time.sleep(.05)
        except BaseException:
            self.close();raise

    def close(self):
        if self.child.poll() is None:self.child.kill()
        self.child.wait(timeout=15)
        stdout,stderr,complete=self.capture.finish()
        self.record.update(stdout_base64=encoded(stdout),stderr_base64=encoded(stderr),exit=self.child.returncode,
                           output_capture_complete=complete,output_capture_errors=self.capture.errors,
                           forced_cleanup_not_graceful_evidence=True)
        assert complete
        assert not any(value.encode() in stdout+stderr for value in [SECRET,PASSPHRASE]+self.known)


class EmptyTLSResponse(ConnectionError):
    """Actual post-handshake EOF with no HTTP application bytes."""


def exchange(port,data,tls,row,server_name='localhost',head=False):
    observed=bytearray()
    try:
        with socket.create_connection(('127.0.0.1',port),timeout=5) as raw:
            with tls.wrap_socket(raw,server_hostname=server_name) as stream:
                row.update(tls_version=stream.version(),cipher=list(stream.cipher()),
                           server_certificate_sha256=hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest())
                stream.sendall(data)
                while True:
                    part=stream.recv(4096)
                    if not part:
                        row.update(peer_terminal_observed=True,peer_terminal_kind='eof');break
                    observed+=part
                    assert len(observed)<1024*1024
        if not observed:raise EmptyTLSResponse('actual empty TLS peer EOF')
        response=parse_response(observed)
        lengths=[v for k,v in response['headers'] if k=='content-length']
        assert len(lengths)==1 and not any(k=='transfer-encoding' for k,v in response['headers'])
        assert len(base64.b64decode(response['body_base64']))==(0 if head else int(lengths[0]))
        return response
    finally:
        row['received_base64']=encoded(observed)


def denied(port,data,tls,row,server_name='localhost'):
    try:
        row['unexpected_response']=exchange(port,data,tls,row,server_name)
    except (ssl.SSLError,ConnectionResetError,BrokenPipeError,EmptyTLSResponse) as error:
        row.update(rejected=True,error_type=type(error).__name__,error_reason=getattr(error,'reason',None),
                   verification_code=getattr(error,'verify_code',None))
    else:
        row['rejected']=False
    assert row['rejected'],'untrusted TLS identity reached an HTTP response'
    assert not base64.b64decode(row['received_base64']),'denied identity received application bytes'


def encrypted_peer(port,tokens,tls,body,row):
    """Complete verified handshake, then progress within one incomplete record."""
    incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO()
    session=tls.wrap_bio(incoming,outgoing,server_side=False,server_hostname='localhost')
    wire_in,wire_out=bytearray(),bytearray()
    received=bytearray()
    row.update(case='encrypted-body-record' if body else 'encrypted-header-record',sent_record_bytes=0,
               peer_terminal_observed=False,forced_client_close=False,sender_joined=False,tls_read_errors=[])
    with socket.create_connection(('127.0.0.1',port),timeout=.25) as stream:
        def flush():
            part=outgoing.read()
            if part:stream.sendall(part);wire_out.extend(part)
        def receive():
            part=stream.recv(65536)
            if part:incoming.write(part);wire_in.extend(part)
            else:incoming.write_eof()
            return part
        deadline=time.monotonic()+5
        while True:
            assert time.monotonic()<deadline,'TLS handshake bound'
            try:session.do_handshake();flush();break
            except ssl.SSLWantReadError:
                flush()
                try:assert receive(),'TLS handshake EOF'
                except socket.timeout:assert time.monotonic()<deadline,'TLS handshake bound'
        row.update(tls_version=session.version(),server_certificate_sha256=hashlib.sha256(session.getpeercert(binary_form=True)).hexdigest())
        original=request('/mcp',port,tokens,body=b' '*1024)
        prefix=original.split(b'\r\n\r\n',1)[0]
        prefix+=b'\r\n\r\n' if body else b'\r\nX-Public-Slow: '
        row['request_prefix_sha256']=hashlib.sha256(prefix).hexdigest()
        row['request_prefix_base64']=encoded(prefix)
        if body:
            assert session.write(prefix)==len(prefix);flush()
            pending=b' '*1024
        else:pending=prefix+b'x'*1024
        assert session.write(pending)==len(pending)
        record=outgoing.read()
        assert len(record)>1000,'large real encrypted record required'
        row.update(record_length=len(record),record_sha256=hashlib.sha256(record).hexdigest())
        stop=threading.Event()
        started=time.monotonic()
        def sender():
            for byte in record:
                if stop.is_set():return
                try:stream.sendall(bytes([byte]));wire_out.append(byte);row['sent_record_bytes']+=1
                except (OSError,TimeoutError):return
                stop.wait(.2)
        worker=threading.Thread(target=sender);worker.start()
        decrypt_failed=False
        try:
            maximum=12.5 if body else 7.5
            while time.monotonic()-started<maximum:
                try:part=receive()
                except socket.timeout:continue
                except ConnectionResetError:
                    row.update(peer_terminal_observed=True,peer_terminal_kind='connection-reset');break
                if not part:
                    row.update(peer_terminal_observed=True,peer_terminal_kind='eof');break
                if decrypt_failed:continue
                while True:
                    try:
                        plain=session.read(65536)
                        if not plain:break
                        received+=plain;assert len(received)<65536
                    except ssl.SSLWantReadError:break
                    except ssl.SSLZeroReturnError:break
                    except ssl.SSLError as error:
                        row['tls_read_errors'].append(dict(type=type(error).__name__,reason=error.reason,message=str(error)))
                        decrypt_failed=True;break
        finally:
            row['forced_client_close']=not row['peer_terminal_observed']
            row['elapsed_seconds']=time.monotonic()-started
            stop.set();worker.join(timeout=5)
            row['sender_joined']=not worker.is_alive()
            row.update(received_base64=encoded(received),encrypted_received_base64=encoded(wire_in),encrypted_sent_base64=encoded(wire_out))


def packets(port,tokens):
    result=[('initialize',request('/mcp',port,tokens,body=INITIALIZE),200),
            ('ping',request('/mcp',port,tokens,body=PING),200),
            ('missing-bearer',request('/mcp',port,tokens,body=PING,auth=None),401),
            ('invalid-bearer',request('/mcp',port,tokens,body=PING,auth='public-invalid-token'),401),
            ('resource-get',request('/.well-known/oauth-protected-resource',port,tokens,method='GET',auth=None,agent=None),200),
            ('resource-head',request('/.well-known/oauth-protected-resource',port,tokens,method='HEAD',auth=None,agent=None),200),
            ('authorization-discovery',request('/.well-known/oauth-authorization-server',port,tokens,method='GET',auth=None,agent=None),200)]
    for name,origin in [('matching',f'https://127.0.0.1:{port}'),('http',f'http://127.0.0.1:{port}'),
                        ('foreign','https://foreign.example'),('port',f'https://127.0.0.1:{1 if port!=1 else 2}')]:
        result.append(('origin-'+name,request('/mcp',port,tokens,body=PING,headers=[('Origin',origin)]),200 if name=='matching' else 403))
    result.append(('recovery-ping',request('/mcp',port,tokens,body=PING),200))
    return result


def discovery_response(response,name,port,secure):
    authority=('https' if secure else 'http')+f'://127.0.0.1:{port}'
    if name.startswith('resource-'):
        entity=dict(bearer_methods_supported=['header'],resource=authority+'/mcp',resource_name='Symaira Vault MCP Server')
    else:
        entity=dict(authorization_endpoint=authority+'/mcp/oauth/authorize',code_challenge_methods_supported=['S256'],
                    grant_types_supported=['authorization_code','refresh_token'],issuer=authority,
                    registration_endpoint=authority+'/oauth/register',response_types_supported=['code'],
                    token_endpoint=authority+'/mcp/oauth/token',token_endpoint_auth_methods_supported=['none'])
    expected=(json.dumps(entity,sort_keys=True,separators=(',',':'))+'\n').encode()
    assert response['status_line']=='HTTP/1.1 200 OK'
    assert response['headers_without_date']==sorted([('connection','close'),('content-length',str(len(expected))),('content-type','application/json')])
    assert base64.b64decode(response['body_base64'])==(b'' if name.endswith('-head') else expected)


def semantic_control(name,left,right,port):
    if name in {'resource-get','resource-head','authorization-discovery'}:
        discovery_response(left,name,port,False);discovery_response(right,name,port,True)
        return 'https-discovery-on-tls'
    if name in {'origin-http','origin-port'}:
        assert_validation_response(left,200);assert_validation_response(right,403)
        return 'secure-origin-matches-http-authority'
    return None


def observe(implementation,binary,home,port,tokens,identities,profile,result):
    mtls,version=profile.startswith('mtls'),ssl.TLSVersion.TLSv1_2 if profile.endswith('12') else ssl.TLSVersion.TLSv1_3
    trusted=context(identities,version,'client' if mtls else None)
    server=NativeServer(binary,home,port,identities,mtls,result['processes'],list(tokens.values()))
    try:
        data=request('/mcp',port,tokens,body=PING)
        controls=[('wrong-server-name',trusted,'wrong.example'),('untrusted-server',context(identities,version,'client' if mtls else None,'foreign-ca'),'localhost')]
        if mtls:controls += [('missing-client-certificate',context(identities,version),'localhost'),('foreign-client-certificate',context(identities,version,'foreign-client'),'localhost')]
        for name,tls,hostname in controls:
            row=dict(case=name);result['identity_controls'].append(row)
            denied(port,data,tls,row,hostname)
        messages=packets(port,tokens)
        for name,data,status in messages[:-1]:
            if implementation=='go' and name in {'origin-http','origin-port'}:status=200
            row=dict(case=name,request_sha256=hashlib.sha256(data).hexdigest(),request_base64=encoded(data),response={})
            result['rows'].append(row)
            row['response'].update(exchange(port,data,trusted,row,head=name.endswith('-head')))
            assert row['response']['status_line'].split()[1]==str(status),'actual TLS route status'
            if name in {'ping','origin-matching'}:assert base64.b64decode(row['response']['body_base64'])==PING_BODY
        errors=[];workers=[]
        def run(body,row):
            try:encrypted_peer(port,tokens,trusted,body,row)
            except BaseException as error:errors.append(type(error).__name__+': '+str(error))
        for body in [False,True]:
            row={};result['encrypted_peers'].append(row)
            worker=threading.Thread(target=run,args=(body,row));workers.append(worker);worker.start()
        for worker in workers:worker.join(timeout=20)
        result.update(control_workers_joined=all(not worker.is_alive() for worker in workers),control_errors=errors)
        assert result['control_workers_joined'] and not errors
        name,data,status=messages[-1]
        row=dict(case=name,request_sha256=hashlib.sha256(data).hexdigest(),request_base64=encoded(data),response={})
        result['rows'].append(row);row['response'].update(exchange(port,data,trusted,row))
        assert row['response']['status_line']=='HTTP/1.1 200 OK' and base64.b64decode(row['response']['body_base64'])==PING_BODY
        known=[SECRET,PASSPHRASE]+list(tokens.values())
        outputs=[base64.b64decode(row['received_base64']) for row in result['rows']+result['identity_controls']+result['encrypted_peers']]
        assert not any(value.encode() in output for value in known for output in outputs)
    finally:server.close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--allow-dirty-for-development',action='store_true')
    args=parser.parse_args()
    clean=not checked(['git','status','--porcelain=v1']).strip()
    assert clean or args.allow_dirty_for_development
    rust=args.rust.resolve()
    paths=sorted(p for p in checked(['git','ls-files','--cached','--others','--exclude-standard']).decode().splitlines()
                 if p.startswith(('crates/','third_party/','testdata/','scripts/rust-port/','internal/mcp/apitemplates/builtin/'))
                 or p in {'Cargo.toml','Cargo.lock','.gitattributes','.github/workflows/rust-http-tls.yml'})
    profiles=['tls12','tls13','mtls12','mtls13']
    receipt=dict(passed=False,candidate_commit=checked(['git','rev-parse','HEAD']).decode().strip(),candidate_worktree_clean=clean,
                 candidate_sources=inventory(paths,ROOT),native_os=platform.system(),architecture=platform.machine(),
                 rust_binary_sha256=hashlib.sha256(rust.read_bytes()).hexdigest(),oracle_commit=ORACLE,
                 go={},rust={},differences=[],declared_differences=[])
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-http-tls-') as raw:
            base,tree=Path(raw),Path(raw)/'oracle'
            checked(['git','worktree','add','--detach',tree,ORACLE])
            try:
                files=checked(['git','ls-tree','-r','--name-only',ORACLE]).decode().splitlines()
                sources=sorted(p for p in files if p in {'go.mod','go.sum'} or p.endswith('.go') and not p.endswith('_test.go'))
                embedded=sorted(p for p in files if p.startswith('internal/mcp/apitemplates/builtin/'));assert len(embedded)==17
                receipt.update(oracle_sources=inventory(sources,tree),oracle_embedded=inventory(embedded,tree),
                               seed_probe_sha256=hashlib.sha256(PROBE.read_bytes()).hexdigest(),identity_probe_sha256=hashlib.sha256(IDENTITY.read_bytes()).hexdigest())
                seed_source=PROBE.read_bytes()
                assert seed_source.count(b'AllowInsecureBind: true')==1
                seed_source=seed_source.replace(b'AllowInsecureBind: true',b'AllowInsecureBind: false',1)
                receipt['actual_tls_seed_source_sha256']=hashlib.sha256(seed_source).hexdigest()
                for name,source in [('httptlsseed',seed_source),('httptlsidentity',IDENTITY.read_bytes())]:
                    helper=tree/'scripts/rust-port/cmd'/name;helper.mkdir();(helper/'main.go').write_bytes(source)
                suffix='.exe' if os.name=='nt' else ''
                go,seed,identity=[base/(name+suffix) for name in ['go-cli','go-seed','go-identity']]
                checked(['go','build','-trimpath','-buildvcs=false','-o',go,'.'],tree)
                checked(['go','build','-trimpath','-buildvcs=false','-o',seed,'./scripts/rust-port/cmd/httptlsseed'],tree)
                checked(['go','build','-trimpath','-buildvcs=false','-o',identity,'./scripts/rust-port/cmd/httptlsidentity'],tree)
                receipt.update(go_binary_sha256=hashlib.sha256(go.read_bytes()).hexdigest(),seed_binary_sha256=hashlib.sha256(seed.read_bytes()).hexdigest(),identity_binary_sha256=hashlib.sha256(identity.read_bytes()).hexdigest())
                identities=base/'identities'
                receipt['identity_parameters']=json.loads(checked([identity,'--root',identities],base))
                identity_paths=sorted(p.name for p in identities.iterdir())
                receipt['identity_inventory']=inventory(identity_paths,identities)
                server_der=ssl.PEM_cert_to_DER_cert((identities/'server.pem').read_text())
                certificate_sha=hashlib.sha256(server_der).hexdigest();receipt['server_certificate_sha256']=certificate_sha
                if os.name!='nt':
                    assert identities.stat().st_mode&0o777==0o700
                    assert all((identities/p).stat().st_mode&0o777==0o600 for p in identity_paths)
                seed_home=base/'seed';seed_home.mkdir()
                tokens=json.loads(checked([seed,'--root',seed_home/'vault'],seed_home,isolated(seed_home)))
                snapshot=vault_snapshot(seed_home/'vault');receipt['fixture_snapshot']=snapshot
                with socket.socket() as selection:selection.bind(('127.0.0.1',0));port=selection.getsockname()[1]
                receipt['port']=port
                for implementation,binary in [('go',go),('rust',rust)]:
                    for profile in profiles:
                        home=base/(implementation+'-'+profile);home.mkdir();shutil.copytree(seed_home/'vault',home/'vault')
                        assert vault_snapshot(home/'vault')==snapshot
                        result=dict(rows=[],processes=[],identity_controls=[],encrypted_peers=[]);receipt[implementation][profile]=result
                        observe(implementation,binary,home,port,tokens,identities,profile,result)
                for profile in profiles:
                    left,right=receipt['go'][profile],receipt['rust'][profile]
                    assert len(left['rows'])==len(right['rows'])==len(packets(port,{}))==12
                    for a,b in zip(left['rows'],right['rows'],strict=True):
                        assert a['case']==b['case'] and a['request_sha256']==b['request_sha256']
                        decision=semantic_control(a['case'],a['response'],b['response'],port)
                        observation=dict(profile=profile,case=a['case'],go=a['response'],rust=b['response'])
                        if decision:receipt['declared_differences'].append(dict(observation,decision=decision))
                        elif any(a['response'][k]!=b['response'][k] for k in FIELDS):receipt['differences'].append(observation)
                    for implementation in ['go','rust']:
                        observed=receipt[implementation][profile]
                        expected=4 if profile.startswith('mtls') else 2
                        assert len(observed['identity_controls'])==expected and all(r['rejected'] for r in observed['identity_controls'])
                        for row in observed['rows']+observed['encrypted_peers']:
                            assert row['server_certificate_sha256']==certificate_sha
                            assert row['tls_version']==('TLSv1.2' if profile.endswith('12') else 'TLSv1.3')
                        assert len(observed['encrypted_peers'])==2
                        for row in observed['encrypted_peers']:
                            assert row['sent_record_bytes']>=4 and row['sent_record_bytes']<row['record_length']
                            assert row['sender_joined'] and row['peer_terminal_observed'] and not row['forced_client_close'],'progressing encrypted record escaped the absolute read deadline'
                            raw=base64.b64decode(row['received_base64'])
                            if raw:
                                assert implementation=='go' and row['case']=='encrypted-body-record','unexpected expired TLS response bytes'
                                row['response']=parse_response(raw)
                                assert_response(row['response'],400,JSON_ERROR)
                                row['termination']='complete-go-json-error-before-write-deadline'
                            else:row['termination']='actual-empty-eof-or-reset'
                            minimum,maximum=(8,12.5) if row['case']=='encrypted-body-record' else (3.5,7.5)
                            assert minimum<=row['elapsed_seconds']<=maximum
                    for a,b in zip(left['encrypted_peers'],right['encrypted_peers'],strict=True):
                        assert a['case']==b['case'] and a['request_prefix_sha256']==b['request_prefix_sha256']
                assert inventory(identity_paths,identities)==receipt['identity_inventory']
                assert inventory(paths,ROOT)==receipt['candidate_sources']
                assert checked(['git','rev-parse','HEAD']).decode().strip()==receipt['candidate_commit']
                assert hashlib.sha256(rust.read_bytes()).hexdigest()==receipt['rust_binary_sha256']
                receipt['candidate_worktree_clean_at_end']=not checked(['git','status','--porcelain=v1']).strip()
                assert receipt['candidate_worktree_clean_at_end'] or args.allow_dirty_for_development
                assert not receipt['differences'],'actual undeclared live TLS/mTLS differences retained'
                receipt['passed']=True
            finally:checked(['git','worktree','remove','--force',tree])
    finally:args.receipt.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print(f'PASS: 48 verified TLS/mTLS response pairs, 12 identity denials and eight progressing encrypted records per implementation on {platform.system()}')


if __name__=='__main__':main()
