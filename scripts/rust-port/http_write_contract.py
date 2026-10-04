#!/usr/bin/env python3
"""Actual absolute HTTP writes and separate TLS admission against production Go."""
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
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode=True
from http_framing_contract import INITIALIZE, PING, PING_BODY, assert_response
from http_head_contract import parse_response
from http_oauth_contract import PASSPHRASE, PROBE, Server
from http_process_contract import SECRET, request
from http_tls_contract import IDENTITY, NativeServer, context, exchange as tls_exchange
from http_head_contract import exchange as tcp_exchange
from mcp_process_contract import ORACLE, ROOT, checked, inventory, isolated, vault_snapshot

PROFILES=[('tcp-five','5s',None),('tcp-short','1s',None),
          ('tls12-short','1s',ssl.TLSVersion.TLSv1_2),('tls13-short','1s',ssl.TLSVersion.TLSv1_3),
          ('tcp-output','30s',None)]


def handshake_peer(port,tls,row):
    incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO()
    session=tls.wrap_bio(incoming,outgoing,server_side=False,server_hostname='localhost')
    try:session.do_handshake()
    except ssl.SSLWantReadError:pass
    hello=outgoing.read();assert len(hello)>100
    row.update(client_hello_sha256=hashlib.sha256(hello).hexdigest(),client_hello_length=len(hello),
               sent_hello_bytes=5,peer_terminal_observed=False,forced_client_close=False)
    observed=bytearray();stop=threading.Event()
    with socket.create_connection(('127.0.0.1',port),timeout=.2) as stream:
        started=time.monotonic();stream.sendall(hello[:5])
        def sender():
            for byte in hello[5:]:
                if stop.is_set():return
                try:stream.sendall(bytes([byte]));row['sent_hello_bytes']+=1
                except OSError:return
                stop.wait(.15)
        worker=threading.Thread(target=sender);worker.start()
        try:
            while time.monotonic()-started<3:
                try:part=stream.recv(4096)
                except socket.timeout:continue
                except ConnectionResetError:
                    row.update(peer_terminal_observed=True,peer_terminal_kind='connection-reset');break
                if not part:
                    row.update(peer_terminal_observed=True,peer_terminal_kind='eof');break
                observed+=part;assert len(observed)<65536
        finally:
            row.update(elapsed_seconds=time.monotonic()-started,received_base64=base64.b64encode(observed).decode())
            row['forced_client_close']=not row['peer_terminal_observed']
            stop.set();worker.join(timeout=5);row['sender_joined']=not worker.is_alive()


def slow_output(port,tokens,row):
    body=b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_entry_metadata","arguments":{"path":"public/bulk"}}}'
    data=request('/mcp',port,tokens,body=body)
    row.update(request_sha256=hashlib.sha256(data).hexdigest(),request_base64=base64.b64encode(data).decode(),
               peer_terminal_observed=False,forced_client_close=False,slow_read_calls=0,slow_received_bytes=0)
    observed=bytearray()
    with socket.socket() as stream:
        stream.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096);stream.settimeout(.25)
        stream.connect(('127.0.0.1',port));started=time.monotonic();stream.sendall(data)
        def receive(limit):
            try:part=stream.recv(limit)
            except socket.timeout:return None
            except ConnectionResetError:
                row.update(peer_terminal_observed=True,peer_terminal_kind='connection-reset');return b''
            if not part:row.update(peer_terminal_observed=True,peer_terminal_kind='eof')
            return part
        try:
            while time.monotonic()-started<34 and not row['peer_terminal_observed']:
                part=receive(1024)
                if part:
                    observed+=part;row['slow_read_calls']+=1;row['slow_received_bytes']+=len(part)
                    time.sleep(.15)
            row['fast_drain_started_seconds']=time.monotonic()-started
            stream.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,256*1024)
            while not row['peer_terminal_observed'] and time.monotonic()-started<59:
                part=receive(65536)
                if part:observed+=part
                assert len(observed)<40*1024*1024
        finally:
            row.update(elapsed_seconds=time.monotonic()-started,received_base64=base64.b64encode(observed).decode())
            row['forced_client_close']=not row['peer_terminal_observed']
    if observed:
        response=parse_response(observed);row['partial_response']=response
        head,wire=bytes(observed).split(b'\r\n\r\n',1)
        row['declared_chunk_length']=int(wire.split(b'\r\n',1)[0],16)
        row['received_chunk_bytes']=len(wire.split(b'\r\n',1)[1])


def late_body(port,tokens,tls,row):
    data=request('/mcp',port,tokens,body=PING)
    prefix=data[:-16]
    row.update(request_sha256=hashlib.sha256(data).hexdigest(),request_base64=base64.b64encode(data).decode(),
               sent_body_suffix_bytes=0,peer_terminal_observed=False,forced_client_close=False,tls_read_errors=[])
    observed=bytearray()
    started=time.monotonic()
    try:
        with socket.create_connection(('127.0.0.1',port),timeout=5) as raw:
            stream=tls.wrap_socket(raw,server_hostname='localhost') if tls else raw
            try:
                if tls:row.update(tls_version=stream.version(),server_certificate_sha256=hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest())
                started=time.monotonic();stream.sendall(prefix)
                for byte in data[-16:]:
                    time.sleep(.15);stream.sendall(bytes([byte]));row['sent_body_suffix_bytes']+=1
                row['body_completed_seconds']=time.monotonic()-started
                while True:
                    try:part=stream.recv(65536)
                    except ConnectionResetError:
                        row.update(peer_terminal_observed=True,peer_terminal_kind='connection-reset');break
                    except ssl.SSLError as error:
                        row['tls_read_errors'].append(dict(type=type(error).__name__,reason=error.reason,message=str(error)))
                        wire=bytearray()
                        with socket.socket(fileno=stream.detach()) as observer:
                            observer.settimeout(.25);bound=time.monotonic()+3
                            while time.monotonic()<bound:
                                try:part=observer.recv(65536)
                                except socket.timeout:continue
                                except ConnectionResetError:
                                    row.update(peer_terminal_observed=True,peer_terminal_kind='connection-reset');break
                                if not part:
                                    row.update(peer_terminal_observed=True,peer_terminal_kind='eof');break
                                wire+=part;assert len(wire)<65536
                        row['post_tls_error_wire_base64']=base64.b64encode(wire).decode()
                        break
                    if not part:
                        row.update(peer_terminal_observed=True,peer_terminal_kind='eof');break
                    observed+=part;assert len(observed)<65536
            finally:
                if stream is not raw:stream.close()
    finally:
        row.update(elapsed_seconds=time.monotonic()-started,received_base64=base64.b64encode(observed).decode())
        row['forced_client_close']=not row['peer_terminal_observed']
    if observed:row['response']=parse_response(observed)


def observe(binary,home,port,tokens,identities,profile,version,result):
    tls=context(identities,version) if version else None
    server=NativeServer(binary,home,port,identities,False,result['processes'],list(tokens.values())) if tls else Server(binary,home,port,result['processes'],list(tokens.values()))
    try:
        for name,body in [('initialize',INITIALIZE),('ping-before',PING)]:
            data=request('/mcp',port,tokens,body=body)
            row=dict(case=name,request_sha256=hashlib.sha256(data).hexdigest(),request_base64=base64.b64encode(data).decode(),response={})
            result['rows'].append(row)
            row['response'].update(tls_exchange(port,data,tls,row) if tls else tcp_exchange(port,data,row))
            assert row['response']['status_line']=='HTTP/1.1 200 OK'
        late_body(port,tokens,tls,result['late_body'])
        if tls:handshake_peer(port,tls,result['handshake_peer'])
        if profile=='tcp-output':slow_output(port,tokens,result['slow_output'])
        data=request('/mcp',port,tokens,body=PING)
        row=dict(case='ping-after',request_sha256=hashlib.sha256(data).hexdigest(),request_base64=base64.b64encode(data).decode(),response={})
        result['rows'].append(row);row['response'].update(tls_exchange(port,data,tls,row) if tls else tcp_exchange(port,data,row))
        assert_response(row['response'],200,PING_BODY)
        known=[SECRET,PASSPHRASE]+list(tokens.values())
        responses=[base64.b64decode(r['response']['raw_base64']) for r in result['rows']]+[base64.b64decode(result['late_body']['received_base64'])]
        if result['slow_output']:responses.append(base64.b64decode(result['slow_output']['received_base64']))
        assert not any(v.encode() in data for v in known for data in responses)
    finally:server.close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--allow-dirty-for-development',action='store_true')
    args=parser.parse_args()
    clean=not checked(['git','status','--porcelain=v1']).strip();assert clean or args.allow_dirty_for_development
    rust=args.rust.resolve()
    paths=sorted(p for p in checked(['git','ls-files','--cached','--others','--exclude-standard']).decode().splitlines()
                 if p.startswith(('crates/','third_party/','testdata/','scripts/rust-port/','internal/mcp/apitemplates/builtin/'))
                 or p in {'Cargo.toml','Cargo.lock','.gitattributes','.github/workflows/rust-http-write.yml'})
    receipt=dict(passed=False,candidate_commit=checked(['git','rev-parse','HEAD']).decode().strip(),candidate_worktree_clean=clean,
                 candidate_sources=inventory(paths,ROOT),native_os=platform.system(),architecture=platform.machine(),
                 rust_binary_sha256=hashlib.sha256(rust.read_bytes()).hexdigest(),oracle_commit=ORACLE,
                 go={},rust={},profiles={},differences=[],declared_differences=[])
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-http-write-') as raw:
            base,tree=Path(raw),Path(raw)/'oracle';checked(['git','worktree','add','--detach',tree,ORACLE])
            try:
                files=checked(['git','ls-tree','-r','--name-only',ORACLE]).decode().splitlines()
                sources=sorted(p for p in files if p in {'go.mod','go.sum'} or p.endswith('.go') and not p.endswith('_test.go'))
                embedded=sorted(p for p in files if p.startswith('internal/mcp/apitemplates/builtin/'));assert len(embedded)==17
                receipt.update(oracle_sources=inventory(sources,tree),oracle_embedded=inventory(embedded,tree),seed_probe_sha256=hashlib.sha256(PROBE.read_bytes()).hexdigest(),identity_probe_sha256=hashlib.sha256(IDENTITY.read_bytes()).hexdigest())
                seed_source=PROBE.read_bytes();old=b'flag.Parse()';assert seed_source.count(old)==1
                seed_source=seed_source.replace(b'"time"',b'"time"\n "strings"',1)
                seed_source=seed_source.replace(old,b'write := flag.Duration("write-timeout", 0, "fixture write budget")\n secure := flag.Bool("secure", false, "fixture TLS selection")\n flag.Parse()',1)
                old=b'AllowInsecureBind: true, RateLimit: 1000';assert seed_source.count(old)==1
                seed_source=seed_source.replace(old,b'AllowInsecureBind: !*secure, RateLimit: 1000, WriteTimeout: *write',1)
                old=b'registry := auth.NewTokenRegistry';assert seed_source.count(old)==1
                extra=b'bulk := &vault.Entry{Data: map[string]any{"notes": "public"}}\n for i := 0; i < 128; i++ { bulk.Metadata.Tags = append(bulk.Metadata.Tags, strings.Repeat("\\\"", 50000)) }\n if err = vault.WriteEntry(*root, "public/bulk", bulk, identity); err != nil { panic(err) }\n '
                seed_source=seed_source.replace(old,extra+old,1)
                receipt['actual_write_seed_source_sha256']=hashlib.sha256(seed_source).hexdigest()
                for name,source in [('httpwriteseed',seed_source),('httpwriteidentity',IDENTITY.read_bytes())]:
                    helper=tree/'scripts/rust-port/cmd'/name;helper.mkdir();(helper/'main.go').write_bytes(source)
                suffix='.exe' if os.name=='nt' else ''
                go,seed,identity=[base/(name+suffix) for name in ['go-cli','go-seed','go-identity']]
                for binary,package in [(go,'.'),(seed,'./scripts/rust-port/cmd/httpwriteseed'),(identity,'./scripts/rust-port/cmd/httpwriteidentity')]:checked(['go','build','-trimpath','-buildvcs=false','-o',binary,package],tree)
                receipt.update(go_binary_sha256=hashlib.sha256(go.read_bytes()).hexdigest(),seed_binary_sha256=hashlib.sha256(seed.read_bytes()).hexdigest(),identity_binary_sha256=hashlib.sha256(identity.read_bytes()).hexdigest())
                identities=base/'identities';checked([identity,'--root',identities],base)
                identity_paths=sorted(p.name for p in identities.iterdir());receipt['identity_inventory']=inventory(identity_paths,identities)
                certificate_sha=hashlib.sha256(ssl.PEM_cert_to_DER_cert((identities/'server.pem').read_text())).hexdigest();receipt['server_certificate_sha256']=certificate_sha
                with socket.socket() as selection:selection.bind(('127.0.0.1',0));port=selection.getsockname()[1]
                receipt['port']=port
                for profile,budget,version in PROFILES:
                    seed_home=base/('seed-'+profile);seed_home.mkdir()
                    tokens=json.loads(checked([seed,'--root',seed_home/'vault','--write-timeout',budget,'--secure='+('true' if version else 'false')],seed_home,isolated(seed_home)))
                    snapshot=vault_snapshot(seed_home/'vault');receipt['profiles'][profile]=dict(write_budget=budget,fixture_snapshot=snapshot)
                    for implementation,binary in [('go',go),('rust',rust)]:
                        home=base/(implementation+'-'+profile);home.mkdir();shutil.copytree(seed_home/'vault',home/'vault');assert vault_snapshot(home/'vault')==snapshot
                        result=dict(rows=[],processes=[],late_body={},handshake_peer={},slow_output={});receipt[implementation][profile]=result
                        observe(binary,home,port,tokens,identities,profile,version,result)
                for profile,budget,version in PROFILES:
                    a,b=receipt['go'][profile],receipt['rust'][profile]
                    assert len(a['rows'])==len(b['rows'])==3
                    for left,right in zip(a['rows'],b['rows'],strict=True):
                        assert left['case']==right['case'] and left['request_sha256']==right['request_sha256']
                        if any(left['response'][k]!=right['response'][k] for k in ['status_line','headers_without_date','body_base64']):receipt['differences'].append(dict(profile=profile,case=left['case'],go=left['response'],rust=right['response']))
                    assert a['late_body']['request_sha256']==b['late_body']['request_sha256']
                    for implementation in ['go','rust']:
                        row=receipt[implementation][profile]['late_body']
                        assert row['sent_body_suffix_bytes']==16 and row['body_completed_seconds']>=2.4
                        assert row['peer_terminal_observed'] and not row['forced_client_close']
                        if version:assert row['server_certificate_sha256']==certificate_sha
                        if profile in {'tcp-five','tcp-output'}:assert_response(row['response'],200,PING_BODY)
                        else:assert not base64.b64decode(row['received_base64']),'expired absolute write budget produced a late HTTP response'
                        observed=receipt[implementation][profile]
                        if version:
                            peer=observed['handshake_peer']
                            assert peer['sender_joined'] and peer['peer_terminal_observed'] and not peer['forced_client_close']
                            assert 9<=peer['sent_hello_bytes']<peer['client_hello_length'] and .6<=peer['elapsed_seconds']<=2
                        if profile=='tcp-output':
                            output=observed['slow_output']
                            assert output['peer_terminal_observed'] and not output['forced_client_close']
                            assert output['slow_read_calls']>=4 and output['slow_received_bytes']>=4096,'actual progressing output required'
                            assert output['fast_drain_started_seconds']>=34
                            if output['received_base64']:
                                assert output['declared_chunk_length']>=10*1024*1024
                                assert output['received_chunk_bytes']<output['declared_chunk_length'],'expired write resumed after fast client drain'
                                response=output['partial_response']
                                assert response['status_line']=='HTTP/1.1 200 OK'
                                assert response['headers_without_date']==sorted([('connection','close'),('content-type','application/json'),('transfer-encoding','chunked')])
                assert not receipt['differences']
                assert inventory(paths,ROOT)==receipt['candidate_sources'] and inventory(identity_paths,identities)==receipt['identity_inventory']
                assert checked(['git','rev-parse','HEAD']).decode().strip()==receipt['candidate_commit']
                assert hashlib.sha256(rust.read_bytes()).hexdigest()==receipt['rust_binary_sha256']
                receipt['candidate_worktree_clean_at_end']=not checked(['git','status','--porcelain=v1']).strip();assert receipt['candidate_worktree_clean_at_end'] or args.allow_dirty_for_development
                receipt['passed']=True
            finally:checked(['git','worktree','remove','--force',tree])
    finally:args.receipt.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print(f'PASS: fifteen runtime response pairs, five admitted-body write controls, two progressing TLS handshakes and one progressing output control per implementation on {platform.system()}')


if __name__=='__main__':main()
