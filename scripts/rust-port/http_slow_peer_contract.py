#!/usr/bin/env python3
"""Actual progressing header/body deadlines and persistent idle admission."""
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
import threading
import time

sys.dont_write_bytecode = True
from http_framing_contract import INITIALIZE, JSON_ERROR, PING, assert_response, exchange
from http_head_contract import parse_response
from http_oauth_contract import PASSPHRASE, PROBE, Server
from http_process_contract import SECRET, request
from mcp_process_contract import (ORACLE, ROOT, add_capture_arguments, bounded, capture_arguments_ok, checked, go_capture_session,
                                  inventory, isolated, load_go_observations, pinned_seed, provenance, replay_seed,
                                  save_go_observations, vault_snapshot, canonical_close)

CONTRACT='http-slow-peer'
PORT=28104  # fixed so request bytes (Host header) are identical in capture and replay
NORMALIZATION=['fixed loopback port','seed vault and tokens pinned in the file','Date header, log timestamps, peer ports',
               'wall-clock values (elapsed_seconds, first_progress_seconds, idle_wait_seconds) and the sender progress count are asserted '
               'against the comparison bounds at capture and recorded as the bounds midpoint / minimum (see check_slow_peers)']


# Progress cadence. The shortest configured deadline is 1s and the contract needs >=4 progress
# bytes before it, so the cadence must leave ample scheduling slack (20 slots, 4 required).
PROGRESS_INTERVAL=.05
MIN_PROGRESS_BYTES=4


def assert_progress(row):
    """Keep the >=4 bytes and joined-sender proof, but name why it failed when it does."""
    if row['sender_joined'] and row['sent_progress_bytes']>=MIN_PROGRESS_BYTES:
        row['progress_shortfall_reason']=None
        return
    if not row['sender_joined']:reason='sender-thread-not-joined-within-5s'
    elif row['sent_progress_bytes']==0:reason='sender-never-wrote-before-peer-terminal'
    else:reason='sender-wrote-%d-of-%d-bytes-before-peer-terminal'%(row['sent_progress_bytes'],MIN_PROGRESS_BYTES)
    row['progress_shortfall_reason']=reason
    raise AssertionError('%s (case=%s sent=%s first_progress_seconds=%s elapsed=%s interval=%s stop=%s terminal=%s): sender starved before the deadline, not a timeout verdict'%(
        reason,row.get('case'),row['sent_progress_bytes'],row.get('first_progress_seconds'),row.get('elapsed_seconds'),
        row.get('progress_interval_seconds'),row.get('sender_stop_reason'),row.get('peer_terminal_kind')))


def cases(port,tokens):
    return [('initialize',request('/mcp',port,tokens,body=INITIALIZE)),
            ('ping-before',request('/mcp',port,tokens,body=PING)),
            ('ping-after',request('/mcp',port,tokens,body=PING))]


def progressing_peer(port,tokens,body,row):
    original=request('/mcp',port,tokens,body=b' '*1024)
    prefix=original.split(b'\r\n\r\n',1)[0]
    prefix=prefix+b'\r\n\r\n' if body else prefix+b'\r\nX-Public-Slow: '
    progress=b' ' if body else b'x'
    maximum=12.5 if body else 7.5
    row.update(case='progressing-body' if body else 'progressing-header',
               request_prefix_sha256=hashlib.sha256(prefix).hexdigest(),
               request_prefix_base64=base64.b64encode(prefix).decode(),
               sent_progress_bytes=0,first_progress_seconds=None,sender_stop_reason=None,progress_interval_seconds=PROGRESS_INTERVAL,peer_terminal_observed=False,peer_terminal_kind=None,forced_client_close=False,received_base64='')
    received=bytearray()
    stop=threading.Event()
    with socket.create_connection(('127.0.0.1',port),timeout=.25) as stream:
        started=time.monotonic()
        stream.sendall(prefix)
        def sender():
            # Drift-free schedule: a late wake-up is caught up by the next send instead of
            # silently losing slots, so scheduler stalls on loaded runners cannot starve the
            # >=4 progress-byte evidence of a 1s deadline.
            slot=0
            while not stop.is_set():
                try:
                    stream.sendall(progress)
                    row['sent_progress_bytes']+=1
                    if row['first_progress_seconds'] is None:row['first_progress_seconds']=time.monotonic()-started
                except (OSError,TimeoutError) as error:
                    row['sender_stop_reason']='write-failed-after-peer-close:'+type(error).__name__
                    return
                slot+=1
                stop.wait(max(0.,started+slot*PROGRESS_INTERVAL-time.monotonic()))
            row['sender_stop_reason']='stopped-by-client'
        worker=threading.Thread(target=sender)
        worker.start()
        try:
            while time.monotonic()-started<maximum:
                try:
                    part=stream.recv(4096)
                except socket.timeout:
                    continue
                except (ConnectionResetError,ConnectionAbortedError) as error:
                    row['peer_terminal_observed']=True
                    row['peer_terminal_kind']='connection-aborted' if isinstance(error,ConnectionAbortedError) else 'connection-reset'
                    break
                if not part:
                    row['peer_terminal_observed']=True
                    row['peer_terminal_kind']='eof'
                    break
                received+=part
                assert len(received)<65536
            row['forced_client_close']=not row['peer_terminal_observed']
        finally:
            row['elapsed_seconds']=time.monotonic()-started
            row['received_base64']=base64.b64encode(received).decode()
            stop.set();worker.join(timeout=5)
            row['sender_joined']=not worker.is_alive()
            assert row['sender_joined'],'sender-thread-not-joined-within-5s'


def idle_boundary(port,tokens,retained):
    data=request('/.well-known/oauth-protected-resource',port,tokens,method='GET',auth=None,agent=None)
    first=data.replace(b'Connection: close\r\n',b'Connection: keep-alive\r\n',1)
    retained.update(request_sha256=hashlib.sha256(first+data).hexdigest(),request_base64=base64.b64encode(first+data).decode(),responses=[])
    observed=bytearray()
    try:
        with socket.create_connection(('127.0.0.1',port),timeout=8) as stream:
            with stream.makefile('rb') as reader:
                for index,packet in enumerate([first,data]):
                    if index:
                        started=time.monotonic();time.sleep(6)
                        retained['idle_wait_seconds']=time.monotonic()-started
                    stream.sendall(packet)
                    raw=bytearray()
                    for _ in range(64):
                        line=reader.readline(8192);observed+=line;raw+=line
                        assert line and line.endswith(b'\r\n'), 'idle admission response header'
                        if line==b'\r\n':break
                    else:raise AssertionError('idle admission header bound')
                    length,=[v for k,v in parse_response(raw)['headers'] if k=='content-length']
                    entity=reader.read(int(length));observed+=entity;raw+=entity
                    assert len(entity)==int(length)
                    response=parse_response(raw);retained['responses'].append(response)
                    assert response['status_line']=='HTTP/1.1 200 OK'
                    assert json.loads(base64.b64decode(response['body_base64']))['resource'].endswith('/mcp')
                extra=reader.read();observed+=extra
                assert not extra
    finally:
        retained['raw_base64']=base64.b64encode(observed).decode()


def observe(binary,home,port,tokens,result):
    known=[SECRET,PASSPHRASE]+list(tokens.values())
    server=Server(binary,home,port,result['processes'],list(tokens.values()))
    errors=[]
    def send(name,data):
        row=dict(case=name,request_sha256=hashlib.sha256(data).hexdigest(),request_base64=base64.b64encode(data).decode(),response={})
        result['rows'].append(row)
        row['response'].update(exchange(port,data,row['response']))
        assert row['response']['status_line']=='HTTP/1.1 200 OK'
        assert 'result' in json.loads(base64.b64decode(row['response']['body_base64']))
        assert not any(value.encode() in base64.b64decode(row['response']['raw_base64']) for value in known)
    def run(callback):
        try:callback()
        except BaseException as error:errors.append(str(error))
    workers=[]
    try:
        messages=cases(port,tokens)
        for name,data in messages[:2]:send(name,data)
        for body in [False,True]:
            row={};result['slow_peers'].append(row)
            workers.append(threading.Thread(target=run,args=(lambda body=body,row=row:progressing_peer(port,tokens,body,row),)))
        workers.append(threading.Thread(target=run,args=(lambda:idle_boundary(port,tokens,result['idle_boundary']),)))
        for worker in workers:worker.start()
        for worker in workers:worker.join(timeout=20)
        result['workers_joined']=all(not w.is_alive() for w in workers)
        result['control_errors']=errors
        assert result['workers_joined'] and not errors
        send(*messages[-1])
        for row in result['slow_peers']:
            assert not any(value.encode() in base64.b64decode(row['received_base64']) for value in known)
        assert not any(value.encode() in base64.b64decode(result['idle_boundary']['raw_base64']) for value in known)
    finally:
        server.close()
        for worker in workers:
            if worker.is_alive():worker.join(timeout=5)


def declared_difference(name,left,right):
    return None


def check_slow_peers(observed,implementation,limits=None):
    """The per-implementation timing/termination verdict (unchanged assertions); idempotent."""
    limits=limits or {'progressing-header':(3.5,7.5),'progressing-body':(8,12.5)}
    assert len(observed['slow_peers'])==2
    for row in observed['slow_peers']:
        assert_progress(row)
        assert row['peer_terminal_observed'] and not row['forced_client_close'], 'progressing peer escaped its absolute request deadline'
        raw=base64.b64decode(row['received_base64'])
        if raw:
            assert implementation=='go' and row['case']=='progressing-body', 'unexpected timeout response bytes'
            response=parse_response(raw)
            assert_response(response,400,JSON_ERROR)
            row['termination']='complete-go-json-error-before-write-deadline'
            row['response']=response
        else:
            row['termination']='actual-empty-eof-or-reset'
        minimum,maximum=limits[row['case']]
        assert minimum<=row['elapsed_seconds']<=maximum
    assert len(observed['idle_boundary']['responses'])==2
    assert observed['idle_boundary']['idle_wait_seconds']>=6


def normalize_slow_peers(observed,limits=None):
    """Capture-time normalisation: replace the measured wall-clock values by the asserted bound."""
    limits=limits or {'progressing-header':(3.5,7.5),'progressing-body':(8,12.5)}
    for row in observed['slow_peers']:
        row['elapsed_seconds']=bounded(row['elapsed_seconds'],*limits[row['case']],('elapsed',row['case']))
        assert row['first_progress_seconds'] is not None and row['first_progress_seconds']<1
        row['first_progress_seconds']=PROGRESS_INTERVAL
        assert row['sent_progress_bytes']>=MIN_PROGRESS_BYTES
        row['sent_progress_bytes']=MIN_PROGRESS_BYTES
        canonical_close(row)
    assert observed['idle_boundary']['idle_wait_seconds']>=6
    observed['idle_boundary']['idle_wait_seconds']=6


def capture(args):
    """Go half only: build the oracle, observe it, write the committed observations."""
    with go_capture_session(CONTRACT, args, {'seed': ('httpslowseed', PROBE.read_bytes())}) as session:
        base = session['base']
        tokens = pinned_seed(session, 'main', base / 'seed',
                             lambda home: json.loads(checked([session['helpers']['seed'], '--root', home / 'vault'], home, isolated(home))))
        snapshot = vault_snapshot(base / 'seed/vault')
        result = dict(rows=[], processes=[], slow_peers=[], idle_boundary={})
        home = base / 'go'
        home.mkdir()
        shutil.copytree(base / 'seed/vault', home / 'vault')
        assert vault_snapshot(home / 'vault') == snapshot
        observe(session['go'], home, PORT, tokens, result)
        check_slow_peers(result, 'go')
        normalize_slow_peers(result)
        data = dict(info=dict(session['info'], seed_probe_sha256=hashlib.sha256(PROBE.read_bytes()).hexdigest()),
                    port=PORT, fixture_snapshot=snapshot, seeds=session['seeds'], go=result)
        path = save_go_observations(CONTRACT, data, {}, NORMALIZATION, session['go_version'])
    print(f'CAPTURED: {len(result["rows"])} Go slow-peer responses -> {path}')


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
                   or p in {'Cargo.toml','Cargo.lock','.gitattributes','.github/workflows/rust-http-read-deadlines.yml'})
    receipt = dict(passed=False, candidate_commit=checked(['git','rev-parse','HEAD']).decode().strip(),
                   candidate_worktree_clean=clean, candidate_sources=inventory(paths,ROOT), native_os=platform.system(),
                   architecture=platform.machine(), rust_binary_sha256=hashlib.sha256(rust.read_bytes()).hexdigest(), oracle_commit=ORACLE,
                   go=recorded['go'], rust=dict(rows=[], processes=[], slow_peers=[], idle_boundary={}), differences=[], declared_differences=[],
                   go_observations=provenance(document), port=recorded['port'], fixture_snapshot=recorded['fixture_snapshot'],
                   **recorded['info'])
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-http-slow-') as raw:
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
            for implementation in ['go','rust']:
                check_slow_peers(receipt[implementation],implementation)
            for a,b in zip(receipt['go']['slow_peers'],receipt['rust']['slow_peers'],strict=True):
                assert a['case']==b['case'] and a['request_prefix_sha256']==b['request_prefix_sha256']
            assert receipt['go']['idle_boundary']['request_sha256']==receipt['rust']['idle_boundary']['request_sha256']
            for a,b in zip(receipt['go']['idle_boundary']['responses'],receipt['rust']['idle_boundary']['responses'],strict=True):
                assert all(a[k]==b[k] for k in ['status_line','headers_without_date','body_base64'])
            assert inventory(paths,ROOT)==receipt['candidate_sources']
            assert checked(['git','rev-parse','HEAD']).decode().strip()==receipt['candidate_commit']
            assert hashlib.sha256(rust.read_bytes()).hexdigest()==receipt['rust_binary_sha256']
            receipt['candidate_worktree_clean_at_end']=not checked(['git','status','--porcelain=v1']).strip()
            assert receipt['candidate_worktree_clean_at_end'] or args.allow_dirty_for_development
            assert not receipt['differences'], 'actual undeclared HTTP slow-peer differences retained'
            receipt['passed']=True
    finally:
        args.receipt.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print(f"PASS: three real runtime responses, two progressing read deadlines and a six-second idle boundary per implementation on {platform.system()} (Go side replayed from {receipt['go_observations']['path']})")


if __name__=='__main__':
    main()
