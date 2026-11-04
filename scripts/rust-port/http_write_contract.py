#!/usr/bin/env python3
"""Actual absolute HTTP writes and separate TLS admission against production Go."""
import argparse
import base64
import ctypes
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import struct
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode=True
from http_framing_contract import INITIALIZE, PING, PING_BODY, assert_response
from http_head_contract import parse_response
from http_oauth_contract import PASSPHRASE, PROBE, Server
from http_process_contract import SECRET, request
from http_tls_contract import IDENTITY, EmptyTLSResponse, NativeServer, context, exchange as tls_exchange
from http_head_contract import exchange as tcp_exchange
from http_tls_contract import secure_identities
from mcp_process_contract import (ORACLE, ROOT, add_capture_arguments, bounded, canonical_close, capture_arguments_ok, checked,
                                  go_capture_session, inventory, isolated, load_go_observations, pack_tree, pinned_seed,
                                  provenance, replay_seed, save_go_observations, scrub_home, unpack_tree, vault_snapshot)
from oracle_build import remove_oracle_worktree

CONTRACT='http-write'
PORT=28107  # fixed so request bytes (Host header) are identical in capture and replay
NORMALIZATION=['fixed loopback port','one seed vault/tokens (bulk entry included) plus the per-profile/budget config.yaml, and the TLS identities, pinned in the file',
               'Date header, log timestamps, peer ports',
               'output profiles are recorded for every budget of OUTPUT_BUDGETS so the Rust retry ladder keeps a Go counterpart',
               'wall-clock/host measurements are asserted against the comparison bounds at capture and recorded as the bound itself '
               '(see normalize_write): body_completed_seconds=2.4, handshake elapsed=midpoint of .6..2, sent_hello_bytes=9, '
               'slow_read_calls=4, slow_received_bytes=4096, fast_drain_started_seconds=budget+4, received_chunk_bytes=declared_chunk_length-1',
               'random TLS bytes (client_hello_sha256, post_tls_error_wire), socket observations, load averages, wall-clock ns and the server pid are not stored',
               'the Go partial response is stored truncated to its first 4096 bytes (status line, headers and the start of the chunk)']
TLS_OUTPUT=('tls-output','30s',ssl.TLSVersion.TLSv1_3)
# #1470, owner decision 2026-10-24: the Go oracle's plain-TCP write deadline does not interrupt an in-flight
# Windows send, so only that one cell is a declared platform difference. Rust stays strictly checked everywhere.
WINDOWS_GO_TCP_OUTPUT_DECISION='windows-go-plain-tcp-write-deadline-not-enforced'
# The write budget starts when the request head is read, so it also covers the handler. The debug Rust binary
# the gates build needs seconds of CPU for the 25 MiB bulk response and, on a starved host, can miss a fixed 30s
# budget before sending one byte; Go (like Rust) then correctly closes with nothing written and the probe
# never reaches its slow-read phase. That is a precondition failure of the probe, not an expired-write
# verdict, so the output profiles are re-seeded with a longer budget. A real Rust defect never gets
# better with time: the strict assertion below still runs on whichever attempt reaches the slow-read phase.
OUTPUT_BUDGETS=('30s','60s','120s')
EXCHANGE_TIMEOUT=30  # response waits on loaded hosts; a hung peer still fails
PROFILES=[('tcp-five','5s',None),('tcp-short','1s',None),
          ('tls12-short','1s',ssl.TLSVersion.TLSv1_2),('tls13-short','1s',ssl.TLSVersion.TLSv1_3),
          TLS_OUTPUT,('tcp-output','30s',None)]


def budget_seconds(budget):
    assert budget.endswith('s');return int(budget[:-1])


class OutputPreconditionUnmet(Exception):
    """The slow-read phase never saw progressing output, so no write-deadline verdict exists for this attempt."""


# The plain request/response exchanges (initialize, ping-before, ping-after) are not deadline probes, but the server
# applies the profile's write budget to them as well: a TLS handshake must finish within min(read, write) and a
# response must be written within the write budget measured from the request head. The *-short profiles use 1s. If
# the process or its CPU is stalled for longer than that between accept and the first response byte (a starved
# docker VM: observed as ConnectionResetError in the TLS handshake and in the TCP recv at the 1s profiles), the
# server correctly closes the connection before a response exists. Both Go and Rust do (re-observed on Linux by
# SIGSTOPping the server for 1.3s mid-handshake: Go answers EOF, Rust a reset, TLS 1.3 Go may even finish). That is
# a precondition failure of the exchange, not a verdict, so the whole profile is re-run on fresh state, like the
# output probes. A server that closes every attempt, dies, or sends part of a response still fails.
EXCHANGE_ATTEMPTS=3


class ExchangeStarved(Exception):
    """A live server closed the connection before any response byte: no verdict exists for this attempt."""

    def __init__(self,details):
        super().__init__(details);self.details=details


def received_bytes(row):
    return base64.b64decode(row.get('raw_base64') or row.get('received_base64') or '')


def starved_exchange(server,binary,profile,case,row,exchange):
    """Run one plain exchange; classify a pre-response close by a still-running server as ExchangeStarved."""
    started=time.monotonic()
    try:return exchange()
    except (ConnectionError,ssl.SSLEOFError,EmptyTLSResponse,ValueError) as error:
        # ValueError: parse_response() of an empty buffer, i.e. a clean close without a single byte.
        if server.child.poll() is not None or received_bytes(row):raise
        raise ExchangeStarved(dict(binary=Path(str(binary)).name,profile=profile,case=case,error_type=type(error).__name__,
                                   error=str(error)[:200],elapsed_seconds=time.monotonic()-started,
                                   load_average=os.getloadavg() if hasattr(os,'getloadavg') else None)) from error


def output_progressing(output):
    return output['slow_read_calls']>=4 and output['slow_received_bytes']>=4096


def declared_write_difference(implementation,profile,native_os,output):
    """Return the declared difference for the single exempt cell, else None (the strict assertion applies)."""
    if (implementation,profile,native_os)!=('go','tcp-output','Windows'):return None
    return dict(implementation=implementation,profile=profile,native_os=native_os,
                received_chunk_bytes=output['received_chunk_bytes'],declared_chunk_length=output['declared_chunk_length'],
                decision=WINDOWS_GO_TCP_OUTPUT_DECISION,
                reason='#1470: on Windows the Go oracle completed the expired in-flight plain-TCP write after the fast client drain; '
                       'recorded as a platform difference (owner decision 2026-10-24). Rust remains strictly checked on every OS.')


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
                except (ConnectionResetError, ConnectionAbortedError) as error:
                    row.update(peer_terminal_observed=True,peer_terminal_kind='connection-aborted' if isinstance(error,ConnectionAbortedError) else 'connection-reset');break
                if not part:
                    row.update(peer_terminal_observed=True,peer_terminal_kind='eof');break
                observed+=part;assert len(observed)<65536
        finally:
            row.update(elapsed_seconds=time.monotonic()-started,received_base64=base64.b64encode(observed).decode())
            row['forced_client_close']=not row['peer_terminal_observed']
            stop.set();worker.join(timeout=5);row['sender_joined']=not worker.is_alive()


# Microsoft WinSDK mstcpip.h TCP_INFO_v0: fixed-width ABI, including padding.
# SIO_TCP_INFO is observational and requires neither elevated privileges nor
# changing TCP settings. These receiver statistics are not sender-write traces.
TCP_INFO_V0=struct.Struct('<IIQ?3x7IQQ5IB3x')
TCP_INFO_FIELDS=('state','mss','connection_time_ms','timestamps_enabled','rtt_us',
                 'min_rtt_us','bytes_in_flight','congestion_window_bytes',
                 'send_window_bytes','receive_window_bytes','receive_buffer_bytes',
                 'bytes_out','bytes_in','bytes_reordered','bytes_retransmitted',
                 'fast_retransmits','duplicate_acks_in','timeout_episodes','syn_retransmits')


def socket_observation(stream,started):
    row=dict(started_seconds=time.monotonic()-started,
             client_endpoint=stream.getsockname(),server_endpoint=stream.getpeername(),
             client_so_rcvbuf=stream.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF),
             client_so_sndbuf=stream.getsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF))
    if os.name=='nt':
        ws2=ctypes.WinDLL('Ws2_32.dll')
        ws2.WSAIoctl.argtypes=[ctypes.c_size_t,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,
                              ctypes.c_void_p,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32),
                              ctypes.c_void_p,ctypes.c_void_p]
        ws2.WSAIoctl.restype=ctypes.c_int
        ws2.WSAGetLastError.argtypes=[];ws2.WSAGetLastError.restype=ctypes.c_int
        version,returned=ctypes.c_uint32(0),ctypes.c_uint32()
        output=ctypes.create_string_buffer(TCP_INFO_V0.size)
        if ws2.WSAIoctl(stream.fileno(),0xC0000000|0x18000000|39,
                       ctypes.byref(version),ctypes.sizeof(version),output,len(output),
                       ctypes.byref(returned),None,None)!=0:
            raise OSError(ws2.WSAGetLastError(),'SIO_TCP_INFO receiver observation failed')
        if returned.value!=TCP_INFO_V0.size:
            raise ValueError('incomplete native TCP_INFO_v0')
        row['windows_tcp_info_v0']=dict(zip(TCP_INFO_FIELDS,TCP_INFO_V0.unpack(output.raw),strict=True))
    row['completed_seconds']=time.monotonic()-started
    return row


def slow_output(port,tokens,row,tls=None,budget=30):
    slow_window,drain_limit=budget+4,budget+29
    body=b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_entry_metadata","arguments":{"path":"public/bulk"}}}'
    data=request('/mcp',port,tokens,body=body)
    row.update(request_sha256=hashlib.sha256(data).hexdigest(),request_base64=base64.b64encode(data).decode(),
               load_average_before=os.getloadavg() if hasattr(os,'getloadavg') else None,
               peer_terminal_observed=False,forced_client_close=False,slow_read_calls=0,slow_received_bytes=0,
               socket_observations=[],socket_observation_errors=[])
    observed=bytearray()
    observation_error=None
    with ExitStack() as sockets:
        stream=sockets.enter_context(socket.socket())
        stream.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096);stream.settimeout(.25)
        row['client_so_rcvbuf_before_connect']=stream.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
        stream.connect(('127.0.0.1',port))
        if tls:
            stream.settimeout(5)
            stream=sockets.enter_context(tls.wrap_socket(stream,server_hostname='localhost'))
            row.update(tls_version=stream.version(),server_certificate_sha256=hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest())
            stream.settimeout(.25)
        row['request_start_wall_ns_before']=time.time_ns()
        started=time.monotonic()
        row['request_start_wall_ns_after']=time.time_ns()
        stream.sendall(data)
        def observe_socket(phase):
            nonlocal observation_error
            if row['peer_terminal_observed'] or observation_error is not None:return
            try:row['socket_observations'].append(dict(phase=phase,**socket_observation(stream,started)))
            except Exception as error:
                # Preserve real peer bytes/closure first, then fail this diagnostic.
                observation_error=error
                row['socket_observation_errors'].append(dict(phase=phase,type=type(error).__name__,
                    code=getattr(error,'winerror',None) or getattr(error,'errno',None)))
        def receive(limit):
            try:part=stream.recv(limit)
            except socket.timeout:return None
            except (ConnectionResetError, ConnectionAbortedError) as error:
                row.update(peer_terminal_observed=True,peer_terminal_kind='connection-aborted' if isinstance(error,ConnectionAbortedError) else 'connection-reset');return b''
            if not part:row.update(peer_terminal_observed=True,peer_terminal_kind='eof')
            return part
        try:
            observe_socket('request-sent')
            while time.monotonic()-started<slow_window and not row['peer_terminal_observed']:
                observe_socket('slow-read')
                part=receive(1024)
                if part:
                    row.setdefault('first_byte_seconds',time.monotonic()-started)
                    observed+=part;row['slow_read_calls']+=1;row['slow_received_bytes']+=len(part)
                    time.sleep(.15)
            row['fast_drain_started_seconds']=time.monotonic()-started
            if not row['peer_terminal_observed']:
                observe_socket('before-fast-drain')
                stream.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,256*1024)
                observe_socket('after-receive-buffer-change')
                while not row['peer_terminal_observed'] and time.monotonic()-started<drain_limit:
                    part=receive(65536)
                    if part:row.setdefault('first_byte_seconds',time.monotonic()-started);observed+=part
                    assert len(observed)<40*1024*1024
        finally:
            row['receive_end_wall_ns_before']=time.time_ns()
            row.update(elapsed_seconds=time.monotonic()-started,received_base64=base64.b64encode(observed).decode())
            row['receive_end_wall_ns_after']=time.time_ns()
            row['forced_client_close']=not row['peer_terminal_observed']
    if observation_error is not None:raise observation_error
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
                    except (ConnectionResetError, ConnectionAbortedError) as error:
                        row.update(peer_terminal_observed=True,peer_terminal_kind='connection-aborted' if isinstance(error,ConnectionAbortedError) else 'connection-reset');break
                    except ssl.SSLError as error:
                        row['tls_read_errors'].append(dict(type=type(error).__name__,reason=error.reason,message=str(error)))
                        wire=bytearray()
                        with socket.socket(fileno=stream.detach()) as observer:
                            observer.settimeout(.25);bound=time.monotonic()+3
                            while time.monotonic()<bound:
                                try:part=observer.recv(65536)
                                except socket.timeout:continue
                                except (ConnectionResetError, ConnectionAbortedError) as error:
                                    row.update(peer_terminal_observed=True,peer_terminal_kind='connection-aborted' if isinstance(error,ConnectionAbortedError) else 'connection-reset');break
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


def observe(binary,home,port,tokens,identities,profile,version,result,budget=30):
    tls=context(identities,version) if version else None
    server=NativeServer(binary,home,port,identities,False,result['processes'],list(tokens.values())) if tls else Server(binary,home,port,result['processes'],list(tokens.values()))
    try:
        if profile in {'tcp-output','tls-output'}:result['server_process_id']=server.child.pid
        for name,body in [('initialize',INITIALIZE),('ping-before',PING)]:
            data=request('/mcp',port,tokens,body=body)
            row=dict(case=name,request_sha256=hashlib.sha256(data).hexdigest(),request_base64=base64.b64encode(data).decode(),response={})
            result['rows'].append(row)
            row['response'].update(starved_exchange(server,binary,profile,name,row,lambda:tls_exchange(port,data,tls,row,timeout=EXCHANGE_TIMEOUT) if tls else tcp_exchange(port,data,row,timeout=EXCHANGE_TIMEOUT)))
            assert row['response']['status_line']=='HTTP/1.1 200 OK'
        late_body(port,tokens,tls,result['late_body'])
        if tls and profile!='tls-output':handshake_peer(port,tls,result['handshake_peer'])
        if profile in {'tcp-output','tls-output'}:
            slow_output(port,tokens,result['slow_output'],tls,budget)
            if not output_progressing(result['slow_output']):raise OutputPreconditionUnmet(profile)
        data=request('/mcp',port,tokens,body=PING)
        row=dict(case='ping-after',request_sha256=hashlib.sha256(data).hexdigest(),request_base64=base64.b64encode(data).decode(),response={})
        result['rows'].append(row);row['response'].update(starved_exchange(server,binary,profile,'ping-after',row,lambda:tls_exchange(port,data,tls,row,timeout=EXCHANGE_TIMEOUT) if tls else tcp_exchange(port,data,row,timeout=EXCHANGE_TIMEOUT)))
        assert_response(row['response'],200,PING_BODY)
        known=[SECRET,PASSPHRASE]+list(tokens.values())
        responses=[base64.b64decode(r['response']['raw_base64']) for r in result['rows']]+[base64.b64decode(result['late_body']['received_base64'])]
        if result['slow_output']:responses.append(base64.b64decode(result['slow_output']['received_base64']))
        assert not any(v.encode() in data for v in known for data in responses)
    finally:server.close()


SEED_BULK=b'bulk := &vault.Entry{Data: map[string]any{"notes": "public"}}\n for i := 0; i < 128; i++ { bulk.Metadata.Tags = append(bulk.Metadata.Tags, strings.Repeat("\\\"", 50000)) }\n if err = vault.WriteEntry(*root, "public/bulk", bulk, identity); err != nil { panic(err) }\n '


def write_seed_source():
    seed_source=PROBE.read_bytes();old=b'flag.Parse()';assert seed_source.count(old)==1
    seed_source=seed_source.replace(b'"time"',b'"time"\n "strings"',1)
    seed_source=seed_source.replace(old,b'write := flag.Duration("write-timeout", 0, "fixture write budget")\n secure := flag.Bool("secure", false, "fixture TLS selection")\n flag.Parse()',1)
    old=b'AllowInsecureBind: true, RateLimit: 1000';assert seed_source.count(old)==1
    seed_source=seed_source.replace(old,b'AllowInsecureBind: !*secure, RateLimit: 1000, WriteTimeout: *write',1)
    old=b'registry := auth.NewTokenRegistry';assert seed_source.count(old)==1
    extra=SEED_BULK
    return seed_source.replace(old,extra+old,1)


def check_write(receipt,implementation,profile,version,certificate_sha):
    """The per-implementation verdict of one profile (unchanged assertions); idempotent apart from declared differences."""
    budget=receipt['profiles'][profile]['write_budget']
    row=receipt[implementation][profile]['late_body']
    assert row['sent_body_suffix_bytes']==16 and row['body_completed_seconds']>=2.4
    assert row['peer_terminal_observed'] and not row['forced_client_close']
    if version:assert row['server_certificate_sha256']==certificate_sha
    if profile in {'tcp-five','tcp-output','tls-output'}:assert_response(row['response'],200,PING_BODY)
    else:assert not base64.b64decode(row['received_base64']),'expired absolute write budget produced a late HTTP response'
    observed=receipt[implementation][profile]
    if version and profile!='tls-output':
        peer=observed['handshake_peer']
        assert peer['sender_joined'] and peer['peer_terminal_observed'] and not peer['forced_client_close']
        assert 9<=peer['sent_hello_bytes']<peer['client_hello_length'] and .6<=peer['elapsed_seconds']<=2
    if profile in {'tcp-output','tls-output'}:
        output=observed['slow_output']
        if version:
            assert output['tls_version']=='TLSv1.3'
            assert output['server_certificate_sha256']==certificate_sha
        assert output['peer_terminal_observed'] and not output['forced_client_close']
        assert output_progressing(output),'actual progressing output required'
        assert output['fast_drain_started_seconds']>=budget_seconds(budget)+4
        if output['received_base64']:
            assert output['declared_chunk_length']>=10*1024*1024
            # Diagnostics go to stderr; the mutation negative control pins the exact assertion message.
            print(f"write-deadline {implementation}/{profile}: {output['received_chunk_bytes']}/{output['declared_chunk_length']} chunk bytes received",file=sys.stderr,flush=True)
            declared=declared_write_difference(implementation,profile,receipt['native_os'],output)
            if declared:receipt['declared_differences'].append(declared)
            else:assert output['received_chunk_bytes']<output['declared_chunk_length'],'expired write resumed after fast client drain'
            response=output['partial_response']
            assert response['status_line']=='HTTP/1.1 200 OK'
            assert response['headers_without_date']==sorted([('connection','close'),('content-type','application/json'),('transfer-encoding','chunked')])


PARTIAL_RESPONSE_KEEP=4096


def normalize_write(result,profile,budget,version):
    """Capture-time normalisation of one Go profile record (the verdict ran on the real values before)."""
    late=result['late_body']
    late['body_completed_seconds']=2.4
    late['elapsed_seconds']=0.0
    late.pop('post_tls_error_wire_base64',None)
    late['tls_read_errors']=[{**e,'message':''} for e in late['tls_read_errors']]
    if late.get('peer_terminal_kind') in ('connection-reset','connection-aborted'):late['peer_terminal_kind']='eof'
    if result['handshake_peer']:
        peer=result['handshake_peer']
        peer['elapsed_seconds']=bounded(peer['elapsed_seconds'],.6,2,'handshake elapsed')
        peer['sent_hello_bytes']=9
        peer['client_hello_sha256']='0'*64
        peer['peer_terminal_kind']='eof'
        peer['received_base64']=''
    if result['slow_output']:
        out=result['slow_output']
        out['slow_read_calls']=4;out['slow_received_bytes']=4096
        out['fast_drain_started_seconds']=budget_seconds(budget)+4
        out['elapsed_seconds']=0.0;out['first_byte_seconds']=0.0
        for key in ('socket_observations','socket_observation_errors'):out[key]=[]
        out['load_average_before']=None
        for key in ('request_start_wall_ns_before','request_start_wall_ns_after','receive_end_wall_ns_before','receive_end_wall_ns_after'):out[key]=0
        out['peer_terminal_kind']='eof'
        if out['received_base64']:
            kept=base64.b64decode(out['received_base64'])[:PARTIAL_RESPONSE_KEEP]
            out['received_base64']=base64.b64encode(kept).decode()
            out['partial_response']=parse_response(kept)
            out['received_chunk_bytes']=out['declared_chunk_length']-1
    result['server_process_id']=0
    return result


def capture(args):
    """Go half only: build the oracle, observe it, write the committed observations."""
    with go_capture_session(CONTRACT, args, {'seed': ('httpwriteseed', write_seed_source()), 'identity': ('httpwriteidentity', IDENTITY.read_bytes())}) as session:
        base = session['base']
        prior = session['prior']
        identities = base / 'identities'
        if prior and prior.get('identities'):
            unpack_tree(prior['identities']['tree'], identities)
        else:
            checked([session['helpers']['identity'], '--root', identities], base)
        session['identities'] = dict(tree=pack_tree(identities))
        identity_paths = sorted(p.name for p in identities.iterdir())
        certificate_sha = hashlib.sha256(ssl.PEM_cert_to_DER_cert((identities/'server.pem').read_text())).hexdigest()
        recorded = {}
        # One bulk-bearing seed vault serves every profile (the 12.8 MB encrypted entry is incompressible); only
        # config.yaml (write_timeout, allow_insecure_bind) differs per profile/budget and is recorded separately.
        tokens = pinned_seed(session, 'base', base / 'seed-base', lambda home: json.loads(checked(
            [session['helpers']['seed'], '--root', home / 'vault', '--write-timeout', '30s', '--secure=false'], home, isolated(home))))
        session['configs'] = {}
        for profile, budget, version in PROFILES:
            output_profile = profile in {'tcp-output', 'tls-output'}
            recorded[profile] = {}
            for tried in (OUTPUT_BUDGETS if output_profile else (budget,)):
                key = profile + '-' + tried
                prior_config = ((session['prior'] or {}).get('configs') or {}).get(key)
                if prior_config is None:
                    scratch = base / ('config-' + key)
                    scratch.mkdir()
                    checked([session['helpers']['seed'], '--root', scratch / 'vault', '--write-timeout', tried, '--secure=' + ('true' if version else 'false')], scratch, isolated(scratch))
                    prior_config = base64.b64encode(scrub_home((scratch / 'vault/config.yaml').read_bytes(), scratch)).decode()
                session['configs'][key] = prior_config
                seed_home = base / ('seed-' + key)
                shutil.copytree(base / 'seed-base/vault', seed_home / 'vault')
                (seed_home / 'vault/config.yaml').write_bytes(base64.b64decode(prior_config))
                snapshot = vault_snapshot(seed_home / 'vault')
                print(f'capture-go: {profile} write budget {tried}', file=sys.stderr, flush=True)
                try:
                    for attempt in range(EXCHANGE_ATTEMPTS):
                        # A host stall longer than the profile's 1s budget between accept and the first response byte makes the
                        # Go server close the exchange: no verdict exists for that attempt, so it is repeated on fresh state and
                        # never recorded (only a completed observation is).
                        home = base / ('go-' + profile + '-' + tried + '-' + str(attempt))
                        home.mkdir()
                        shutil.copytree(seed_home / 'vault', home / 'vault')
                        assert vault_snapshot(home / 'vault') == snapshot
                        result = dict(rows=[], processes=[], late_body={}, handshake_peer={}, slow_output={})
                        try:
                            observe(session['go'], home, PORT, tokens, identities, profile, version, result, budget_seconds(tried))
                            break
                        except ExchangeStarved as starved:
                            print(f'capture-go: {profile} attempt {attempt} starved: {starved.details}', file=sys.stderr, flush=True)
                            if attempt == EXCHANGE_ATTEMPTS - 1:
                                raise
                except OutputPreconditionUnmet:
                    recorded[profile][tried] = dict(unmet=True, fixture_snapshot=snapshot)
                    continue
                except Exception as error:
                    # The Rust retry ladder only reaches a budget when the shorter ones were unmet; Go never ran there
                    # before. Keep the budgets Go cannot serve cleanly out of the ladder (never the first one).
                    if not any(not e['unmet'] for e in recorded[profile].values()):
                        raise
                    print(f'capture-go: {profile} budget {tried} not recordable: {type(error).__name__}', file=sys.stderr)
                    recorded[profile][tried] = dict(unmet=True, fixture_snapshot=snapshot, unavailable=type(error).__name__)
                    continue
                receipt = dict(native_os=platform.system(), profiles={profile: dict(write_budget=tried)}, go={profile: result}, declared_differences=[])
                check_write(receipt, 'go', profile, version, certificate_sha)
                recorded[profile][tried] = dict(unmet=False, fixture_snapshot=snapshot,
                                                go=normalize_write(result, profile, tried, version), declared=receipt['declared_differences'])
            assert any(not e['unmet'] for e in recorded[profile].values()), ('no usable Go observation', profile)
        data = dict(info=dict(session['info'], seed_probe_sha256=hashlib.sha256(PROBE.read_bytes()).hexdigest(),
                              identity_probe_sha256=hashlib.sha256(IDENTITY.read_bytes()).hexdigest(),
                              actual_write_seed_source_sha256=hashlib.sha256(write_seed_source()).hexdigest()),
                    port=PORT, seeds=session['seeds'], configs=session['configs'], identities=session['identities'],
                    identity_inventory=inventory(identity_paths, identities), server_certificate_sha256=certificate_sha,
                    profiles=recorded)
        path = save_go_observations(CONTRACT, data, {}, NORMALIZATION, session['go_version'])
    print(f'CAPTURED: Go write observations for {len(recorded)} profiles -> {path}')


def main():
    parser=argparse.ArgumentParser()
    add_capture_arguments(parser, rust_required=False)
    parser.add_argument('--allow-dirty-for-development',action='store_true')
    parser.add_argument('--tls-output-probe-only',action='store_true',help='Run only the additional TLS backpressure probe, not full HTTP acceptance')
    args=parser.parse_args()
    if capture_arguments_ok(args):
        return capture(args)
    document=load_go_observations(CONTRACT,{});recorded=document['data']
    profiles=[TLS_OUTPUT] if args.tls_output_probe_only else PROFILES
    clean=not checked(['git','status','--porcelain=v1']).strip();assert clean or args.allow_dirty_for_development
    rust=args.rust.resolve()
    paths=sorted(p for p in checked(['git','ls-files','--cached','--others','--exclude-standard']).decode().splitlines()
                 if p.startswith(('crates/','third_party/','testdata/','scripts/rust-port/','internal/mcp/apitemplates/builtin/'))
                 or p in {'Cargo.toml','Cargo.lock','.gitattributes','.github/workflows/rust-http-write.yml'})
    receipt: dict=dict(passed=False,candidate_commit=checked(['git','rev-parse','HEAD']).decode().strip(),candidate_worktree_clean=clean,
                 candidate_sources=inventory(paths,ROOT),native_os=platform.system(),architecture=platform.machine(),
                 rust_binary_sha256=hashlib.sha256(rust.read_bytes()).hexdigest(),oracle_commit=ORACLE,
                 scope='tls-output-probe-only' if args.tls_output_probe_only else 'full',
                 go={},rust={},profiles={},differences=[],declared_differences=[],
                 go_observations=provenance(document),port=recorded['port'],identity_inventory=recorded['identity_inventory'],
                 server_certificate_sha256=recorded['server_certificate_sha256'],**recorded['info'])
    port=receipt['port'];certificate_sha=receipt['server_certificate_sha256']
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-http-write-') as raw:
            base=Path(raw)
            identities=unpack_tree(recorded['identities']['tree'],base/'identities');secure_identities(identities)
            identity_paths=sorted(p.name for p in identities.iterdir())
            assert inventory(identity_paths,identities)==receipt['identity_inventory'],'recorded TLS identities changed'
            assert hashlib.sha256(ssl.PEM_cert_to_DER_cert((identities/'server.pem').read_text())).hexdigest()==certificate_sha
            for profile,budget,version in profiles:
                output_profile=profile in {'tcp-output','tls-output'}
                unmet=[]
                # The recorded Go row is fixed: only the live Rust side is repeated (fresh dirs per attempt), and only when a
                # live server closed a plain exchange before any response byte (ExchangeStarved, bounded by EXCHANGE_ATTEMPTS).
                for tried,attempt in [(t,a) for t in (OUTPUT_BUDGETS if output_profile else (budget,)) for a in range(1 if output_profile else EXCHANGE_ATTEMPTS)]:
                    entry=recorded['profiles'][profile][tried]
                    if entry['unmet']:
                        unmet.append(dict(write_budget=tried,implementation='go',recorded_unmet=True));continue
                    seed_home=base/('seed-'+profile+'-'+tried+'-'+str(attempt))
                    tokens=replay_seed(recorded,'base',seed_home)
                    (seed_home/'vault/config.yaml').write_bytes(base64.b64decode(recorded['configs'][profile+'-'+tried]))
                    snapshot=vault_snapshot(seed_home/'vault');assert snapshot==entry['fixture_snapshot'],'recorded seed vault bytes changed'
                    receipt['profiles'][profile]=dict(write_budget=tried,fixture_snapshot=snapshot,unmet_precondition_attempts=unmet)
                    receipt['go'][profile]=entry['go'];receipt['declared_differences']+=entry['declared']
                    home=base/('rust-'+profile+'-'+tried+'-'+str(attempt));home.mkdir();shutil.copytree(seed_home/'vault',home/'vault');assert vault_snapshot(home/'vault')==snapshot
                    result=dict(rows=[],processes=[],late_body={},handshake_peer={},slow_output={});receipt['rust'][profile]=result
                    try:observe(rust,home,port,tokens,identities,profile,version,result,budget_seconds(tried))
                    except OutputPreconditionUnmet:
                        so=result['slow_output'];unmet.append(dict(write_budget=tried,implementation='rust',slow_read_calls=so['slow_read_calls'],
                            slow_received_bytes=so['slow_received_bytes'],first_byte_seconds=so.get('first_byte_seconds'),load_average_before=so.get('load_average_before')))
                        continue
                    except ExchangeStarved as starved:
                        unmet.append(dict(write_budget=tried,implementation='rust',exchange_starved=starved.details));continue
                    break
                else:assert False,f'no attempt of {profile} produced a verdict (actual progressing output / uninterrupted exchanges required): {unmet}'
            for profile,budget,version in profiles:
                a,b=receipt['go'][profile],receipt['rust'][profile]
                assert len(a['rows'])==len(b['rows'])==3
                for left,right in zip(a['rows'],b['rows'],strict=True):
                    assert left['case']==right['case'] and left['request_sha256']==right['request_sha256']
                    if any(left['response'][k]!=right['response'][k] for k in ['status_line','headers_without_date','body_base64']):receipt['differences'].append(dict(profile=profile,case=left['case'],go=left['response'],rust=right['response']))
                assert a['late_body']['request_sha256']==b['late_body']['request_sha256']
                for implementation in ['go','rust']:
                    check_write(receipt,implementation,profile,version,certificate_sha)
            assert not receipt['differences']
            assert inventory(paths,ROOT)==receipt['candidate_sources'] and inventory(identity_paths,identities)==receipt['identity_inventory']
            assert checked(['git','rev-parse','HEAD']).decode().strip()==receipt['candidate_commit']
            assert hashlib.sha256(rust.read_bytes()).hexdigest()==receipt['rust_binary_sha256']
            receipt['candidate_worktree_clean_at_end']=not checked(['git','status','--porcelain=v1']).strip();assert receipt['candidate_worktree_clean_at_end'] or args.allow_dirty_for_development
            receipt['passed']=True
    except BaseException as error:
        receipt['passed']=False
        receipt.setdefault('primary_failure',{'type':type(error).__name__,'message':str(error)[-2000:]})
        raise
    finally:args.receipt.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
    print(f'PASS: {receipt["scope"]}: {3*len(profiles)} runtime response pairs, {len(profiles)} admitted-body controls and verified output controls on {platform.system()} (Go side replayed from {receipt["go_observations"]["path"]})')


if __name__=='__main__':main()
