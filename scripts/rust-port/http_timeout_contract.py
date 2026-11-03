#!/usr/bin/env python3
"""Actual configured input deadlines and positive/non-positive Go overrides."""
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
import time

sys.dont_write_bytecode = True
from http_framing_contract import JSON_ERROR, assert_response
from http_head_contract import parse_response
from http_oauth_contract import PASSPHRASE, PROBE
from http_process_contract import ProcessCapture, SECRET
from http_slow_peer_contract import MIN_PROGRESS_BYTES, PROGRESS_INTERVAL, assert_progress, observe
from mcp_process_contract import (ORACLE, ROOT, add_capture_arguments, bounded, capture_arguments_ok, checked, go_capture_session,
                                  inventory, isolated, load_go_observations, pinned_seed, provenance, replay_seed,
                                  save_go_observations, vault_snapshot, canonical_close, redact_path)

CONTRACT='http-timeout'
PORT=28105  # fixed so request bytes (Host header) are identical in capture and replay
NORMALIZATION=['fixed loopback port','seed vaults and tokens pinned in the file (one per profile plus the invalid-config seed)',
               'Date header, log timestamps, peer ports',
               'wall-clock values (elapsed_seconds, first_progress_seconds, idle_wait_seconds, invalid-config elapsed) and the sender progress count '
               'are asserted against the comparison bounds at capture and recorded as the bounds midpoint / minimum (see check_profile)']

PROFILES=[('positive','1s','3s',(.6,2),(2,4)),
          ('zero','0s','0s',(3.5,7.5),(8,12.5)),
          ('negative','-1s','-2s',(3.5,7.5),(8,12.5))]


def timeout_seed_source():
    seed_source=PROBE.read_bytes()
    first=b'flag.Parse()'
    replacement=b'header := flag.Duration("read-header", 0, "fixture header timeout")\n read := flag.Duration("read", 0, "fixture overall read timeout")\n flag.Parse()'
    assert seed_source.count(first)==1
    seed_source=seed_source.replace(first,replacement,1)
    first=b'AllowInsecureBind: true, RateLimit: 1000'
    assert seed_source.count(first)==1
    return seed_source.replace(first,b'AllowInsecureBind: true, RateLimit: 1000, ReadHeaderTimeout: *header, ReadTimeout: *read',1)


def check_profile(observed,implementation,header_bounds,body_bounds):
    """The per-implementation verdict of one profile (unchanged assertions); idempotent."""
    assert len(observed['rows'])==3 and len(observed['slow_peers'])==2
    for row in observed['slow_peers']:
        assert_progress(row)
        assert row['peer_terminal_observed'] and not row['forced_client_close']
        raw=base64.b64decode(row['received_base64'])
        if raw:
            assert implementation=='go' and row['case']=='progressing-body','unexpected timeout response bytes'
            response=parse_response(raw);assert_response(response,400,JSON_ERROR)
            row['termination']='complete-go-json-error-before-write-deadline';row['response']=response
        else:row['termination']='actual-empty-eof-or-reset'
        minimum,maximum=body_bounds if row['case']=='progressing-body' else header_bounds
        assert minimum<=row['elapsed_seconds']<=maximum,'configured input deadline was not applied'
    assert len(observed['idle_boundary']['responses'])==2 and observed['idle_boundary']['idle_wait_seconds']>=6


def normalize_profile(observed,header_bounds,body_bounds):
    for row in observed['slow_peers']:
        row['elapsed_seconds']=bounded(row['elapsed_seconds'],*(body_bounds if row['case']=='progressing-body' else header_bounds),('elapsed',row['case']))
        assert row['first_progress_seconds'] is not None and row['first_progress_seconds']<1
        row['first_progress_seconds']=PROGRESS_INTERVAL
        assert row['sent_progress_bytes']>=MIN_PROGRESS_BYTES
        row['sent_progress_bytes']=MIN_PROGRESS_BYTES
        canonical_close(row)
    assert observed['idle_boundary']['idle_wait_seconds']>=6
    observed['idle_boundary']['idle_wait_seconds']=6


def invalid_config(implementation,binary,home,port,value,tokens,row):
    config=home/'vault/config.yaml'
    changed,count=re.subn(r'(?m)^([ \t]*read_timeout:[ \t]*).+$',lambda m:m[1]+json.dumps(value),config.read_text())
    assert count==1,'one actual Go-config duration field'
    config.write_text(changed)
    row.update(value=value,config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),forced_cleanup=False)
    child=subprocess.Popen([str(binary),'--quiet','mcp','--bind','127.0.0.1','--port',str(port)],
                           cwd=home,env=isolated(home),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    capture=ProcessCapture(child);started=time.monotonic()
    try:
        # Go offers config repair through $EDITOR; decline it for this probe.
        try:child.stdin.write(b'n\n');child.stdin.close()
        except BrokenPipeError:pass
        try:child.wait(timeout=10)
        except subprocess.TimeoutExpired:row['forced_cleanup']=True;child.kill();child.wait(timeout=10)
    finally:
        if child.poll() is None:child.kill();child.wait(timeout=10)
        stdout,stderr,complete=capture.finish()
        row.update(exit=child.returncode,elapsed_seconds=time.monotonic()-started,
                   stdout_base64=base64.b64encode(stdout).decode(),stderr_base64=base64.b64encode(stderr).decode(),
                   output_capture_complete=complete,output_capture_errors=capture.errors)
        assert complete
        assert not any(v.encode() in stdout+stderr for v in [SECRET,PASSPHRASE]+list(tokens.values()))
    diagnostic=value.encode() in stderr or b'cannot unmarshal' in stderr
    # Both exit 6 (ExitConfigError + doctor hint) since c44e6c45 ported Go's config refusal for mcp serve.
    row['expected_exit']=6
    assert not row['forced_cleanup'] and row['exit']==row['expected_exit'] and diagnostic,'malformed network timeout was not rejected by actual CLI config loading'


def capture(args):
    """Go half only: build the oracle, observe it, write the committed observations."""
    with go_capture_session(CONTRACT, args, {'seed': ('httptimeoutseed', timeout_seed_source())}) as session:
        base = session['base']
        result = dict(profiles={}, invalid_config=[], go={})
        for profile, header, body, header_bounds, body_bounds in PROFILES:
            seed_home = base / ('seed-' + profile)
            tokens = pinned_seed(session, profile, seed_home,
                                 lambda home, header=header, body=body: json.loads(checked(
                                     [session['helpers']['seed'], '--root', home / 'vault', '--read-header', header, '--read', body], home, isolated(home))))
            snapshot = vault_snapshot(seed_home / 'vault')
            result['profiles'][profile] = dict(header_config=header, read_config=body, header_bounds=header_bounds, body_bounds=body_bounds, fixture_snapshot=snapshot)
            home = base / ('go-' + profile)
            home.mkdir()
            shutil.copytree(seed_home / 'vault', home / 'vault')
            assert vault_snapshot(home / 'vault') == snapshot
            observed = dict(rows=[], processes=[], slow_peers=[], idle_boundary={})
            observe(session['go'], home, PORT, tokens, observed)
            check_profile(observed, 'go', header_bounds, body_bounds)
            normalize_profile(observed, header_bounds, body_bounds)
            result['go'][profile] = observed
        for index, value in enumerate(['not-a-duration','9223372036854775808ns']):
            home = base / ('go-invalid-' + str(index))
            home.mkdir()
            shutil.copytree(base / 'seed-negative/vault', home / 'vault')
            row = {}
            invalid_config('go', session['go'], home, PORT, value, tokens, row)
            row['elapsed_seconds'] = bounded(row['elapsed_seconds'], 0, 10, 'invalid-config elapsed')
            redact_path(row, ('stdout_base64', 'stderr_base64'), home)
            result['invalid_config'].append(row)
        data = dict(info=dict(session['info'], seed_probe_sha256=hashlib.sha256(PROBE.read_bytes()).hexdigest(),
                              actual_timeout_seed_source_sha256=hashlib.sha256(timeout_seed_source()).hexdigest()),
                    port=PORT, seeds=session['seeds'], **result)
        path = save_go_observations(CONTRACT, data, {}, NORMALIZATION, session['go_version'])
    print(f'CAPTURED: {sum(len(p["rows"]) for p in result["go"].values())} Go timeout responses -> {path}')


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
                   or p in {'Cargo.toml','Cargo.lock','.gitattributes','.github/workflows/rust-http-timeouts.yml'})
    receipt = dict(passed=False, candidate_commit=checked(['git','rev-parse','HEAD']).decode().strip(),
                   candidate_worktree_clean=clean, candidate_sources=inventory(paths,ROOT), native_os=platform.system(),
                   architecture=platform.machine(), rust_binary_sha256=hashlib.sha256(rust.read_bytes()).hexdigest(), oracle_commit=ORACLE,
                   go=recorded['go'], rust={}, invalid_config=dict(go=recorded['invalid_config'],rust=[]),differences=[], declared_differences=[],
                   go_observations=provenance(document), port=recorded['port'], profiles=recorded['profiles'], **recorded['info'])
    port=receipt['port']
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-http-timeouts-') as raw:
            base = Path(raw)
            for profile,header,body,header_bounds,body_bounds in PROFILES:
                seed_home=base/('seed-'+profile)
                tokens=replay_seed(recorded,profile,seed_home)
                snapshot=vault_snapshot(seed_home/'vault')
                assert snapshot==receipt['profiles'][profile]['fixture_snapshot'],'recorded seed vault bytes changed'
                home=base/('rust-'+profile);home.mkdir();shutil.copytree(seed_home/'vault',home/'vault')
                assert vault_snapshot(home/'vault')==snapshot
                result=dict(rows=[],processes=[],slow_peers=[],idle_boundary={})
                receipt['rust'][profile]=result
                observe(rust,home,port,tokens,result)
            for index,value in enumerate(['not-a-duration','9223372036854775808ns']):
                home=base/('rust-invalid-'+str(index));home.mkdir()
                shutil.copytree(base/'seed-negative/vault',home/'vault')
                row={};receipt['invalid_config']['rust'].append(row)
                invalid_config('rust',rust,home,port,value,tokens,row)
                assert receipt['invalid_config']['go'][index]['config_sha256']==receipt['invalid_config']['rust'][-1]['config_sha256']
            for profile,header,body,header_bounds,body_bounds in PROFILES:
                for a,b in zip(receipt['go'][profile]['rows'],receipt['rust'][profile]['rows'],strict=True):
                    assert a['case']==b['case'] and a['request_sha256']==b['request_sha256']
                    if any(a['response'][k]!=b['response'][k] for k in ['status_line','headers_without_date','body_base64']):
                        receipt['differences'].append(dict(profile=profile,case=a['case'],go=a['response'],rust=b['response']))
                for implementation in ['go','rust']:
                    check_profile(receipt[implementation][profile],implementation,header_bounds,body_bounds)
                for a,b in zip(receipt['go'][profile]['slow_peers'],receipt['rust'][profile]['slow_peers'],strict=True):
                    assert a['case']==b['case'] and a['request_prefix_sha256']==b['request_prefix_sha256']
                assert receipt['go'][profile]['idle_boundary']['request_sha256']==receipt['rust'][profile]['idle_boundary']['request_sha256']
                for a,b in zip(receipt['go'][profile]['idle_boundary']['responses'],receipt['rust'][profile]['idle_boundary']['responses'],strict=True):
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
    print(f'PASS: nine configured runtime responses, six progressing read deadlines and three real six-second idle boundaries per implementation on {platform.system()} (Go side replayed from {receipt["go_observations"]["path"]})')


if __name__=='__main__':
    main()
