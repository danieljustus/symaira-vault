#!/usr/bin/env python3
"""Real native MCP CLI/profile discovery and call-time authorization comparison."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_timeout import oracle_build_timeout, remove_worktree
from mcp_oracle import CONTRACT, HISTORICAL, ORDERED, pinned_go, tool_environment, validate_reference

if sys.flags.optimize:
    raise SystemExit('Parity acceptance requires unoptimized Python; remove -O / PYTHONOPTIMIZE.')

ROOT = Path(__file__).resolve().parents[2]
ORACLE = HISTORICAL
PROBE = ROOT / 'scripts/rust-port/mcp_process_seed.go.txt'
CANARIES = ['public-mcp-secret-6af2', 'public-nested-secret-88d1']
UNICODE_FIXTURE = 'public-fixture-user\u2028line\u2029paragraph'


def run(args, cwd, env, data=b'', timeout=120):
    return subprocess.run([str(a) for a in args], cwd=cwd, env=env, input=data,
                          capture_output=True, timeout=timeout)


def checked(args, cwd=ROOT, env=None, timeout=120):
    r = run(args, cwd, env or os.environ.copy(), timeout=timeout)
    if r.returncode:
        raise RuntimeError(f'{args[0]} failed ({r.returncode}): '+r.stderr.decode(errors='replace')[-2000:])
    return r.stdout


def isolated(home):
    env = tool_environment(os.environ)
    env.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home/'config'),
               XDG_DATA_HOME=str(home/'data'), XDG_CACHE_HOME=str(home/'cache'),
               SYMVAULT_VAULT=str(home/'vault'), SYMVAULT_TEST_KEYRING='memory',
               SYMVAULT_SECUREUI='none', SYMVAULT_PASSPHRASE='correct horse battery staple',
               SYMVAULT_ALLOW_ENV_PASSPHRASE='1', SYMVAULT_NO_ENV_WARNING='1', SYMVAULT_NO_NOTIFY='1',
               CI='1', NO_COLOR='1', TZ='UTC')
    return env


def profiles():
    result = [('legacy', {})]
    result += [('tier-'+tier, {'tier':tier}) for tier in ['read-only','standard','admin']]
    result += [
        ('admin-value-hidden', {'tier':'admin', 'exposeValueTools':False, 'approvalMode':'none', 'requireApproval':False}),
        ('admin-value-visible', {'tier':'admin', 'exposeValueTools':True, 'approvalMode':'none', 'requireApproval':False}),
        ('standard-command-override', {'tier':'standard', 'canRunCommands':True}),
        ('readonly-capability-overrides', {'tier':'read-only', 'canRunCommands':True, 'canWrite':True,
                                         'canReadValues':True, 'exposeValueTools':True, 'approvalMode':'none', 'requireApproval':False}),
        ('admin-command-disabled', {'tier':'admin','canRunCommands':False}),
        ('admin-tools-health-only', {'tier':'admin','allowed_tools':['health']}),
        ('admin-tools-self-only', {'tier':'admin','allowed_tools':['health','symaira_whoami']}),
        ('admin-api-explicit', {'tier':'admin','allowed_tools':['execute_api_request']}),
        ('standard-no-value-capabilities', {'tier':'standard','canReadValues':False,'canUseClipboard':False,'canUseAutotype':False}),
    ]
    result += [('builtin-'+name, {'__builtin':name}) for name in
               ['default','claude-code','codex','hermes','openclaw','opencode']]
    result += [('tier-'+tier+'-real-child', {'tier':tier, 'canRunCommands':True,
                'canReadValues':True, 'approvalMode':'none', 'requireApproval':False,
                'exposeValueTools':True, 'allowedExecutables':[Path(sys.executable).name]})
               for tier in ['read-only','standard','admin']]
    # Go scope is a literal root/prefix, not a shell glob.
    return [(name, dict(profile, allowedPaths=['public'])) for name,profile in result]


def messages(home=None):
    result = [(0, 'tools/list', {}),
        (1,'initialize',{'protocolVersion':'2025-11-25','clientInfo':{'name':'public-fixture','version':'1'},'capabilities':{}}),
        (2,'tools/list',{}),(3,'tools/list',{'include_all_tools':True}),(4,'ping',{})]
    calls = [('symaira_whoami',{}),('symaira_search',{'intent':'','return':'names'}),
        ('symaira_search',{'intent':'credential','return':'spec'}),
        ('get_entry_value',{'path':'public/fixture','field':'password'}),
        ('execute_api_request',{}),('run_command',{}),('execute_with_secret',{}),
        ('delete_entry',{'path':'public/missing'}),('symaira_delete',{'path':'public/missing'}),
        ('set_entry_field',{}),('secure_input',{}),('request_credential',{}),
        ('generate_totp',{'path':'public/fixture'}),('fetch',{'id':'public/fixture'}),
        ('public_unknown_tool',{})]
    result += [(5+i,'tools/call',{'name':name,'arguments':args}) for i,(name,args) in enumerate(calls)]
    if home is not None:
        for i,tool in enumerate(['run_command','execute_with_secret'],start=20):
            args = {'command':[sys.executable,str(home/'child.py'),str(home/(tool+'-marker.json'))],
                    'working_dir':str(home),'timeout':10}
            if tool=='run_command':
                args['env'] = {'FIXTURE_TOKEN':'public/fixture.password'}
            else:
                args['secret_refs'] = ['op://vault/public/fixture/password']
            result.append((i,'tools/call',{'name':tool,'arguments':args}))
        # Observe execution before the value reads. Avoid manufacturing a
        # read-then-execute tool-chain anomaly merely through fixture ordering.
        result = result[:8] + result[20:] + result[9:12] + [result[8]] + result[12:20]
    return result


def semantic(value, home):
    if isinstance(value,str):
        value = value.replace(str(home),'__HOME__')
        if value.startswith('<!-- DATA_'):
            match = re.fullmatch(r'<!-- DATA_([0-9a-f]{16}) label=(token|password|username|command_output) -->([\s\S]*)<!-- /DATA_\1 -->', value)
            assert match is not None, 'unpaired or malformed security data marker'
            value = f'<!-- DATA___RANDOM_ID__ label={match[2]} -->{match[3]}<!-- /DATA___RANDOM_ID__ -->'
        try:
            nested = json.loads(value)
        except (json.JSONDecodeError,ValueError):
            return value
        if isinstance(nested,(dict,list)):
            return {'json_text':semantic(nested,home)}
        return value
    if isinstance(value,list):
        return [semantic(v,home) for v in value]
    if isinstance(value,dict):
        if set(value)=={'exit_code','stdout','stderr','duration_ms'}:
            assert type(value['duration_ms']) is int and 0 <= value['duration_ms'] < 120_000
            value = dict(value,duration_ms='__MEASURED_DURATION_MS__')
        return {k:semantic(v,home) for k,v in value.items()}
    return value


def protocol_bytes(r, home, name, implementation, agent):
    stdout = r.stdout
    raw = stdout.decode('utf-8')
    assert not raw or stdout.endswith(b'\n'), (name,'unterminated stdout response')
    frames = [json.loads(line.decode('utf-8')) for line in stdout[:-1].split(b'\n')] if stdout else []
    assert all(isinstance(f,dict) and f.get('jsonrpc')=='2.0' for f in frames), (name,'non-protocol stdout')
    stderr = r.stderr.decode('utf-8')
    assert not any(c in stderr for c in CANARIES), (name,'credential in stderr')
    # Actual Go off-hours alerts use the real UTC wall clock. Suppress only
    # desktop UI through Go's supported opt-out; retain and validate every log.
    pattern = (r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} WARN anomaly detected '
               r'type=off_hours severity=low agent='+re.escape(agent)+
               r'(?: path=public/(?:fixture|missing) request_id=[0-9a-f]{16})?'
               r' description="Entry access during off-hours by agent '+re.escape(agent)+r'"')
    # Both implementations run the same detector since PLATFORM-002 (ADR 0034
    # item 29): the Rust port emits the identical off-hours line, so the same
    # narrow allowance applies to it. Anything else on stderr still fails.
    assert implementation in ('go','rust'), (name,'unknown implementation')
    assert len(stderr)<65536 and all(re.fullmatch(pattern,line)
                                  for line in stderr.splitlines()), (name,'unexpected stderr retained')
    return raw, stderr, semantic(frames,home)


def observe(binary, home, name, agent, implementation, observations):
    (home/'child.py').write_text('import os,json,sys\nfrom pathlib import Path\n'
        'value=os.environ.get("FIXTURE_TOKEN",os.environ.get("PUBLIC_FIXTURE_PASSWORD"))\n'
        'assert value=="public-mcp-secret-6af2"\n'
        'Path(sys.argv[1]).write_text(json.dumps({"received_expected_secret":True}))\n'
        'print("public child completed "+value)\n'
        'print("public child error stream "+value,file=sys.stderr)\n',encoding='utf-8')
    requests = messages(home)
    data = b''.join((json.dumps({'jsonrpc':'2.0','id':i,'method':m,'params':p})+'\n').encode() for i,m,p in requests)
    r = run([binary,'--quiet','mcp','--stdio','--agent',agent],home,isolated(home),data)
    retained = {'case':name,'exit':r.returncode,'stdout_raw':r.stdout.decode('utf-8',errors='replace'),
                'stderr_raw':r.stderr.decode('utf-8',errors='replace'),
                'stdin_raw':data.decode('utf-8'),'stdin_sha256':hashlib.sha256(data).hexdigest()}
    observations.append(retained)
    markers = {tool:json.loads((home/(tool+'-marker.json')).read_text())
               if (home/(tool+'-marker.json')).exists() else None
               for tool in ['run_command','execute_with_secret']}
    retained['child_markers'] = markers
    raw,stderr,frames = protocol_bytes(r,home,name,implementation,agent)
    assert r.returncode == 0 and len(frames) == len(requests), (name,'native process did not produce every response')
    assert [f.get('id') for f in frames] == [r[0] for r in requests], (name,'response ordering')
    retained.update(stdout_raw=raw,stderr_raw=stderr,child_markers=markers,frames=frames,
                    response_count=len(frames),stdout_is_only_protocol=True)
    return retained


def tool_error(frame_id, text):
    return {'jsonrpc':'2.0','id':frame_id,'result':{
        'content':[{'type':'text','text':text}],'isError':True}}


def declared_profile_difference(profile, a, b, go_catalog_names):
    frame_id = a['id']
    requests = {i:p for i,m,p in messages(Path('__HOME__')) if m=='tools/call'}
    name = requests.get(frame_id,{}).get('name')
    allowed = profile.get('allowed_tools',[])
    if allowed and frame_id in [0,2,3]:
        expected = json.loads(json.dumps(a))
        expected['result']['tools'] = [t for t in a['result']['tools'] if t['name'] in allowed]
        assert b==expected, 'explicit allowlist discovery must retain exact permitted Go definitions'
        return 'operator-allowlist-discovery'
    if allowed and name and name not in allowed:
        assert b==tool_error(frame_id,f'tool "{name}" is not allowed')
        if frame_id==8:
            assert all(c in json.dumps(a) for c in CANARIES), 'actual Go allowlist bypass control'
        return 'operator-allowlist-call'
    if allowed and name=='symaira_whoami':
        expected = json.loads(json.dumps(a))
        tools = expected['result']['content'][0]['text']['json_text']['tools']
        prior_unavailable = {tool['name']:tool for tool in tools['unavailable']}
        tools['available'] = [tool for tool in tools['available'] if tool in allowed]
        tools['unavailable'] = [({'name':tool,'code':'blocked_by_agent','reason':f'tool "{tool}" is not allowed'}
                                  if tool not in allowed else prior_unavailable[tool])
                                for tool in go_catalog_names if tool not in tools['available']]
        assert b==expected, 'complete restricted whoami must match actual Go registry and declared operator restriction'
        return 'operator-allowlist-whoami'
    if name=='symaira_delete' and profile.get('tier') in ['read-only','standard']:
        required = 'standard' if profile['tier']=='read-only' else 'admin'
        assert b==tool_error(frame_id,f'Tool "symaira_delete" requires tier "{required}"')
        assert a in [tool_error(frame_id,'entry not found: public/missing'),
                     {'jsonrpc':'2.0','id':frame_id,'error':{
                         'code':-32603,'message':'delete operations not permitted for this agent'}}]
        return 'canonical-delete-alias-tier'
    if profile=={'allowedPaths':['public']} and name=='get_entry_value':
        assert all(c in json.dumps(a) for c in CANARIES), 'actual legacy value-return control'
        assert b==tool_error(frame_id,'get_entry_value requires approval but no interactive approval is available')
        return 'legacy-missing-value-authorization'
    if platform.system()=='Windows' and profile.get('tier')=='admin' and name in ['delete_entry','symaira_delete','execute_with_secret']:
        operation = 'delete_entry' if name=='symaira_delete' else name
        go_text = operation+' approval failed: failed to read from terminal: file type does not support deadline'
        rust_text = operation+' requires approval but no TTY or GUI dialog available'
        if operation=='execute_with_secret':
            expected_go = {'jsonrpc':'2.0','id':frame_id,'error':{'code':-32603,'message':go_text}}
            expected_rust = {'jsonrpc':'2.0','id':frame_id,'error':{'code':-32603,'message':rust_text}}
        else:
            expected_go,expected_rust = tool_error(frame_id,go_text),tool_error(frame_id,rust_text)
        assert a==expected_go and b==expected_rust, 'both native headless approval denials must retain the exact error classification'
        return 'windows-headless-approval-denial'
    return None


def hostile_inputs():
    init = b'{"jsonrpc":"2.0","id":201,"method":"initialize"}\n'
    ping = b'{"jsonrpc":"2.0","id":203,"method":"ping"}\n'
    prefix = b'{"jsonrpc":"2.0","id":201,"method":"initialize","padding":"'
    def padded(size):
        return prefix+b'x'*(size-len(prefix)-2)+b'"}'
    limit = 8*1024*1024
    return [
        ('unterminated',init[:-1]),('crlf',init.replace(b'\n',b'\r\n')+ping),
        ('blank-line',b'\n'+init+ping),('null-frame',b'null\n'+init+ping),
        ('nul-byte',b'{"jsonrpc":"2.0","id":202,"method":"p\x00ing"}\n'+init+ping),
        ('two-objects-one-line',init[:-1]+ping+init+ping),
        ('duplicate-envelope-id',init+b'{"jsonrpc":"2.0","id":202,"id":204,"method":"ping"}\n'+ping),
        ('frame-exact-limit',padded(limit)+b'\n'+ping),
        ('frame-over-limit',padded(limit+1)+b'\n'+init+ping),
        ('unterminated-over-limit',padded(limit+1)),
        ('depth-10000',b'{"jsonrpc":"2.0","id":201,"method":"initialize","padding":'+b'['*9999+b'0'+b']'*9999+b'}\n'+ping),
        ('depth-10001',b'{"jsonrpc":"2.0","id":201,"method":"initialize","padding":'+b'['*10000+b'0'+b']'*10000+b'}\n'+init+ping),
    ]


def malformed_frame(frame, code, message):
    assert frame.get('id') is None and set(frame).issubset({'jsonrpc','id','error'})
    error = frame['error']
    assert error['code']==code and error['message']==message
    if 'data' in error:
        assert isinstance(error['data'],str) and error['data']


def compare_hostile(case, left, right, go_initialize_control):
    a,b = left['frames'],right['frames']
    assert len(a)==len(b), (case,'native hostile response count')
    declarations = []
    for index,(go_frame,rust_frame) in enumerate(zip(a,b,strict=True)):
        if go_frame==rust_frame:
            continue
        decision = None
        if case in {'blank-line','nul-byte','two-objects-one-line','depth-10001'} and index==0:
            malformed_frame(go_frame,-32700,'Parse error')
            malformed_frame(rust_frame,-32700,'Parse error')
            decision = 'native-json-parser-diagnostic'
        elif case=='duplicate-envelope-id' and index==1:
            assert go_frame=={'jsonrpc':'2.0','id':204,'result':{}}
            malformed_frame(rust_frame,-32700,'Parse error')
            assert 'duplicate field' in rust_frame['error']['data']
            decision = 'reject-duplicate-envelope-fields'
        elif case=='frame-over-limit' and index==0:
            assert go_frame==go_initialize_control, 'actual oversized Go initialization equals actual ordinary control'
            malformed_frame(rust_frame,-32600,'MCP frame exceeds 8 MiB limit')
            assert 'data' not in rust_frame['error']
            decision = 'bounded-eight-mib-frame'
        assert decision is not None, (case,index,'unexpected native hostile difference retained')
        declarations.append({'case':case,'index':index,'go':go_frame,'rust':rust_frame,'decision':decision})
    expected_counts = {'unterminated':0,'unterminated-over-limit':0,'crlf':2,
                       'frame-exact-limit':2,'depth-10000':2}
    assert len(a)==expected_counts.get(case,3), (case,'complete protocol recovery')
    if a:
        assert a[-1]==b[-1]=={'jsonrpc':'2.0','id':203,'result':{}}
    return declarations


def inventory(paths, root):
    h = hashlib.sha256()
    for p in paths:
        h.update(p.encode()+b'\0'+(root/p).read_bytes()+b'\0')
    return h.hexdigest()


def vault_snapshot(root):
    result = {}
    for path in sorted(root.rglob('*')):
        assert not path.is_symlink(), 'fixture must not follow a host symlink'
        if path.is_file():
            data = path.read_bytes()
            result[path.relative_to(root).as_posix()] = {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    return result


# ---------------------------------------------------------------------------
# Committed Go observations (capture once with Go, replay without Go).
#
# Every http_*/mcp process contract used to build the Go oracle from its pinned
# commit and run it next to the Rust binary. The Go half is now recorded once
# (`--capture-go`, Go required, no Rust binary needed) into
# scripts/rust-port/fixtures/go-observations/<contract>.<goos>.json and the
# default replay mode runs only Rust against those observations with the
# unchanged comparison logic. A missing, foreign-OS, foreign-oracle or
# foreign-argument file is a failure, never a skip.
#
# Normalisation before recording (so two captures are byte-identical): ports are
# fixed per contract, the encrypted seed vault / TLS identities are pinned in the
# file (a re-capture reuses them; --reseed regenerates), measured wall-clock
# values are replaced by the midpoint of the bounds the comparison already
# asserts (the real value is asserted inside those bounds at capture time, see
# bounded()), and per-run entropy that the comparison never reads byte-for-byte
# is replaced by length-preserving deterministic placeholders (stable_entropy()).
# ---------------------------------------------------------------------------
GO_OBS_DIR = Path(os.environ.get('SYMVAULT_GO_OBSERVATIONS_DIR') or ROOT / 'scripts/rust-port/fixtures/go-observations')
GO_OBS_SCHEMA = 1


def native_goos():
    return {'Darwin': 'darwin', 'Linux': 'linux', 'Windows': 'windows'}[platform.system()]


def go_obs_path(contract, goos=None):
    return GO_OBS_DIR / f'{contract}.{goos or native_goos()}.json'


def canonical_json(value):
    return json.dumps(value, indent=1, sort_keys=True, ensure_ascii=True) + '\n'


DATE_HEADER = re.compile(rb'(?i)(\r?\n|^)(date: )[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT')
LOG_TIMESTAMP = re.compile(rb'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}')
PEER_PORT = re.compile(rb'((?:remote=|from |->)\[?(?:127\.0\.0\.1|::1)\]?:)\d{5}')
EPOCH_DATE = 'Thu, 01 Jan 1970 00:00:00 GMT'
LARGE_REQUEST_BASE64 = 65536


DATA_MARKER = re.compile(rb'(DATA_)[0-9a-f]{16}')


OFF_HOURS_LINE = re.compile(rb'(?m)^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} WARN anomaly detected type=off_hours[^\n]*\n')
REQUEST_ID = re.compile(rb'(request_id=)[0-9a-f]{16}')
HEALTH_TIMESTAMP = re.compile(rb'("timestamp":")\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')


TOKEN_ID_BYTES = re.compile(rb'tok-\d{8}-[0-9a-f]{8}')


def _normalize_bytes(raw):
    raw = TOKEN_ID_BYTES.sub(b'tok-19700101-00000000', raw)
    # The off-hours detector logs only outside UTC working hours: a time-of-day dependent line, not an observation.
    raw = OFF_HOURS_LINE.sub(b'', raw)
    raw = REQUEST_ID.sub(lambda m: m[1] + b'0' * 16, raw)
    raw = HEALTH_TIMESTAMP.sub(lambda m: m[1] + b'1970-01-01T00:00:00Z', raw)
    raw = DATA_MARKER.sub(lambda m: m[1] + b'0123456789abcdef', raw)
    raw = DATE_HEADER.sub(lambda m: m[1] + m[2] + EPOCH_DATE.encode(), raw)
    raw = LOG_TIMESTAMP.sub(b'1970/01/01 00:00:00', raw)
    return PEER_PORT.sub(lambda m: m[1] + b'00000', raw)


def normalize_go_record(value):
    """Strip the per-run bytes no comparison reads: Date headers, log timestamps, peer ports.

    Same-length replacements (framing stays valid). Request bodies above 64 KiB are not stored: the
    driver regenerates them and the comparison reads only request_sha256.
    """
    import base64
    if isinstance(value, (list, tuple)):
        if len(value) == 2 and isinstance(value[0], str) and value[0].lower() == 'date' and isinstance(value[1], str):
            return [value[0], EPOCH_DATE]
        return [normalize_go_record(v) for v in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key == 'request_base64' and isinstance(item, str) and len(item) > LARGE_REQUEST_BASE64:
                result[key] = ''
            elif (key.endswith('_base64') or key in ('stdout', 'stderr')) and isinstance(item, str) and (key.endswith('_base64') or item[:1] and re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', item)):
                try:
                    raw = base64.b64decode(item, validate=True)
                except Exception:
                    result[key] = item
                else:
                    result[key] = base64.b64encode(_normalize_bytes(raw)).decode()
            else:
                result[key] = normalize_go_record(item)
        return result
    if isinstance(value, str) and len(value) < 4_000_000:
        return _normalize_bytes(value.encode('utf-8', 'surrogatepass')).decode('utf-8', 'surrogatepass')
    return value


def save_go_observations(contract, data, contract_args, normalization, go_version, oracle=None):
    """Write the committed Go observations of one contract (canonical, byte-stable)."""
    data = normalize_go_record(data)
    document = dict(schema=GO_OBS_SCHEMA, contract=contract, goos=native_goos(), goarch=platform.machine(),
                    oracle_commit=oracle or ORACLE, go_version=go_version, contract_args=contract_args,
                    normalization=normalization, data=data)
    path = go_obs_path(contract)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(document), encoding='utf-8')
    return path


def load_go_observations(contract, contract_args=None, oracle=None, required=True, goos=None):
    """Return the committed document; missing/mismatched observations FAIL (never skip)."""
    path = go_obs_path(contract, goos)
    if not path.is_file():
        if not required:
            return None
        raise SystemExit(f'FAIL: no committed Go observations for {contract} on {native_goos()}: {path} '
                         '(run `make go-observations-capture-http` with Go installed, then commit)')
    raw = path.read_bytes()
    document = json.loads(raw)
    assert document.get('schema') == GO_OBS_SCHEMA, (contract, 'observation schema')
    assert document['contract'] == contract and document['goos'] == (goos or native_goos()), (contract, 'observation identity')
    assert document['oracle_commit'] == (oracle or ORACLE), (contract, 'observation oracle commit')
    assert contract_args is None or document['contract_args'] == contract_args, (contract, 'observation contract args',
                                                                                  document['contract_args'], contract_args)
    assert canonical_json(document).encode() == raw, (contract, 'observation file is not canonical')
    document['data'] = restore_pairs(document['data'])
    document['_path'] = str(path)
    document['_sha256'] = hashlib.sha256(raw).hexdigest()
    return document


PAIR_LISTS = {'headers', 'headers_without_date'}
TUPLE_ROWS = {'entries'}


def restore_pairs(value):
    """JSON turns the live (name, value) header tuples into lists; restore them so == against Rust holds."""
    if isinstance(value, list):
        return [restore_pairs(v) for v in value]
    if isinstance(value, dict):
        return {k: ([tuple(pair) for pair in v] if k in PAIR_LISTS and isinstance(v, list) and all(isinstance(p, list) and len(p) == 2 for p in v)
                    else [tuple(e) for e in v] if k in TUPLE_ROWS and isinstance(v, list) and all(isinstance(e, list) for e in v)
                    else restore_pairs(v)) for k, v in value.items()}
    return value


def provenance(document):
    return dict(path=Path(document['_path']).relative_to(ROOT).as_posix() if Path(document['_path']).is_relative_to(ROOT) else document['_path'],
                sha256=document['_sha256'], goos=document['goos'], goarch=document['goarch'],
                oracle_commit=document['oracle_commit'], go_version=document['go_version'],
                normalization=document['normalization'])


BLOB_THRESHOLD = 256 * 1024


def pack_tree(root):
    """{relative path: base64 bytes} of every file below root; files above 256 KiB become content-addressed blobs.

    A blob is stored once, as raw bytes, in go-observations/blobs/<sha256> (shared by every observation and OS that records the same
    bytes) and referenced as {"blob": sha256}.
    """
    import base64
    packed = {}
    for p in sorted(Path(root).rglob('*')):
        if not p.is_file():
            continue
        data = p.read_bytes()
        name = p.relative_to(root).as_posix()
        if len(data) > BLOB_THRESHOLD:
            digest = hashlib.sha256(data).hexdigest()
            blob = GO_OBS_DIR / 'blobs' / digest
            blob.parent.mkdir(parents=True, exist_ok=True)
            if not blob.exists():
                blob.write_bytes(data)
            packed[name] = {'blob': digest, 'bytes': len(data)}
        else:
            packed[name] = base64.b64encode(data).decode()
    return packed


def unpack_tree(packed, root):
    import base64
    for name, entry in packed.items():
        target = Path(root) / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(entry, dict):
            data = (GO_OBS_DIR / 'blobs' / entry['blob']).read_bytes()
            assert hashlib.sha256(data).hexdigest() == entry['blob'] and len(data) == entry['bytes'], ('observation blob corrupt', entry['blob'])
            target.write_bytes(data)
        else:
            target.write_bytes(base64.b64decode(entry))
    return Path(root)


def bounded(value, lower, upper, what):
    """Assert a measured value inside the contract's bounds; record the bounds' midpoint."""
    assert lower <= value <= upper, (what, value, lower, upper)
    return (lower + upper) / 2


def canonical_close(row):
    """Record a slow peer's terminal state in its canonical form.

    Go races a complete 400 JSON error against a bare close when the absolute read deadline expires,
    and the peer sees EOF or a reset depending on scheduling. The comparison accepts every one of
    those outcomes, so the recording is canonicalised to the bare EOF (the verdict was asserted on
    the real outcome at capture time, before this call).
    """
    assert row['peer_terminal_observed'] and not row['forced_client_close']
    row['received_base64'] = ''
    row.pop('response', None)
    row['termination'] = 'actual-empty-eof-or-reset'
    row['peer_terminal_kind'] = 'eof'
    row['sender_stop_reason'] = 'write-failed-after-peer-close:BrokenPipeError'
    return row


def redact_path(row, keys, path):
    """Replace a per-run temp path inside base64 text members."""
    import base64
    for key in keys:
        if row.get(key):
            row[key] = base64.b64encode(base64.b64decode(row[key]).replace(str(path).encode(), b'<HOME>')).decode()
    return row


def at_least_recorded(value, minimum, what):
    """Assert a measured lower bound; record the bound itself (the comparison only reads `>=`)."""
    assert value >= minimum, (what, value, minimum)
    return minimum


EPOCH_FIELD = re.compile(r'("[a-z_]*_at\\?"\s*:\s*)(\d{9,11})')
ISO_TIMESTAMP = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})')
TOKEN_ID = re.compile(r'tok-\d{8}-[0-9a-f]{8}')
OAUTH_LABEL = re.compile(r'oauth-[0-9a-f]{8}')


def scrub_parts(record, keys, seen=None):
    """stable_entropy() on the named members only (deterministic rows stay byte-exact)."""
    seen = {} if seen is None else seen
    for key in keys:
        if key in record:
            record[key] = stable_entropy(record[key], seen)
    return record


def stable_entropy(value, seen=None):
    """Replace 32/64-hex entropy by deterministic same-length placeholders.

    Applies to strings and, recursively, to base64 payloads that decode to text. Equal inputs map to
    equal placeholders (first-seen index), so structural equalities survive.
    """
    import base64
    seen = {} if seen is None else seen
    hexish = re.compile(r'(?<![0-9a-f])([0-9a-f]{64}|[0-9a-f]{32})(?![0-9a-f])')

    def placeholder(match):
        token = match.group(1)
        if token not in seen:
            seen[token] = hashlib.sha256(f'placeholder-{len(seen)}'.encode()).hexdigest()
        return seen[token][:len(token)]

    def scrub_text(text):
        text = EPOCH_FIELD.sub(lambda m: m[1] + '0' * len(m[2]), text)
        text = ISO_TIMESTAMP.sub('1970-01-01T00:00:00Z', text)
        text = TOKEN_ID.sub('tok-19700101-00000000', text)
        text = OAUTH_LABEL.sub('oauth-00000000', text)
        return hexish.sub(placeholder, text)

    def walk(item):
        if isinstance(item, str):
            return scrub_text(item)
        if isinstance(item, float):
            return 0.0
        if isinstance(item, (list, tuple)):
            return [walk(v) for v in item]
        if isinstance(item, dict):
            return {scrub_text(k): ('0000' if k == 'prefix' and isinstance(v, str) and len(v) == 4 else
                                    walk_b64(v) if k.endswith('_base64') and isinstance(v, str) else walk(v)) for k, v in item.items()}
        return item

    def walk_b64(text):
        try:
            raw = base64.b64decode(text, validate=True).decode('utf-8')
        except Exception:
            return text
        return base64.b64encode(scrub_text(raw).encode('utf-8')).decode()

    return walk(value)


@contextlib.contextmanager
def oracle_checkout(reference):
    """Detached worktree of the pinned oracle commit (capture mode only; needs Git, not Go)."""
    with tempfile.TemporaryDirectory(prefix='symvault-go-capture-') as raw:
        tree = Path(raw) / 'oracle'
        checked(['git', 'worktree', 'add', '--detach', tree, reference])
        try:
            yield Path(raw), tree
        finally:
            remove_worktree(lambda: checked(['git', 'worktree', 'remove', '--force', tree]), 'oracle worktree')


def oracle_inventory(tree, reference):
    files = checked(['git', 'ls-tree', '-r', '--name-only', reference]).decode().splitlines()
    sources = sorted(p for p in files if p in {'go.mod', 'go.sum'} or p.endswith('.go') and not p.endswith('_test.go'))
    embedded = sorted(p for p in files if p.startswith('internal/mcp/apitemplates/builtin/'))
    assert len(embedded) == 17
    return sources, embedded


@contextlib.contextmanager
def go_capture_session(contract, args, helpers, builder=None, reference=ORACLE, env=None):
    """Capture mode: build the Go CLI and fixture helpers from the pinned oracle commit.

    helpers: {receipt-name: (cmd-dir, source bytes)}; every helper is written below
    scripts/rust-port/cmd/<cmd-dir>/main.go of the detached oracle worktree and built.
    Yields a dict with base, tree, go, helper binaries, prior observations (to reuse the
    pinned seed vault / identities unless --reseed) and the oracle receipt fields.
    """
    prior = None if args.reseed else load_go_observations(contract, required=False)
    if prior is None and not args.reseed:
        # The encrypted seed vaults are OS independent: a first capture on another OS reuses the pinned seeds of an existing
        # observation (so Go and Rust see identical vault bytes on every OS and the large blobs are stored once).
        for other in ('darwin', 'linux'):
            if other != native_goos():
                prior = load_go_observations(contract, required=False, goos=other)
                if prior is not None:
                    break
    build_env = env
    with oracle_checkout(reference) as (base, tree):
        sources, embedded = oracle_inventory(tree, reference)
        info = dict(oracle_sources=inventory(sources, tree), oracle_embedded=inventory(embedded, tree))
        suffix = '.exe' if os.name == 'nt' else ''
        go = base / ('go-cli' + suffix)

        def build(binary, package):
            if builder is not None:
                builder(tree, binary, package)
            elif os.environ.get('SYMVAULT_ORACLE_BUILD_RUNNER'):
                from oracle_build import build_go
                build_go(tree, binary, package, [])
            else:
                checked(['go', 'build', '-trimpath', '-buildvcs=false', '-o', binary, package], tree, build_env,
                        timeout=oracle_build_timeout())

        binaries = {}
        for name, (directory, source) in helpers.items():
            target = tree / 'scripts/rust-port/cmd' / directory
            target.mkdir()
            (target / 'main.go').write_bytes(source)
            binaries[name] = base / ('go-' + name + suffix)
        build(go, '.')
        for name, (directory, _) in helpers.items():
            build(binaries[name], './scripts/rust-port/cmd/' + directory)
        info['go_binary_sha256'] = hashlib.sha256(go.read_bytes()).hexdigest()
        for name, binary in binaries.items():
            info[name + '_binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        yield dict(base=base, tree=tree, go=go, helpers=binaries, prior=prior['data'] if prior else None,
                   info=info, go_version=go_version_of(build_env))


def pinned_seed(session, key, seed_home, produce):
    """Tokens + seed vault for one fixture; a re-capture reuses the pinned bytes (determinism)."""
    session.setdefault('seeds', {})
    prior = ((session['prior'] or {}).get('seeds') or {}).get(key)
    seed_home.mkdir(parents=True, exist_ok=True)
    if prior:
        unpack_tree(prior['vault'], seed_home / 'vault')
        tokens = prior['tokens']
    else:
        tokens = produce(seed_home)
        prior = dict(tokens=tokens, vault=pack_tree(seed_home / 'vault'))
    session['seeds'][key] = prior
    return tokens


def replay_seed(data, key, seed_home):
    """Replay counterpart: write the recorded seed vault, return its tokens."""
    entry = data['seeds'][key]
    Path(seed_home).mkdir(parents=True, exist_ok=True)
    unpack_tree(entry['vault'], Path(seed_home) / 'vault')
    return entry['tokens']


def go_version_of(env=None):
    return subprocess.check_output(['go', 'env', 'GOVERSION'], env=env or os.environ.copy()).decode().strip()


def add_capture_arguments(parser, rust_required=True):
    parser.add_argument('--rust', type=Path, required=rust_required)
    parser.add_argument('--receipt', type=Path, required=rust_required)
    parser.add_argument('--capture-go', action='store_true',
                        help='build/run ONLY the Go oracle and write the committed Go observations (Go required)')
    parser.add_argument('--reseed', action='store_true',
                        help='with --capture-go: regenerate the pinned seed vault / identities instead of reusing them')


def capture_arguments_ok(args):
    if not args.capture_go:
        assert args.rust and args.receipt, '--rust and --receipt are required in replay mode'
    return args.capture_go


# ---------------------------------------------------------------------------
# Termination-signal contract (issue #1242, Unix only).
#
# Go's serve command subscribes SIGINT/SIGTERM (and SIGQUIT), cancels its
# context and returns success: exit 0, no extra output, runtime port/TLS
# records removed. A stdio server answers at most one more frame after the
# signal and always waits <= 2 s for its blocked stdin read. Each case below is
# run against the real Go binary and the Rust binary in separate disposable
# HOMEs, synchronised on observable readiness (never a bare sleep).
# ---------------------------------------------------------------------------
# Windows has no SIGQUIT; the signal contract is Unix-only and asserts that
# before use, so the table stays empty there and the module still imports.
SIGNALS = [] if os.name == 'nt' else [('SIGINT', signal.SIGINT), ('SIGTERM', signal.SIGTERM), ('SIGQUIT', signal.SIGQUIT)]
SIGNAL_MODES = ('stdio', 'http')
SIGNAL_STATES = ('idle', 'after-init', 'idle-stale-runtime')
STALE_RUNTIME = {'.runtime-port': b'{"port":1,"bind":"127.0.0.1"}', '.runtime-tls-cert': b'{}'}
# Files whose bytes differ between any two runs of the SAME implementation
# (random key material, timestamps): only their existence is compared.
RANDOM_CONTENT = {'vault/mcp-server.crt', 'vault/mcp-server.key', 'vault/mcp-server.enroll-secret',
                  'vault/audit-auth-failures.log', 'vault/audit-token-cleanup.log'}
# Startup-only differences that exist without any signal and belong to other
# slices. Pinned exactly: a new or vanished difference fails the harness.
STARTUP_ONLY_DIFFERENCES = {
    'stdio': {'only_go': set(), 'only_rust': set(), 'content': {'vault/config.yaml'}},
    'http': {'only_go': {'vault/audit-auth-failures.log', 'vault/audit-token-cleanup.log'}, 'only_rust': set(),
             'content': {'vault/config.yaml'}},
}
STDIO_INITIALIZE = (b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25",'
                    b'"clientInfo":{"name":"public-fixture","version":"1"},"capabilities":{}}}\n')
HTTP_BINDING_MARKER = b'without TLS; bearer tokens travel in cleartext'


class PipeCapture:
    """Drain both pipes of an owned child into bounded buffers."""
    LIMIT = 1024 * 1024

    def __init__(self, process):
        self.buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        self.condition = threading.Condition()
        self.workers = []
        for name, pipe in [('stdout', process.stdout), ('stderr', process.stderr)]:
            worker = threading.Thread(target=self._drain, args=(name, pipe), daemon=True)
            worker.start()
            self.workers.append(worker)

    def _drain(self, name, pipe):
        try:
            while True:
                data = os.read(pipe.fileno(), 4096)
                if not data:
                    break
                with self.condition:
                    assert len(self.buffers[name]) + len(data) <= self.LIMIT, name + ' exceeds capture bound'
                    self.buffers[name] += data
                    self.condition.notify_all()
        finally:
            pipe.close()
            with self.condition:
                self.condition.notify_all()

    def wait_for(self, name, predicate, deadline):
        with self.condition:
            while not predicate(bytes(self.buffers[name])):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self.condition.wait(min(remaining, 0.05))
        return True

    def finish(self):
        for worker in self.workers:
            worker.join(timeout=10)
        assert not any(worker.is_alive() for worker in self.workers), 'output readers did not reach EOF'
        return bytes(self.buffers['stdout']), bytes(self.buffers['stderr'])


def tree_snapshot(root):
    result = {}
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[rel] = {'kind': 'symlink'}
        elif path.is_dir():
            result[rel] = {'kind': 'dir'}
        else:
            data = path.read_bytes()
            result[rel] = {'kind': 'file', 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    return result


def comparable(snapshot):
    """Drop the content of files that are random in every run."""
    return {path: ({'kind': 'file'} if path in RANDOM_CONTENT and row['kind'] == 'file' else row)
            for path, row in snapshot.items()}


def settled_snapshot(root, deadline):
    """Snapshot after two consecutive identical reads (startup writes done)."""
    previous = None
    while True:
        current = tree_snapshot(root)
        if current == previous or time.monotonic() > deadline:
            return current
        previous = current
        time.sleep(0.05)


def snapshot_delta(before, after):
    before, after = comparable(before), comparable(after)
    return {'removed': sorted(set(before) - set(after)), 'added': sorted(set(after) - set(before)),
            'changed': sorted(path for path in set(before) & set(after) if before[path] != after[path])}


def startup_differences(go_final, rust_final):
    go, rust = comparable(go_final), comparable(rust_final)
    return {'only_go': set(go) - set(rust), 'only_rust': set(rust) - set(go),
            'content': {path for path in set(go) & set(rust) if go[path] != rust[path]}}


def group_members(pgid):
    out = subprocess.run(['ps', '-axo', 'pid=,pgid='], capture_output=True, text=True, check=True).stdout
    return sorted(int(pid) for pid, group in (line.split() for line in out.splitlines() if line.strip())
                  if int(group) == pgid)


def normalise_process_text(text, home):
    """Normalise only PIDs, ports, timestamps and temp paths."""
    text = text.replace(str(home), '<HOME>')
    text = re.sub(r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}', '<TIMESTAMP>', text)
    text = re.sub(r'(127\.0\.0\.1|\[::1\]):\d+', r'\1:<PORT>', text)
    return re.sub(r'\bpid[= ]\d+', 'pid=<PID>', text)


def free_loopback_port():
    with socket.socket() as selection:
        selection.bind(('127.0.0.1', 0))
        return selection.getsockname()[1]


def http_initialize(port, token):
    body = STDIO_INITIALIZE.strip()
    request = (f'POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n'
               f'Authorization: Bearer {token}\r\nX-Symaira-Agent: fixture\r\n'
               # Go warns on stderr for an Origin-less /mcp request; that warning is a request-handling
               # difference outside this slice, so the fixture sends an allowed loopback Origin.
               f'Origin: http://127.0.0.1:{port}\r\n'
               'Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n'
               f'Content-Length: {len(body)}\r\n\r\n').encode() + body
    received = bytearray()
    with socket.create_connection(('127.0.0.1', port), timeout=15) as connection:
        connection.sendall(request)
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            received += chunk
    head, _, payload = bytes(received).partition(b'\r\n\r\n')
    assert head.startswith(b'HTTP/1.1 200 '), 'initialize must complete before the signal'
    assert b'"protocolVersion"' in payload, 'initialize must return a result'
    return head.split(b'\r\n')[0].decode()


def stop_group(process):
    """Kill only the process group this harness started."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_signal_case(binary, home, env, mode, state, sig_name, sig, port=None, token=None):
    assert mode in SIGNAL_MODES and state in SIGNAL_STATES and sig in dict(SIGNALS).values()
    vault = home / 'vault'
    if state == 'idle-stale-runtime':
        for name, data in STALE_RUNTIME.items():
            (vault / name).write_bytes(data)
    if mode == 'stdio':
        args = [binary, '--quiet', 'mcp', '--stdio', '--agent', 'fixture']
    else:
        args = [binary, '--quiet', 'mcp', '--bind', '127.0.0.1', '--port', str(port)]
    process = subprocess.Popen([str(a) for a in args], cwd=home, env=env, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    capture = PipeCapture(process)
    row = {'mode': mode, 'state': state, 'signal': sig_name}
    deadline = time.monotonic() + 30
    try:
        if mode == 'http':
            # The cleartext-bind confirmation is part of the Go CLI contract.
            process.stdin.write(b'y\n')
            process.stdin.close()
            process.stdin = None
            assert capture.wait_for('stderr', lambda data: HTTP_BINDING_MARKER in data, deadline), 'server never announced its listener'
            while True:
                assert process.poll() is None, 'server exited before serving'
                try:
                    socket.create_connection(('127.0.0.1', port), timeout=.2).close()
                    break
                except OSError:
                    assert time.monotonic() < deadline, 'server never listened'
                    time.sleep(.02)
        else:
            # server.New creates the agent audit log after the signal subscription exists.
            while not (vault / 'audit-fixture.log').exists():
                assert process.poll() is None, 'stdio server exited before serving'
                assert time.monotonic() < deadline, 'stdio server never became ready'
                time.sleep(.02)
        if state == 'after-init':
            if mode == 'stdio':
                process.stdin.write(STDIO_INITIALIZE)
                process.stdin.flush()
                assert capture.wait_for('stdout', lambda data: data.endswith(b'\n'), deadline), 'initialize response missing'
                row['initialize'] = 'stdio-response'
            else:
                row['initialize'] = http_initialize(port, token)
        ready = settled_snapshot(home, time.monotonic() + 5)
        started = time.monotonic()
        os.kill(process.pid, sig)
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            raise AssertionError(f'{mode}/{state}/{sig_name}: process ignored the signal for 15 s')
        row['elapsed_seconds'] = time.monotonic() - started
    finally:
        if process.poll() is None:
            stop_group(process)
            process.wait(timeout=15)
        # A surviving descendant keeps the output pipes open: look for it, and
        # reap only the group this harness started, before waiting for EOF.
        row['orphans'] = group_members(process.pid)
        stop_group(process)
        stdout, stderr = capture.finish()
        if process.stdin:
            process.stdin.close()
    assert not row['orphans'], (mode, state, sig_name, 'orphaned process group members', row['orphans'])
    if mode == 'http':
        try:
            socket.create_connection(('127.0.0.1', port), timeout=.3).close()
            row['listener_closed'] = False
        except OSError:
            row['listener_closed'] = True
        assert row['listener_closed'], 'listener still accepting after exit'
    final = tree_snapshot(home)
    text = stderr.decode('utf-8')
    row.update(exit_code=process.returncode, stdout=stdout.decode('utf-8'),
               stderr=normalise_process_text(text, home), delta=snapshot_delta(ready, final),
               final=comparable(final), final_raw=final, ready_files=sorted(ready))
    return row


def compare_signal_rows(go_row, rust_row):
    """Strict Go/Rust equality for one case; returns the startup-only differences."""
    key = (go_row['mode'], go_row['state'], go_row['signal'])
    assert key == (rust_row['mode'], rust_row['state'], rust_row['signal'])
    for field in ('exit_code', 'stdout', 'stderr', 'delta', 'orphans', 'initialize'):
        assert go_row.get(field) == rust_row.get(field), (key, field, go_row.get(field), rust_row.get(field))
    differences = startup_differences(go_row['final_raw'], rust_row['final_raw'])
    assert differences == STARTUP_ONLY_DIFFERENCES[go_row['mode']], (key, 'unpinned startup difference', differences)
    return differences


def signal_suite(go, rust, base, seed_vault, mode, tokens=None, repeats=2):
    """Run every state x signal for one mode; return the rows and executed count."""
    rows = []
    for state in SIGNAL_STATES:
        for sig_name, sig in SIGNALS:
            observed = {}
            for implementation, binary in [('go', go), ('rust', rust)]:
                observed[implementation] = []
                for attempt in range(repeats):
                    home = base / f'signal-{mode}-{state}-{sig_name}-{implementation}-{attempt}'
                    home.mkdir()
                    shutil.copytree(seed_vault, home / 'vault')
                    port = free_loopback_port() if mode == 'http' else None
                    row = run_signal_case(binary, home, isolated(home), mode, state, sig_name, sig, port,
                                          (tokens or {}).get('full'))
                    row['implementation'] = implementation
                    row['attempt'] = attempt
                    observed[implementation].append(row)
                    rows.append(row)
            go_first, go_rest = observed['go'][0], observed['go'][1:]
            for repeat in go_rest:
                for field in ('exit_code', 'stdout', 'stderr', 'delta', 'initialize'):
                    assert repeat.get(field) == go_first.get(field), (mode, state, sig_name, 'Go oracle is nondeterministic', field)
            for rust_row in observed['rust']:
                compare_signal_rows(go_first, rust_row)
            # Positive controls: Go really exits successfully, and the runtime port
            # record present at readiness is really gone afterwards.
            assert go_first['exit_code'] == 0, (mode, state, sig_name, 'Go exits 0 on a handled signal')
            expects_port = mode == 'http' or state == 'idle-stale-runtime'
            assert ('vault/.runtime-port' in go_first['ready_files']) == expects_port, (mode, state, 'runtime port at readiness')
            assert ('vault/.runtime-port' in go_first['delta']['removed']) == expects_port, (mode, state, 'runtime port removed by shutdown')
            assert 'vault/.runtime-tls-cert' not in go_first['final'], (mode, state, 'runtime TLS record cleared')
    return rows


def signals_main(args):
    go, rust = args.go_cli.resolve(), args.rust.resolve()
    assert platform.system() in {'Darwin', 'Linux'}, 'signal contract is Unix-only; Windows Ctrl-C/Ctrl-Break is not covered'
    receipt = {'passed': False, 'native_os': platform.system(), 'architecture': platform.machine(),
               'candidate_commit': checked(['git', 'rev-parse', 'HEAD']).decode().strip(),
               'go_binary_sha256': hashlib.sha256(go.read_bytes()).hexdigest(),
               'rust_binary_sha256': hashlib.sha256(rust.read_bytes()).hexdigest(),
               'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               'startup_only_differences': {k: {a: sorted(b) for a, b in v.items()} for k, v in STARTUP_ONLY_DIFFERENCES.items()},
               'rows': [], 'executed': {}}
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-mcp-signals-') as raw:
            base = Path(raw)
            seed_home = base / 'seed'
            seed_home.mkdir()
            (seed_home / 'profile.json').write_text(json.dumps({'tier': 'admin', 'allowedPaths': ['public']}), encoding='utf-8')
            checked([args.go_seed, '--root', seed_home / 'vault', '--profile', seed_home / 'profile.json',
                     '--builtin', '', '--agent', 'fixture'], seed_home, isolated(seed_home))
            rows = signal_suite(go, rust, base, seed_home / 'vault', 'stdio')
            receipt['rows'] += [{k: v for k, v in r.items() if k not in {'final', 'final_raw'}} for r in rows]
            receipt['executed']['stdio'] = len(rows)
            receipt['passed'] = True
    finally:
        args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print('PASS: ' + ', '.join(f'{count} {mode} signal runs' for mode, count in receipt['executed'].items()) + f' on {platform.system()}')


def candidate_paths():
    return sorted(p for p in checked(['git','ls-files','--cached','--others','--exclude-standard']).decode().splitlines()
                  if p.startswith(('crates/','third_party/','testdata/','internal/mcp/apitemplates/builtin/'))
                  or p in {'Cargo.toml','Cargo.lock','.gitattributes','scripts/rust-port/mcp_process_contract.py',
                           'scripts/rust-port/mcp_process_seed.go.txt','scripts/rust-port/mcp_oracle.py',
                           'scripts/rust-port/build_timeout.py',
                           '.github/workflows/rust-mcp-process.yml'})


PROCESS_CONTRACT = 'mcp-process'
PROCESS_NORMALIZATION = [
    'seed vaults (22 profiles; the last one doubles as the hostile-input vault) and the Go loaded-profile documents pinned in the file',
    'fixture HOME prefix replaced by __HOME__ in the retained stdin/stdout/stderr text, off-hours anomaly warnings (time-of-day dependent) '
    'removed from retained stderr, measured duration_ms in retained stdout set to 0 and the random DATA_ ids to a fixed id (frames were already '
    'normalised by the driver and are what is compared)',
    'compiler recorded as version, binary sha256 and build settings (cache paths are machine specific)']
RAW_KEYS = ('stdin_raw', 'stdout_raw', 'stderr_raw')
DURATION = re.compile(r'(duration_ms\\*"?:)\d+')


def scrub_process_row(row, home):
    for key in RAW_KEYS:
        if key in row:
            row[key] = DURATION.sub(lambda m: m[1] + '0', row[key].replace(str(home), '__HOME__'))
    if 'stdin_raw' in row:
        row['stdin_sha256'] = hashlib.sha256(row['stdin_raw'].encode()).hexdigest()  # of the HOME-normalised text
    return row


def check_profile_row(implementation, name, row):
    """Value-permission and credential controls on one implementation's profile row (unchanged assertions)."""
    if name.endswith('-real-child'):
        expected_marker = {'received_expected_secret': True} if name == 'tier-admin-real-child' else None
        assert all(marker == expected_marker for marker in row['child_markers'].values()), (implementation, name, 'actual executor control')
    allowed_value = name in {'tier-admin', 'admin-value-visible', 'readonly-capability-overrides',
                             'admin-command-disabled', 'tier-read-only-real-child',
                             'tier-standard-real-child', 'tier-admin-real-child'}
    if implementation == 'go':
        allowed_value |= name in {'legacy', 'admin-tools-health-only', 'admin-tools-self-only', 'admin-api-explicit'}
    value_frame = next(frame for frame in row['frames'] if frame['id'] == 8)
    assert all((c in json.dumps(value_frame)) == allowed_value for c in CANARIES), (implementation, name, 'value permission control')
    for frame in row['frames']:
        if frame['id'] not in [8, 18]:
            assert not any(c in json.dumps(frame) for c in CANARIES), (implementation, name, 'credential outside authorized value frame')
    fetch_frame = next(frame for frame in row['frames'] if frame['id'] == 18)
    assert all((c in json.dumps(fetch_frame)) == (allowed_value and name != 'legacy')
               for c in CANARIES), (implementation, name, 'fetch value permission control')
    unicode_frames = [frame for frame in row['frames'] if UNICODE_FIXTURE in json.dumps(frame, ensure_ascii=False)]
    expected_unicode_frames = [value_frame, fetch_frame] if name == 'admin-value-visible' else []
    assert unicode_frames == expected_unicode_frames, (implementation, name, 'Unicode encrypted-store permission control')
    assert UNICODE_FIXTURE not in row['stderr_raw'], (implementation, name, 'Unicode value in stderr')


def observe_hostile(binary, base, seed_vault, name, data, implementation):
    home = base / ('hostile-' + name + '-' + implementation)
    home.mkdir()
    shutil.copytree(seed_vault, home / 'vault')
    result = run([binary, '--quiet', 'mcp', '--stdio', '--agent', 'fixture'], home, isolated(home), data)
    retained = {'case': name, 'exit': result.returncode, 'input_bytes': len(data), 'input_sha256': hashlib.sha256(data).hexdigest(),
                'stdout_raw': result.stdout.decode('utf-8', errors='replace'),
                'stderr_raw': result.stderr.decode('utf-8', errors='replace')}
    raw, stderr, frames = protocol_bytes(result, home, name, implementation, 'fixture')
    assert result.returncode == 0 and not any(c in raw for c in CANARIES)
    retained.update(stdout_raw=raw, stderr_raw=stderr, frames=frames, stdout_is_only_protocol=True)
    return retained


def compare_profiles(receipt):
    for left, right in zip(receipt['go'], receipt['rust'], strict=True):
        go_names = next(frame for frame in left['frames'] if frame['id'] == 6)['result']['content'][0]['text']['json_text']
        for a, b in zip(left['frames'], right['frames'], strict=True):
            if a != b:
                difference = {'case': left['case'], 'id': a.get('id'), 'go': a, 'rust': b}
                declared = declared_profile_difference(dict(profiles())[left['case']], a, b, go_names)
                if declared:
                    receipt['declared_differences'].append(dict(difference, decision=declared))
                else:
                    receipt['differences'].append(difference)


def seed_profile(go_seed_tools, base, name, profile):
    """Seed one profile's encrypted vault with the Go helper; returns (seed_home, loaded document, agent)."""
    seed_home = base / (name + '-seed')
    seed_home.mkdir()
    profile_file = seed_home / 'profile.json'
    profile = dict(profile)
    builtin = profile.pop('__builtin', '')
    agent = builtin or 'fixture'
    profile_file.write_text(json.dumps(profile), encoding='utf-8')
    profile_seed = go_seed_tools['unicode'] if name == 'admin-value-visible' else go_seed_tools['seed']
    loaded = checked([profile_seed, '--root', seed_home / 'vault', '--profile', profile_file,
                      '--builtin', builtin, '--agent', agent], seed_home, isolated(seed_home))
    return seed_home, json.loads(loaded), agent


def capture_process(args):
    """Go half only: build the corrected oracle, observe every profile and hostile input, write the observations."""
    reference = ORDERED
    validate_reference(ROOT)
    prior = None if args.reseed else load_go_observations(PROCESS_CONTRACT, dict(reference=args.reference), oracle=reference, required=False)
    with oracle_checkout(reference) as (base, tree):
        sources, embedded = oracle_inventory(tree, reference)
        info = dict(oracle_source_files=sources, oracle_source_digest=inventory(sources, tree),
                    oracle_embedded_files=embedded, oracle_embedded_digest=inventory(embedded, tree))
        helper = tree / 'scripts/rust-port/cmd/mcpprocessseed'
        helper.mkdir()
        seed_source = PROBE.read_bytes()
        username_field = b'"username":"public-fixture-user"'
        assert seed_source.count(username_field) == 1
        unicode_seed_source = seed_source.replace(
            username_field, ('"username":' + json.dumps(UNICODE_FIXTURE, ensure_ascii=True)).encode(), 1)
        (helper / 'main.go').write_bytes(seed_source)
        unicode_helper = tree / 'scripts/rust-port/cmd/mcpprocessseedunicode'
        unicode_helper.mkdir()
        (unicode_helper / 'main.go').write_bytes(unicode_seed_source)
        build_inputs = sorted(checked(['git', 'ls-files'], tree).decode().splitlines() + [
            'scripts/rust-port/cmd/mcpprocessseed/main.go', 'scripts/rust-port/cmd/mcpprocessseedunicode/main.go'])
        info.update(oracle_build_inputs=build_inputs, oracle_build_input_digest=inventory(build_inputs, tree),
                    seed_probe_sha256=hashlib.sha256(PROBE.read_bytes()).hexdigest())
        go_compiler, build_env, compiler = pinned_go(os.environ.copy(), ROOT)
        suffix = '.exe' if os.name == 'nt' else ''
        go, seed, unicode_seed = base / ('go-cli' + suffix), base / ('go-seed' + suffix), base / ('go-seed-unicode' + suffix)
        for binary, package in [(go, '.'), (seed, './scripts/rust-port/cmd/mcpprocessseed'), (unicode_seed, './scripts/rust-port/cmd/mcpprocessseedunicode')]:
            checked([go_compiler, 'build', '-trimpath', '-buildvcs=false', '-o', binary, package], tree, build_env, timeout=oracle_build_timeout())
        info.update(go_binary_sha256=hashlib.sha256(go.read_bytes()).hexdigest(), seed_binary_sha256=hashlib.sha256(seed.read_bytes()).hexdigest(),
                    unicode_seed_binary_sha256=hashlib.sha256(unicode_seed.read_bytes()).hexdigest())
        prior_seeds = ((prior or {}).get('data') or {}).get('seeds') or {}
        seeds, rows, loaded_profiles, snapshots = {}, [], {}, {}
        for name, profile in profiles():
            seed_home, loaded, agent = seed_profile({'seed': seed, 'unicode': unicode_seed}, base, name, profile)
            if name in prior_seeds:
                shutil.rmtree(seed_home / 'vault')
                unpack_tree(prior_seeds[name]['vault'], seed_home / 'vault')
                loaded = prior_seeds[name]['loaded']
            seeds[name] = dict(vault=pack_tree(seed_home / 'vault'), loaded=loaded)
            assert loaded['Name'] == agent
            loaded_profiles[name] = loaded
            snapshots[name] = vault_snapshot(seed_home / 'vault')
            home = base / (name + '-go')
            home.mkdir()
            shutil.copytree(seed_home / 'vault', home / 'vault')
            assert vault_snapshot(home / 'vault') == snapshots[name], 'actual Go encrypted input equality'
            row = observe(go, home, name, agent, 'go', [])
            check_profile_row('go', name, row)
            rows.append(scrub_process_row(row, home))
        hostile = []
        for name, data in hostile_inputs():
            retained = observe_hostile(go, base, seed_home / 'vault', name, data, 'go')
            hostile.append(scrub_process_row(retained, base / ('hostile-' + name + '-go')))
        payload = dict(info=info, compiler={k: compiler[k] for k in ('version', 'compiler_sha256', 'build_settings')}, go=rows, go_hostile=hostile,
                       seeds=seeds, loaded_go_profiles=loaded_profiles, fixture_snapshots=snapshots)
        path = save_go_observations(PROCESS_CONTRACT, payload, dict(reference=args.reference), PROCESS_NORMALIZATION, compiler['version'], oracle=reference)
    print(f'CAPTURED: {len(rows)} Go MCP profiles and {len(hostile)} hostile stdio cases -> {path}')


def main():
    parser = argparse.ArgumentParser()
    add_capture_arguments(parser, rust_required=False)
    parser.add_argument('--allow-dirty-for-development',action='store_true')
    parser.add_argument('--reference', choices=['historical', CONTRACT])
    parser.add_argument('--signals',action='store_true',
                        help='run only the SIGINT/SIGTERM stdio contract against prebuilt binaries')
    parser.add_argument('--go-cli',type=Path,help='prebuilt Go oracle CLI (with --signals)')
    parser.add_argument('--go-seed',type=Path,help='prebuilt Go fixture seed helper (with --signals)')
    args = parser.parse_args()
    if args.signals:
        assert args.rust and args.receipt, '--signals needs --rust and --receipt'
        assert args.go_cli and args.go_seed, '--signals needs --go-cli and --go-seed'
        return signals_main(args)
    assert args.reference, '--reference is required unless --signals is used'
    reference = ORACLE if args.reference=='historical' else ORDERED
    if reference == ORDERED:
        validate_reference(ROOT)
    if capture_arguments_ok(args):
        assert args.reference == CONTRACT, 'Go observations are recorded for the ordered reference only'
        return capture_process(args)
    document = load_go_observations(PROCESS_CONTRACT, dict(reference=args.reference), oracle=reference)
    recorded = document['data']
    rust = args.rust.resolve()
    clean = not checked(['git','status','--porcelain=v1']).strip()
    assert clean or args.allow_dirty_for_development
    paths = candidate_paths()
    receipt = {'passed':False,'candidate_commit':checked(['git','rev-parse','HEAD']).decode().strip(),
        'candidate_worktree_clean':clean,'native_os':platform.system(),'architecture':platform.machine(),
        'candidate_source_files':paths,'candidate_source_digest':inventory(paths,ROOT),
        'rust_binary_sha256':hashlib.sha256(rust.read_bytes()).hexdigest(), 'oracle_commit':reference,
        'reference_contract':args.reference, 'historical_oracle_commit':ORACLE,
        'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'profiles':dict(profiles()),
        'loaded_go_profiles':recorded['loaded_go_profiles'],'fixture_snapshots':recorded['fixture_snapshots'],'declared_differences':[],
        'normalizations':['JSON object key order and nested JSON text','actual fixture HOME prefix',
                          'paired 16-hex random security data IDs with unchanged label/content',
                          'validated actual nonnegative command duration_ms, raw values retained'],
        'fixture_kdf':{'algorithm':'argon2id','memory_kib':19456,'iterations':2,'lanes':1}, 'requests':messages(Path('__HOME__')),
        'go':recorded['go'],'rust':[],'go_hostile':recorded['go_hostile'],'rust_hostile':[],'differences':[],
        'compiler':recorded['compiler'],'go_observations':provenance(document),**recorded['info']}
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-mcp-process-') as raw:
            base = Path(raw)
            for (name,profile),go_row in zip(profiles(),receipt['go'],strict=True):
                assert go_row['case'] == name
                agent = recorded['seeds'][name]['loaded']['Name']
                seed_home = base/(name+'-seed')
                unpack_tree(recorded['seeds'][name]['vault'], seed_home/'vault')
                snapshot = vault_snapshot(seed_home/'vault')
                assert snapshot == receipt['fixture_snapshots'][name], 'recorded seed vault bytes changed'
                home = base/(name+'-rust')
                home.mkdir()
                shutil.copytree(seed_home/'vault',home/'vault')
                assert vault_snapshot(home/'vault')==snapshot, 'actual Go/Rust encrypted input equality'
                row = observe(rust,home,name,agent,'rust',receipt['rust'])
                check_profile_row('go',name,go_row)
                check_profile_row('rust',name,row)
            compare_profiles(receipt)
            for (name,data),go_row in zip(hostile_inputs(),receipt['go_hostile'],strict=True):
                assert go_row['case'] == name and go_row['input_sha256'] == hashlib.sha256(data).hexdigest()
                receipt['rust_hostile'].append(observe_hostile(rust,base,seed_home/'vault',name,data,'rust'))
                ordinary = next((row['frames'][0] for row in receipt['go_hostile'] if row['case']=='crlf'),None)
                receipt['declared_differences'] += compare_hostile(name,go_row,receipt['rust_hostile'][-1],ordinary)
            assert not receipt['differences'], 'actual MCP/profile differences retained in receipt'
            assert candidate_paths()==paths and inventory(paths,ROOT)==receipt['candidate_source_digest'], 'candidate changed during native observation'
            assert checked(['git','rev-parse','HEAD']).decode().strip()==receipt['candidate_commit']
            receipt['passed'] = True
    finally:
        args.receipt.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
        receipt['candidate_worktree_clean_at_end'] = not checked(
            ['git','status','--porcelain=v1','--untracked-files=normal']).strip()
        if not receipt['candidate_worktree_clean_at_end'] and not args.allow_dirty_for_development:
            receipt['passed'] = False
        args.receipt.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
        assert receipt['candidate_worktree_clean_at_end'] or args.allow_dirty_for_development
    print(f"PASS: {len(receipt['go'])} actual Go/Rust native MCP profiles and {len(receipt['go_hostile'])} hostile stdio cases on {platform.system()} (Go side replayed from {receipt['go_observations']['path']})")


if __name__=='__main__':
    main()
