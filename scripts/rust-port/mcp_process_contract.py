#!/usr/bin/env python3
"""Real native MCP CLI/profile discovery and call-time authorization comparison."""
import argparse
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
from mcp_oracle import CONTRACT, HISTORICAL, ORDERED, pinned_go, tool_environment, validate_reference

if sys.flags.optimize:
    raise SystemExit('Parity acceptance requires unoptimized Python; remove -O / PYTHONOPTIMIZE.')

ROOT = Path(__file__).resolve().parents[2]
ORACLE = HISTORICAL
PROBE = ROOT / 'scripts/rust-port/mcp_process_seed.go.txt'
CANARIES = ['public-mcp-secret-6af2', 'public-nested-secret-88d1']
UNICODE_FIXTURE = 'public-fixture-user\u2028line\u2029paragraph'


def run(args, cwd, env, data=b''):
    return subprocess.run([str(a) for a in args], cwd=cwd, env=env, input=data,
                          capture_output=True, timeout=120)


def checked(args, cwd=ROOT, env=None):
    r = run(args, cwd, env or os.environ.copy())
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
    assert len(stderr)<65536 and all(implementation=='go' and re.fullmatch(pattern,line)
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
# Termination-signal contract (issue #1242, Unix only).
#
# Go's serve command subscribes SIGINT/SIGTERM (and SIGQUIT), cancels its
# context and returns success: exit 0, no extra output, runtime port/TLS
# records removed. A stdio server answers at most one more frame after the
# signal and always waits <= 2 s for its blocked stdin read. Each case below is
# run against the real Go binary and the Rust binary in separate disposable
# HOMEs, synchronised on observable readiness (never a bare sleep).
# ---------------------------------------------------------------------------
SIGNALS = [('SIGINT', signal.SIGINT), ('SIGTERM', signal.SIGTERM), ('SIGQUIT', signal.SIGQUIT)]
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
                           '.github/workflows/rust-mcp-process.yml'})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--allow-dirty-for-development',action='store_true')
    parser.add_argument('--reference', choices=['historical', CONTRACT])
    parser.add_argument('--signals',action='store_true',
                        help='run only the SIGINT/SIGTERM stdio contract against prebuilt binaries')
    parser.add_argument('--go-cli',type=Path,help='prebuilt Go oracle CLI (with --signals)')
    parser.add_argument('--go-seed',type=Path,help='prebuilt Go fixture seed helper (with --signals)')
    args = parser.parse_args()
    if args.signals:
        assert args.go_cli and args.go_seed, '--signals needs --go-cli and --go-seed'
        return signals_main(args)
    assert args.reference, '--reference is required unless --signals is used'
    reference = ORACLE if args.reference=='historical' else ORDERED
    if reference == ORDERED:
        validate_reference(ROOT)
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
        'seed_probe_sha256':hashlib.sha256(PROBE.read_bytes()).hexdigest(), 'profiles':dict(profiles()),
        'loaded_go_profiles':{},'fixture_snapshots':{},'declared_differences':[],
        'normalizations':['JSON object key order and nested JSON text','actual fixture HOME prefix',
                          'paired 16-hex random security data IDs with unchanged label/content',
                          'validated actual nonnegative command duration_ms, raw values retained'],
        'fixture_kdf':{'algorithm':'argon2id','memory_kib':19456,'iterations':2,'lanes':1}, 'requests':messages(Path('__HOME__')),
        'go':[],'rust':[],'go_hostile':[],'rust_hostile':[],'differences':[]}
    try:
        go_compiler, build_env, compiler = pinned_go(os.environ.copy(), ROOT)
        receipt['compiler'] = compiler
        with tempfile.TemporaryDirectory(prefix='symvault-mcp-process-') as raw:
            base = Path(raw)
            tree = base/'oracle'
            checked(['git','worktree','add','--detach',tree,reference])
            try:
                sources = checked(['git','ls-tree','-r','--name-only',reference]).decode().splitlines()
                sources = sorted(p for p in sources if p in {'go.mod','go.sum'} or p.endswith('.go') and not p.endswith('_test.go'))
                embedded = sorted(p for p in checked(['git','ls-tree','-r','--name-only',reference]).decode().splitlines()
                                  if p.startswith('internal/mcp/apitemplates/builtin/'))
                assert len(embedded)==17
                receipt.update(oracle_source_files=sources,oracle_source_digest=inventory(sources,tree),
                               oracle_embedded_files=embedded,oracle_embedded_digest=inventory(embedded,tree))
                helper = tree/'scripts/rust-port/cmd/mcpprocessseed'
                helper.mkdir()
                seed_source = PROBE.read_bytes()
                username_field = b'"username":"public-fixture-user"'
                assert seed_source.count(username_field)==1
                unicode_seed_source = seed_source.replace(
                    username_field, ('"username":'+json.dumps(UNICODE_FIXTURE,ensure_ascii=True)).encode(), 1)
                (helper/'main.go').write_bytes(seed_source)
                unicode_helper = tree/'scripts/rust-port/cmd/mcpprocessseedunicode'
                unicode_helper.mkdir()
                (unicode_helper/'main.go').write_bytes(unicode_seed_source)
                build_inputs = sorted(checked(['git','ls-files'],tree).decode().splitlines()+[
                    'scripts/rust-port/cmd/mcpprocessseed/main.go',
                    'scripts/rust-port/cmd/mcpprocessseedunicode/main.go'])
                receipt['oracle_build_inputs'] = build_inputs
                receipt['oracle_build_input_digest'] = inventory(build_inputs,tree)
                suffix = '.exe' if os.name=='nt' else ''
                go, seed = base/('go-cli'+suffix), base/('go-seed'+suffix)
                unicode_seed = base/('go-seed-unicode'+suffix)
                checked([go_compiler,'build','-trimpath','-buildvcs=false','-o',go,'.'],tree,build_env)
                checked([go_compiler,'build','-trimpath','-buildvcs=false','-o',seed,'./scripts/rust-port/cmd/mcpprocessseed'],tree,build_env)
                checked([go_compiler,'build','-trimpath','-buildvcs=false','-o',unicode_seed,'./scripts/rust-port/cmd/mcpprocessseedunicode'],tree,build_env)
                receipt.update(go_binary_sha256=hashlib.sha256(go.read_bytes()).hexdigest(),
                               seed_binary_sha256=hashlib.sha256(seed.read_bytes()).hexdigest(),
                               unicode_seed_binary_sha256=hashlib.sha256(unicode_seed.read_bytes()).hexdigest())
                for name,profile in profiles():
                    seed_home = base/(name+'-seed')
                    seed_home.mkdir()
                    profile_file = seed_home/'profile.json'
                    profile = dict(profile)
                    builtin = profile.pop('__builtin','')
                    agent = builtin or 'fixture'
                    profile_file.write_text(json.dumps(profile),encoding='utf-8')
                    profile_seed = unicode_seed if name=='admin-value-visible' else seed
                    loaded = checked([profile_seed,'--root',seed_home/'vault','--profile',profile_file,
                                      '--builtin',builtin,'--agent',agent],seed_home,isolated(seed_home))
                    receipt['loaded_go_profiles'][name] = json.loads(loaded)
                    assert receipt['loaded_go_profiles'][name]['Name']==agent
                    snapshot = vault_snapshot(seed_home/'vault')
                    receipt['fixture_snapshots'][name] = snapshot
                    homes = {}
                    for implementation in ['go','rust']:
                        home = base/(name+'-'+implementation)
                        home.mkdir()
                        shutil.copytree(seed_home/'vault',home/'vault')
                        assert vault_snapshot(home/'vault')==snapshot, 'actual Go/Rust encrypted input equality'
                        homes[implementation] = home
                    for implementation,binary in [('go',go),('rust',rust)]:
                        row = observe(binary,homes[implementation],name,agent,implementation,receipt[implementation])
                        if name.endswith('-real-child'):
                            expected_marker = {'received_expected_secret':True} if name=='tier-admin-real-child' else None
                            assert all(marker==expected_marker for marker in row['child_markers'].values()), (implementation,name,'actual executor control')
                        allowed_value = name in {'tier-admin','admin-value-visible','readonly-capability-overrides',
                                                'admin-command-disabled','tier-read-only-real-child',
                                                'tier-standard-real-child','tier-admin-real-child'}
                        if implementation=='go':
                            allowed_value |= name in {'legacy','admin-tools-health-only','admin-tools-self-only','admin-api-explicit'}
                        value_frame = next(frame for frame in row['frames'] if frame['id']==8)
                        assert all((c in json.dumps(value_frame))==allowed_value for c in CANARIES), (implementation,name,'value permission control')
                        for frame in row['frames']:
                            if frame['id'] not in [8,18]:
                                assert not any(c in json.dumps(frame) for c in CANARIES), (implementation,name,'credential outside authorized value frame')
                        fetch_frame = next(frame for frame in row['frames'] if frame['id']==18)
                        assert all((c in json.dumps(fetch_frame))==(allowed_value and name!='legacy')
                                   for c in CANARIES), (implementation,name,'fetch value permission control')
                        unicode_frames = [frame for frame in row['frames']
                                         if UNICODE_FIXTURE in json.dumps(frame,ensure_ascii=False)]
                        expected_unicode_frames = [value_frame,fetch_frame] if name=='admin-value-visible' else []
                        assert unicode_frames==expected_unicode_frames, (implementation,name,'Unicode encrypted-store permission control')
                        assert UNICODE_FIXTURE not in row['stderr_raw'], (implementation,name,'Unicode value in stderr')
                for left,right in zip(receipt['go'],receipt['rust'],strict=True):
                    go_names = next(frame for frame in left['frames'] if frame['id']==6)['result']['content'][0]['text']['json_text']
                    for a,b in zip(left['frames'],right['frames'],strict=True):
                        if a!=b:
                            difference = {'case':left['case'],'id':a.get('id'),'go':a,'rust':b}
                            declared = declared_profile_difference(dict(profiles())[left['case']],a,b,go_names)
                            if declared:
                                receipt['declared_differences'].append(dict(difference,decision=declared))
                            else:
                                receipt['differences'].append(difference)
                for name,data in hostile_inputs():
                    for implementation,binary in [('go',go),('rust',rust)]:
                        home = base/('hostile-'+name+'-'+implementation)
                        home.mkdir()
                        shutil.copytree(seed_home/'vault',home/'vault')
                        result = run([binary,'--quiet','mcp','--stdio','--agent','fixture'],home,isolated(home),data)
                        retained = {'case':name,'exit':result.returncode,
                            'input_bytes':len(data),'input_sha256':hashlib.sha256(data).hexdigest(),
                            'stdout_raw':result.stdout.decode('utf-8',errors='replace'),
                            'stderr_raw':result.stderr.decode('utf-8',errors='replace')}
                        receipt[implementation+'_hostile'].append(retained)
                        raw,stderr,frames = protocol_bytes(result,home,name,implementation,'fixture')
                        assert result.returncode==0 and not any(c in raw for c in CANARIES)
                        retained.update(stdout_raw=raw,stderr_raw=stderr,frames=frames,stdout_is_only_protocol=True)
                    ordinary = next((row['frames'][0] for row in receipt['go_hostile'] if row['case']=='crlf'),None)
                    receipt['declared_differences'] += compare_hostile(name,receipt['go_hostile'][-1],receipt['rust_hostile'][-1],ordinary)
                assert not receipt['differences'], 'actual MCP/profile differences retained in receipt'
                assert inventory(build_inputs,tree)==receipt['oracle_build_input_digest'], 'oracle build inputs changed during observation'
                assert inventory(sources,tree)==receipt['oracle_source_digest'], 'oracle source changed during observation'
                assert inventory(embedded,tree)==receipt['oracle_embedded_digest'], 'oracle embedded inputs changed during observation'
                assert candidate_paths()==paths and inventory(paths,ROOT)==receipt['candidate_source_digest'], 'candidate changed during native observation'
                assert checked(['git','rev-parse','HEAD']).decode().strip()==receipt['candidate_commit']
                receipt['passed'] = True
            finally:
                checked(['git','worktree','remove','--force',tree])
    finally:
        args.receipt.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
        receipt['candidate_worktree_clean_at_end'] = not checked(
            ['git','status','--porcelain=v1','--untracked-files=normal']).strip()
        if not receipt['candidate_worktree_clean_at_end'] and not args.allow_dirty_for_development:
            receipt['passed'] = False
        args.receipt.write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
        assert receipt['candidate_worktree_clean_at_end'] or args.allow_dirty_for_development
    print(f"PASS: {len(receipt['go'])} actual Go/Rust native MCP profiles and {len(receipt['go_hostile'])} hostile stdio cases on {platform.system()}")


if __name__=='__main__':
    main()
