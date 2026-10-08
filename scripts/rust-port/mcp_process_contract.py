#!/usr/bin/env python3
"""Real native MCP CLI/profile discovery and call-time authorization comparison."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
ORACLE = 'd1cd0f97ac550bc3020bc86b0514989f8d28d95c'
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
    env = {k:v for k,v in os.environ.items() if not k.startswith('SYMVAULT_')}
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
    raw,stderr,frames = protocol_bytes(r,home,name,implementation,agent)
    assert r.returncode == 0 and len(frames) == len(requests), (name,'native process did not produce every response')
    assert [f.get('id') for f in frames] == [r[0] for r in requests], (name,'response ordering')
    markers = {tool:json.loads((home/(tool+'-marker.json')).read_text())
               if (home/(tool+'-marker.json')).exists() else None
               for tool in ['run_command','execute_with_secret']}
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


def candidate_paths():
    return sorted(p for p in checked(['git','ls-files','--cached','--others','--exclude-standard']).decode().splitlines()
                  if p.startswith(('crates/','third_party/','testdata/','internal/mcp/apitemplates/builtin/'))
                  or p in {'Cargo.toml','Cargo.lock','.gitattributes','scripts/rust-port/mcp_process_contract.py',
                           'scripts/rust-port/mcp_process_seed.go.txt','.github/workflows/rust-mcp-process.yml'})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rust',type=Path,required=True)
    parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--allow-dirty-for-development',action='store_true')
    args = parser.parse_args()
    rust = args.rust.resolve()
    clean = not checked(['git','status','--porcelain=v1']).strip()
    assert clean or args.allow_dirty_for_development
    paths = candidate_paths()
    receipt = {'passed':False,'candidate_commit':checked(['git','rev-parse','HEAD']).decode().strip(),
        'candidate_worktree_clean':clean,'native_os':platform.system(),'architecture':platform.machine(),
        'candidate_source_files':paths,'candidate_source_digest':inventory(paths,ROOT),
        'rust_binary_sha256':hashlib.sha256(rust.read_bytes()).hexdigest(), 'oracle_commit':ORACLE,
        'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'seed_probe_sha256':hashlib.sha256(PROBE.read_bytes()).hexdigest(), 'profiles':dict(profiles()),
        'loaded_go_profiles':{},'fixture_snapshots':{},'declared_differences':[],
        'normalizations':['JSON object key order and nested JSON text','actual fixture HOME prefix',
                          'paired 16-hex random security data IDs with unchanged label/content',
                          'validated actual nonnegative command duration_ms, raw values retained'],
        'fixture_kdf':{'algorithm':'argon2id','memory_kib':19456,'iterations':2,'lanes':1}, 'requests':messages(Path('__HOME__')),
        'go':[],'rust':[],'go_hostile':[],'rust_hostile':[],'differences':[]}
    try:
        with tempfile.TemporaryDirectory(prefix='symvault-mcp-process-') as raw:
            base = Path(raw)
            tree = base/'oracle'
            checked(['git','worktree','add','--detach',tree,ORACLE])
            try:
                sources = checked(['git','ls-tree','-r','--name-only',ORACLE]).decode().splitlines()
                sources = sorted(p for p in sources if p in {'go.mod','go.sum'} or p.endswith('.go') and not p.endswith('_test.go'))
                embedded = sorted(p for p in checked(['git','ls-tree','-r','--name-only',ORACLE]).decode().splitlines()
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
                suffix = '.exe' if os.name=='nt' else ''
                go, seed = base/('go-cli'+suffix), base/('go-seed'+suffix)
                unicode_seed = base/('go-seed-unicode'+suffix)
                checked(['go','build','-trimpath','-buildvcs=false','-o',go,'.'],tree)
                checked(['go','build','-trimpath','-buildvcs=false','-o',seed,'./scripts/rust-port/cmd/mcpprocessseed'],tree)
                checked(['go','build','-trimpath','-buildvcs=false','-o',unicode_seed,'./scripts/rust-port/cmd/mcpprocessseedunicode'],tree)
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
