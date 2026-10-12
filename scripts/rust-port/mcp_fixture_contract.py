#!/usr/bin/env python3
"""Replay unchanged historical MCP fixtures, then compare a corrected source lane.

The two lanes reuse the existing Go generators. Only oracle identity literals
are rebased in the disposable corrected generator, never in historical files.
Every response/state/case field is compared without a provenance exemption.
The explicit approval-lifetime-v1 mode records new generator executions on H
and C, not unchanged historical replay or acceptance of old failed captures.
"""
import argparse
import difflib
import functools
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import sys
import tempfile

from mcp_oracle import CONTRACT, HISTORICAL, ORDERED, inventory, git, pinned_go, validate_reference
import mcp_compiler_adapter as compiler_adapter

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_BASE = '2b596f916bf736250b7fd3bb4d39f5f89fb20aa2'
ANCHOR = ROOT/'scripts/rust-port/fixtures/mcp-anomaly/historical-inputs.json'
ANCHOR_SHA256 = '678531bead3d9bc4a8d754ce7996b8cd29f94d8a4dbb8ef91cef71577296394d'
ARCHIVED_INPUTS = {
    'internal/mcp/server/mcp_copy_clipboard_fixture_generator_test.go',
    'internal/mcp/server/mcp_secure_input_fixture_generator_test.go',
    'internal/mcp/server/mcpexecutewithsecret_fixture_generator_test.go',
    'scripts/rust-port/cmd/mcpcallgen/main_test.go',
    'scripts/rust-port/cmd/http001initgen/main_test.go',
    'scripts/rust-port/cmd/execute_secret_provenance/main.go',
    'testdata/port/mcp/copy-clipboard.json',
    'testdata/port/mcp/execute-with-secret.json',
    'testdata/port/mcp/secure-input.json',
}
ARCHIVE = 'scripts/rust-port/fixtures/mcp-anomaly/historical/'
CAADD = 'caadd5ef95e8f19fabd3ae3d2c04caa296f2fd44'
# Explicit inventory: do not derive acceptance counts from whatever ran.
CASES = {
    'CopyClipboard': ('COPY_CLIPBOARD', 'copy-clipboard.json', 16),
    'ExecuteAPIHTTPS': ('EXECUTE_API_HTTPS', 'execute-api-https.json', 3),
    'ExecuteAPIPolicy': ('EXECUTE_API_POLICY', 'execute-api-policy.json', 9),
    'ExecuteAPIRequest': ('EXECUTE_API_REQUEST', 'execute-api-request.json', 15),
    'ExecuteWithSecret': ('EXECUTE_WITH_SECRET', 'execute-with-secret.json', 13),
    'Prompts': ('PROMPTS', 'prompts.json', 25),
    'SecureInput': ('SECURE_INPUT', 'secure-input.json', 11),
    'List': ('LIST', 'tool-list.json', 11),
    'AuditSelf': ('AUDIT_SELF', 'tools-audit-self.json', 15),
    'AuthStatus': ('AUTH_STATUS', 'tools-auth-status.json', 2),
    'Call': ('CALL', 'tools-call-initialized.json', 1),
    'DeleteEntry': ('DELETE_ENTRY', 'tools-delete-entry.json', 7),
    'GeneratePassword': ('GENERATE_PASSWORD', 'tools-generate-password.json', 4),
    'GenerateTemplate': ('GENERATE_TEMPLATE', 'tools-generate-template.json', 8),
    'GenerateTOTP': ('GENERATE_TOTP', 'tools-generate-totp.json', 4),
    'GetValue': ('GET_VALUE', 'tools-get-value.json', 8),
    'ListEntries': ('LIST_ENTRIES', 'tools-list-entries.json', 3),
    'RateLimit': ('RATE_LIMIT', 'tools-rate-limit.json', 4),
    'SanitizeOutput': ('SANITIZE_OUTPUT', 'tools-sanitize-output.json', 7),
    'SearchFetch': ('SEARCH_FETCH', 'tools-search-fetch.json', 13),
    'SecretUnseal': ('SECRET_UNSEAL', 'tools-secret-unseal.json', 6),
    'SetEntry': ('SET_ENTRY', 'tools-set-entry.json', 11),
    'SymairaSearch': ('SYMAIRA_SEARCH', 'tools-symaira-search.json', 7),
    'WriteApproval': ('WRITE_APPROVAL', 'write-tty-approval.json', 14),
}
FIXTURES = {'testdata/port/mcp/'+name: count for _,name,count in CASES.values()}
FIXTURES.update({'testdata/port/mcp/tools-call.json':4, 'testdata/port/mcp/http-initialize.json':27})
IDENTITY_KEYS = {'commit', 'commit_sha', 'source_hash', 'source_digest', 'generator_hash', 'generator_digest'}
APPROVAL_GENERATOR = 'internal/mcp/server/mcp_write_approval_fixture_generator_test.go'
APPROVAL_SOURCE = 'scripts/rust-port/fixtures/mcp-anomaly/approval-lifetime-v1.go.txt'
# Independently reviewed source admission, NOT compiler/native provenance.
APPROVAL_SHA256 = '91e62899d00eecb039d93bc4630c762b213d49798fbf9ae82c8a595d2a036562'
APPROVAL_FIXTURE = 'testdata/port/mcp/write-tty-approval.json'


def corrected_generator(data):
    for old in [HISTORICAL, 'd1cd0f97', CAADD, 'caadd5e']:
        for suffix in ['"', ':"']:
            data = data.replace(('"'+old+suffix).encode(), ('"'+ORDERED+suffix).encode())
    old_hash,new_hash = legacy_hashes()
    return data.replace(('"'+old_hash+'"').encode(),('"'+new_hash+'"').encode())


@functools.cache
def legacy_hashes():
    # Four legacy generators independently pin this hash. Recompute from Git
    # blobs with their actual name/NUL/bytes algorithm, never the working tree.
    names = json.loads((ROOT/'testdata/port/mcp/prompts.json').read_bytes())['oracle']['source_files']
    digests=[]
    for commit in [HISTORICAL, ORDERED]:
        digest=hashlib.sha256()
        for name in names:
            if name not in {'go.mod','go.sum'}:
                digest.update(name.encode()+b'\0'+git(ROOT,'show',commit+':'+name))
        digests.append(digest.hexdigest())
    expected=json.loads((ROOT/'testdata/port/mcp/prompts.json').read_bytes())['oracle']['source_hash']
    if digests[0] != expected:
        raise ValueError('legacy generator source-hash algorithm drift')
    return digests


def compare_fixture(old, new, count):
    # JSON numeric equality must not accept bool/int or int/float substitution.
    def compare(a, b, path=''):
        if type(a) is not type(b):
            raise ValueError('fixture type drift: '+path)
        if isinstance(a, dict):
            if a.keys() != b.keys():
                raise ValueError('fixture key drift: '+path)
            for key in a:
                if (path == '/oracle' and key in IDENTITY_KEYS) or (not path and key == 'generator_digest'):
                    continue
                compare(a[key], b[key], path+'/'+key)
        elif isinstance(a, list):
            if len(a) != len(b):
                raise ValueError('fixture length drift: '+path)
            for i,(left,right) in enumerate(zip(a,b,strict=True)):
                compare(left,right,path+'/'+str(i))
        elif a != b:
            raise ValueError('fixture value drift: '+path)
    if len(old['cases']) != count or len(new['cases']) != count:
        raise ValueError('fixture case inventory drift')
    if new['oracle']['commit_sha'] != ORDERED:
        raise ValueError('corrected fixture is not bound to the corrected oracle')
    compare(old, new)


def confined_file(root, name):
    if not isinstance(name,str) or '\\' in name:
        raise ValueError('invalid fixture input path')
    parts=PurePosixPath(name)
    if parts.is_absolute() or '..' in parts.parts or parts.as_posix()!=name:
        raise ValueError('invalid fixture input path')
    root=root.resolve()
    path=root
    for component in parts.parts:
        path=path/component
        if path.is_symlink():
            raise ValueError('symlink fixture input')
    if not path.resolve().is_relative_to(root) or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('fixture input must be a contained regular file')
    return path


def fixture_anchor(root, names):
    raw=confined_file(ANCHOR.parent,ANCHOR.name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != ANCHOR_SHA256:
        raise ValueError('independent historical input anchor drift')
    manifest=json.loads(raw)
    if manifest['source_commit'] != FIXTURE_BASE:
        raise ValueError('historical input identity drift')
    # Validate membership and file types for ALL inputs before opening ANY.
    for name in names:
        if not isinstance(name,str) or name not in manifest['files']:
            raise ValueError('unanchored fixture input path')
        historical_file(root,name)
    for name in names:
        if hashlib.sha256(historical_file(root,name).read_bytes()).hexdigest() != manifest['files'][name]:
            raise ValueError('historical fixture/generator anchor drift: '+name)


def historical_file(root, name):
    # Explicit relocated originals, not an automatic fallback on checksum error.
    # The unchanged independent anchor still authenticates every byte.
    return confined_file(root, ARCHIVE+name+'.txt' if name in ARCHIVED_INPUTS else name)


def generator_paths():
    fixture_anchor(ROOT, ())
    return sorted(set(json.loads(ANCHOR.read_bytes())['files']) - set(FIXTURES))


def approval_generator_source(root):
    """Admit only the reviewed five-line lifetime delta to the anchored original."""
    fixture_anchor(root, [APPROVAL_GENERATOR])
    original = historical_file(root, APPROVAL_GENERATOR).read_bytes()
    data = confined_file(root, APPROVAL_SOURCE).read_bytes()
    if hashlib.sha256(data).hexdigest() != APPROVAL_SHA256:
        raise ValueError('unreviewed approval generator source')
    anchor = b'\tlogger.SetSyncMode(true)\n\tsrv.auditLog = logger'
    addition = (b'\tdefer func() {\n'
                b'\t\tif err := logger.Close(); err != nil {\n'
                b'\t\t\tt.Errorf("close fixture audit logger: %v", err)\n'
                b'\t\t}\n\t}()\n')
    if original.count(anchor) != 1 or data != original.replace(anchor, addition+anchor, 1):
        raise ValueError('approval generator delta exceeds reviewed lifetime correction')
    return data


def materialize_inputs(tree, generators, commit, approval_generator):
    """The real producer's source-only materialization, before compiler inventory."""
    if commit not in (HISTORICAL, ORDERED) or approval_generator not in ('original', 'approval-lifetime-v1'):
        raise ValueError('unknown fixture execution identity')
    corrected = approval_generator_source(ROOT) if approval_generator != 'original' else None
    mapping = None
    for name in [*generators, *FIXTURES]:
        original = historical_file(ROOT, name).read_bytes()
        data = corrected if name == APPROVAL_GENERATOR and corrected is not None else original
        before_identity = data
        if commit == ORDERED and name in generators and name.endswith('.go'):
            data = corrected_generator(data)
        if name == APPROVAL_GENERATOR and corrected is not None:
            literal = ('const writeApprovalOracleCommit = "'+HISTORICAL+'"').encode()
            expected = corrected if commit == HISTORICAL else corrected.replace(
                literal, ('const writeApprovalOracleCommit = "'+ORDERED+'"').encode(), 1)
            if corrected.count(literal) != 1 or data != expected:
                raise ValueError('unexpected approval identity-literal transform')
            mapping = {
                'version': approval_generator, 'product_source_commit': commit,
                'original_path': name, 'original_sha256': hashlib.sha256(original).hexdigest(),
                'corrected_path': APPROVAL_SOURCE, 'corrected_sha256': APPROVAL_SHA256,
                'materialized_path': name, 'materialized_sha256': hashlib.sha256(data).hexdigest(),
                'lifetime_delta': ''.join(difflib.unified_diff(original.decode().splitlines(True),
                    corrected.decode().splitlines(True), fromfile=name, tofile=APPROVAL_SOURCE)),
                'identity_delta': ''.join(difflib.unified_diff(before_identity.decode().splitlines(True),
                    data.decode().splitlines(True), fromfile=APPROVAL_SOURCE, tofile=name)),
            }
        target = tree/name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    if corrected is not None and mapping is None:
        raise ValueError('corrected approval generator was not materialized')
    return mapping


def approval_capture_oracle(tree, commit):
    """Exact metadata from admitted materialized inputs, never a native verdict."""
    fixture_anchor(ROOT, [APPROVAL_FIXTURE])
    old = json.loads(historical_file(ROOT, APPROVAL_FIXTURE).read_bytes())['oracle']
    def digest(names):
        value = hashlib.sha256()
        for name in names:
            value.update(name.encode()+b'\0'+confined_file(tree, name).read_bytes())
        return value.hexdigest()
    return dict(old, commit=commit[:8], commit_sha=commit,
                source_hash=digest(old['source_files']), generator_hash=digest(old['generator_files']))


def compare_approval_capture(captured, expected_oracle):
    # No identity exemption here: hash the actual materialized sources BEFORE
    # execution, then compare every field, including all 14 behavioral cases.
    old = json.loads(historical_file(ROOT, APPROVAL_FIXTURE).read_bytes())
    expected = dict(old, oracle=expected_oracle)
    if len(captured['cases']) != CASES['WriteApproval'][2] or json.dumps(
            captured, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError('corrected approval capture identity or behavior drift')


def candidate_fixture_payloads():
    # Product captures may bind patched dependencies; historical bytes may not.
    # Their separate provenance gates check those metadata changes. No response,
    # state, request, count or JSON type may drift from the historical contract.
    for name, count in FIXTURES.items():
        old=json.loads(historical_file(ROOT,name).read_bytes())
        new=json.loads(confined_file(ROOT,name).read_bytes())
        new['oracle']=dict(old['oracle'],commit_sha=ORDERED)
        compare_fixture(old,new,count)


def run_step(command, cwd, env, output, name, steps, tests=(), timeout=600, test_binary=False):
    row = {'name':name, 'command':command, 'cwd':str(cwd), 'exit':None, 'timed_out':False,
           'stdout':str((output/(name+'.stdout')).resolve()),
           'stderr':str((output/(name+'.stderr')).resolve()), 'passed':False}
    steps.append(row)
    with (output/row['stdout']).open('wb') as out, (output/row['stderr']).open('wb') as err:
        child = subprocess.Popen(command, cwd=cwd, env=env, stdout=out, stderr=err,
                                 start_new_session=os.name!='nt')
        try:
            row['exit'] = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            row['timed_out'] = True
            if os.name=='nt':
                subprocess.run(['taskkill','/PID',str(child.pid),'/T','/F'],check=True,
                               stdout=err,stderr=err,timeout=15)
            else:
                os.killpg(child.pid,signal.SIGKILL)
            row['exit'] = child.wait(timeout=15)
            raise
    if row['exit']:
        raise RuntimeError(name+' failed; retained '+str(output/row['stdout']))
    if tests:
        text = (output/row['stdout']).read_text()
        actual = re.findall(r'^--- PASS: (\w+) ', text, re.M)
        trailer = r'^PASS\n\Z' if test_binary else r'^PASS\nok\s'
        if sorted(actual) != sorted(tests) or not re.search(trailer,text,re.M):
            raise ValueError(name+' missing/extra executed generator tests: '+repr(actual))
        row['executed_tests'] = actual
    row['passed'] = True


def run_generators(binary, tests, tree, env, output, steps):
    command = [str(binary), '-test.run=^('+'|'.join(tests)+')$',
               '-test.count=1', '-test.timeout=8m', '-test.v']
    try:
        run_step(command, tree/'internal/mcp/server', env, output, 'generators',
                 steps, tests, test_binary=True)
    except RuntimeError:
        # Retain a separate real capture after a failed CHECK. This does not
        # repair, replace or approve the failed historical execution.
        name = 'TestGenerateMCPExecuteWithSecretFixture'
        failed = (output/'generators.stdout').read_text()
        if name in tests and re.search(r'^--- FAIL: '+name+r' ', failed, re.M):
            diagnostic = dict(env)
            diagnostic.pop('SYMAIRA_CHECK_MCP_EXECUTE_WITH_SECRET_FIXTURE', None)
            diagnostic['SYMAIRA_GENERATE_MCP_EXECUTE_WITH_SECRET_FIXTURE'] = '1'
            try:
                run_step([str(binary), '-test.run=^'+name+'$', '-test.count=1',
                          '-test.timeout=8m', '-test.v'], tree/'internal/mcp/server',
                         diagnostic, output, 'execute-with-secret-diagnostic',
                         steps, [name], test_binary=True)
            except Exception as error:
                (output/'execute-with-secret-diagnostic.error').write_text(str(error)+'\n')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    destinations = parser.add_mutually_exclusive_group(required=True)
    destinations.add_argument('--output', type=Path, help='new evidence directory, never overwrites a prior run')
    destinations.add_argument('--output-root', type=Path, help='parent for a fresh retained run directory')
    parser.add_argument('--generator', choices=['tools-call','http-initialize','execute-with-secret'],
                        help='bounded two-reference acceptance for ordinary Go generator tests')
    parser.add_argument('--approval-generator', choices=['original', 'approval-lifetime-v1'], default='original',
                        help='explicit corrected-generator execution on both sources; not historical replay')
    args = parser.parse_args()
    if sys.flags.optimize:
        parser.error('unoptimized Python is required')
    if args.approval_generator != 'original' and args.generator:
        parser.error('corrected approval execution requires the full two-lane fixture gate')
    validate_reference(ROOT)
    fixture_anchor(ROOT, FIXTURES)
    generators = generator_paths()
    fixture_anchor(ROOT, [*FIXTURES, *generators])
    if args.approval_generator != 'original':
        approval_generator_source(ROOT)  # reject changed/unreviewed bytes before any compiler
    candidate_fixture_payloads()
    # Every currently declared production input must equal the corrected source.
    sources = sorted({p for name in FIXTURES for p in json.loads(historical_file(ROOT,name).read_bytes())['oracle']['source_files']})
    for name in sources:
        # The oracle lanes build the exact immutable module files, while the
        # product's patched dependencies are tested separately, not relabelled.
        if name in {'go.mod','go.sum'}:
            continue
        if (ROOT/name).read_bytes() != git(ROOT, 'show', ORDERED+':'+name):
            raise ValueError('candidate production input drift: '+name)
    if args.output_root:
        args.output_root.mkdir(parents=True,exist_ok=True)
        output=Path(tempfile.mkdtemp(prefix='run-',dir=args.output_root)).resolve()
    else:
        output = args.output.resolve()
        output.mkdir(parents=True, exist_ok=False)
    receipt = {'contract':CONTRACT, 'historical_oracle':HISTORICAL, 'corrected_oracle':ORDERED,
               'fixture_anchor':FIXTURE_BASE, 'candidate_commit':git(ROOT, 'rev-parse', 'HEAD').decode().strip(),
               'candidate_inputs':inventory(ROOT,[*FIXTURES,*generators,*sources,
                   *(ARCHIVE+n+'.txt' for n in ARCHIVED_INPUTS),
                   *compiler_adapter.SOURCES,
                   *([APPROVAL_SOURCE] if args.approval_generator != 'original' else []),
                   'scripts/rust-port/mcp_oracle.py','scripts/rust-port/mcp_fixture_contract.py',ANCHOR.relative_to(ROOT).as_posix()]),
               'approval_generator':args.approval_generator,
               'native_os':sys.platform, 'passed':False, 'lanes':[]}
    selected = {name:count for name,count in FIXTURES.items()
                if not args.generator or Path(name).stem==args.generator}
    try:
        go, env, compiler = pinned_go(os.environ.copy(), ROOT)
        receipt['compiler'] = compiler
        for lane,commit in [('historical',HISTORICAL),('corrected',ORDERED)]:
            execution = lane if args.approval_generator == 'original' else lane+'-'+args.approval_generator
            lane_out = output/execution
            lane_out.mkdir()
            row = {'lane':execution,'source_commit':commit,'passed':False,'steps':[]}
            receipt['lanes'].append(row)
            with tempfile.TemporaryDirectory(prefix='mcp-fixtures-'+lane+'-') as raw:
                base = Path(raw)
                tree = base/'oracle'
                git(ROOT, 'worktree','add','--detach',str(tree),commit)
                try:
                    mapping = materialize_inputs(tree, generators, commit, args.approval_generator)
                    if mapping is not None:
                        row['approval_generator'] = mapping
                        row['approval_capture_oracle'] = approval_capture_oracle(tree, commit)
                    home=base/'home'
                    home.mkdir(mode=0o700)
                    isolated={k:v for k,v in env.items() if not k.startswith(('SYMVAULT_','SYMAIRA_'))}
                    isolated.update(HOME=str(home),USERPROFILE=str(home),XDG_CONFIG_HOME=str(home/'config'),
                                    XDG_DATA_HOME=str(home/'data'),XDG_CACHE_HOME=str(home/'cache'),
                                    SYMVAULT_TEST_KEYRING='memory',SYMVAULT_RUN_WINDOWS_CROSSLANG='1',
                                    SYMVAULT_SECUREUI='none',SYMVAULT_NO_NOTIFY='1',TZ='UTC')
                    mode = 'CHECK' if lane=='historical' else 'GENERATE'
                    isolated.update({'SYMAIRA_'+mode+'_MCP_'+flag+'_FIXTURE':'1' for flag,_,_ in CASES.values()})
                    if mapping is not None:
                        # New bytes cannot pass original historical CHECK. Only
                        # this fixture is generated on H; the other 25 stay CHECK.
                        isolated.pop('SYMAIRA_CHECK_MCP_WRITE_APPROVAL_FIXTURE', None)
                        isolated['SYMAIRA_GENERATE_MCP_WRITE_APPROVAL_FIXTURE'] = '1'
                    # Bind the entire immutable tree plus overlaid generators.
                    # Only the explicitly captured output files may change.
                    names = git(tree,'ls-files').decode().splitlines()
                    inputs = sorted((set(names) | set(generators)) - set(FIXTURES))
                    row['build_inputs'] = inventory(tree,inputs)
                    row['build_environment'] = dict(isolated)
                    check = ['-check'] if lane=='historical' else []
                    if not args.generator or args.generator=='tools-call':
                        run_step([go,'run','./scripts/rust-port/cmd/mcpcallgen',*check],tree,isolated,lane_out,'tools-call',row['steps'])
                    if not args.generator or args.generator=='http-initialize':
                        run_step([go,'run','./scripts/rust-port/cmd/http001initgen',*check],tree,isolated,lane_out,'http-initialize',row['steps'])
                    tests = ['TestGenerateMCP'+name+'Fixture' for name in CASES
                             if not args.generator or CASES[name][1]=='execute-with-secret.json']
                    if not args.generator or args.generator=='execute-with-secret':
                        isolated,row['compiler_adapter'] = compiler_adapter.prepare(
                            go,isolated,tree,lane_out/'compiler-adapter',row['steps'],run_step)
                        row['generator_environment'] = dict(isolated)
                        # go test prepends GOROOT/bin to PATH. Compile first,
                        # then run the unmodified test binary from its package
                        # directory so our separately recorded PATH is effective.
                        binary=lane_out/('generators.test.exe' if os.name=='nt' else 'generators.test')
                        run_step([go,'test','-c','./internal/mcp/server','-o',str(binary)],
                                 tree,isolated,lane_out,'generators-build',row['steps'])
                        row['generator_binary_sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
                        if mapping is not None:
                            run_step([go,'version','-m',str(binary)],tree,isolated,lane_out,
                                     'generators-build-info',row['steps'])
                        run_generators(binary, tests, tree, isolated, lane_out, row['steps'])
                        compiler_adapter.verify(row['compiler_adapter'])
                        if hashlib.sha256(binary.read_bytes()).hexdigest() != row['generator_binary_sha256']:
                            raise ValueError('generator binary changed during execution')
                    if lane=='corrected' and not args.generator:
                        regressions=['TestAnomalyDispatch'+suffix for suffix in [
                            'CompletionOrder','GenuineToolChain','EOFAuditLifetime','Timestamp',
                            'BusyWorkerDoesNotBlockTools','CloseDrainsAdmittedTool']]
                        run_step([go,'test','-race','./internal/mcp/server','-run','^TestAnomalyDispatch','-count=1','-timeout=8m','-v'],
                                 tree,isolated,lane_out,'anomaly-race',row['steps'],regressions)
                    for name,count in selected.items():
                        captured=(tree/name).read_bytes()
                        (lane_out/Path(name).name).write_bytes(captured)
                        old=json.loads(historical_file(ROOT,name).read_bytes())
                        if mapping is not None and name == APPROVAL_FIXTURE:
                            compare_approval_capture(json.loads(captured), row['approval_capture_oracle'])
                        elif lane=='historical':
                            if captured != historical_file(ROOT,name).read_bytes():
                                raise ValueError('historical fixture changed: '+name)
                        else:
                            compare_fixture(old,json.loads(captured),count)
                    if row['build_inputs'] != inventory(tree,inputs):
                        raise ValueError('oracle build inputs changed during execution')
                    row.update(passed=True,fixtures=len(selected),cases=sum(selected.values()),
                               captures=inventory(lane_out,[Path(p).name for p in selected]))
                finally:
                    # Preserve available outputs even when a generator fails.
                    for name in FIXTURES:
                        if (tree/name).is_file():
                            (lane_out/Path(name).name).write_bytes((tree/name).read_bytes())
                    git(ROOT,'worktree','remove','--force',str(tree))
        if not args.generator:
            # The product captures bind patched module inputs separately from
            # both immutable lanes. Replay, do not merely trust their metadata.
            product_out=output/'product'
            product_out.mkdir()
            product={'passed':False,'steps':[]}
            receipt['product_replay']=product
            with tempfile.TemporaryDirectory(prefix='mcp-product-fixtures-') as raw:
                home=Path(raw)
                current=dict(env,HOME=str(home),USERPROFILE=str(home),
                             XDG_CONFIG_HOME=str(home/'config'),XDG_DATA_HOME=str(home/'data'),
                             XDG_CACHE_HOME=str(home/'cache'),SYMVAULT_TEST_KEYRING='memory',
                             SYMVAULT_RUN_WINDOWS_CROSSLANG='1',SYMVAULT_SECUREUI='none',SYMVAULT_NO_NOTIFY='1',TZ='UTC')
                names=['CopyClipboard','SecureInput','ExecuteWithSecret']
                current.update({'SYMAIRA_CHECK_MCP_'+CASES[n][0]+'_FIXTURE':'1' for n in names})
                tests=['TestGenerateMCP'+n+'Fixture' for n in names]
                run_step([go,'test','./internal/mcp/server','-run','^('+'|'.join(tests)+')$','-count=1','-timeout=8m','-v'],
                         ROOT,current,product_out,'generators',product['steps'],tests)
            product['passed']=True
        if receipt['candidate_inputs'] != inventory(ROOT,receipt['candidate_inputs']):
            raise ValueError('candidate inputs changed during fixture acceptance')
        receipt['passed']=True
    finally:
        (output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    mode = 'historical replay' if args.approval_generator == 'original' else 'new approval-lifetime-v1 generator executions'
    print(f'PASS {mode} and {CONTRACT}: {len(selected)} fixtures, {sum(selected.values())} cases per lane; {output}/receipt.json')


if __name__=='__main__':
    main()
