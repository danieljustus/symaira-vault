#!/usr/bin/env python3
"""Replay unchanged historical MCP fixtures, then compare a corrected source lane.

The two lanes reuse the existing Go generators. Only oracle identity literals
are rebased in the disposable corrected generator, never in historical files.
Every response/state/case field is compared without a provenance exemption.
"""
import argparse
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

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_BASE = '2b596f916bf736250b7fd3bb4d39f5f89fb20aa2'
ANCHOR = ROOT/'scripts/rust-port/fixtures/mcp-anomaly/historical-inputs.json'
ANCHOR_SHA256 = '678531bead3d9bc4a8d754ce7996b8cd29f94d8a4dbb8ef91cef71577296394d'
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
        confined_file(root,name)
    for name in names:
        if hashlib.sha256(confined_file(root,name).read_bytes()).hexdigest() != manifest['files'][name]:
            raise ValueError('historical fixture/generator anchor drift: '+name)


def generator_paths():
    paths = set()
    for name in FIXTURES:
        data = json.loads((ROOT/name).read_bytes())
        paths.update(data['oracle'].get('generator_files', []))
    paths.update(p.relative_to(ROOT).as_posix() for p in (ROOT/'internal/mcp/server').glob('*fixture*_test.go'))
    for directory in ['mcpcallgen', 'http001initgen', 'execute_secret_provenance']:
        paths.update(p.relative_to(ROOT).as_posix() for p in (ROOT/'scripts/rust-port/cmd'/directory).glob('*.go'))
    paths.update(p.relative_to(ROOT).as_posix() for p in (ROOT/'scripts/rust-port/internal/provenance').glob('*.go'))
    return sorted(paths)


def run_step(command, cwd, env, output, name, steps, tests=(), timeout=600):
    row = {'name':name, 'command':command, 'exit':None, 'timed_out':False,
           'stdout':name+'.stdout', 'stderr':name+'.stderr', 'passed':False}
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
        if sorted(actual) != sorted(tests) or not re.search(r'^PASS\nok\s',text,re.M):
            raise ValueError(name+' missing/extra executed generator tests: '+repr(actual))
        row['executed_tests'] = actual
    row['passed'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    destinations = parser.add_mutually_exclusive_group(required=True)
    destinations.add_argument('--output', type=Path, help='new evidence directory, never overwrites a prior run')
    destinations.add_argument('--output-root', type=Path, help='parent for a fresh retained run directory')
    args = parser.parse_args()
    if sys.flags.optimize:
        parser.error('unoptimized Python is required')
    validate_reference(ROOT)
    fixture_anchor(ROOT, FIXTURES)
    generators = generator_paths()
    fixture_anchor(ROOT, [*FIXTURES, *generators])
    # Every currently declared production input must equal the corrected source.
    sources = sorted({p for name in FIXTURES for p in json.loads((ROOT/name).read_bytes())['oracle']['source_files']})
    for name in sources:
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
               'candidate_inputs':inventory(ROOT,[*FIXTURES,*generators,*sources,'scripts/rust-port/mcp_oracle.py','scripts/rust-port/mcp_fixture_contract.py',ANCHOR.relative_to(ROOT).as_posix()]),
               'native_os':sys.platform, 'passed':False, 'lanes':[]}
    try:
        go, env, compiler = pinned_go(os.environ.copy(), ROOT)
        receipt['compiler'] = compiler
        for lane,commit in [('historical',HISTORICAL),('corrected',ORDERED)]:
            lane_out = output/lane
            lane_out.mkdir()
            row = {'lane':lane,'source_commit':commit,'passed':False,'steps':[]}
            receipt['lanes'].append(row)
            with tempfile.TemporaryDirectory(prefix='mcp-fixtures-'+lane+'-') as raw:
                base = Path(raw)
                tree = base/'oracle'
                git(ROOT, 'worktree','add','--detach',str(tree),commit)
                try:
                    for name in [*generators,*FIXTURES]:
                        target = tree/name
                        target.parent.mkdir(parents=True,exist_ok=True)
                        data = (ROOT/name).read_bytes()
                        if lane=='corrected' and name in generators and name.endswith('.go'):
                            data = corrected_generator(data)
                        target.write_bytes(data)
                    home=base/'home'
                    home.mkdir(mode=0o700)
                    isolated={k:v for k,v in env.items() if not k.startswith(('SYMVAULT_','SYMAIRA_'))}
                    isolated.update(HOME=str(home),USERPROFILE=str(home),XDG_CONFIG_HOME=str(home/'config'),
                                    XDG_DATA_HOME=str(home/'data'),XDG_CACHE_HOME=str(home/'cache'),
                                    SYMVAULT_TEST_KEYRING='memory',SYMVAULT_RUN_WINDOWS_CROSSLANG='1',
                                    SYMVAULT_SECUREUI='none',SYMVAULT_NO_NOTIFY='1',TZ='UTC')
                    mode = 'CHECK' if lane=='historical' else 'GENERATE'
                    isolated.update({'SYMAIRA_'+mode+'_MCP_'+flag+'_FIXTURE':'1' for flag,_,_ in CASES.values()})
                    # Bind the entire immutable tree plus overlaid generators.
                    # Only the explicitly captured output files may change.
                    names = git(tree,'ls-files').decode().splitlines()
                    inputs = sorted((set(names) | set(generators)) - set(FIXTURES))
                    row['build_inputs'] = inventory(tree,inputs)
                    check = ['-check'] if lane=='historical' else []
                    run_step([go,'run','./scripts/rust-port/cmd/mcpcallgen',*check],tree,isolated,lane_out,'tools-call',row['steps'])
                    run_step([go,'run','./scripts/rust-port/cmd/http001initgen',*check],tree,isolated,lane_out,'http-initialize',row['steps'])
                    tests = ['TestGenerateMCP'+name+'Fixture' for name in CASES]
                    run_step([go,'test','./internal/mcp/server','-run','^('+'|'.join(tests)+')$','-count=1','-timeout=8m','-v'],tree,isolated,lane_out,'generators',row['steps'],tests)
                    if lane=='corrected':
                        regressions=['TestAnomalyDispatch'+suffix for suffix in [
                            'CompletionOrder','GenuineToolChain','EOFAuditLifetime','Timestamp',
                            'BusyWorkerDoesNotBlockTools','CloseDrainsAdmittedTool']]
                        run_step([go,'test','-race','./internal/mcp/server','-run','^TestAnomalyDispatch','-count=1','-timeout=8m','-v'],
                                 tree,isolated,lane_out,'anomaly-race',row['steps'],regressions)
                    for name,count in FIXTURES.items():
                        captured=(tree/name).read_bytes()
                        (lane_out/Path(name).name).write_bytes(captured)
                        old=json.loads((ROOT/name).read_bytes())
                        if lane=='historical':
                            if captured != (ROOT/name).read_bytes():
                                raise ValueError('historical fixture changed: '+name)
                        else:
                            compare_fixture(old,json.loads(captured),count)
                    if row['build_inputs'] != inventory(tree,inputs):
                        raise ValueError('oracle build inputs changed during execution')
                    row.update(passed=True,fixtures=len(FIXTURES),cases=sum(FIXTURES.values()),
                               captures=inventory(lane_out,[Path(p).name for p in FIXTURES]))
                finally:
                    # Preserve available outputs even when a generator fails.
                    for name in FIXTURES:
                        if (tree/name).is_file():
                            (lane_out/Path(name).name).write_bytes((tree/name).read_bytes())
                    git(ROOT,'worktree','remove','--force',str(tree))
        if receipt['candidate_inputs'] != inventory(ROOT,receipt['candidate_inputs']):
            raise ValueError('candidate inputs changed during fixture acceptance')
        receipt['passed']=True
    finally:
        (output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(f'PASS historical replay and {CONTRACT}: {len(FIXTURES)} fixtures, {sum(FIXTURES.values())} cases per lane; {output}/receipt.json')


if __name__=='__main__':
    main()
