#!/usr/bin/env python3
"""One original Linux/x86 deadline observation in the existing MCP workflow.

No installer, acceptance verdict or dirty-source override. Source staging is
separate from compilation. The scheduler supplies an independently reviewed
commit and receipt digest through repository variables, not through this file.
"""
import argparse
import ast
import ctypes
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import Any

from mcp_oracle import inventory
from mcp_fixture_contract import confined_file

BASE = '01f7daae181eba3a34bc90382cfb58e7fa9925c8'
PATCH = 'scripts/rust-port/mcp_deadline_diagnostic.patch'
PATCH_SHA = 'fce9a709c1e89d45206653eb1a860bd2db63b264e42cb98dfaf6f502211a2ce8'
TARGETS = {
    'crates/symvault-mcp/src/broker.rs': '40c21b44a97ac08bb62f549a79348d96af4c8d20711b3d9c24dc9e37077f84c2',
    'crates/symvault-mcp/src/request_context.rs': 'bb1197aedd9959b901024446b0c18c2d59e2cb463d0a6c2caa05480bcdd5030a',
}
ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT/'target/deadline-x86-evidence'
SUITE = ['cargo', 'test', '-p', 'symvault-mcp', '--all-targets', '--locked', '--', '--show-output']
FMT = ['cargo', 'fmt', '--all', '--check']
CLIPPY = ['cargo', 'clippy', '-p', 'symvault-cli', '-p', 'symvault-mcp',
          '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings']
NO_RUN = ['cargo', 'test', '-p', 'symvault-mcp', '--all-targets', '--locked',
          '--no-run', '--message-format=json']
TEST = 'broker::tests::slow_response_cannot_extend_the_request_deadline'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    # Exclusive writes preserve failed/previous attempts, including partial ones.
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def git(root, *args):
    env = {k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
    return subprocess.check_output(['git', *args], cwd=root, env=env, timeout=60)


def sources(root):
    names = git(root, 'ls-files', '-z').decode().rstrip('\0').split('\0')
    for name in names:
        confined_file(root, name)
    return inventory(root, names)


def stage(root, evidence):
    """Materialize the real reviewed patch, with an explicit two-file delta."""
    require(not git(root, 'status', '--porcelain=v1', '--untracked-files=all').strip(),
            'staging requires a clean checkout/index, no dirty override')
    require(digest(confined_file(root, PATCH)) == PATCH_SHA, 'unreviewed diagnostic patch')
    for name in TARGETS:
        require((root/name).read_bytes() == git(root, 'show', BASE+':'+name),
                'product source differs from original diagnostic base')
    before = sources(root)
    index = git(root, 'ls-files', '--stage', '-z')
    save(evidence/'source-before.json', before)
    git(root, 'apply', '--check', PATCH)
    git(root, 'apply', PATCH)
    after = sources(root)
    changed = {name for name in before if before[name] != after[name]}
    require(changed == set(TARGETS), 'diagnostic source delta escaped its two files')
    require({name:after[name] for name in TARGETS} == TARGETS, 'staged bytes differ from review')
    require(index == git(root, 'ls-files', '--stage', '-z'), 'staging changed the Git index')
    save(evidence/'source-staged.json', after)
    save(evidence/'staging.json', {'base':BASE, 'checkout':git(root,'rev-parse','HEAD').decode().strip(),
         'patch_sha256':PATCH_SHA, 'changed':sorted(changed),
         'index_sha256':hashlib.sha256(index).hexdigest(), 'acceptance':False})
    shutil.copyfile(root/PATCH, evidence/'diagnostic.patch')


def admission(env, head, review):
    require(env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'manual diagnostic only')
    require(env.get('GITHUB_RUN_ATTEMPT') == '1', 'no unchanged diagnostic reruns')
    require(env.get('RUNNER_ENVIRONMENT') == 'github-hosted', 'disposable hosted runner required')
    require(env.get('RUNNER_OS') == 'Linux' and platform.system() == 'Linux'
            and platform.machine() == 'x86_64', 'original Linux/x86_64 target required')
    require(re.fullmatch('[0-9a-f]{40}', env.get('DEADLINE_REVIEWED_COMMIT', '')) is not None,
            'missing independently reviewed commit variable')
    require(head == env['DEADLINE_REVIEWED_COMMIT'] == env.get('GITHUB_SHA'),
            'selected checkout is not the independently admitted commit')
    pin = env.get('DEADLINE_REVIEW_SHA256', '')
    require(re.fullmatch('[0-9a-f]{64}', pin) is not None
            and hashlib.sha256(review.encode()).hexdigest() == pin, 'independent review digest mismatch')
    require('RUST_TEST_THREADS' not in env, 'libtest defaults must remain unoverridden')


def installed(env, name):
    path = shutil.which(name, path=env['PATH'])
    require(path is not None, 'required installed tool missing: '+name)
    return str(Path(path).resolve(strict=True))


def private_environment(root, env):
    """Resolve installed tools first; copy only dependency caches, not credentials."""
    rustup = installed(env, 'rustup')
    resolution = {k:env[k] for k in ('PATH','HOME','RUSTUP_HOME') if k in env}
    def rust_tool(name):
        return Path(subprocess.check_output([rustup,'which','--toolchain','1.98.0',name],
                    env=resolution, text=True, timeout=30).strip()).resolve(strict=True)
    cargo, rustc, rustdoc = (rust_tool(n) for n in ('cargo','rustc','rustdoc'))
    for name in ('rustfmt','clippy-driver','cargo-clippy','cargo-fmt'):
        require((cargo.parent/name).is_file(), 'installed Rust component missing: '+name)
    go_candidates = sorted(Path(env['RUNNER_TOOL_CACHE']).glob('go/1.26.6/x64/bin/go'))
    require(len(go_candidates) == 1, 'installed Go 1.26.6 required; no download fallback')
    go = go_candidates[0].resolve(strict=True)
    home = root/'home'
    for leaf in ('home','config','data','cache','runtime','tmp','cargo','build','gocache','gopath'):
        (root/leaf).mkdir(mode=0o700)
    original_cargo = Path(env.get('CARGO_HOME', str(Path(env['HOME'])/'.cargo')))
    for leaf in ('registry','git'):
        require((original_cargo/leaf).is_dir(), 'installed offline Cargo cache missing: '+leaf)
        shutil.copytree(original_cargo/leaf, root/'cargo'/leaf, symlinks=True)
    private = dict(PATH=os.pathsep.join([str(cargo.parent),str(go.parent),str(Path(sys.executable).parent),'/usr/bin','/bin']),
        HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(root/'config'),
        XDG_DATA_HOME=str(root/'data'), XDG_CACHE_HOME=str(root/'cache'), XDG_RUNTIME_DIR=str(root/'runtime'),
        TMPDIR=str(root/'tmp'), TMP=str(root/'tmp'), TEMP=str(root/'tmp'),
        CARGO_HOME=str(root/'cargo'), CARGO_TARGET_DIR=str(root/'build'), CARGO_NET_OFFLINE='true',
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='2', RUSTUP_TOOLCHAIN='1.98.0',
        RUSTC=str(rustc), RUSTDOC=str(rustdoc), GOROOT=str(go.parent.parent), GOTOOLCHAIN='local',
        GOENV='off', GOWORK='off', GOPATH=str(root/'gopath'), GOCACHE=str(root/'gocache'),
        GOMODCACHE=str(root/'gopath/pkg/mod'), GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
        PYTHONDONTWRITEBYTECODE='1', LANG='C.UTF-8', LC_ALL='C.UTF-8', TZ='UTC',
        SYMVAULT_TEST_KEYRING='memory', SYMVAULT_SECUREUI='none', SYMVAULT_NO_NOTIFY='1')
    # Native test invocation only. Compilation itself never receives a filtered suite.
    private['CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER'] = shlex.join(
        [sys.executable,'-B',str(Path(__file__).resolve()),'binary'])
    return private, cargo.parent.parent


def reap_owned():
    """Reap this Linux subreaper's children, including double-fork/setsid exits.

    Called only after the direct child ended. No host-wide process scan, name
    match or recycled process-group signal. pidfds bind the exact live child.
    """
    until = time.monotonic() + 10
    killed = []
    children_file = Path('/proc/self/task')/str(os.getpid())/'children'
    while time.monotonic() < until:
        children = [int(n) for n in children_file.read_text().split()]
        if not children:
            return {'complete':True, 'killed_owned_children':killed}
        for pid in children:
            try:
                fd = getattr(os, 'pidfd_open')(pid)
            except ProcessLookupError:
                continue
            try:
                # pidfd was acquired before the fresh parent check. A recycled
                # PID no longer belonging to this process is never signalled.
                fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
                require(int(fields[1]) == os.getpid(), 'cleanup child identity changed')
                getattr(signal, 'pidfd_send_signal')(fd, signal.SIGKILL)
                killed.append(pid)
            except (ProcessLookupError, FileNotFoundError):
                pass
            finally:
                os.close(fd)
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
        time.sleep(0.01)
    return {'complete':False, 'killed_owned_children':killed}


def run(command, env, output, name, seconds):
    """Keep raw exits/streams, contain only this process's owned descendants."""
    require(platform.system() == 'Linux', 'native Linux process ownership required')
    # Process-local ownership, no privilege/mount/root or runner configuration change.
    require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0,
            'cannot acquire child-subreaper ownership')
    row = {'command':command, 'cwd':str(ROOT), 'exit':None, 'timeout':False,
           'cleanup':'NOT_STARTED'}
    try:
        with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
            child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=out, stderr=err,
                                     start_new_session=True)
            row['pid'] = child.pid
            try:
                row['raw_exit'] = child.wait(timeout=seconds)
                row['exit'] = row['raw_exit'] if row['raw_exit'] >= 0 else 128-row['raw_exit']
            except subprocess.TimeoutExpired:
                row['timeout'] = True
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=10)
                row['raw_exit'] = child.returncode
                row['exit'] = 124
            finally:
                try:
                    row['cleanup'] = reap_owned()
                except Exception as error:
                    row['cleanup'] = {'complete':False, 'error':str(error)}
    finally:
        save(output/(name+'.json'), row)
    if name != 'suite':
        require(row['cleanup']['complete'], 'owned descendant cleanup incomplete')
    return row['exit']


def snapshot(roots):
    """Conservative complete inventories, including symlinks and file modes.

    Bounded to the actual offline packages/SDK and Linux native tool directories,
    not operator homes. strace must account for every successful compiler open or
    exec against these inventories or newly produced private build/tmp outputs.
    """
    result = {}
    total = 0
    for root in sorted(set(Path(p).resolve(strict=True) for p in roots)):
        entries = itertools.chain([root], root.rglob('*') if root.is_dir() else ())
        for path in entries:
            key = str(path)
            if key in result:
                continue
            st = path.lstat()
            require(len(result) < 250000, 'compiler inventory file bound exceeded')
            item: dict[str, Any] = {'mode':stat.S_IMODE(st.st_mode)}
            if path.is_symlink():
                item['symlink'] = os.readlink(path)
                # Resolved successful opens are checked independently below.
            elif stat.S_ISREG(st.st_mode):
                total += st.st_size
                require(total <= 32 * 1024**3, 'compiler inventory byte bound exceeded')
                item.update(size=st.st_size, sha256=digest(path))
            elif not stat.S_ISDIR(st.st_mode):
                raise ValueError('special compiler input: '+key)
            result[key] = item
    return result


def accessed_files(raw):
    """Consume only complete successful open/exec records from strace -f -yy.

    -z excludes failed calls; -s 65535 prevents ordinary path truncation. Unknown
    successful forms are errors, not silently omitted compiler inputs.
    """
    paths = set()
    pending = None
    for line in raw.splitlines():
        if '<unfinished ...>' in line:
            require(pending is None, 'overlapping per-process compiler trace')
            pending = line.replace('<unfinished ...>', '')
            continue
        if 'resumed>' in line:
            require(pending is not None, 'unmatched compiler trace continuation')
            line = pending + line.split('resumed>', 1)[1]
            pending = None
        if not re.search(r'\b(open|openat|openat2|execve|execveat)\(', line):
            require('resumed>' not in line and 'unfinished' not in line,
                    'split strace record cannot establish input closure')
            continue
        require('unfinished' not in line and '...' not in line.split(' = ')[0],
                'truncated/split compiler trace')
        if 'execve(' in line:
            match = re.search(r'execve\(("(?:[^"\\]|\\.)*")', line)
            if match is None:
                raise ValueError('unknown exec trace')
            path = ast.literal_eval(match[1])
        else:
            match = re.search(r' = \d+<([^<>]+)>\s*$', line)
            if match is None:
                raise ValueError('unknown successful open/exec trace')
            path = match[1]
        require(Path(path).is_absolute() and ' (deleted)' not in path, 'unresolved compiler path')
        paths.add(path)
    require(pending is None, 'incomplete compiler trace')
    return sorted(paths)


def closure_accesses(paths, before, after, private):
    generated = []
    special = {'/dev/null', '/dev/urandom', '/dev/random'}
    cargo_state = {str(private/'cargo'/name) for name in
                   ('.global-cache','.global-cache-journal','.package-cache','.package-cache-mutate')}
    for raw in paths:
        path = Path(raw)
        if raw in special or raw in cargo_state:
            continue
        resolved_path = path.resolve()
        if resolved_path.is_relative_to(private/'build') or resolved_path.is_relative_to(private/'compiler-tmp'):
            generated.append(raw)
            continue
        resolved = str(path.resolve(strict=True))
        if path.is_dir():
            require(any(Path(p).is_relative_to(resolved) for p in before), 'unbound input directory: '+raw)
            continue
        require(resolved in before and before[resolved] == after.get(resolved),
                'unbound or changed compiler input: '+raw)
    return generated


def binaries(raw, target):
    result = {}
    for line in raw.splitlines():
        row = json.loads(line)
        if row.get('reason') == 'compiler-artifact' and row.get('executable') and row['profile']['test']:
            path = Path(row['executable']).resolve(strict=True)
            require(path.is_relative_to(target) and path.is_file(), 'foreign test binary')
            result[str(path)] = digest(path)
    require(result, 'cargo produced zero owning test executables')
    return result


def check_staged():
    expected = json.loads((EVIDENCE/'source-staged.json').read_bytes())
    require(sources(ROOT) == expected, 'source changed since staging')
    index = git(ROOT,'ls-files','--stage','-z')
    staged = json.loads((EVIDENCE/'staging.json').read_bytes())
    require(hashlib.sha256(index).hexdigest() == staged['index_sha256'], 'source index changed')
    require(not git(ROOT,'ls-files','--others','--exclude-standard').strip(), 'unexpected untracked source')


def begin():
    env = os.environ.copy()
    head = git(ROOT,'rev-parse','HEAD').decode().strip()
    review = env.get('DEADLINE_REVIEW', '')
    admission(env, head, review)
    require(sys.version_info[:2] == (3,13), 'installed pinned Python 3.13 required')
    require(not EVIDENCE.exists(), 'refusing to reuse an earlier diagnostic directory')
    EVIDENCE.mkdir(parents=True, mode=0o700)
    (EVIDENCE/'independent-review.json').write_text(review)
    save(EVIDENCE/'admission.json', {'checkout':head, 'review_sha256':env['DEADLINE_REVIEW_SHA256'],
         'run_id':env['GITHUB_RUN_ID'], 'attempt':env['GITHUB_RUN_ATTEMPT'], 'acceptance':False})
    stage(ROOT, EVIDENCE)
    private = Path(env['RUNNER_TEMP'])/('vault-deadline-'+env['GITHUB_RUN_ID'])
    private.mkdir(mode=0o700)
    isolated, sdk = private_environment(private, env)
    require(Path(isolated['RUSTC']).is_relative_to(sdk), 'Rust SDK resolution mismatch')
    # These commands only query installed tools; rustup is never invoked later.
    for name, command, expected in [
        ('rustc',[isolated['RUSTC'],'--version','--verbose'],'rustc 1.98.0 '),
        ('cargo',['cargo','--version'],'cargo 1.98.0 '),
        ('go',['go','version'],'go version go1.26.6 linux/amd64')]:
        require(run(command,isolated,EVIDENCE,name,30) == 0, 'installed tool query failed: '+name)
        text = (EVIDENCE/(name+'.stdout')).read_text()
        require(text.startswith(expected), 'installed tool identity mismatch: '+name)
        if name == 'rustc':
            require('host: x86_64-unknown-linux-gnu' in text, 'non-native Rust compiler')
    installed(isolated, 'strace')
    installed(isolated, 'timeout')
    save(EVIDENCE/'environment.json', isolated)
    save(EVIDENCE/'paths.json', {'private':str(private),'sdk':str(sdk)})
    context: dict[str, Any] = {k:env[k] for k in ('ImageOS','ImageVersion','RUNNER_OS','RUNNER_ARCH','GITHUB_RUN_ID',
               'GITHUB_RUN_ATTEMPT','GITHUB_SHA') if k in env}
    context.update(kernel=platform.release(), architecture=platform.machine(),
                   affinity=sorted(getattr(os, 'sched_getaffinity')(0)), test_threads_overridden=False)
    for name in ('cpu.max','cpu.stat'):
        p = Path('/sys/fs/cgroup')/name
        context[name] = p.read_text() if p.is_file() else None
    save(EVIDENCE/'runner.json', context)


def generator():
    env = json.loads((EVIDENCE/'environment.json').read_bytes())
    check_staged()
    code = run(['make','mcp-ordered-fixtures-check'],env,EVIDENCE,'generator',1500)
    check_staged()
    return code


def owning():
    env = json.loads((EVIDENCE/'environment.json').read_bytes())
    paths = json.loads((EVIDENCE/'paths.json').read_bytes())
    private = Path(paths['private'])
    check_staged()
    require(not any((private/'build').iterdir()), 'diagnostic build directory must start empty')
    compiler_tmp = private/'compiler-tmp'
    compiler_tmp.mkdir(mode=0o700)
    env.update(TMPDIR=str(compiler_tmp),TMP=str(compiler_tmp),TEMP=str(compiler_tmp))
    save(EVIDENCE/'compiler-environment.json',env)
    # Actual Cargo metadata provides the dependency graph, not a handwritten list.
    require(run(['cargo','metadata','--locked','--offline','--format-version=1'],env,
                EVIDENCE,'metadata',60) == 0, 'offline dependency graph unavailable')
    metadata = json.loads((EVIDENCE/'metadata.stdout').read_bytes())
    roots = {str(ROOT/p) for p in sources(ROOT)}
    roots.update(str(Path(p['manifest_path']).parent) for p in metadata['packages']
                 if not Path(p['manifest_path']).is_relative_to(ROOT))
    roots.add(paths['sdk'])
    # Conservative full native linker/header/library closure. No SDK download or
    # inference from a compiler version; unexpected successful reads fail closed.
    roots.update(p for p in ['/usr/bin','/usr/lib','/usr/lib64','/usr/include','/lib','/lib64',
                            '/etc/ld.so.cache','/etc/ld.so.conf','/etc/ld.so.conf.d',
                            '/etc/ssl/certs'] if Path(p).exists())
    roots.update(str(private/'cargo'/name) for name in ('registry','git'))
    # A fresh hosted checkout has no operator Git configuration/credential store.
    require((ROOT/'.git').is_dir(), 'diagnostic requires its own hosted Git checkout')
    roots.add(str(ROOT/'.git'))
    before = snapshot(roots)
    save(EVIDENCE/'compiler-inputs-before.json', before)
    code = run(FMT,env,EVIDENCE,'fmt',120)
    if code:
        return code
    def traced(command, name):
        return ['strace','-ff','-z','-yy','-s','65535','-e',
                'trace=open,openat,openat2,execve,execveat','-o',str(EVIDENCE/(name+'.trace')), *command]
    # Clippy can compile native dependencies/build scripts too. Bind those real
    # reads in the same closure; a later warm no-run build cannot account for them.
    code = run(traced(CLIPPY,'clippy'),env,EVIDENCE,'clippy',900)
    if code:
        return code
    # The no-run build records real compiler access. It does NOT execute any test.
    code = run(traced(NO_RUN,'build-tests'),env,EVIDENCE,'build-tests',900)
    after = snapshot(roots)
    save(EVIDENCE/'compiler-inputs-after.json', after)
    require(before == after, 'compiler input closure changed during build')
    if code:
        return code
    observed = set()
    for trace in sorted(EVIDENCE.glob('*.trace.*')):
        require(trace.stat().st_size <= 64*1024**2, 'compiler trace size bound exceeded')
        observed.update(accessed_files(trace.read_text()))
    require(observed, 'empty compiler access trace')
    observed = sorted(observed)
    generated = closure_accesses(observed,before,after,private)
    save(EVIDENCE/'compiler-accesses.json', {'observed':observed,'generated':generated})
    generated_inputs = snapshot([private/'build'])
    save(EVIDENCE/'generated-inputs.json', generated_inputs)
    test_binaries = binaries((EVIDENCE/'build-tests.stdout').read_text(),private/'build')
    save(EVIDENCE/'test-binaries.json',test_binaries)
    check_staged()
    save(EVIDENCE/'suite-started.json',{'command':SUITE, 'acceptance':False})
    # Original timeout and full unfiltered concurrent suite. The runner hashes each
    # actual executable immediately before/after its one invocation, without tracing
    # the timed test. No --exact, thread override or second suite invocation.
    code = run(['timeout','--kill-after=10s','480s',*SUITE],env,EVIDENCE,'suite',500)
    (ROOT/'target/deadline-x86-suite.exit').write_text(str(code)+'\n')
    shutil.copyfile(EVIDENCE/'suite.stdout',ROOT/'target/native-mcp-tests.txt')
    shutil.copyfile(EVIDENCE/'suite.stderr',ROOT/'target/native-mcp-tests.stderr')
    # Failures are retained before fallible parsing. The workflow returns the
    # original suite exit; provenance failure is separate, never a native PASS.
    final = {'suite_exit':code, 'provenance_error':None, 'acceptance':False}
    try:
        lifecycle = json.loads((EVIDENCE/'suite.json').read_bytes())
        require(lifecycle['cleanup']['complete'], 'owning process tree cleanup incomplete')
        check_staged()
        require(snapshot(roots) == before, 'compiler inputs changed during suite')
        require(all(digest(p) == h for p,h in test_binaries.items()), 'binary identity changed')
        for p,row in generated_inputs.items():
            if 'sha256' in row:
                require(Path(p).is_file() and digest(p) == row['sha256'], 'generated build input changed')
        text = (EVIDENCE/'suite.stdout').read_text()
        final['libtest_results'] = [list(map(int,m[1:])) for m in re.findall(
            r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out',text)]
        require(final['libtest_results'], 'zero observed libtest results')
        require(len(re.findall(r'^test '+re.escape(TEST)+r' \.\.\. (?:ok|FAILED)$',text,re.M)) == 1,
                'named deadline case not executed exactly once')
        require(all(r[2:] == [0,0,0] for r in final['libtest_results']), 'ignored/measured/filtered cases')
        require(sum(final['libtest_results'][0][:2]) == 135, 'owning library count changed')
        if code == 0:
            require(sum(r[0] for r in final['libtest_results']) == 238, 'full owning suite not reached')
        executions = [json.loads(p.read_bytes()) for p in EVIDENCE.glob('binary-*.json')]
        require(executions, 'no observed native test executable')
        require(all(r['before'] == r['after'] == test_binaries[r['executable']] for r in executions),
                'executed test executable identity mismatch')
        if code == 0:
            require({r['executable'] for r in executions} == set(test_binaries), 'unreached owning executables')
        final['trace_dropped'] = re.findall(r'DEADLINE_DROPPED (\d+)',text)
        require(final['trace_dropped'] == ['0'], 'missing/dropped diagnostic trace')
    except Exception as error:
        final['provenance_error'] = str(error)
    save(EVIDENCE/'observation.json', final)
    return code


def binary(arguments):
    """Cargo target runner: keep libtest args/default concurrency unchanged."""
    require(len(arguments) == 2 and arguments[1] == '--show-output', 'unexpected libtest arguments')
    executable = str(Path(arguments[0]).resolve(strict=True))
    admitted = json.loads((EVIDENCE/'test-binaries.json').read_bytes())
    require(executable in admitted and digest(executable) == admitted[executable], 'unbound executable')
    record = EVIDENCE/('binary-'+hashlib.sha256(executable.encode()).hexdigest()+'.json')
    # Exclusive start marker prevents re-execution even after a crash or failure.
    save(record.with_suffix('.started'), {'executable':executable,'sha256':admitted[executable]})
    result = subprocess.run([executable,*arguments[1:]], check=False)
    save(record, {'executable':executable,'before':admitted[executable],
                 'after':digest(executable),'exit':result.returncode})
    return result.returncode if result.returncode >= 0 else 128-result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=['stage','generator','owning','binary'])
    parser.add_argument('arguments',nargs=argparse.REMAINDER)
    args = parser.parse_args()
    require(not sys.flags.optimize, 'unoptimized Python required')
    if args.mode == 'binary':
        return binary(args.arguments)
    require(not args.arguments, 'unexpected diagnostic arguments')
    if args.mode == 'stage':
        begin()
        return 0
    return generator() if args.mode == 'generator' else owning()


if __name__ == '__main__':
    sys.exit(main())
