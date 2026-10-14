#!/usr/bin/env python3
"""Noncompiling source/file controls, never a simulated native observation."""
import ast
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import platform
import shutil
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import mcp_deadline_diagnostic as diagnostic
import mcp_deadline_capture as capture

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT/'.github/workflows/rust-mcp-process.yml'
SELECTOR = "github.event_name == 'workflow_dispatch' && inputs.deadline_diagnostic"


def workflow_boundaries(text):
    def need(condition):
        if not condition:
            raise ValueError('diagnostic workflow boundary drift')
    need('default: false' in text and 'deadline_review:' in text)
    preflight = text.split('  compiler-capture-preflight:\n',1)[1].split('  mcp-process:\n',1)[0]
    need('    if: ${{ !('+SELECTOR+') }}\n' in preflight)
    need('    runs-on: ubuntu-latest\n' in preflight)
    need('          ref: ${{ github.event.pull_request.head.sha || github.sha }}' in preflight)
    need('run: python3 -B scripts/rust-port/mcp_deadline_preflight.py' in preflight)
    need('timeout-minutes: ${{ ('+SELECTOR+') && 150 || 40 }}' in text)
    preparation = [('Verify diagnostic preparation authorization',1),
                   ('Prepare diagnostic Python',5), ('Prepare diagnostic Go',5),
                   ('Prepare diagnostic tools and dependency caches',20)]
    previous = -1
    for name, minutes in preparation:
        marker = '      - name: '+name+'\n'
        position = text.index(marker)
        need(previous < position < text.index('      - name: Admit and stage'))
        previous = position
        block = text.split(marker,1)[1].split('      - name:',1)[0]
        need('        if: ${{ '+SELECTOR+' }}\n' in block)
        need('        timeout-minutes: '+str(minutes)+'\n' in block)
    need('target/deadline-preparation/' in text)
    for name, minutes in [('Checkout retained Go oracle and candidate',5),
                          ('Admit and stage the reviewed original-target diagnostic',10),
                          ('Check narrow diagnostic and receipt evidence boundaries',5),
                          ('Execute the same corrected generator with private diagnostic state',26),
                          ('Test the owning runtime and production CLI assembly',55),
                          ('Upload complete actual native observations',10)]:
        block = text.split('      - name: '+name+'\n',1)[1].split('      - name:',1)[0]
        expected = (str(minutes) if name.startswith(('Admit','Execute the same'))
                    else '${{ ('+SELECTOR+') && '+str(minutes)+' || 40 }}')
        need('        timeout-minutes: '+expected+'\n' in block)
    controls = text.split('      - name: Check narrow diagnostic and receipt evidence boundaries\n',1)[1].split('      - name:',1)[0]
    need(controls.count('"${DEADLINE_PYTHON:-python3}" -B') == 3)
    need('          python3 ' not in controls)
    headers = text.split('      - name: Check frozen diagnostic header reader\n',1)[1].split('      - name:',1)[0]
    need(('        if: ${{ !('+SELECTOR+') }}') in headers)
    need("'[\"ubuntu-latest\"]' || '[\"ubuntu-latest\",\"macos-latest\",\"windows-latest\"]'" in text)
    owning = text.split('      - name: Test the owning runtime and production CLI assembly\n',1)[1]
    owning, later = owning.split('      - name: Execute actual Go and Rust native profiles and hostile stdio\n',1)
    need(owning.count('exec "$DEADLINE_PYTHON" -B scripts/rust-port/mcp_deadline_diagnostic.py owning') == 1)
    need(owning.index('diagnostic.py owning') < owning.index('cargo fmt --all --check'))
    need(('        if: ${{ success() && !('+SELECTOR+') }}') in later)
    upload = later.split('      - name: Upload complete actual native observations\n',1)[1]
    need('        if: always()\n' in upload)
    for path in ('target/native-mcp-tests.txt','target/native-mcp-tests.stderr',
                 'target/deadline-x86-suite.exit','target/deadline-x86-evidence/',
                 'target/mcp-fixture-evidence/'):
        need(path in upload)
    need('continue-on-error' not in text)
    for name in ('Set up pinned Go','Set up pinned Python','Install pinned Rust'):
        block = text.split('      - name: '+name+'\n',1)[1].split('      - name:',1)[0]
        need(('        if: ${{ !('+SELECTOR+') }}') in block)


class SourceControls(unittest.TestCase):
    def test_absent_real_rustup_toolchain_never_downloads_or_installs(self):
        from mcp_oracle import tool_environment
        offline = {'GOPROXY':'off','GOSUMDB':'off'}
        self.assertEqual(tool_environment(offline, build=True), offline)
        self.assertEqual(tool_environment(offline), {})
        credentialed = 'https://user:synthetic-only@proxy.example.invalid'
        for key in ('GOPROXY','GOSUMDB','goproxy','gosumdb'):
            for value in (credentialed,'sum.golang.org','direct','OFF','off,direct',''):
                with self.subTest(key=key,value=value):
                    self.assertEqual(tool_environment({key:value},build=True),{})
            self.assertEqual(tool_environment({key:'off'},build=True),{key:'off'})
            self.assertEqual(tool_environment({key:'off'}),{})
        self.assertEqual(tool_environment({'PATH':os.defpath,'GOPROXY':credentialed,
                         'GOSUMDB':'off'},build=True),{'PATH':os.defpath,'GOSUMDB':'off'})
        rustup = shutil.which('rustup')
        if rustup is None:
            self.fail('real rustup required for this regression')
        requests = []
        class RejectDownload(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_error(503)
            def log_message(self, format, *args):
                pass
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as raw:
            root = Path(raw)
            env = {'PATH':os.environ['PATH'], 'HOME':raw, 'RUSTUP_HOME':str(root/'rustup'),
                   'RUSTUP_AUTO_INSTALL':'1'}
            if os.name != 'nt':
                # Exercise actual multicall dispatch, as on Homebrew CI runners.
                shutil.copy2(rustup,root/'rustup-init')
                (root/'bin').mkdir()
                (root/'bin/rustup').symlink_to(root/'rustup-init')
                env['PATH'] = str(root/'bin')+os.pathsep+env['PATH']
            for key in ('SYSTEMROOT','WINDIR'):
                if key in os.environ:
                    env[key] = os.environ[key]
            server = ThreadingHTTPServer(('127.0.0.1',0),RejectDownload)
            thread = threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            actual = subprocess.check_output
            def guarded(command, **kwargs):
                # Real rustup, with an observed loopback distribution endpoint.
                # The control prevents an unfixed implementation downloading Rust.
                kwargs['env'] = dict(kwargs['env'], RUSTUP_DIST_SERVER=f'http://127.0.0.1:{server.server_port}')
                kwargs['stderr'] = subprocess.PIPE
                return actual(command, **kwargs)
            try:
                with patch.object(diagnostic.subprocess,'check_output',side_effect=guarded):
                    with self.assertRaises(subprocess.CalledProcessError) as failed:
                        diagnostic.private_environment(root/'private',env)
                self.assertIn('not installed',failed.exception.stderr)
                self.assertEqual(requests,[])
                self.assertFalse(any((root/'rustup/toolchains').glob('*')))
                self.assertFalse(any((root/'rustup/downloads').glob('*')))
                self.assertFalse((root/'private').exists())
            finally:
                server.shutdown()
                thread.join()
                server.server_close()

    def test_real_entrypoint_refuses_missing_admission_and_optimization(self):
        script = ROOT/'scripts/rust-port/mcp_deadline_diagnostic.py'
        env = {k:v for k,v in os.environ.items() if k in ('PATH','TMPDIR','SYSTEMROOT','WINDIR')}
        for flags,reason in [([], 'manual diagnostic only'), (['-O'], 'unoptimized Python required')]:
            with self.subTest(flags=flags):
                result = subprocess.run([sys.executable,'-B',*flags,str(script),'stage'],
                                        cwd=ROOT,env=env,capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0)
                self.assertIn(reason,result.stderr)
                self.assertEqual(result.stdout,'')

    def test_compiler_preflight_refuses_nonhosted_and_optimized_execution(self):
        script = ROOT/'scripts/rust-port/mcp_deadline_preflight.py'
        env = {k:v for k,v in os.environ.items() if k in ('PATH','TMPDIR','SYSTEMROOT','WINDIR')}
        reason = ('hosted runner required' if platform.system() == 'Linux' and platform.machine() == 'x86_64'
                  else 'native Linux/x86_64 preflight required')
        for flags,message in [([],reason),(['-O'],'unoptimized Python required')]:
            with self.subTest(flags=flags):
                result = subprocess.run([sys.executable,'-B',*flags,str(script)],
                                        env=env,capture_output=True,text=True,timeout=30)
                self.assertNotEqual(result.returncode,0)
                self.assertIn(message,result.stderr)
                self.assertEqual(result.stdout,'')

    def test_frozen_patch_and_actual_git_applicability(self):
        patch = ROOT/diagnostic.PATCH
        self.assertEqual(diagnostic.digest(patch), diagnostic.PATCH_SHA)
        staged = all(diagnostic.digest(ROOT/name) == value for name,value in diagnostic.TARGETS.items())
        command = ['git','apply','--check',*(['--reverse'] if staged else []),str(patch)]
        subprocess.run(command,cwd=ROOT,check=True)
        # Read actual retained Git blobs; apply the reviewed unified hunks in
        # memory, not to the operator worktree or a second implementation tree.
        lines = patch.read_text().splitlines(keepends=True)
        i = 0
        results = {}
        while i < len(lines):
            self.assertTrue(lines[i].startswith('--- a/'))
            name = lines[i][6:].strip()
            self.assertEqual(lines[i+1], '+++ b/'+name+'\n')
            original = diagnostic.git(ROOT,'show',diagnostic.BASE+':'+name).decode().splitlines(True)
            output = []
            position = 0
            i += 2
            while i < len(lines) and not lines[i].startswith('--- a/'):
                header = lines[i]
                self.assertTrue(header.startswith('@@ -'))
                start = int(header.split(' ')[1][1:].split(',')[0])-1
                output.extend(original[position:start])
                position = start
                i += 1
                while i < len(lines) and not lines[i].startswith(('@@ ', '--- a/')):
                    line = lines[i]
                    if line.startswith((' ', '-')):
                        self.assertEqual(original[position],line[1:])
                        position += 1
                    if line.startswith((' ', '+')):
                        output.append(line[1:])
                    i += 1
            output.extend(original[position:])
            results[name] = hashlib.sha256(''.join(output).encode()).hexdigest()
        self.assertEqual(results, diagnostic.TARGETS)

    def test_real_file_closure_and_mutations(self):
        # These are explicitly algorithm fixture files, not native tool outputs.
        with tempfile.TemporaryDirectory(prefix='deadline-source-',dir=os.environ['TMPDIR']) as raw:
            root = Path(raw)
            source = root/'compiler-input.txt'
            source.write_text('source-control-only\n')
            before = diagnostic.snapshot([source])
            self.assertEqual(diagnostic.closure_accesses([str(source)],before,before,root/'private'), [])
            source.write_text('changed-source-control-only\n')
            after = diagnostic.snapshot([source])
            with self.assertRaisesRegex(ValueError,'changed compiler input'):
                diagnostic.closure_accesses([str(source)],before,after,root/'private')
            foreign = root/'not-in-closure.txt'
            foreign.write_text('unbound-source-control\n')
            with self.assertRaisesRegex(ValueError,'unbound'):
                diagnostic.closure_accesses([str(foreign)],before,before,root/'private')
            private = root/'private'
            (private/'build').mkdir(parents=True)
            escape = private/'build/../../not-in-closure.txt'
            with self.assertRaisesRegex(ValueError,'unbound'):
                diagnostic.closure_accesses([str(escape)],before,before,private)

    def test_generated_inputs_need_both_boundaries_including_compiler_tmp(self):
        # Real algorithm files only, not compiler products or native observations.
        with tempfile.TemporaryDirectory(prefix='deadline-source-',dir=os.environ['TMPDIR']) as raw:
            private = Path(raw)
            for directory in ('build','compiler-tmp'):
                with self.subTest(directory=directory):
                    root = private/directory
                    root.mkdir()
                    source = root/'input.txt'
                    before = diagnostic.snapshot([root])
                    with self.assertRaisesRegex(ValueError,'missing compiler input'):
                        diagnostic.closure_accesses([str(source)],before,before,private)
                    source.write_text('algorithm file A\n')
                    after = diagnostic.snapshot([root])
                    # Surviving after-only bytes do NOT bind same-command consumption.
                    with self.assertRaisesRegex(ValueError,'unbound'):
                        diagnostic.closure_accesses([str(source)],before,after,private)
                    self.assertEqual(diagnostic.closure_accesses([str(source)],after,after,private),[str(source)])
                    source.write_text('algorithm file B\n')
                    changed = diagnostic.snapshot([root])
                    with self.assertRaisesRegex(ValueError,'changed compiler input'):
                        diagnostic.closure_accesses([str(source)],after,changed,private)
                    source.rename(root/'retained-deleted-input.txt')
                    with self.assertRaisesRegex(ValueError,'missing compiler input'):
                        diagnostic.closure_accesses([str(source)],after,diagnostic.snapshot([root]),private)

    def test_actual_descriptor_capture_survives_rename_and_binds_both_roots(self):
        # Ordinary file IO only. No lease/ptrace/compile or invented native record.
        with tempfile.TemporaryDirectory(prefix='deadline-source-',dir=os.environ['TMPDIR']) as raw:
            private = Path(raw).resolve()
            blobs = private/'blobs'
            blobs.mkdir()
            for directory in ('build','compiler-tmp'):
                with self.subTest(directory=directory):
                    root = private/directory
                    root.mkdir()
                    before = diagnostic.snapshot([root])
                    source = root/'new-input.txt'
                    content = b'actual generated file-only control\n'
                    source.write_bytes(content)
                    with source.open('rb') as stream:
                        # The production copying primitive sees a real open input.
                        row = capture.retain_fd(stream.fileno(),blobs/(directory+'.input'))
                        capture.verify_fd(stream.fileno(),row)
                        capture.verify_blob(blobs,row)
                        self.assertEqual((blobs/row['blob']).read_bytes(),content)
                        after = diagnostic.snapshot([root])
                        self.assertEqual(diagnostic.closure_accesses([str(source)],before,after,private,
                                         {str(source):row}),[str(source)])
                        # Windows CRT does not share delete access. Its ordinary
                        # workflow control reopens the same inode after rename;
                        # Unix additionally checks the still-held descriptor.
                        if os.name == 'nt':
                            stream.close()
                        source.rename(root/'moved-input.txt')
                        with (root/'moved-input.txt').open('rb') as moved:
                            capture.verify_fd(moved.fileno(),row)
                        if not stream.closed:
                            # Unlink only this test-created fixture. The retained
                            # input is now genuinely absent from the directory.
                            (root/'moved-input.txt').unlink()
                            capture.verify_fd(stream.fileno(),row)
                        after = diagnostic.snapshot([root])
                        self.assertEqual(diagnostic.closure_accesses([str(source)],before,after,private,
                                         {str(source):row}),[str(source)])
                        # Reopening the pathname would capture the wrong inode.
                        source.write_bytes(b'replacement input\n')
                        if not stream.closed:
                            capture.verify_fd(stream.fileno(),row)
                        with self.assertRaisesRegex(ValueError,'captured generated input changed'):
                            diagnostic.closure_accesses([str(source)],before,diagnostic.snapshot([root]),
                                                        private,{str(source):row})

    def test_descriptor_and_retained_blob_mutations_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix='deadline-source-',dir=os.environ['TMPDIR']) as raw:
            root = Path(raw)
            source = root/'algorithm-input'
            source.write_bytes(b'file-only content A\n')
            with source.open('rb') as stream:
                blob = root/'held.input'
                row = capture.retain_fd(stream.fileno(),blob)
                source.write_bytes(b'file-only content B\n')
                with self.assertRaisesRegex(ValueError,'changed'):
                    capture.verify_fd(stream.fileno(),row)
                blob.write_bytes(b'corrupted blob\n')
                with self.assertRaisesRegex(ValueError,'captured blob changed'):
                    capture.verify_blob(root,row)
                blob.rename(root/'removed.input')
                with self.assertRaises(FileNotFoundError):
                    capture.verify_blob(root,row)
                with self.assertRaisesRegex(ValueError,'invalid captured blob'):
                    capture.verify_blob(root,{**row,'blob':'../outside.input'})
            with self.assertRaises(OSError):
                capture.retain_fd(-1,root/'absent.input')
            self.assertFalse((root/'absent.input').exists())

    def test_native_dispatch_source_and_unsupported_syscalls_fail_closed(self):
        # ABI argument controls, not fabricated kernel logs or successful receipts.
        args = [7,8,1,2,9,0]
        for number in (0,17,19,295,327,275,326):
            self.assertEqual(capture.input_fd(number,args),7)
        self.assertEqual(capture.input_fd(40,args),8)
        self.assertEqual(capture.input_fd(16,[7,0x40049409,8,0,0,0]),8)
        # Exact FIONBIO operands retained from native run 38409669738.
        self.assertIsNone(capture.input_fd(16,[4,21537,140731676179844,
                                             93851314414128,93851312766992,7]))
        with self.assertRaisesRegex(ValueError,'unsupported compiler ioctl'):
            capture.input_fd(16,[7,0x4020940d,8,0,0,0])
        with self.assertRaisesRegex(ValueError,'untraced/namespaced'):
            capture.input_fd(56,[0x00800000,0,0,0,0,0])
        with self.assertRaisesRegex(ValueError,'number/ABI'):
            capture.input_fd(0x40000000,args)
        self.assertEqual(capture.input_fd(9,args),9)
        self.assertIsNone(capture.input_fd(9,[7,8,3,0x22,9,0]))
        with self.assertRaisesRegex(ValueError,'shared mapping'):
            capture.input_fd(9,[7,8,3,1,9,0])
        for number in (101,206,209,310,311,425,426,427):
            with self.subTest(number=number), self.assertRaisesRegex(ValueError,'unsupported'):
                capture.input_fd(number,args)
        with self.assertRaisesRegex(ValueError,'unsupported compiler syscall ABI'):
            capture.read_syscall(bytes(88),0)
        text = Path(capture.__file__).read_text()
        self.assertLess(text.index('fcntl.fcntl(fd,fcntl.F_SETLEASE'),text.index('row = retain_fd('))
        self.assertIn('verify_fd(fd,row)',text)
        self.assertIn("signal.signal(sig,interrupted)",text)
        self.assertIn("record['complete'] = False",text)
        producer = Path(diagnostic.__file__).read_text()
        self.assertIn("str(ROOT/'scripts/rust-port/mcp_deadline_capture.py')",producer)
        self.assertIn("verify_blob(directory/'blobs',row)",producer)
        self.assertNotIn("return ['strace'",producer)

    def test_shared_memory_and_remote_advice_are_rejected(self):
        # ABI argument controls, not native observations. Without a bound reader
        # and verified descriptor mode, even PROT_READ shared maps fail closed.
        for flags in (1,3,0x21,0x23):
            for protection in (1,3):
                with self.subTest(flags=flags,protection=protection):
                    with self.assertRaisesRegex(ValueError,'shared mapping'):
                        capture.input_fd(9,[0,4096,protection,flags,7,0])
        for number in (29,30,440):  # shmget, shmat, process_madvise
            with self.subTest(number=number), self.assertRaisesRegex(ValueError,'unsupported'):
                capture.input_fd(number,[0,0,0,0,0,0])
        self.assertIsNone(capture.input_fd(9,[0,4096,3,0x22,0,0]))
        self.assertEqual(capture.input_fd(9,[0,4096,1,2,7,0]),7)

    def test_shared_file_mapping_requires_readonly_descriptor_evidence(self):
        # Injected fdinfo only, not a kernel observation.
        for flags,protection in ((0x21,1),(0x23,1),(1,3)):
            with self.subTest(flags=flags,protection=protection):
                with patch.object(capture.Path,'read_text',return_value='flags:\t02000000\n'):
                    with self.assertRaisesRegex(ValueError,'shared mapping'):
                        capture.input_fd(9,[0,4096,protection,flags,7,0],pid=10)
        for flags in (1,3):
            args = [0,4096,1,flags,7,0]
            with patch.object(capture.Path,'read_text',return_value='flags:\t02000000\n'):
                self.assertEqual(capture.input_fd(9,args,pid=10),7)
            for info in ('flags:\t02000002\n','flags:\t02000001\n',
                         'flags:\t02000003\n','flags:\tinvalid\n','pos:\t0\n',
                         'flags:\t0\nflags:\t0\n'):
                with self.subTest(flags=flags,info=info):
                    with patch.object(capture.Path,'read_text',return_value=info):
                        with self.assertRaisesRegex(ValueError,'shared mapping'):
                            capture.input_fd(9,args,pid=10)
            with patch.object(capture.Path,'read_text',side_effect=FileNotFoundError):
                with self.assertRaises(FileNotFoundError):
                    capture.input_fd(9,args,pid=10)

    @unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64',
                         'requires real Linux mapping and fdinfo semantics')
    def test_native_readonly_shared_mapping_cannot_gain_write_permission(self):
        import ctypes
        import errno
        libc = ctypes.CDLL(None,use_errno=True)
        libc.mmap.restype = ctypes.c_void_p
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as raw:
            source = Path(raw)/'mapping-input'
            source.write_bytes(b'x'*4096)
            with source.open('rb') as readonly, source.open('r+b') as writable:
                for flags in (1,3):
                    args = [0,4096,1,flags,readonly.fileno(),0]
                    self.assertEqual(capture.input_fd(9,args,pid=os.getpid()),readonly.fileno())
                    with self.assertRaisesRegex(ValueError,'not verified O_RDONLY'):
                        capture.input_fd(9,[0,4096,1,flags,writable.fileno(),0],pid=os.getpid())
                    address = libc.mmap(ctypes.c_void_p(),ctypes.c_size_t(4096),
                                        1,flags,readonly.fileno(),ctypes.c_long(0))
                    self.assertNotIn(address,(None,ctypes.c_void_p(-1).value))
                    try:
                        self.assertEqual(ctypes.string_at(address,4096),b'x'*4096)
                        self.assertEqual(libc.mprotect(ctypes.c_void_p(address),ctypes.c_size_t(4096),3),-1)
                        self.assertEqual(ctypes.get_errno(),errno.EACCES)
                    finally:
                        self.assertEqual(libc.munmap(ctypes.c_void_p(address),ctypes.c_size_t(4096)),0)

    @unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64',
                         'requires the real Linux/x86_64 tracer ABI')
    def test_native_fionbio_capture_keeps_file_consumption(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as raw:
            root = Path(raw).resolve()
            (root/'build').mkdir()
            (root/'compiler-tmp').mkdir()
            source = root/'build/input'
            source.write_bytes(b'native FIONBIO fixture\n')
            child = ('import fcntl, os, struct, sys; '
                     'fd=os.open(sys.argv[1],os.O_RDONLY); '
                     'fcntl.ioctl(fd,0x5421,struct.pack("i",1)); '
                     'assert fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_NONBLOCK; '
                     'assert os.read(fd,128)==b"native FIONBIO fixture\\n"; os.close(fd)')
            result = subprocess.run([sys.executable,'-B',str(Path(capture.__file__)),
                str(root),str(root/'capture'),'--',sys.executable,'-B','-c',child,str(source)],
                capture_output=True,text=True,timeout=60)
            record = json.loads((root/'capture/capture.json').read_bytes())
            self.assertEqual(result.returncode,0,str(record['errors'])+result.stderr)
            self.assertTrue(record['complete'],record['errors'])
            self.assertEqual(record['command_exit'],0)
            self.assertIn(str(source),record['observed'])
            rows = [row for row in record['generated'] if row['path']==str(source)]
            self.assertEqual(len(rows),1)
            capture.verify_blob(root/'capture/blobs',rows[0])
            self.assertEqual((root/'capture/blobs'/rows[0]['blob']).read_bytes(),source.read_bytes())
            calls = [json.loads(line) for line in (root/'capture/syscalls.jsonl').read_text().splitlines()]
            self.assertTrue(any(row.get('op')==1 and row['values'][0]==16
                                and row['values'][2]==0x5421 for row in calls))

    def test_open_argument_grammar_only_exempts_unambiguous_output(self):
        # Lexical unit arguments, deliberately NOT strace logs or native receipts.
        for call in ('open("algorithm-output", O_WRONLY|O_CREAT, 0600)',
                     'openat(AT_FDCWD, "algorithm-output", O_WRONLY|O_CLOEXEC)',
                     'openat2(AT_FDCWD, "algorithm-output", {flags=O_WRONLY, resolve=0}, 24)'):
            with self.subTest(call=call):
                self.assertFalse(diagnostic.readable_open(call))
        for call in ('open("algorithm-input", O_RDONLY)',
                     'openat(AT_FDCWD, "algorithm-input", O_RDWR|O_CLOEXEC)',
                     'open("filename, O_WRONLY", O_RDONLY)',
                     'open("filename\\\", O_WRONLY", O_RDONLY)'):
            with self.subTest(call=call):
                self.assertTrue(diagnostic.readable_open(call))
        for call in ('open("algorithm-unknown", 0x80)',
                     'open("algorithm-unknown", O_PATH)',
                     'open("algorithm-unknown", O_RDONLY|O_WRONLY)'):
            with self.subTest(call=call), self.assertRaises(ValueError):
                diagnostic.readable_open(call)

    def test_failed_capture_keeps_available_inventories_and_real_child_exit(self):
        # This is a real failing Python child, never a simulated compiler run.
        result = subprocess.run([sys.executable,'-B','-c','raise SystemExit(37)'],check=False)
        self.assertEqual(result.returncode,37)
        with tempfile.TemporaryDirectory(prefix='deadline-source-',dir=os.environ['TMPDIR']) as raw:
            root = Path(raw)
            private = root/'private'
            for name in ('build','compiler-tmp'):
                (private/name).mkdir(parents=True)
                (private/name/'control.txt').write_text('file-only control\n')
            source = root/'source.txt'
            source.write_text('static file control\n')
            before = diagnostic.snapshot([source])
            generated = diagnostic.snapshot([private/'build',private/'compiler-tmp'])
            for missing in (False,True):
                with self.subTest(missing_inventory=missing):
                    evidence = root/('missing' if missing else 'available')
                    evidence.mkdir()
                    inputs = [root/'absent-root'] if missing else [source]
                    record = diagnostic.compiler_capture(inputs,before,generated,private,evidence,
                                                         'file-only-control',result.returncode,None)
                    self.assertFalse(record['complete'])
                    self.assertEqual(record['command_exit'],result.returncode)
                    self.assertEqual(json.loads((evidence/'compiler-closure.json').read_bytes()),record)
                    self.assertEqual(json.loads((evidence/'generated-inputs.json').read_bytes()),generated)
                    self.assertEqual((evidence/'compiler-inputs-after.json').exists(),not missing)
                    self.assertTrue(record['errors'])
                    self.assertFalse((evidence/'suite-started.json').exists())

    def test_exclusive_evidence_and_incomplete_trace_rejections(self):
        with tempfile.TemporaryDirectory(prefix='deadline-source-',dir=os.environ['TMPDIR']) as raw:
            path = Path(raw)/'source-control.json'
            diagnostic.save(path, {'scope':'unit algorithm, not native'})
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                diagnostic.save(path, {'scope':'must not replace prior evidence'})
            self.assertEqual(path.read_bytes(),original)
        # Rejections only: no invented successful strace/native receipt is used.
        for raw in ('openat(AT_FDCWD, "truncated"...', '<... openat resumed> = 3'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                diagnostic.accessed_files(raw)

    def test_actual_observation_finalization_fails_on_invalid_provenance(self):
        # Execute the actual finalization statements, not an imitation of owning().
        # Unit arguments only: this does not create native-suite evidence.
        tree = ast.parse(Path(diagnostic.__file__).read_text())
        owning = next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='owning')
        unit = ast.parse('def finalize(code, final):\n    pass\n')
        function = unit.body[0]
        self.assertIsInstance(function,ast.FunctionDef)
        assert isinstance(function,ast.FunctionDef)
        function.body = owning.body[-3:]
        with tempfile.TemporaryDirectory(prefix='deadline-finalize-',dir=os.environ['TMPDIR']) as raw:
            for code in (0,37):
                for error in (None,'unit provenance rejection',''):
                    with self.subTest(code=code,error=error):
                        evidence = Path(raw)/str(len(list(Path(raw).iterdir())))
                        evidence.mkdir()
                        scope = {'EVIDENCE':evidence,'save':diagnostic.save}
                        exec(compile(ast.fix_missing_locations(unit),'<actual finalization>','exec'),scope)
                        final = {'suite_exit':code,'provenance_error':error,'acceptance':False}
                        expected = code or int(error is not None)
                        self.assertEqual(scope['finalize'](code,final),expected)
                        retained = json.loads((evidence/'observation.json').read_bytes())
                        self.assertEqual(retained,{**final,'diagnostic_exit':expected})
                        self.assertEqual(retained['suite_exit'],code)
                        self.assertIs(retained['acceptance'],False)

    def test_workflow_and_real_source_mutations(self):
        text = WORKFLOW.read_text()
        workflow_boundaries(text)
        for before,after in [
            ('exec "$DEADLINE_PYTHON" -B scripts/rust-port/mcp_deadline_diagnostic.py owning',
             '"$DEADLINE_PYTHON" -B scripts/rust-port/mcp_deadline_diagnostic.py owning'),
            ('if: ${{ success() && !('+SELECTOR+') }}','if: success()'),
            ('if: always()','if: success()'),
            ('&& 150 || 40','&& 40 || 40'),
            ('"${DEADLINE_PYTHON:-python3}" -B - <<','python3 - <<')]:
            self.assertEqual(text.count(before),1)
            with self.subTest(mutation=before), self.assertRaises(ValueError):
                workflow_boundaries(text.replace(before,after,1))
        # Every original ordinary run/assertion body is still intact. New branches
        # are additive; no original test condition, count or CLI build is removed.
        original = diagnostic.git(ROOT,'show',diagnostic.BASE+':.github/workflows/rust-mcp-process.yml').decode()
        for start,end in [('          cargo fmt --all --check\n','      - name: Execute actual Go'),
                          ('          python3 scripts/rust-port/test_mcp_oracle.py\n','      - name: Execute corrected'),
                          ('          test "$(go env GOVERSION)"','      - name: Upload complete')]:
            body = original.split(start,1)[1].split(end,1)[0]
            # Only the interpreter selection changed in the receipt control body.
            self.assertIn(body,text.replace('"${DEADLINE_PYTHON:-python3}" -B -','python3 -'))

    def test_real_command_source_and_fail_closed_staging(self):
        self.assertEqual(diagnostic.SUITE,['cargo','test','-p','symvault-mcp','--all-targets','--locked','--','--show-output'])
        self.assertEqual(diagnostic.FMT,['cargo','fmt','--all','--check'])
        self.assertEqual(diagnostic.CLIPPY,['cargo','clippy','-p','symvault-cli','-p','symvault-mcp',
                                         '--all-targets','--all-features','--locked','--','-D','warnings'])
        source = Path(diagnostic.__file__).read_text()
        tree = ast.parse(source)
        functions = {n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
        owning = ast.get_source_segment(source,functions['owning'])
        if owning is None:
            self.fail('missing actual owning producer source')
        self.assertEqual(owning.count('*SUITE'),1)
        self.assertLess(owning.index('run(FMT'),owning.index("traced(CLIPPY"))
        self.assertLess(owning.index('traced(CLIPPY'),owning.index('traced(NO_RUN'))
        self.assertLess(owning.index('compiler_capture'),owning.index('*SUITE'))
        self.assertLess(owning.index("require(closure['complete']"),owning.index("'suite-started.json'"))
        capture = ast.get_source_segment(source,functions['compiler_capture'])
        if capture is None:
            self.fail('missing actual compiler capture source')
        self.assertIn('closure_accesses',capture)
        self.assertIn("[private/'build', private/'compiler-tmp']",capture)
        self.assertIn("save(evidence/'compiler-closure.json', record)",capture)
        # Both nonzero and exceptional compiler paths reach real finalization;
        # no earlier return can lose the after-inventory on Clippy failure.
        capture_try = next(n for n in functions['owning'].body if isinstance(n,ast.Try)
                           and any(isinstance(c,ast.Call) and isinstance(c.func,ast.Name)
                                   and c.func.id == 'compiler_capture' for c in ast.walk(n)))
        preceding = functions['owning'].body[:functions['owning'].body.index(capture_try)]
        self.assertFalse(any(isinstance(n,ast.Return) for item in preceding
                             if not isinstance(item,ast.FunctionDef) for n in ast.walk(item)))
        self.assertTrue(any(isinstance(n,ast.Return) and isinstance(n.value,ast.Name) and n.value.id=='code'
                            for handler in capture_try.handlers for n in ast.walk(handler)))
        self.assertIn("'--kill-after=10s','480s'",owning)
        self.assertIn("return code",owning)
        self.assertNotIn('allow_dirty',source)
        self.assertNotIn("'RUST_TEST_THREADS':",source)
        self.assertNotIn('toolchain install',source)
        # A minimal source-only Git fixture, never an implementation worktree.
        # The actual producer rejects its untracked input before patch access.
        with tempfile.TemporaryDirectory(prefix='deadline-source-',dir=os.environ['TMPDIR']) as raw:
            root = Path(raw)
            subprocess.run(['git','init','-q',str(root)],check=True)
            (root/'unexpected-source.txt').write_text('source control only\n')
            with self.assertRaisesRegex(ValueError,'clean checkout/index'):
                diagnostic.stage(root,root/'not-created')
            self.assertFalse((root/'not-created').exists())


class SelfMapsRuntimeControls(unittest.TestCase):
    """Typed self_maps_runtime controls: pure record checks plus real Linux children.

    Native children prove only the tests' own reads. They are not product evidence.
    """

    def fixture(self, root, returned=4, data=b'abcd'):
        (root/'blobs').mkdir(exist_ok=True)
        (root/'blobs/0.runtime').write_bytes(data)
        row = {'class':'self_maps_runtime','version':1,'pid':10,'tgid':10,'path':'/proc/10/maps',
               'fd':3,'buffer':4096,'requested':8,'entry_event':1,'exit_event':2,'returned':returned,
               'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'blob':'0.runtime'}
        transcript = [{'event':1,'pid':10,'wait_status':0},
                      {'event':1,'pid':10,'op':1,'values':[0,3,4096,8,0,0,0]},
                      {'event':2,'pid':10,'wait_status':0},
                      {'event':2,'pid':10,'op':2,'values':[returned,0]}]
        transcript.append({'event':1,'pid':10,'self_maps_entry':'/proc/10/maps'})
        return {'self_maps':[row], 'self_maps_entries':[1]}, transcript

    def test_exact_path_and_read_kind_are_the_only_admitted_shape(self):
        for raw in ('/proc/10/smaps', '/proc/10/task/10/maps', '/proc/self/maps',
                    '/proc/10/status', '/proc/10/mem'):
            with self.subTest(raw=raw):
                self.assertIsNone(capture.self_maps_target(raw))
        self.assertEqual(capture.self_maps_target('/proc/10/maps'), '/proc/10/maps')
        capture.self_maps_entry(0, 10, 10, ['10'], '/proc/10/maps', set())
        for number, pid, tgid, tasks, target, sharers, message in [
                (17, 10, 10, ['10'], '/proc/10/maps', set(), 'unsupported self-maps read'),
                (0, 10, 10, ['10'], '/proc/11/maps', set(), 'foreign or multi-task'),
                (0, 10, 11, ['10'], '/proc/11/maps', set(), 'foreign or multi-task'),
                (0, 10, 10, ['10', '11'], '/proc/10/maps', set(), 'foreign or multi-task'),
                (0, 10, 10, ['10'], '/proc/10/maps', {12}, 'CLONE_VM/CLONE_FILES sharer')]:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                capture.self_maps_entry(number, pid, tgid, tasks, target, sharers)

    def test_repeated_reads_and_zero_length_eof_are_each_retained(self):
        with tempfile.TemporaryDirectory(prefix='deadline-selfmaps-', dir=os.environ['TMPDIR']) as raw:
            root = Path(raw)
            data, transcript = self.fixture(root, returned=0, data=b'')
            (root/'blobs/1.runtime').write_bytes(b'abcd')
            data['self_maps'].append({**data['self_maps'][0], 'returned':4, 'size':4,
                                      'sha256':hashlib.sha256(b'abcd').hexdigest(),
                                      'blob':'1.runtime', 'entry_event':3, 'exit_event':4})
            data['self_maps_entries'] = [1, 3]
            transcript += [{'event':3,'pid':10,'wait_status':0},
                           {'event':3,'pid':10,'op':1,'values':[0,3,4096,8,0,0,0]},
                           {'event':4,'pid':10,'wait_status':0},
                           {'event':4,'pid':10,'op':2,'values':[4,0]},
                           {'event':3,'pid':10,'self_maps_entry':'/proc/10/maps'}]
            self.assertEqual(capture.verify_self_maps(root, data, transcript), {'/proc/10/maps'})

    def test_runtime_record_binds_exact_bytes_and_rejects_every_mismatch(self):
        def negative_return(root, data, transcript):
            data['self_maps'][0].update(returned=-1, size=0)
            transcript[3]['values'] = [-1, 0]
        def error_return(root, data, transcript):
            transcript[3]['values'] = [4, 1]
        def longer_than_requested(root, data, transcript):
            data['self_maps'][0]['returned'] = 9
        def read_kind(root, data, transcript):
            transcript[1]['values'][0] = 17
        def other_buffer(root, data, transcript):
            transcript[1]['values'][2] = 4097
        def foreign_path(root, data, transcript):
            data['self_maps'][0]['path'] = '/proc/11/maps'
        def unmatched_exit(root, data, transcript):
            transcript[:] = [item for item in transcript if item.get('op') != 2]
        def intervening_stop(root, data, transcript):
            data['self_maps'][0]['exit_event'] = 3
            transcript[:] = [{'event':1,'pid':10,'wait_status':0},
                             {'event':1,'pid':10,'op':1,'values':[0,3,4096,8,0,0,0]},
                             {'event':2,'pid':10,'wait_status':0},
                             {'event':3,'pid':10,'wait_status':0},
                             {'event':3,'pid':10,'op':2,'values':[4,0]},
                             {'event':1,'pid':10,'self_maps_entry':'/proc/10/maps'}]
        def no_entry_marker(root, data, transcript):
            data['self_maps_entries'] = []
        def untyped(root, data, transcript):
            data['self_maps'][0]['class'] = 'self_maps'
        def changed_blob(root, data, transcript):
            (root/'blobs/0.runtime').write_bytes(b'wxyz')
        def missing_blob(root, data, transcript):
            (root/'blobs/0.runtime').unlink()
        def invalid_name(root, data, transcript):
            data['self_maps'][0]['blob'] = '../0.runtime'
        def unmarked(root, data, transcript):
            transcript[:] = [item for item in transcript if 'self_maps_entry' not in item]
        def foreign_marker(root, data, transcript):
            transcript[-1]['self_maps_entry'] = '/proc/11/maps'
        def foreign_marker_pid(root, data, transcript):
            transcript[-1]['pid'] = 11
        def other_task_stop(root, data, transcript):
            data['self_maps'][0]['exit_event'] = 3
            for item in transcript:
                if item['event'] == 2:
                    item['event'] = 3
            transcript.append({'event':2,'pid':11,'wait_status':0})
        cases = [('not one-to-one', unmarked), ('exit mismatch', negative_return), ('exit mismatch', error_return),
                 ('exit mismatch', longer_than_requested), ('not the recorded read', read_kind),
                 ('not the recorded read', other_buffer), ('identity mismatch', foreign_path),
                 ('unmatched self-maps event', unmatched_exit), ('intervening stop', intervening_stop),
                 ('one-to-one', no_entry_marker), ('untyped self-maps record', untyped),
                 ('self-maps blob changed', changed_blob), ('missing or symlink', missing_blob),
                 ('invalid self-maps blob name', invalid_name),
                 ('self-maps raw marker mismatch', foreign_marker),
                 ('self-maps raw marker mismatch', foreign_marker_pid),
                 ('intervening stop', other_task_stop)]
        if os.name != 'nt':
            def symlink_blob(root, data, transcript):
                other = root/'other.bin'
                other.write_bytes(b'abcd')
                (root/'blobs/0.runtime').unlink()
                os.symlink(other, root/'blobs/0.runtime')
            cases.append(('missing or symlink', symlink_blob))
        for index, (message, mutate) in enumerate(cases):
            with self.subTest(case=index, message=message):
                with tempfile.TemporaryDirectory(prefix='deadline-selfmaps-', dir=os.environ['TMPDIR']) as raw:
                    root = Path(raw)
                    data, transcript = self.fixture(root)
                    mutate(root, data, transcript)
                    with self.assertRaisesRegex(ValueError, message):
                        capture.verify_self_maps(root, data, transcript)

    def test_runtime_bytes_are_bound_only_by_their_verified_record(self):
        with tempfile.TemporaryDirectory(prefix='deadline-selfmaps-', dir=os.environ['TMPDIR']) as raw:
            root = Path(raw).resolve()
            source = root/'static.txt'
            source.write_text('static control\n')
            private = root/'private'
            (private/'build').mkdir(parents=True)
            (private/'compiler-tmp').mkdir()
            before = diagnostic.snapshot([source])
            with self.assertRaisesRegex(ValueError, 'unbound self-maps runtime input'):
                diagnostic.closure_accesses(['/proc/10/maps'], before, before, private)
            self.assertEqual(diagnostic.closure_accesses(['/proc/10/maps', str(source)], before, before,
                                                         private, None, {'/proc/10/maps'}), [])
            with self.assertRaisesRegex(ValueError, 'unbound self-maps runtime input'):
                diagnostic.closure_accesses(['/proc/11/maps'], before, before, private, None, {'/proc/10/maps'})

    def test_gitconfig_root_is_identity_bound_and_never_exempt(self):
        with tempfile.TemporaryDirectory(prefix='deadline-gitconfig-', dir=os.environ['TMPDIR']) as raw:
            root = Path(raw).resolve()
            config = root/'gitconfig'
            config.write_text('[fixture]\n\tvalue = before\n')
            before = diagnostic.snapshot([config])
            self.assertEqual(diagnostic.closure_accesses([str(config)], before, before, root/'private'), [])
            config.write_text('[fixture]\n\tvalue = after\n')
            after = diagnostic.snapshot([config])
            with self.assertRaisesRegex(ValueError, 'changed compiler input'):
                diagnostic.closure_accesses([str(config)], before, after, root/'private')
            config.unlink()
            with self.assertRaisesRegex(ValueError, 'missing compiler input'):
                diagnostic.closure_accesses([str(config)], before, after, root/'private')

    def synthetic_capture(self, evidence, name, command, runtime=True, corrupt=False, complete=True):
        """File-only capture shape for compiler_capture. Not a native observation."""
        directory = evidence/(name+'-capture')
        (directory/'blobs').mkdir(parents=True)
        data = b'abcd'
        (directory/'blobs/0.runtime').write_bytes(b'wxyz' if corrupt else data)
        rows, entries = [], []
        if runtime:
            rows = [{'class':'self_maps_runtime','version':1,'pid':10,'tgid':10,'path':'/proc/10/maps',
                     'fd':3,'buffer':4096,'requested':8,'entry_event':1,'exit_event':2,'returned':4,
                     'size':4,'sha256':hashlib.sha256(data).hexdigest(),'blob':'0.runtime'}]
            entries = [1]
        transcript = [{'event':1,'pid':10,'wait_status':0},
                      {'event':1,'pid':10,'op':1,'values':[0,3,4096,8,0,0,0]},
                      {'event':2,'pid':10,'wait_status':0},
                      {'event':2,'pid':10,'op':2,'values':[4,0]}]
        if runtime:
            transcript.append({'event':1,'pid':10,'self_maps_entry':'/proc/10/maps'})
        (directory/'syscalls.jsonl').write_text(''.join(json.dumps(item)+'\n' for item in transcript))
        record = {'complete':complete, 'command':command, 'command_exit':0,
                  'errors':[] if complete else ['historical incomplete capture'],
                  'generated':[], 'observed':['/proc/10/maps'], 'acceptance':False, 'events':2,
                  'self_maps':rows, 'self_maps_entries':entries}
        (directory/'capture.json').write_text(json.dumps(record))

    def test_admission_requires_a_bound_complete_runtime_record(self):
        with tempfile.TemporaryDirectory(prefix='deadline-selfmaps-', dir=os.environ['TMPDIR']) as raw:
            root = Path(raw).resolve()
            source = root/'source'
            source.mkdir()
            (source/'lib.txt').write_text('static\n')
            private = root/'private'
            (private/'build').mkdir(parents=True)
            (private/'compiler-tmp').mkdir()
            before = diagnostic.snapshot([source])
            generated = diagnostic.snapshot([private/'build', private/'compiler-tmp'])
            cases = [(True, False, True, True),    # bound runtime record, both captures complete
                     (False, False, True, False),  # observed maps read without its record
                     (True, True, True, False),    # corrupt blob
                     (True, False, False, False)]  # historical incomplete capture
            for index, (runtime, corrupt, complete, admitted) in enumerate(cases):
                with self.subTest(case=index):
                    evidence = root/('evidence-'+str(index))
                    evidence.mkdir()
                    self.synthetic_capture(evidence, 'clippy', diagnostic.CLIPPY, runtime, corrupt, complete)
                    self.synthetic_capture(evidence, 'build-tests', diagnostic.NO_RUN, runtime, corrupt, complete)
                    record = diagnostic.compiler_capture([source], before, generated, private, evidence,
                                                         'build-tests', 0, None)
                    self.assertIs(record['complete'], admitted, record['errors'])
                    if admitted:
                        self.assertEqual(record['self_maps_runtime'], ['/proc/10/maps'])

    def test_legacy_capture_without_runtime_record_stays_rejected(self):
        # Shape of a retained capture from before the typed class: observed maps, no records.
        legacy = {'complete':True, 'command':diagnostic.CLIPPY, 'command_exit':0, 'errors':[], 'events':2,
                  'generated':[], 'observed':['/proc/23166/maps','/etc/gitconfig']}
        with tempfile.TemporaryDirectory(prefix='deadline-legacy-', dir=os.environ['TMPDIR']) as raw:
            with self.assertRaisesRegex(ValueError, 'self-maps records absent'):
                capture.verify_self_maps(Path(raw), legacy, [])

    def test_non_maps_proc_reads_are_unbound_by_closure(self):
        with tempfile.TemporaryDirectory(prefix='deadline-proc-', dir=os.environ['TMPDIR']) as raw:
            root = Path(raw).resolve()
            source = root/'static.txt'
            source.write_text('static control\n')
            before = diagnostic.snapshot([source])
            for proc in ('/proc/10/status', '/proc/10/smaps', '/proc/self/maps'):
                with self.subTest(proc=proc), self.assertRaisesRegex(ValueError, 'unbound'):
                    diagnostic.closure_accesses([proc], before, before, root/'private', None, {'/proc/10/maps'})

    def test_owning_roots_include_gitconfig_but_closure_never_exempts_it(self):
        source = Path(diagnostic.__file__).read_text()
        functions = {n.name: n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef)}
        self.assertIn("'/etc/gitconfig'", ast.get_source_segment(source, functions['owning']))
        self.assertNotIn('gitconfig', ast.get_source_segment(source, functions['closure_accesses']))

    @unittest.skipUnless(hasattr(os, 'WSTOPSIG'), 'POSIX wait-status encoding only')
    def test_any_other_stop_or_exit_while_a_self_maps_read_is_pending_is_intervention(self):
        # Raw wait statuses only; the wiring into the tracer is checked from source.
        syscall_stop = (0x85 << 8) | 0x7f
        clone_event = (signal.SIGTRAP << 8) | 0x7f | (3 << 16)
        sigstop = (signal.SIGSTOP << 8) | 0x7f
        self.assertFalse(capture.intervention({}, 11, sigstop))
        self.assertFalse(capture.intervention({10: {}}, 10, syscall_stop))
        for pid, status in [(10, clone_event), (10, sigstop), (10, 0), (11, syscall_stop),
                            (11, sigstop), (11, clone_event)]:
            with self.subTest(pid=pid, status=status):
                self.assertTrue(capture.intervention({10: {}}, pid, status))
        source = Path(capture.__file__).read_text()
        self.assertLess(source.index('pid,status = os.waitpid(-1'), source.index('require(not intervention(self_pending'))
        self.assertNotIn('vfork_child', source)

    def native_capture(self, root, child):
        (root/'build').mkdir()
        (root/'compiler-tmp').mkdir()
        result = subprocess.run([sys.executable, '-B', str(Path(capture.__file__)), str(root),
                                 str(root/'capture'), '--', sys.executable, '-B', '-c', child],
                                capture_output=True, text=True, timeout=120)
        directory = root/'capture'
        record = json.loads((directory/'capture.json').read_bytes())
        transcript = [json.loads(line) for line in (directory/'syscalls.jsonl').read_text().splitlines()]
        # Each child prints its identity/result. Surface capture failures before
        # stdout parsing hides them behind an IndexError or empty assertion.
        self.assertTrue(result.stdout.strip(),str(record['errors'])+result.stderr)
        return result, record, transcript, directory

    @unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64',
                         'requires the real Linux/x86_64 tracer ABI')
    def test_native_reader_bytes_equal_the_retained_runtime_blobs(self):
        child = ('import hashlib, os\n'
                 'fd = os.open("/proc/self/maps", os.O_RDONLY)\n'
                 'data = b""\n'
                 'reads = 0\n'
                 'while True:\n'
                 '    chunk = os.read(fd, 4096)\n'
                 '    reads += 1\n'
                 '    if not chunk:\n'
                 '        break\n'
                 '    data += chunk\n'
                 'os.close(fd)\n'
                 'print(os.getpid(), reads, len(data), hashlib.sha256(data).hexdigest())\n')
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as raw:
            result, record, transcript, directory = self.native_capture(Path(raw).resolve(), child)
            self.assertEqual(result.returncode, 0, result.stderr)
            pid, reads, length, digest = result.stdout.split()
            self.assertTrue(record['complete'], record['errors'])
            self.assertIn(f'/proc/{pid}/maps', record['observed'])
            rows = [row for row in record['self_maps'] if row['path'] == f'/proc/{pid}/maps']
            own = rows[-int(reads):]  # earlier startup reads, if any, precede the child's own reads
            self.assertEqual(own[-1]['returned'], 0)
            content = b''.join((directory/'blobs'/row['blob']).read_bytes() for row in own)
            self.assertEqual((len(content), hashlib.sha256(content).hexdigest()), (int(length), digest))
            self.assertEqual(capture.verify_self_maps(directory, record, transcript), {f'/proc/{pid}/maps'})

    @unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64',
                         'requires the real Linux/x86_64 tracer ABI')
    def test_native_second_thread_rejects_self_maps_read(self):
        child = ('import os, threading, time\n'
                 'threading.Thread(target=time.sleep, args=(60,), daemon=True).start()\n'
                 'fd = os.open("/proc/self/maps", os.O_RDONLY)\n'
                 'print(os.getpid(), flush=True)\n'
                 'os.read(fd, 4096)\n')
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as raw:
            result, record, _, _ = self.native_capture(Path(raw).resolve(), child)
            pid = result.stdout.split()[0]
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(record['complete'])
            self.assertIn('foreign or multi-task self-maps read', record['errors'])
            self.assertIn(f'/proc/{pid}/maps', record['observed'])

    @unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64',
                         'requires the real Linux/x86_64 tracer ABI')
    def test_native_foreign_maps_read_is_rejected(self):
        child = ('import os\n'
                 'print(os.getpid(), os.getppid(), flush=True)\n'
                 'fd = os.open("/proc/%d/maps" % os.getppid(), os.O_RDONLY)\n'
                 'os.read(fd, 4096)\n')
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as raw:
            result, record, _, _ = self.native_capture(Path(raw).resolve(), child)
            _, parent = result.stdout.split()[:2]
            self.assertFalse(record['complete'])
            self.assertIn('foreign or multi-task self-maps read', record['errors'])
            self.assertIn(f'/proc/{parent}/maps', record['observed'])

    @unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64',
                         'requires real Linux memfd, shm and capture semantics')
    def test_native_memfd_and_shm_mappings_remain_observed_and_unbound(self):
        for kind in ('memfd','shm','unlinked-shm'):
            with self.subTest(kind=kind):
                with tempfile.TemporaryDirectory(dir='/dev/shm',prefix='vault-capture-') as shared:
                    name = str(Path(shared)/'input')
                    child = ('import mmap, os\n'
                             f'name = {name!r}\n'
                             + ('fd = os.memfd_create("deadline-control")\n' if kind == 'memfd'
                                else 'fd = os.open(name, os.O_RDWR|os.O_CREAT|os.O_EXCL, 0o600)\n')
                             + 'os.write(fd, b"native closure fixture")\n'
                             'rd = os.open("/proc/self/fd/%d" % fd, os.O_RDONLY)\n'
                             'target = os.readlink("/proc/self/fd/%d" % rd).removesuffix(" (deleted)")\n'
                             'view = mmap.mmap(rd, 0, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ)\n'
                             'assert view[:] == b"native closure fixture"\n'
                             'view.close()\n'
                             + ('os.unlink(name)\n' if kind == 'unlinked-shm' else '')
                             + 'print(target, flush=True)\n')
                    with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as raw:
                        root = Path(raw).resolve()
                        result, record, _, _ = self.native_capture(root,child)
                        self.assertEqual(result.returncode,0,str(record['errors'])+result.stderr)
                        self.assertTrue(record['complete'],record['errors'])
                        target = result.stdout.strip()
                        self.assertIn(target,record['observed'])
                        self.assertTrue(target.startswith('/memfd:') if kind == 'memfd' else target == name)
                        self.assertFalse(any(row['path'] == target for row in record['generated']))
                        with self.assertRaisesRegex(ValueError,'unbound'):
                            diagnostic.closure_accesses([target],{},{},root,{},set())

    @unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64',
                         'requires the real Linux/x86_64 tracer ABI')
    def test_native_pread_of_own_maps_is_rejected(self):
        child = ('import os\n'
                 'print(os.getpid(), flush=True)\n'
                 'fd = os.open("/proc/self/maps", os.O_RDONLY)\n'
                 'os.pread(fd, 4096, 0)\n')
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as raw:
            result, record, _, _ = self.native_capture(Path(raw).resolve(), child)
            pid = result.stdout.split()[0]
            self.assertFalse(record['complete'])
            self.assertIn('unsupported self-maps read syscall: 17', record['errors'])
            self.assertIn(f'/proc/{pid}/maps', record['observed'])

    @unittest.skipUnless(platform.system() == 'Linux' and platform.machine() == 'x86_64',
                         'requires the real Linux/x86_64 tracer ABI')
    def test_native_vfork_child_that_execs_does_not_reject_later_reads(self):
        child = ('import hashlib, os, subprocess, sys\n'
                 'subprocess.run([sys.executable, "-B", "-c", "pass"], check=True)\n'
                 'fd = os.open("/proc/self/maps", os.O_RDONLY)\n'
                 'data = b""\n'
                 'while chunk := os.read(fd, 4096):\n'
                 '    data += chunk\n'
                 'print(os.getpid(), len(data), hashlib.sha256(data).hexdigest(), flush=True)\n')
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as raw:
            result, record, transcript, directory = self.native_capture(Path(raw).resolve(), child)
            self.assertEqual(result.returncode, 0, result.stderr)
            pid = result.stdout.split()[0]
            self.assertTrue(record['complete'], record['errors'])
            self.assertIn(f'/proc/{pid}/maps', record['observed'])
            self.assertIn(f'/proc/{pid}/maps', capture.verify_self_maps(directory, record, transcript))


if __name__ == '__main__':
    unittest.main(verbosity=2)
