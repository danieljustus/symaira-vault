#!/usr/bin/env python3
"""Noncompiling source/file controls, never a simulated native observation."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

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
        with self.assertRaisesRegex(ValueError,'unsupported compiler ioctl'):
            capture.input_fd(16,[7,0x4020940d,8,0,0,0])
        with self.assertRaisesRegex(ValueError,'untraced/namespaced'):
            capture.input_fd(56,[0x00800000,0,0,0,0,0])
        with self.assertRaisesRegex(ValueError,'number/ABI'):
            capture.input_fd(0x40000000,args)
        self.assertEqual(capture.input_fd(9,args),9)
        self.assertIsNone(capture.input_fd(9,[7,8,3,0x22,9,0]))
        with self.assertRaisesRegex(ValueError,'writable shared'):
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

    def test_workflow_and_three_real_source_mutations(self):
        text = WORKFLOW.read_text()
        workflow_boundaries(text)
        for before,after in [
            ('exec "$DEADLINE_PYTHON" -B scripts/rust-port/mcp_deadline_diagnostic.py owning',
             '"$DEADLINE_PYTHON" -B scripts/rust-port/mcp_deadline_diagnostic.py owning'),
            ('if: ${{ success() && !('+SELECTOR+') }}','if: success()'),
            ('if: always()','if: success()')]:
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
            self.assertIn(body,text)

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


if __name__ == '__main__':
    unittest.main(verbosity=2)
