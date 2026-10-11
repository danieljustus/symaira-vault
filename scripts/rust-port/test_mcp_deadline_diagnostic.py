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
        self.assertLess(owning.index('closure_accesses'),owning.index('*SUITE'))
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
