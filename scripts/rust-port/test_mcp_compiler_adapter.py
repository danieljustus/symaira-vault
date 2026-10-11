#!/usr/bin/env python3
"""Opt-in real historical handler/compiler regression; retains rejection logs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import mcp_compiler_adapter as adapter
import mcp_fixture_contract as fixtures


class CompilerVerificationControls(unittest.TestCase):
    """Constructed verifier metadata only; never compiler/native evidence."""

    def setUp(self):
        # These tests must not silently acquire a compiler dependency.
        no_process = patch.object(subprocess, 'Popen', side_effect=AssertionError('no subprocess in verifier controls'))
        no_process.start()
        self.addCleanup(no_process.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.child = self.root/'child.go'
        self.child.write_bytes(b'unit-only child source, not compiled\n')
        self.binary = self.root/'adapter.not-executable'
        self.binary.write_bytes(b'unit-only binary placeholder, not executable\n')
        goroot = self.root/'toolchain'
        goroot.mkdir()
        (goroot/'input.txt').write_bytes(b'unit-only toolchain input\n')
        (self.root/'toolchain-inputs.json').write_text(json.dumps(fixtures.inventory(goroot, ['input.txt'])))
        digest = hashlib.sha256(self.child.read_bytes()).hexdigest()
        self.trace = self.root/'invocations.jsonl'
        self.row = {
            'binary': str(self.binary),
            'binary_sha256': hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            'source_inputs': fixtures.inventory(self.root, ['toolchain-inputs.json']),
            'configuration': {
                'compiler': str(goroot/'compiler.not-executable'),
                'compiler_sha256': '1'*64,
                'child_source': str(self.child), 'child_source_sha256': digest,
                'environment': {'GOROOT': str(goroot)}, 'trace': str(self.trace),
            },
        }
        self.call = {
            'command': [self.row['configuration']['compiler'], 'run', str(self.child)],
            'compiler_sha256': '1'*64, 'child_source_sha256': digest,
            'input_keys': ['PATH', 'HOME', 'GITHUB_PASSWORD', 'PLAIN'], 'exit': 0,
        }

    def verify(self, calls):
        self.trace.write_text(''.join(json.dumps(call)+'\n' for call in calls))
        row = copy.deepcopy(self.row)
        adapter.verify(row)
        self.assertTrue(row['verified'])

    def test_existing_file_aliases_pass_but_identical_copy_does_not(self):
        self.verify([self.call])
        alias = self.root/'alias.go'
        os.link(self.child, alias)
        self.verify([dict(self.call, command=[*self.call['command'][:2], str(alias)])])
        wrong = self.root/'copy.go'
        wrong.write_bytes(self.child.read_bytes())
        with self.assertRaisesRegex(ValueError, 'invocation failed or changed'):
            self.verify([dict(self.call, command=[*self.call['command'][:2], str(wrong)])])

    def test_wrong_command_exit_and_invocation_counts_are_rejected(self):
        for command in [self.call['command']+['extra'],
                        [*self.call['command'][:2], 'child.go'],
                        ['different-compiler', 'run', str(self.child)]]:
            with self.subTest(command=command), self.assertRaisesRegex(ValueError, 'invocation failed or changed'):
                self.verify([dict(self.call, command=command)])
        with self.assertRaisesRegex(ValueError, 'invocation failed or changed'):
            self.verify([dict(self.call, exit=1)])
        for calls in [[], [self.call, self.call]]:
            with self.subTest(count=len(calls)), self.assertRaisesRegex(ValueError, 'expected one real'):
                self.verify(calls)
        with self.assertRaises(FileNotFoundError):
            adapter.verify(copy.deepcopy(self.row) | {'configuration': dict(self.row['configuration'], trace=str(self.root/'missing'))})

    def test_source_and_compiler_digest_drift_are_rejected(self):
        for key in ['child_source_sha256', 'compiler_sha256']:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'identity drift'):
                self.verify([dict(self.call, **{key: '0'*64})])
        self.child.write_bytes(self.child.read_bytes()+b'changed\n')
        with self.assertRaisesRegex(ValueError, 'child source identity drift'):
            self.verify([self.call])

    def test_binary_build_and_toolchain_input_drift_are_rejected(self):
        for path, message in [(self.binary, 'adapter binary changed'),
                              (self.root/'toolchain-inputs.json', 'adapter build inputs changed'),
                              (self.root/'toolchain/input.txt', 'adapter toolchain inputs changed')]:
            original = path.read_bytes()
            try:
                path.write_bytes(original+b'changed\n')
                with self.subTest(path=path.name), self.assertRaisesRegex(ValueError, message):
                    self.verify([self.call])
            finally:
                path.write_bytes(original)

    def test_filtered_environment_keys_are_enforced(self):
        for keys in [['PATH', 'PLAIN'], self.call['input_keys']+['GOCACHE'],
                     self.call['input_keys']+['AWS_SESSION_TOKEN']]:
            with self.subTest(keys=keys), self.assertRaisesRegex(ValueError, 'unexpected filtered compiler environment'):
                self.verify([dict(self.call, input_keys=keys)])


class ApprovalLifetimeSourceControl(unittest.TestCase):
    def test_separate_generator_is_only_the_checked_close_insertion(self):
        name = 'internal/mcp/server/mcp_write_approval_fixture_generator_test.go'
        fixtures.fixture_anchor(fixtures.ROOT, [name])
        original = (fixtures.ROOT/name).read_bytes()
        anchor = b'\tlogger.SetSyncMode(true)\n\tsrv.auditLog = logger'
        addition = (b'\tdefer func() {\n'
                    b'\t\tif err := logger.Close(); err != nil {\n'
                    b'\t\t\tt.Errorf("close fixture audit logger: %v", err)\n'
                    b'\t\t}\n\t}()\n')
        self.assertEqual(original.count(anchor), 1)
        corrected = fixtures.ROOT/'scripts/rust-port/fixtures/mcp-anomaly/approval-lifetime-v1.go.txt'
        self.assertEqual(corrected.read_bytes(), original.replace(anchor, addition+anchor, 1))


class HistoricalCompilerRegression(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('MCP_COMPILER_ADAPTER_EVIDENCE'),
                         'set MCP_COMPILER_ADAPTER_EVIDENCE to a new retained directory')
    def test_real_generator_compiler_and_invalid_cache_rejection(self):
        output=Path(os.environ['MCP_COMPILER_ADAPTER_EVIDENCE']).resolve()
        output.mkdir(parents=True,exist_ok=False)
        # An actual directory alias reproduces Git's canonical root spelling
        # without writing under /var or changing any historical source bytes.
        real_tmp=output/'real-temp'
        real_tmp.mkdir()
        alias_tmp=output/'alias-temp'
        if os.name=='nt':
            # Native Windows does not require symlink privileges for 8.3 names.
            import ctypes
            size=ctypes.windll.kernel32.GetShortPathNameW(str(real_tmp),None,0)
            self.assertGreater(size,0)
            buf=ctypes.create_unicode_buffer(size)
            self.assertGreater(ctypes.windll.kernel32.GetShortPathNameW(str(real_tmp),buf,size),0)
            alias_tmp=Path(buf.value)
        else:
            alias_tmp.symlink_to(real_tmp,target_is_directory=True)
        def invoke(name):
            with patch.object(sys,'argv',['mcp_fixture_contract.py','--generator',
                                          'execute-with-secret','--output',str(output/name)]):
                fixtures.main()
        # Synthetic ambient sentinels must not reach the actual filtered child;
        # inherited compiler overrides must not replace the resolved compiler.
        noise={'AWS_SESSION_TOKEN':'adapter-synthetic-sentinel',
               'HTTPS_PROXY':'http://invalid.invalid', 'SSH_AUTH_SOCK':'synthetic',
               'GOFLAGS':'-overlay=does-not-exist.json','GOOS':'windows','GOARCH':'386'}
        with patch.dict(os.environ,noise), patch.object(fixtures.tempfile,'tempdir',str(alias_tmp)):
            invoke('positive')
        receipt=json.loads((output/'positive/receipt.json').read_bytes())
        self.assertTrue(receipt['passed'])
        for lane in receipt['lanes']:
            self.assertEqual((lane['fixtures'],lane['cases']),(1,13))
            self.assertTrue(lane['compiler_adapter']['verified'])
            self.assertEqual(lane['steps'][-1]['executed_tests'],['TestGenerateMCPExecuteWithSecretFixture'])
        original_prepare=adapter.prepare
        self.identity_controls(output, original_prepare)
        def invalid_cache(go,env,tree,out,steps,run_step):
            isolated,row=original_prepare(go,env,tree,out,steps,run_step)
            # Mutate only the separately compiled preparation, not historical
            # generator/product/fixture bytes. The real Go compiler rejects it.
            config=copy.deepcopy(row['configuration'])
            config['environment']['GOCACHE']='relative-invalid-cache'
            (out/'config.go').write_text('package main\n\nconst configJSON = '+json.dumps(json.dumps(config,sort_keys=True))+'\n')
            command=steps[-2]['command']
            run_step(command,out,row['build_environment'],out,'negative-build',steps)
            row.update(configuration=config,
                       source_inputs=fixtures.inventory(out,row['source_inputs']),
                       binary_sha256=hashlib.sha256(Path(row['binary']).read_bytes()).hexdigest())
            (out/'mutation.json').write_text(json.dumps(row,indent=2)+'\n')
            return isolated,row
        with patch.object(adapter,'prepare',side_effect=invalid_cache), self.assertRaisesRegex(RuntimeError,'generators failed'):
            invoke('invalid-cache')
        rejected=json.loads((output/'invalid-cache/receipt.json').read_bytes())
        self.assertFalse(rejected['passed'])
        lane=rejected['lanes'][0]
        self.assertEqual(lane['steps'][-1]['exit'],1)
        log=(output/'invalid-cache/historical/generators.stdout').read_text()
        self.assertIn('--- FAIL: TestGenerateMCPExecuteWithSecretFixture',log)
        self.assertIn('execute_with_secret fixture stale',log)
        call=json.loads(Path(lane['compiler_adapter']['configuration']['trace']).read_text())
        self.assertNotEqual(call['exit'],0)
        self.assertEqual(call['command'][0],lane['compiler_adapter']['configuration']['compiler'])
        fixtures.fixture_anchor(fixtures.ROOT,[*fixtures.FIXTURES,*fixtures.generator_paths()])

    def identity_controls(self, output, prepare):
        go,env,_=fixtures.pinned_go(os.environ.copy(),fixtures.ROOT)
        home=output/'control-home'
        home.mkdir()
        env.update(HOME=str(home),USERPROFILE=str(home))
        steps=[]
        out=output/'identity-controls'
        _,row=prepare(go,env,fixtures.ROOT,out,steps,fixtures.run_step)
        config=row['configuration']
        child=Path(config['child_source'])
        # Same bytes at a DIFFERENT identity must not earn compiler adaptation.
        wrong=out/'different-child.go'
        wrong.write_bytes(child.read_bytes())
        alias=out/'alias-child.go'
        os.link(child,alias)
        filtered={k:v for k,v in env.items() if k in {'PATH','HOME','TMPDIR','TMP','TEMP','SYSTEMROOT'}}
        filtered.update(PLAIN='literal-value',GITHUB_PASSWORD='synthetic-control',GOCACHE='invalid-relative-cache')
        trace=Path(config['trace'])
        results=[]
        def run(name,args,success):
            result=subprocess.run([row['binary'],*args],cwd=fixtures.ROOT,env=filtered,
                                  capture_output=True,timeout=120)
            (out/(name+'.stdout')).write_bytes(result.stdout)
            (out/(name+'.stderr')).write_bytes(result.stderr)
            results.append({'name':name,'args':args,'exit':result.returncode})
            self.assertEqual(result.returncode==0,success,name)
        try:
            for name,args in [('wrong-path',['run',str(wrong)]),
                              ('relative-path',['run',child.relative_to(fixtures.ROOT).as_posix()]),
                              ('extra-argument',['run',str(child),'unexpected'])]:
                run(name,args,False)
                self.assertFalse(trace.exists(),name)
            for name,path in [('canonical',child),('alias',alias)]:
                run(name,['run',str(path)],True)
            calls=[json.loads(line) for line in trace.read_text().splitlines()]
            self.assertEqual(len(calls),2)
            self.assertEqual([c['command'][2] for c in calls],[str(child),str(alias)])
            # Every call records the resolved, anchored source identity, while
            # retaining the exact original command (including an alias).
            self.assertTrue(all(c['child_source_sha256']==config['child_source_sha256'] for c in calls))
            config['compiler_sha256']='0'*64
            (out/'config.go').write_text('package main\n\nconst configJSON = '+json.dumps(json.dumps(config,sort_keys=True))+'\n')
            fixtures.run_step(steps[0]['command'],out,row['build_environment'],out,'wrong-compiler-build',steps)
            run('wrong-compiler',['run',str(child)],False)
            self.assertIn(b'fixture compiler identity changed',(out/'wrong-compiler.stderr').read_bytes())
            self.assertEqual(len(trace.read_text().splitlines()),2)
        finally:
            (out/'controls.json').write_text(json.dumps({'steps':steps,'results':results},indent=2)+'\n')


if __name__=='__main__':
    unittest.main()
