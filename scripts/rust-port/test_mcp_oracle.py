#!/usr/bin/env python3
"""Fail-closed controls; constructed metadata here is not native evidence."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import mcp_fixture_contract as fixtures
import mcp_oracle as oracle
import mcp_process_contract as process


class OracleControls(unittest.TestCase):
    def test_real_reference_and_fixture_anchors(self):
        oracle.validate_reference(fixtures.ROOT)
        fixtures.fixture_anchor(fixtures.ROOT, [*fixtures.FIXTURES, *fixtures.generator_paths()])
        self.assertEqual(len(fixtures.FIXTURES), 26)
        for invalid in ['HEAD', oracle.ORDERED[:8], oracle.ORDERED.upper(), '', None, oracle.HISTORICAL]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                oracle.validate_reference(fixtures.ROOT, invalid)

    def test_reference_rejects_wrong_parent_extra_file_and_candidate_drift(self):
        real_git = oracle.git
        for fault in ['parent', 'files', 'candidate']:
            def mutate(root,*args):
                if args[0]=='rev-parse' and fault=='parent':
                    return (oracle.ORDERED+'\n').encode()
                if args[0]=='diff' and fault=='files':
                    return real_git(root,*args)+b'go.mod\n'
                if args[0]=='show' and fault=='candidate':
                    return real_git(root,*args)+b'\n'
                return real_git(root,*args)
            # Explicit structural Git stub only in this unit test.
            with self.subTest(fault=fault), patch.object(oracle,'git',side_effect=mutate), self.assertRaises(ValueError):
                oracle.validate_reference(fixtures.ROOT)

    def test_fixture_semantics_types_inventory_and_reference_fail_closed(self):
        old=json.loads((fixtures.ROOT/'testdata/port/mcp/tools-call.json').read_bytes())
        new=copy.deepcopy(old)
        new['oracle']['commit_sha']=oracle.ORDERED
        fixtures.compare_fixture(old,new,4)  # structural positive control first
        def changes(value):
            yield ('missing-null', lambda: value['cases'][0].pop('output'))
            yield ('extra-case', lambda: value['cases'].append(copy.deepcopy(value['cases'][0])))
            yield ('changed-response', lambda: value['cases'][0]['output'][0].update(jsonrpc='9.0'))
            yield ('type-substitution', lambda: value['cases'][0]['output'][0].update(id=True))
            yield ('source-inventory', lambda: value['oracle']['source_files'].pop())
            yield ('oracle', lambda: value['oracle'].update(commit_sha=oracle.HISTORICAL))
        for index in range(6):
            value=copy.deepcopy(new)
            name,mutate=list(changes(value))[index]
            mutate()
            with self.subTest(name=name), self.assertRaises(ValueError):
                fixtures.compare_fixture(old,value,4)

    def test_frozen_fixture_cannot_self_baseline(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw)
            name='testdata/port/mcp/tools-call.json'
            (root/name).parent.mkdir(parents=True)
            (root/name).write_bytes((fixtures.ROOT/name).read_bytes())
            fixtures.fixture_anchor(root,[name])
            changed=json.loads((root/name).read_bytes())
            changed['cases'][0]['output'][0]['jsonrpc']='9.0'
            (root/name).write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError,'anchor drift'):
                fixtures.fixture_anchor(root,[name])

    def test_compiler_is_effective_not_an_environment_label(self):
        with patch.object(oracle.subprocess,'check_output',return_value=b'go1.26.9\n'):
            with self.assertRaisesRegex(ValueError,'actual go1.26.6'):
                oracle.pinned_go(dict(os.environ,GOTOOLCHAIN='go1.26.6'),fixtures.ROOT)

    def test_windows_cache_paths_survive_home_isolation_without_environment_leaks(self):
        # Exercise the real Windows cache-resolution branch and drive-qualified
        # paths. Compiler responses are explicit unit stubs, not native evidence.
        settings={'GOOS':'windows','GOARCH':'amd64'}
        caches={'GOCACHE':r'D:\runner\AppData\Local\go-build',
                'GOMODCACHE':r'D:\runner\go\pkg\mod','GOPATH':r'D:\runner\go'}
        inherited={'PATH':os.defpath,'HOME':'before','LOCALAPPDATA':r'D:\runner\AppData\Local',
                   'GOTOOLCHAIN':'go1.26.6','AWS_SESSION_TOKEN':'synthetic-only',
                   'HTTPS_PROXY':'synthetic-only','GOFLAGS':'-overlay=outside.json'}
        replies=[b'go1.26.6',b'/compiler',b'go1.26.6',json.dumps(settings).encode(),json.dumps(caches).encode()]
        with patch.object(oracle.subprocess,'check_output',side_effect=replies) as calls, \
             patch.object(oracle.platform,'system',return_value='Windows'), \
             patch.object(oracle.platform,'machine',return_value='AMD64'), \
             patch.object(oracle.Path,'read_bytes',return_value=b'unit-compiler'):
            _,env,identity=oracle.pinned_go(inherited,fixtures.ROOT)
        env.update(HOME=r'D:\isolated',USERPROFILE=r'D:\isolated')
        for key,value in caches.items():
            self.assertEqual(env[key],value)
        self.assertEqual(identity['cache_paths'],caches)
        self.assertEqual(calls.call_args.kwargs['env']['LOCALAPPDATA'],inherited['LOCALAPPDATA'])
        for key in ('LOCALAPPDATA','AWS_SESSION_TOKEN','HTTPS_PROXY'):
            self.assertNotIn(key,env)
        self.assertEqual(env['GOFLAGS'],'-p=2')
        self.assertEqual(env['GOTOOLCHAIN'],'local')
        self.assertTrue(env['PATH'].startswith(str(Path('/compiler')/'bin')+os.pathsep))
        for key in ('GOCACHE','GOMODCACHE'):
            invalid=dict(caches,**{key:'relative-cache'})
            with self.subTest(key=key), \
                 patch.object(oracle.subprocess,'check_output',side_effect=replies[:-1]+[json.dumps(invalid).encode()]), \
                 patch.object(oracle.platform,'system',return_value='Windows'), \
                 patch.object(oracle.platform,'machine',return_value='AMD64'), \
                 self.assertRaisesRegex(ValueError,'absolute controlled path'):
                oracle.pinned_go(inherited,fixtures.ROOT)

    def test_archived_originals_and_product_payloads_cannot_self_baseline(self):
        fixtures.candidate_fixture_payloads()
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw)
            name='testdata/port/mcp/copy-clipboard.json'
            archived=root/(fixtures.ARCHIVE+name+'.txt')
            archived.parent.mkdir(parents=True)
            original=fixtures.historical_file(fixtures.ROOT,name).read_bytes()
            archived.write_bytes(original)
            fixtures.fixture_anchor(root,[name])
            archived.write_bytes(original+b'\n')
            with self.assertRaisesRegex(ValueError,'anchor drift'):
                fixtures.fixture_anchor(root,[name])
            # Mutate the product capture while retaining a valid old archive.
            archived.write_bytes(original)
            current=root/name
            current.parent.mkdir(parents=True)
            changed=json.loads((fixtures.ROOT/name).read_bytes())
            changed['cases'][0]['name']='mutated-case'
            current.write_text(json.dumps(changed))
            with patch.object(fixtures,'ROOT',root), patch.object(fixtures,'FIXTURES',{name:16}), \
                 self.assertRaisesRegex(ValueError,'fixture value drift'):
                fixtures.candidate_fixture_payloads()

    def test_coordinated_fixture_and_sidecar_mutation_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            anchor=Path(raw)/'anchor.json'
            data=json.loads(fixtures.ANCHOR.read_bytes())
            data['files']['testdata/port/mcp/tools-call.json']='0'*64
            anchor.write_text(json.dumps(data))
            with patch.object(fixtures,'ANCHOR',anchor), self.assertRaisesRegex(ValueError,'independent historical input anchor drift'):
                fixtures.fixture_anchor(fixtures.ROOT,['testdata/port/mcp/tools-call.json'])

    @unittest.skipIf(os.name=='nt','native Windows taskkill cleanup remains a separate gate')
    def test_timeout_retains_failure_and_terminates_descendant(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw)
            rows=[]
            code='import subprocess,sys,time; p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]); print(p.pid,flush=True); time.sleep(60)'
            with self.assertRaises(subprocess.TimeoutExpired):
                fixtures.run_step([sys.executable,'-c',code],root,os.environ.copy(),root,'timeout',rows,timeout=1)
            self.assertTrue(rows[0]['timed_out'])
            self.assertFalse(rows[0]['passed'])
            self.assertLess(rows[0]['exit'],0)
            pid=int((root/'timeout.stdout').read_text())
            state=subprocess.run(['ps','-p',str(pid),'-o','stat='],capture_output=True,text=True,check=False)
            self.assertTrue(state.returncode!=0 or state.stdout.strip().startswith('Z'),state.stdout)

    def test_child_failure_and_zero_or_wrong_tests_retain_logs(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw)
            rows=[]
            for name,code,tests in [
                ('failed','print("retained child failure"); raise SystemExit(7)',()),
                ('zero','print("PASS\\nok example 0.01s")',('TestExpected',)),
                ('wrong','print("--- PASS: TestOther (0.01s)")',('TestExpected',)),
            ]:
                with self.subTest(name=name), self.assertRaises((RuntimeError,ValueError)):
                    fixtures.run_step([sys.executable,'-c',code],root,os.environ.copy(),root,name,rows,tests)
                self.assertFalse(rows[-1]['passed'])
                self.assertTrue((root/rows[-1]['stdout']).is_file())
                self.assertTrue((root/rows[-1]['stderr']).is_file())
            self.assertEqual(rows[0]['exit'],7)
            self.assertIn('retained child failure',(root/'failed.stdout').read_text())

    def test_real_historical_stderr_stays_rejected(self):
        raw=(Path(__file__).parent/'fixtures/mcp-anomaly/darwin-tool-chain.stderr').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'5fba1c4d2a6cd7e175173ea2f5e4346e9218fafaccbdb8b77f33640a282f38bb')
        with self.assertRaisesRegex(AssertionError,'unexpected stderr retained'):
            process.protocol_bytes(SimpleNamespace(stdout=b'',stderr=raw),Path('__HOME__'),'historical-native','go','fixture')
        # Synthetic controls for the existing narrow off-hours exception.
        allowed=b'2026/10/05 01:24:19 WARN anomaly detected type=off_hours severity=low agent=fixture description="Entry access during off-hours by agent fixture"\n'
        process.protocol_bytes(SimpleNamespace(stdout=b'',stderr=allowed),Path('__HOME__'),'unit','go','fixture')
        for data in [allowed+b'audit log write failed err="audit logger is closed"\n', allowed.replace(b'severity=low',b'severity=high')]:
            with self.assertRaisesRegex(AssertionError,'unexpected stderr retained'):
                process.protocol_bytes(SimpleNamespace(stdout=b'',stderr=data),Path('__HOME__'),'unit','go','fixture')

    def test_untrusted_paths_are_rejected_before_read(self):
        for name in ['/dev/zero','../outside','nested/../../outside','C:\\outside',None]:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError,'unanchored'):
                fixtures.fixture_anchor(fixtures.ROOT,[name])
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw)
            name='testdata/port/mcp/tools-call.json'
            (root/name).parent.mkdir(parents=True)
            (root/name).mkdir()
            with self.assertRaisesRegex(ValueError,'regular file'):
                fixtures.fixture_anchor(root,[name])
            (root/name).rmdir()
            # Portable symlink construction is native-platform dependent.
            if os.name!='nt':
                (root/name).symlink_to(fixtures.ROOT/name)
                with self.assertRaisesRegex(ValueError,'symlink'):
                    fixtures.fixture_anchor(root,[name])
                (root/name).unlink()
                os.mkfifo(root/name)
                with self.assertRaisesRegex(ValueError,'regular file'):
                    fixtures.fixture_anchor(root,[name])

    def test_runtime_environment_drops_ambient_credentials_and_build_overrides(self):
        inherited={'PATH':os.defpath,'HOME':'old','OPENAI_API_KEY':'synthetic-only',
                   'AWS_SESSION_TOKEN':'synthetic-only','SSH_AUTH_SOCK':'synthetic-only',
                   'HTTPS_PROXY':'synthetic-only','GIT_CONFIG_COUNT':'1',
                   'GOFLAGS':'-overlay=outside.json','GOOS':'windows','GOARCH':'386',
                   'CGO_CFLAGS':'synthetic-only','GOTOOLCHAIN':'go1.26.6'}
        self.assertEqual(oracle.tool_environment(inherited),{'PATH':os.defpath,'HOME':'old'})
        with patch.dict(os.environ,inherited,clear=True):
            actual=process.isolated(Path('__HOME__'))
        self.assertEqual(actual['HOME'],'__HOME__')
        for key in set(inherited)-{'PATH','HOME'}:
            self.assertNotIn(key,actual)
        self.assertEqual(oracle.tool_environment(inherited,build=True),
                         {'PATH':os.defpath,'HOME':'old','GOTOOLCHAIN':'go1.26.6'})

    def test_marker_observation_survives_stderr_rejection(self):
        with tempfile.TemporaryDirectory() as raw:
            home=Path(raw)
            marker={'received_expected_secret':True}
            (home/'run_command-marker.json').write_text(json.dumps(marker))
            rows=[]
            with patch.object(process,'run',return_value=SimpleNamespace(stdout=b'',stderr=b'unexpected\n',returncode=0)):
                with self.assertRaisesRegex(AssertionError,'unexpected stderr retained'):
                    process.observe(Path('synthetic'),home,'unit','fixture','go',rows)
            self.assertEqual(rows[0]['child_markers'],{'run_command':marker,'execute_with_secret':None})
            self.assertEqual(rows[0]['stderr_raw'],'unexpected\n')


class ApprovalProducerControls(unittest.TestCase):
    """Real source materialization; constructed capture metadata is UNIT ONLY."""

    def test_actual_native_entrypoints_select_full_corrected_mode_and_default_stays_original(self):
        # Expand the real workflow Make dependencies, then drive the producer's
        # actual parser. Stop before source admission: no compiler/native claim.
        commands = [['mcp_fixture_contract.py', '--output', 'not-created']]
        for workflow, target in [('.github/workflows/rust-mcp-process.yml', 'mcp-ordered-fixtures-check'),
                                 ('.github/workflows/ci.yml', 'mcp-call-fixtures-check')]:
            text = (fixtures.ROOT/workflow).read_text()
            self.assertRegex(text, r'(?m)^\s+run: make '+re.escape(target)+r'\s*$')
            expanded = subprocess.check_output(['make', '-n', target], cwd=fixtures.ROOT, text=True)
            producer = [shlex.split(line) for line in expanded.splitlines()
                        if 'scripts/rust-port/mcp_fixture_contract.py' in line]
            self.assertEqual(len(producer), 1)
            words = producer[0]
            commands.append(words[words.index('scripts/rust-port/mcp_fixture_contract.py'):])
        original_parse = fixtures.argparse.ArgumentParser.parse_args
        selected = []
        def observe(parser, *args, **kwargs):
            parsed = original_parse(parser, *args, **kwargs)
            selected.append((parsed.approval_generator, parsed.generator))
            return parsed
        for argv in commands:
            with patch.object(sys, 'argv', argv), \
                 patch.object(fixtures.argparse.ArgumentParser, 'parse_args', observe), \
                 patch.object(fixtures, 'validate_reference', side_effect=RuntimeError('unit admission boundary')), \
                 self.assertRaisesRegex(RuntimeError, 'unit admission boundary'):
                fixtures.main()
        self.assertEqual(selected, [('original', None), ('approval-lifetime-v1', None), ('approval-lifetime-v1', None)])
        self.assertEqual((len(fixtures.FIXTURES), sum(fixtures.FIXTURES.values()),
                          fixtures.CASES['WriteApproval'][2]), (26, 248, 14))

    def test_materialization_and_exact_capture_identity_on_both_sources(self):
        original = json.loads(fixtures.historical_file(fixtures.ROOT, fixtures.APPROVAL_FIXTURE).read_bytes())
        generators = fixtures.generator_paths()
        for commit in (oracle.HISTORICAL, oracle.ORDERED):
            with self.subTest(commit=commit), tempfile.TemporaryDirectory() as raw:
                tree = Path(raw)
                # Read immutable Git source blobs, without creating a worktree or
                # launching a compiler. No generated native capture is claimed.
                archive = fixtures.git(fixtures.ROOT, 'archive', commit, *original['oracle']['source_files'])
                with tarfile.open(fileobj=io.BytesIO(archive)) as files:
                    for member in files.getmembers():
                        if member.isfile():
                            path = tree/member.name
                            path.parent.mkdir(parents=True, exist_ok=True)
                            data = files.extractfile(member)
                            assert data is not None
                            path.write_bytes(data.read())
                mapping = fixtures.materialize_inputs(tree, generators, commit, 'approval-lifetime-v1')
                assert mapping is not None
                data = (tree/fixtures.APPROVAL_GENERATOR).read_bytes()
                approved = fixtures.approval_generator_source(fixtures.ROOT)
                expected = approved if commit == oracle.HISTORICAL else approved.replace(
                    oracle.HISTORICAL.encode(), oracle.ORDERED.encode())
                self.assertEqual(data, expected)
                self.assertEqual(mapping['materialized_sha256'], hashlib.sha256(data).hexdigest())
                self.assertEqual(mapping['corrected_sha256'], fixtures.APPROVAL_SHA256)
                self.assertEqual(mapping['product_source_commit'], commit)
                self.assertEqual(bool(mapping['identity_delta']), commit == oracle.ORDERED)
                for name in [*generators, *fixtures.FIXTURES]:
                    if name == fixtures.APPROVAL_GENERATOR:
                        continue
                    expected = fixtures.historical_file(fixtures.ROOT, name).read_bytes()
                    if commit == oracle.ORDERED and name in generators and name.endswith('.go'):
                        expected = fixtures.corrected_generator(expected)
                    self.assertEqual((tree/name).read_bytes(), expected, name)
                identity = fixtures.approval_capture_oracle(tree, commit)
                self.assertNotEqual(identity['generator_hash'], original['oracle']['generator_hash'])
                self.assertEqual(identity['commit_sha'], commit)
                # Positive/negative structural controls, NOT fresh observations.
                unit_capture = dict(original, oracle=identity)
                fixtures.compare_approval_capture(unit_capture, identity)
                with self.assertRaisesRegex(ValueError, 'identity or behavior drift'):
                    fixtures.compare_approval_capture(original, identity)
                for field in ('commit_sha', 'commit', 'source_hash', 'generator_hash', 'generator_files'):
                    changed = copy.deepcopy(unit_capture)
                    changed['oracle'][field] = original['oracle'][field] if field == 'generator_hash' else 'unit-invalid'
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        fixtures.compare_approval_capture(changed, identity)
                for field in ('audit_actions', 'prompt_details', 'exists', 'text', 'approval_calls'):
                    changed = copy.deepcopy(unit_capture)
                    changed['cases'][0][field] = None
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        fixtures.compare_approval_capture(changed, identity)
                changed = copy.deepcopy(unit_capture)
                changed['cases'][0]['approval_calls'] = float(changed['cases'][0]['approval_calls'])
                with self.assertRaises(ValueError):
                    fixtures.compare_approval_capture(changed, identity)
                with self.assertRaises(ValueError):
                    fixtures.compare_approval_capture(dict(unit_capture, cases=[]), identity)

    def test_original_mode_never_reads_or_falls_back_to_corrected_source(self):
        for commit in (oracle.HISTORICAL, oracle.ORDERED):
            with self.subTest(commit=commit), tempfile.TemporaryDirectory() as raw, patch.object(
                    fixtures, 'approval_generator_source', side_effect=AssertionError('implicit correction')):
                tree = Path(raw)
                generators = fixtures.generator_paths()
                self.assertIsNone(fixtures.materialize_inputs(tree, generators, commit, 'original'))
                for name in [*generators, *fixtures.FIXTURES]:
                    expected = fixtures.historical_file(fixtures.ROOT, name).read_bytes()
                    if commit == oracle.ORDERED and name in generators and name.endswith('.go'):
                        expected = fixtures.corrected_generator(expected)
                    self.assertEqual((tree/name).read_bytes(), expected, name)

    def test_unreviewed_source_and_widened_delta_fail_before_materialization(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)/'inputs'
            tree = Path(raw)/'destination'
            original = fixtures.historical_file(fixtures.ROOT, fixtures.APPROVAL_GENERATOR).read_bytes()
            approved = fixtures.approval_generator_source(fixtures.ROOT)
            for name, data in [(fixtures.APPROVAL_GENERATOR, original), (fixtures.APPROVAL_SOURCE, approved)]:
                (root/name).parent.mkdir(parents=True, exist_ok=True)
                (root/name).write_bytes(data)
            changed = approved+b'// unreviewed\n'
            (root/fixtures.APPROVAL_SOURCE).write_bytes(changed)
            with patch.object(fixtures, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'unreviewed approval'):
                    fixtures.materialize_inputs(tree, [fixtures.APPROVAL_GENERATOR], oracle.HISTORICAL, 'approval-lifetime-v1')
                self.assertFalse(tree.exists())
                # Even coordinated digest drift must not widen the exact delta.
                with patch.object(fixtures, 'APPROVAL_SHA256', hashlib.sha256(changed).hexdigest()), \
                     self.assertRaisesRegex(ValueError, 'delta exceeds'):
                    fixtures.materialize_inputs(tree, [fixtures.APPROVAL_GENERATOR], oracle.HISTORICAL, 'approval-lifetime-v1')
                self.assertFalse(tree.exists())

    def test_cli_cannot_narrow_corrected_mode_or_pass_without_native_evidence(self):
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw)/'no-native-evidence'
            argv = ['mcp_fixture_contract.py', '--approval-generator', 'approval-lifetime-v1', '--output', str(output)]
            with patch.object(sys, 'argv', argv+['--generator', 'tools-call']), \
                 patch.object(fixtures, 'pinned_go', side_effect=AssertionError('no compiler allowed')) as compiler, \
                 self.assertRaises(SystemExit) as rejected:
                fixtures.main()
            self.assertEqual(rejected.exception.code, 2)
            compiler.assert_not_called()
            self.assertFalse(output.exists())
            with patch.object(sys, 'argv', argv), patch.object(fixtures, 'pinned_go',
                    side_effect=RuntimeError('unit-only missing native evidence')), \
                    self.assertRaisesRegex(RuntimeError, 'missing native evidence'):
                fixtures.main()
            receipt = json.loads((output/'receipt.json').read_bytes())
            self.assertFalse(receipt['passed'])
            self.assertEqual(receipt['lanes'], [])
            self.assertNotIn('compiler', receipt)
            self.assertEqual(receipt['approval_generator'], 'approval-lifetime-v1')
            self.assertEqual(receipt['candidate_inputs'][fixtures.APPROVAL_SOURCE], fixtures.APPROVAL_SHA256)


if __name__=='__main__':
    unittest.main()
