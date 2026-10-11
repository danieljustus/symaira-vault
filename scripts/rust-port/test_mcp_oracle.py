#!/usr/bin/env python3
"""Fail-closed controls; constructed metadata here is not native evidence."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
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


if __name__=='__main__':
    unittest.main()
