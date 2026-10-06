#!/usr/bin/env python3
"""Retained real Go timeout capture plus explicitly synthetic guard controls."""
import ast
import base64
import copy
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import http_process_contract as contract

FIXTURE = Path(__file__).resolve().parents[2] / 'testdata/http-default-deadline/windows-incomplete.json'
FIXTURE_SHA256 = '5deeeb1328552ef31b65173c96af912ff3ab3045bb34eda2a061e94982ee1b41'


class DefaultDeadlineContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = FIXTURE.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == FIXTURE_SHA256, 'unchanged real timeout observation'
        cls.capture = json.loads(raw)
        assert cls.capture['full_capture_sha256'] == 'a5039d6e57180434587259ee5ae1c7d7c9ee0a093ded60b6938622016569a555'
        assert cls.capture['oracle_commit'] == contract.ORACLE
        assert cls.capture['native_os'] == 'Windows'
        assert cls.capture['original_full_capture_passed'] is False
        cls.actual = cls.capture['observation']
        cls.wire = base64.b64decode(cls.actual['received_base64'], validate=True)

    def test_real_error_and_rust_silence_are_distinct(self):
        self.assertEqual(contract.stalled_response_class(self.actual, 'go'), 'complete-invalid-json-400')
        with self.assertRaisesRegex(AssertionError, 'unexpected stalled-client response'):
            contract.stalled_response_class(self.actual, 'rust')
        silent = dict(self.actual, received_base64='')
        self.assertEqual(contract.stalled_response_class(silent, 'go'), 'silent-eof')
        self.assertEqual(contract.stalled_response_class(silent, 'rust'), 'silent-eof')
        # The original incomplete failed capture is not promoted to acceptance.
        self.assertIs(self.capture['original_full_capture_passed'], False)

    def test_complete_error_mutations_fail(self):
        mutations = [
            ('status', self.wire.replace(b'400 Bad Request', b'200 OK')),
            ('body', self.wire.replace(b'invalid JSON', b'invalid XSEN')),
            ('short', self.wire[:-1]),
            ('extra', self.wire + b'public-unexpected-output'),
            ('header', self.wire.replace(b'application/json', b'application/text')),
            ('duplicate', self.wire.replace(b'Content-Length: 67', b'Content-Length: 67\r\nContent-Length: 67')),
            ('cookie', self.wire.replace(b'\r\n\r\n', b'\r\nSet-Cookie: public-invalid\r\n\r\n', 1)),
            ('missing-date', self.wire.replace(b'Date: Sun, 04 Oct 2026 16:51:55 GMT\r\n', b'')),
        ]
        self.assertEqual(contract.stalled_response_class(self.actual, 'go'), 'complete-invalid-json-400')
        for name, wire in mutations:
            with self.subTest(name=name):
                self.assertNotEqual(wire, self.wire, 'mutation must change genuine bytes')
                row = dict(self.actual, received_base64=base64.b64encode(wire).decode())
                with self.assertRaises((AssertionError, ValueError)):
                    contract.stalled_response_class(row, 'go')
        row = dict(self.actual, case='idle-before-request', elapsed_seconds=5)
        with self.assertRaisesRegex(AssertionError, 'unexpected stalled-client response'):
            contract.stalled_response_class(row, 'go')

    def test_unchanged_timing_and_known_case_guards(self):
        for elapsed in [True, 8.999, 15, float('nan'), float('inf'), '10']:
            with self.subTest(elapsed=repr(elapsed)):
                row = dict(self.actual, elapsed_seconds=elapsed)
                with self.assertRaisesRegex(AssertionError, 'bounded transport closure'):
                    contract.stalled_response_class(row, 'go')
        with self.assertRaisesRegex(AssertionError, 'known stalled-client case'):
            contract.stalled_response_class(dict(self.actual, case='other'), 'go')
        with self.assertRaisesRegex(AssertionError, 'known timeout implementation'):
            contract.stalled_response_class(self.actual, 'other')

    def structural_receipt(self):
        # Synthetic registration structure, not additional native evidence.
        result = {}
        for implementation in ['go', 'rust']:
            rows = []
            for case, elapsed in [('idle-before-request', 5), ('incomplete-request-body', 10)]:
                row = dict(case=case, elapsed_seconds=elapsed, received_base64='', peer_eof=True,
                           passed=True, response_class='silent-eof', request_sha256='a' * 64)
                if implementation == 'go' and case == 'incomplete-request-body':
                    row.update(received_base64=self.actual['received_base64'], response_class='complete-invalid-json-400')
                rows.append(row)
            result[implementation + '_stalled_clients'] = rows
        return result

    def test_executed_case_schema_and_pairing_fail_closed(self):
        valid = self.structural_receipt()
        contract.validate_stalled_observations(valid)
        for field, value, reason in [
            ('passed', False, 'executed successful EOF'), ('passed', 1, 'executed successful EOF'),
            ('peer_eof', False, 'executed successful EOF'), ('peer_eof', 1, 'executed successful EOF'),
            ('response_class', 'silent-eof', 'derived timeout response class'),
            ('request_sha256', 'b' * 64, 'same complete stalled request'),
        ]:
            changed = copy.deepcopy(valid)
            changed['go_stalled_clients'][1][field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(AssertionError, reason):
                    contract.validate_stalled_observations(changed)
        for field in ['passed', 'peer_eof', 'response_class', 'request_sha256']:
            changed = copy.deepcopy(valid)
            del changed['go_stalled_clients'][1][field]
            with self.subTest(missing=field):
                with self.assertRaises(KeyError):
                    contract.validate_stalled_observations(changed)
        for rows in [[], valid['go_stalled_clients'][:1], valid['go_stalled_clients'] * 2]:
            changed = copy.deepcopy(valid)
            changed['go_stalled_clients'] = rows
            with self.assertRaisesRegex(AssertionError, 'exact stalled-case inventory'):
                contract.validate_stalled_observations(changed)

    def test_actual_receive_exception_retains_partial_bytes_and_failed_verdict(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.side_effect = [b'public-partial-wire', TimeoutError('injected actual receive failure')]
        observations = []
        with mock.patch.object(contract.socket, 'create_connection', return_value=connection), \
             mock.patch.object(contract.time, 'monotonic', side_effect=[10, 25]):
            with self.assertRaisesRegex(TimeoutError, 'injected actual receive failure'):
                contract.stalled_connections(1, {}, observations, 'go')
        self.assertEqual(len(observations), 1)
        self.assertEqual(base64.b64decode(observations[0]['received_base64']), b'public-partial-wire')
        self.assertEqual(observations[0]['elapsed_seconds'], 15)
        self.assertIs(observations[0]['peer_eof'], False)
        self.assertIs(observations[0]['passed'], False)

    def test_failing_child_predicate_retains_eof_and_nonpassing_observation(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.return_value = b''
        observations = []
        with mock.patch.object(contract.socket, 'create_connection', return_value=connection), \
             mock.patch.object(contract.time, 'monotonic', side_effect=[10, 15]), \
             mock.patch.object(contract, 'stalled_response_class', side_effect=AssertionError('injected predicate failure')):
            with self.assertRaisesRegex(AssertionError, 'injected predicate failure'):
                contract.stalled_connections(1, {}, observations, 'go')
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]['elapsed_seconds'], 5)
        self.assertIs(observations[0]['peer_eof'], True)
        self.assertIs(observations[0]['passed'], False)

    def test_head_framing_and_workflow_source_inventory(self):
        # Synthetic framing unit input, not a native server observation.
        raw = b'HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n'
        self.assertEqual(contract.parse_response(raw, request_method='HEAD')['body_base64'], '')
        with self.assertRaisesRegex(AssertionError, 'HEAD must not transmit'):
            contract.parse_response(raw + b'x', request_method='HEAD')
        with self.assertRaisesRegex(AssertionError, 'complete HTTP framing'):
            contract.parse_response(raw)
        workflow = (contract.ROOT / '.github/workflows/rust-mcp-http-process.yml').read_text()
        paths = [line.strip()[3:-1] for line in workflow.split('    paths:\n', 1)[1].split('  workflow_dispatch:', 1)[0].splitlines()]
        uncovered = [path for path in contract.candidate_paths() if not any(fnmatch.fnmatchcase(path, pattern) for pattern in paths)]
        self.assertEqual(uncovered, [], 'every fingerprinted candidate input must trigger its native gate')

    def test_early_invalid_admission_corpus_retains_partial_input(self):
        # Request-shape unit control; native responses come from the real CLIs.
        rows=dict(contract.cases(48175, {}))
        self.assertEqual(len(contract.EARLY_INVALID_ADMISSION_CASES), 8)
        for name, _, status in contract.EARLY_INVALID_ADMISSION_CASES:
            with self.subTest(name=name):
                data=rows['mcp-early-invalid-oversized-'+name]
                headers,body=data.split(b'\r\n\r\n',1)
                self.assertEqual(body,b'x')
                self.assertIn(b'Content-Length: 1048577\r\n',headers+b'\r\n')
                self.assertIn(status,{401,403,415,406})

    def test_receipt_finalization_rejects_unignored_output(self):
        tree = ast.parse(Path(contract.__file__).read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        final = next(node for node in main.body if isinstance(node, ast.Try)).finalbody
        code = compile(ast.Module(body=final, type_ignores=[]), '<actual HTTP receipt finalization>', 'exec')
        env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
        for location, expected_clean in [('target/control.json', True), ('root-control.json', False)]:
            with self.subTest(location=location), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                subprocess.run(['git', 'init', '-q', str(root)], env=env, check=True)
                (root / '.git/info/exclude').write_text('target/\n')
                receipt_path = root / location
                receipt_path.parent.mkdir(parents=True, exist_ok=True)
                # Algorithm unit state only, not native HTTP observations.
                receipt = {'passed': True, 'candidate_worktree_clean': True}
                scope = {'args': SimpleNamespace(receipt=receipt_path, allow_dirty_for_development=False),
                         'json': json, 'receipt': receipt,
                         'checked': lambda args: subprocess.check_output(args, cwd=root, env=env)}
                rejected = False
                try:
                    exec(code, scope)
                except AssertionError:
                    rejected = True
                result = json.loads(receipt_path.read_text())
                self.assertIs(result['candidate_worktree_clean_at_end'], expected_clean)
                self.assertIs(result['passed'], expected_clean)
                self.assertIs(rejected, not expected_clean)


if __name__ == '__main__':
    unittest.main()
