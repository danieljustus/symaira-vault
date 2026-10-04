#!/usr/bin/env python3
"""Guards for the actual-Go completion inventory and raw child failures."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

import cli_artifacts_contract as contract


class CompletionCaptureGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = json.loads(contract.ARTIFACT.read_bytes())

    def test_complete_ordered_actual_go_inventory(self):
        cases = self.artifact['entry_completions']
        queries = contract.validate_observations(cases, self.artifact['commands'])
        self.assertEqual(len(cases), 519)
        self.assertEqual(len(queries), 485)
        self.assertEqual(len(contract.PARSER_REQUESTS), 64)
        self.assertTrue(all(c['name'].startswith('parser/') for c in cases[455:]))
        by_name = {c['name']: c for c in cases}
        for name in ('invalid-int', 'invalid-bool', 'invalid-duration',
                     'unknown-final-inline', 'unknown-typed-short'):
            self.assertIn('[Debug] [Error]', by_name['parser/' + name]['stderr'])
        for name in ('unfinished-int', 'unfinished-inline-int', 'unfinished-duration'):
            self.assertNotIn('[Debug] [Error]', by_name['parser/' + name]['stderr'])

    def test_missing_duplicate_reordered_and_mutated_requests_fail_closed(self):
        original = self.artifact['entry_completions']
        mutations = []
        mutations.append(original[:-1])
        mutations.append(original + [original[-1]])
        duplicate = copy.deepcopy(original)
        duplicate[-1] = duplicate[-2]
        mutations.append(duplicate)
        reordered = copy.deepcopy(original)
        reordered[-2:] = reversed(reordered[-2:])
        mutations.append(reordered)
        for field, value in [('name', 'unexecuted'), ('args', ['config', 'get', 'vaultDir']),
                             ('state', 'cached'), ('error', 'child failed'), ('stderr', None)]:
            mutated = copy.deepcopy(original)
            mutated[-1][field] = value
            mutations.append(mutated)
        for cases in mutations:
            with self.subTest(last=cases[-1]['name'], count=len(cases)):
                with self.assertRaises(AssertionError):
                    contract.validate_observations(cases, self.artifact['commands'])

    def test_real_child_nonzero_preserves_all_stdout_stderr_and_exit(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            env = dict(os.environ, CLI_ARTIFACTS_EXECUTION_DIR=str(base / 'records'))
            args = [sys.executable, '-c',
                    'import sys; sys.stdout.buffer.write(b"out\\x00"*20000); '
                    'sys.stderr.buffer.write(b"err\\x00"*20000); sys.exit(17)']
            with self.assertRaisesRegex(RuntimeError, r'failed \(17\)'):
                contract.execute(args, base, env)
            records = list((base / 'records').iterdir())
            self.assertEqual(len(records), 1)
            self.assertEqual((records[0] / 'stdout.bin').read_bytes(), b'out\x00' * 20000)
            self.assertEqual((records[0] / 'stderr.bin').read_bytes(), b'err\x00' * 20000)
            command = json.loads((records[0] / 'command.json').read_bytes())
            self.assertEqual(command['returncode'], 17)
            self.assertEqual(command['args'], args)
            self.assertFalse(command['timed_out'])

    def test_real_successful_child_bytes_survive_later_assertion_failure(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            env = dict(os.environ, CLI_ARTIFACTS_EXECUTION_DIR=str(base / 'records'))
            args = [sys.executable, '-c', 'import sys; print("public-output"); sys.stderr.write("public-diagnostic\\n")']
            result = contract.execute(args, base, env)
            with self.assertRaises(AssertionError):
                assert result.stdout == b'intentionally-different'
            records = list((base / 'records').iterdir())
            self.assertEqual(len(records), 1)
            self.assertEqual((records[0] / 'stdout.bin').read_bytes(), result.stdout)
            self.assertEqual((records[0] / 'stderr.bin').read_bytes(), result.stderr)
            self.assertEqual(json.loads((records[0] / 'command.json').read_bytes())['returncode'], 0)


if __name__ == '__main__':
    unittest.main()
