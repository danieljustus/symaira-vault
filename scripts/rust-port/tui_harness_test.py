#!/usr/bin/env python3
"""Pure harness checks and an explicit real-editor regression; never clipboard.

python tui_harness_test.py --go-cli /path/go-cli --go-helper /path/go-fixture
executes the pinned binaries. Without those arguments only pure checks execute.
"""
import argparse
import base64
import copy
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import tui_contract as tui

STRUCTURAL_BYTES = b'public-safe-terminal'
STRUCTURAL_SHA = hashlib.sha256(STRUCTURAL_BYTES).hexdigest()


class HarnessTests(unittest.TestCase):
    def valid_structural_receipt(self):
        # Synthetic schema control only. Never registered as native evidence.
        r = {'schema_version': 2, 'candidate_commit': 'a'*40, 'oracle_commit': tui.ORACLE,
             'native_os': 'Darwin', 'architecture': 'arm64', 'candidate_sources': {'fixture': 'b'*64},
             'candidate_sources_at_end': {'fixture': 'b'*64}, 'rust_executable_sha256': STRUCTURAL_SHA,
             'rebuilt_rust_executable_sha256': STRUCTURAL_SHA, 'binary_source_verified': True,
             'rebuilt_binary_artifact': 'safe', 'rebuilt_binary_bytes': len(STRUCTURAL_BYTES),
             'passed': True, 'candidate_worktree_clean': True, 'candidate_worktree_clean_at_end': True}
        for label in ['go', 'rust']:
            r[label] = []
            for case in tui.CASES:
                row = {'case': case, 'passed': True, 'exit_code': 0, 'terminal_restored': True,
                       'input_restored': True, 'output_restored': True, 'canary_disclosure': False,
                       'before': [{'path': 'alpha/login', 'tags': None, 'version': 1, 'data_sha256': 'e'*64}],
                       'after': [{'path': 'alpha/login', 'tags': None, 'version': 1, 'data_sha256': 'e'*64}], 'stdout_sha256': 'd'*64}
                if case in {'locked-wrong-passphrase', 'uninitialized'}:
                    row['exit_code'] = 6 if label == 'go' else 1
                row['console'] = {'exit_code': row['exit_code'], 'input_restored': True, 'output_restored': True}
                if case.startswith(('editor-', 'add-')):
                    row['editor'] = {'environment_filtered': True, 'input_is_terminal': True,
                                     'output_is_terminal': True, 'document_bytes': 1,
                                     'foreground_terminal_restored': label == 'rust'}
                r[label].append(row)
        return r

    def validate(self, r):
        tui.validate_receipt(r, 'a'*40, 'Darwin', 'arm64', {'fixture': 'b'*64}, STRUCTURAL_SHA)

    def test_success_and_clean_flags_reject_missing_false_and_integer_true(self):
        valid = self.valid_structural_receipt()
        self.validate(valid)
        for key in ['passed', 'candidate_worktree_clean', 'candidate_worktree_clean_at_end', 'binary_source_verified']:
            for value in [False, 1, None, 'true']:
                with self.subTest(key=key, value=value):
                    r = copy.deepcopy(valid); r[key] = value
                    with self.assertRaises(AssertionError): self.validate(r)
            r = copy.deepcopy(valid); del r[key]
            with self.assertRaises(KeyError): self.validate(r)

    def test_case_inventory_and_per_case_success_are_fail_closed(self):
        valid = self.valid_structural_receipt(); self.validate(valid)
        for label in ['go', 'rust']:
            for mutation in ['missing', 'duplicate', 'false', 'integer', 'absent']:
                r = copy.deepcopy(valid)
                if mutation == 'missing': r[label].pop()
                elif mutation == 'duplicate': r[label][-1] = r[label][0]
                elif mutation == 'absent': del r[label][0]['passed']
                else: r[label][0]['passed'] = False if mutation == 'false' else 1
                with self.subTest(label=label, mutation=mutation), self.assertRaises((AssertionError, KeyError)):
                    self.validate(r)

    def test_source_binary_target_and_semantic_mismatch_are_rejected(self):
        valid = self.valid_structural_receipt(); self.validate(valid)
        for key in ['candidate_commit', 'native_os', 'architecture', 'rust_executable_sha256',
                    'rebuilt_rust_executable_sha256', 'candidate_sources', 'candidate_sources_at_end']:
            r = copy.deepcopy(valid); r[key] = 'wrong'
            with self.subTest(key=key), self.assertRaises(AssertionError): self.validate(r)
        r = copy.deepcopy(valid); r['rust'][0]['after'][0]['version'] = True
        with self.assertRaisesRegex(AssertionError, 'invalid snapshot version'): self.validate(r)
        r = copy.deepcopy(valid)
        for label in ['go', 'rust']: del r[label][0]['after'][0]['tags']
        with self.assertRaisesRegex(AssertionError, 'incomplete snapshot fields'): self.validate(r)

    def test_terminal_canary_and_editor_security_flags_are_rejected(self):
        valid = self.valid_structural_receipt(); self.validate(valid)
        for key in ['terminal_restored', 'input_restored', 'output_restored']:
            r = copy.deepcopy(valid); r['rust'][0][key] = False
            with self.subTest(key=key), self.assertRaisesRegex(AssertionError, 'terminal modes'): self.validate(r)
        for value in [True, None, 0]:
            r = copy.deepcopy(valid); r['rust'][0]['canary_disclosure'] = value
            with self.assertRaisesRegex(AssertionError, 'canary disclosure'): self.validate(r)
        r = copy.deepcopy(valid); r['rust'][3]['editor']['environment_filtered'] = False
        with self.assertRaisesRegex(AssertionError, 'environment filtering'): self.validate(r)

    def test_failure_receipt_preserves_prefix_and_nonzero_exception(self):
        with tempfile.TemporaryDirectory() as raw:
            receipt = Path(raw)/'failed.json'
            def fail(args, r):
                r['go'].append({'case': tui.CASES[0], 'passed': True})
                raise AssertionError('injected ordinary child failure')
            with patch.object(tui.sys, 'argv', ['tui', '--rust-cli', str(Path(raw)/'binary'), '--receipt', str(receipt)]), patch.object(tui, 'execute', fail):
                with self.assertRaisesRegex(AssertionError, 'ordinary child failure'): tui.main()
            observed = json.loads(receipt.read_bytes())
            self.assertIs(observed['passed'], False)
            self.assertEqual(len(observed['go']), 1)
            self.assertIn('ordinary child failure', observed['failure'])

    def test_checked_child_failure_retains_output_and_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as raw, patch.object(tui, 'COMMAND_OUTPUT', Path(raw)):
            with self.assertRaises(AssertionError):
                tui.checked([tui.sys.executable, '-c', 'print("child-failure-control"); raise SystemExit(7)'])
            records = [json.loads(p.read_bytes()) for p in Path(raw).glob('*.json')]
            self.assertEqual([r['exit_code'] for r in records], [7])
            self.assertTrue(any(b'child-failure-control' in p.read_bytes() for p in Path(raw).glob('*.stdout')))

    def test_terminal_artifact_paths_sizes_digests_and_canaries(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); data = b'public-safe-terminal'; (root/'safe').write_bytes(data)
            valid = self.valid_structural_receipt()
            for label in ['go', 'rust']:
                for row in valid[label][:-1]:
                    row.update(capture_artifact='safe', capture_bytes=len(data), capture_sha256=hashlib.sha256(data).hexdigest())
            def validate(r):
                tui.validate_receipt(r, 'a'*40, 'Darwin', 'arm64', {'fixture': 'b'*64}, STRUCTURAL_SHA, root)
            validate(valid)
            for key, value in [('capture_artifact', '../outside'), ('capture_artifact', str(root/'safe')),
                               ('capture_bytes', 1), ('capture_sha256', 'e'*64)]:
                r = copy.deepcopy(valid); r['rust'][1][key] = value
                with self.subTest(key=key), self.assertRaises(AssertionError): validate(r)
            leak = tui.CANARIES[0].encode(); (root/'leak').write_bytes(leak)
            r = copy.deepcopy(valid); r['rust'][1].update(capture_artifact='leak', capture_bytes=len(leak), capture_sha256=hashlib.sha256(leak).hexdigest())
            with self.assertRaisesRegex(AssertionError, 'canary disclosure'): validate(r)

    def test_wait_rechecks_predicate_after_process_exit_transition(self):
        browser = object.__new__(tui.Browser)
        browser.pump = lambda seconds=0.12: None
        browser.alive = lambda: False
        observations = iter([False, True])
        browser.wait(lambda: next(observations), 'exit between observations')

    def test_genuine_deleted_status_is_not_a_remaining_entry(self):
        fixture = json.loads(Path(__file__).with_name('tui_delete_status_fixture.json').read_bytes())
        raw = base64.b64decode(fixture['capture'], validate=True)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), '50c290f1aca0dd001e454b8dfd3bd0cd090cfa54d312990a23813508af3de62f')
        self.assertEqual(len(raw), 9675)
        browser = object.__new__(tui.Browser)
        browser.screen = tui.pyte.Screen(120, 32)
        stream = tui.pyte.Stream(browser.screen)
        stream.feed(raw.decode('utf-8'))
        self.assertIn('Deleted alpha/login', browser.view())
        self.assertIn(tui.PATHS[0], browser.view())  # genuine old-predicate failure
        self.assertTrue(browser.deletion_visible())
        # Structural negative control only, not another native capture.
        stream.feed('\x1b[1;44Halpha/login')
        self.assertFalse(browser.deletion_visible())

    def test_darwin_pending_input_exclusion_keeps_application_mode_checks(self):
        state = [1, 2, 3, 4, 5, 6, []]
        pending = [1, 2, 3, 4 | 0x20000000, 5, 6, []]
        with patch.object(tui.platform, 'system', return_value='Darwin'):
            self.assertEqual(tui.terminal_modes(state), tui.terminal_modes(pending))
            changed = [1, 2, 3, 5, 5, 6, []]
            self.assertNotEqual(tui.terminal_modes(state), tui.terminal_modes(changed))
        with patch.object(tui.platform, 'system', return_value='Linux'):
            self.assertNotEqual(tui.terminal_modes(state), tui.terminal_modes(pending))

    def test_terminal_profile_does_not_advertise_unimplemented_osc_color_queries(self):
        with tempfile.TemporaryDirectory() as raw:
            env = tui.fixture_env(Path(raw)/'home', {})
            self.assertEqual(env['TERM'], 'screen-256color')
            self.assertEqual(env['SYMVAULT_TEST_KEYRING'], 'memory')


def editor_keydelivery(go, helper):
    # No private_provider, clipboard calls, credential stores or user HOME.
    # The real Go reference is unmodified; the fixture opens the real document.
    with tempfile.TemporaryDirectory(prefix='tui-editor-keydelivery-') as raw:
        base = Path(raw)
        env = tui.fixture_env(base/'seed-home', {})
        seed = base/'seed'
        tui.checked([helper, '--root', seed], env=env)
        with patch.object(tui, 'clipboard', side_effect=AssertionError('clipboard forbidden in editor-only regression')):
            for attempt in range(8):
                work = base/str(attempt)
                work.mkdir()
                row = tui.run_case('editor-empty', 'go', go, helper, seed, work, {})
                assert row['terminal_restored'] is True and row['after'] == row['before']
                assert row['editor']['document_bytes'] > 0
                print('PASS actual Go editor-empty keydelivery '+str(attempt+1), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--go-cli', type=Path)
    parser.add_argument('--go-helper', type=Path)
    args, remaining = parser.parse_known_args()
    assert bool(args.go_cli) == bool(args.go_helper), 'supply both real Go binaries'
    if args.go_cli:
        editor_keydelivery(args.go_cli.resolve(), args.go_helper.resolve())
    else:
        unittest.main(argv=[__file__, *remaining])
