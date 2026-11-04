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
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import tui_contract as tui
import tui_mutation_test as mutations

STRUCTURAL_BYTES = b'public-safe-terminal'
STRUCTURAL_SHA = hashlib.sha256(STRUCTURAL_BYTES).hexdigest()


class HarnessTests(unittest.TestCase):
    def test_exit_observation_precedes_console_wrapper_release(self):
        # Structural lifecycle test only, no native or clipboard claim.
        with tempfile.TemporaryDirectory(prefix='tui-exit-order-') as raw:
            browser = object.__new__(tui.Browser)
            browser.console_receipt = Path(raw)/'console.json'
            browser.console_receipt.write_text(json.dumps({'exit_code': 0, 'input_restored': True, 'output_restored': True}))
            release = Path(str(browser.console_receipt)+'.release')
            browser.original = [0, 0, 0, 0, 0, 0, []]
            browser.slave = -1
            browser.alive = lambda: not release.exists()
            browser.pump = lambda seconds=0.12: None
            browser.wait = lambda predicate, description, timeout=15: self.assertTrue(predicate(), description)
            observed = []
            def observation():
                self.assertTrue(browser.alive())
                self.assertFalse(release.exists())
                observed.append('after-cli-exit-before-wrapper-release')
            if os.name != 'nt':
                with patch('termios.tcgetattr', return_value=browser.original): browser.finish(0, observation)
            else:
                browser.finish(0, observation)
            self.assertEqual(observed, ['after-cli-exit-before-wrapper-release'])
            self.assertTrue(release.exists())

    def valid_structural_receipt(self):
        # Synthetic schema control only. Never registered as native evidence.
        r = {'schema_version': 2, 'candidate_commit': 'a'*40, 'oracle_commit': tui.ORACLE,
             'native_os': 'Darwin', 'architecture': 'arm64', 'candidate_sources': {'fixture': 'b'*64},
             'candidate_sources_at_end': {'fixture': 'b'*64}, 'rust_executable_sha256': STRUCTURAL_SHA,
             'rebuilt_rust_executable_sha256': STRUCTURAL_SHA, 'binary_source_verified': True,
             'rebuilt_binary_artifact': 'safe', 'rebuilt_binary_bytes': len(STRUCTURAL_BYTES),
             'seed_configs': {str(ttl): {'requested_clipboard_seconds': ttl, 'effective_clipboard_seconds': ttl,
                                        'initial_roundtrip_clipboard_seconds': 30 if ttl == 0 else 2} for ttl in [0, 2]},
             'passed': True, 'candidate_worktree_clean': True, 'candidate_worktree_clean_at_end': True,
             'go_observation': {'goos': 'darwin', 'goarch': 'arm64', 'go_version': 'go1.26.6',
                                'oracle_commit': tui.ORACLE, 'sha256': 'c'*64}}
        for label in ['go', 'rust']:
            r[label] = []
            for case in tui.CASES:
                row = {'case': case, 'passed': True, 'exit_code': 0,
                       'before_config': {k: 0 if case == 'zero-ttl-quit-cleanup' else 2
                                         for k in ['vault_clipboard_seconds', 'persisted_clipboard_seconds']}, 'terminal_restored': True,
                       'input_restored': True, 'output_restored': True, 'canary_disclosure': False,
                       'before': [{'path': 'alpha/login', 'tags': None, 'version': 1, 'data_sha256': 'e'*64}],
                       'after': [{'path': 'alpha/login', 'tags': None, 'version': 1, 'data_sha256': 'e'*64}], 'stdout_sha256': 'd'*64}
                if case in {'locked-wrong-passphrase', 'uninitialized'}:
                    row['exit_code'] = tui.EXIT_CLASSES[case][label]
                row['console'] = {'exit_code': row['exit_code'], 'input_restored': True, 'output_restored': True}
                if case.startswith(('editor-', 'add-')):
                    row['editor'] = {'environment_filtered': True, 'input_is_terminal': True,
                                     'output_is_terminal': True, 'document_bytes': 1,
                                     'foreground_terminal_restored': label == 'rust'}
                if case == 'zero-ttl-quit-cleanup':
                    row.update(clipboard_survived_quit=label == 'go', zero_ttl_observation_seconds=2.2)
                if label == 'go':
                    # The Go side is the committed observation: normalized rows, no timings or document sizes.
                    row = dict(tui.normalize_row(row), replayed=True, capture_policy_checked_at_capture=True)
                r[label].append(row)
        return r

    def validate(self, r):
        tui.validate_receipt(r, 'a'*40, 'Darwin', 'arm64', {'fixture': 'b'*64}, STRUCTURAL_SHA)

    def test_exit_classes_are_at_parity_with_go(self):
        # #1241: Rust returns Go's exit code for an uninitialized vault, so no
        # exit-code difference may be declared for any case.
        self.assertEqual(tui.EXIT_CLASSES['uninitialized'], {'go': 3, 'rust': 3})
        for case, classes in tui.EXIT_CLASSES.items():
            self.assertEqual(classes['go'], classes['rust'], case)

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
        r = copy.deepcopy(valid); r['seed_configs']['0']['effective_clipboard_seconds'] = 30
        with self.assertRaisesRegex(AssertionError, 'fixture clipboard duration mismatch'): self.validate(r)
        r = copy.deepcopy(valid); r['go'][tui.CASES.index('zero-ttl-quit-cleanup')]['before_config']['persisted_clipboard_seconds'] = 30
        with self.assertRaisesRegex(AssertionError, 'pre-runtime fixture duration changed'): self.validate(r)

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

    def test_relative_rejection_receipt_stays_in_parent_evidence_root(self):
        # Deliberate synthetic rejection child, not native acceptance evidence.
        with tempfile.TemporaryDirectory(prefix='tui-relative-receipt-') as raw:
            base = Path(raw); tree = base/'clone'; script = tree/'scripts/rust-port/tui_contract.py'
            script.parent.mkdir(parents=True)
            script.write_text('import sys,json\nfrom pathlib import Path\np=Path(sys.argv[sys.argv.index("--receipt")+1]);p.parent.mkdir(parents=True,exist_ok=True)\np.write_text(json.dumps({"passed":False,"failure":"structural rejection"}))\nprint("structural child output")\nsys.exit(7)\n')
            expected = base/'evidence/receipt.json'
            relative = Path(os.path.relpath(expected))
            result = mutations.rejected(tree, base/'unused-binary', relative, 'structural rejection', source_only=True)
            self.assertIs(result['passed'], False)
            self.assertTrue(expected.is_file())
            self.assertIn(b'structural child output', expected.with_suffix('.stdout').read_bytes())

    def test_cleanup_failure_cannot_erase_primary_row_and_capture(self):
        with tempfile.TemporaryDirectory(prefix='tui-failure-retention-') as raw:
            base = Path(raw); seed = base/'seed'; seed.mkdir(); (seed/'fixture').write_bytes(b'structural fixture')
            browser = Mock()
            browser.capture = bytearray(b'structural terminal failure')
            browser.unlock.side_effect = AssertionError('primary child failure')
            browser.close.side_effect = RuntimeError('secondary cleanup failure')
            def snapshot(helper, root, home, env, config_receipt=None):
                if config_receipt is not None:
                    config_receipt.write_text(json.dumps({'vault_clipboard_seconds': 2, 'persisted_clipboard_seconds': 2}))
                return []
            with patch.object(tui, 'Browser', return_value=browser), patch.object(tui, 'snapshot', side_effect=snapshot), patch.object(tui, 'CAPTURE_OUTPUT', base/'captures'):
                with self.assertRaisesRegex(tui.CaseFailure, 'primary child failure') as context:
                    tui.run_case(tui.CASES[0], 'go', base/'binary', base/'helper', seed, base, {})
            row = context.exception.row
            self.assertIs(row['passed'], False)
            self.assertIn('secondary cleanup failure', row['cleanup_failure'])
            self.assertEqual((base/row['capture_artifact']).read_bytes(), browser.capture)

    def test_native_windows_cleanup_attempts_all_owned_resources(self):
        browser = object.__new__(tui.Browser)
        browser.child = Mock()
        browser.alive = lambda: True
        browser.child.terminate.side_effect = RuntimeError('structural termination failure')
        browser.child.fileobj.close.side_effect = OSError('structural socket failure')
        browser.child._thread.is_alive.return_value = False
        with patch.object(tui.os, 'name', 'nt'), \
                patch.object(tui, 'checked', side_effect=RuntimeError('structural tree termination failure')):
            with self.assertRaises(ExceptionGroup) as context: browser.close()
        browser.child._server.close.assert_called_once_with()
        browser.child._thread.join.assert_called_once_with(timeout=5)
        self.assertEqual(len(context.exception.exceptions), 3)
        self.assertIn('structural tree termination failure', str(context.exception))
        self.assertIn('structural termination failure', str(context.exception))
        self.assertIn('structural socket failure', str(context.exception))

    def test_windows_abort_kills_descendants_before_console_wrapper(self):
        # Structural ordering control; the native mutation job exercises the
        # actual ConPTY -> Go wrapper -> Rust CLI process tree on Windows.
        browser = object.__new__(tui.Browser)
        browser.child = Mock(pid=12345)
        browser.alive = lambda: True
        browser.child._thread.is_alive.return_value = False
        calls = []
        def kill_tree(argv, **kwargs):
            self.assertEqual(argv, ['taskkill.exe', '/PID', '12345', '/T', '/F'])
            self.assertEqual(kwargs, {'timeout': 10})
            calls.append('tree')
        browser.child.terminate.side_effect = lambda **kwargs: calls.append('wrapper') or True
        with patch.object(tui.os, 'name', 'nt'), patch.object(tui, 'checked', side_effect=kill_tree):
            browser.close()
        self.assertEqual(calls, ['tree', 'wrapper'])
        browser.child.fileobj.close.assert_called_once_with()
        browser.child._server.close.assert_called_once_with()
        browser.child._thread.join.assert_called_once_with(timeout=5)

    def test_windows_normal_exit_only_closes_owned_transport(self):
        browser = object.__new__(tui.Browser)
        browser.child = Mock()
        browser.alive = lambda: False
        browser.child._thread.is_alive.return_value = False
        with patch.object(tui.os, 'name', 'nt'), patch.object(tui, 'checked') as checked:
            browser.close()
        checked.assert_not_called()
        browser.child.terminate.assert_not_called()
        browser.child.fileobj.close.assert_called_once_with()
        browser.child._server.close.assert_called_once_with()
        browser.child._thread.join.assert_called_once_with(timeout=5)

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


class RecordedGoObservationTests(unittest.TestCase):
    """Negative controls: the recorded Go side is authoritative and cannot be bent or faked."""

    valid_structural_receipt = HarnessTests.valid_structural_receipt
    validate = HarnessTests.validate

    def test_valid_replayed_receipt_passes(self):
        self.validate(self.valid_structural_receipt())

    def test_tampered_recorded_go_store_snapshot_is_a_differential_mismatch(self):
        for field in ['before', 'after']:
            r = self.valid_structural_receipt()
            r['go'][1][field][0]['data_sha256'] = 'f'*64
            with self.subTest(field=field), self.assertRaisesRegex(AssertionError, 'encrypted-store differential mismatch'):
                self.validate(r)

    def test_tampered_recorded_go_exit_class_or_keybinding_digest_is_rejected(self):
        r = self.valid_structural_receipt(); r['go'][tui.CASES.index('uninitialized')]['exit_code'] = 99
        with self.assertRaises(AssertionError): self.validate(r)
        r = self.valid_structural_receipt(); r['go'][-1]['stdout_sha256'] = '0'*64
        with self.assertRaisesRegex(AssertionError, 'keybinding byte mismatch'): self.validate(r)

    def test_only_the_go_side_may_be_a_recording(self):
        r = self.valid_structural_receipt(); r['rust'][2]['replayed'] = True
        with self.assertRaisesRegex(AssertionError, 'recorded observation'): self.validate(r)
        r = self.valid_structural_receipt(); r['go'][2]['replayed'] = False
        with self.assertRaisesRegex(AssertionError, 'recorded observation'): self.validate(r)

    def test_recorded_go_capture_policy_and_identity_are_required(self):
        r = self.valid_structural_receipt(); r['go'][0]['capture_policy_checked_at_capture'] = False
        with self.assertRaisesRegex(AssertionError, 'recorded Go terminal capture'): self.validate(r)
        r = self.valid_structural_receipt(); r['go_observation']['oracle_commit'] = 'a'*40
        with self.assertRaisesRegex(AssertionError, 'recorded Go observation identity'): self.validate(r)
        r = self.valid_structural_receipt(); del r['go_observation']
        with self.assertRaises(KeyError): self.validate(r)

    def test_missing_or_foreign_observation_is_a_failure_never_a_skip(self):
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(tui.obs.MissingObservation): tui.load_observation(Path(raw)/'absent.json')
            foreign = Path(raw)/'foreign.json'
            foreign.write_text(json.dumps({'schema': 1, 'contract': 'other', 'goos': tui.obs.host_goos()}))
            with self.assertRaises(tui.obs.MissingObservation): tui.load_observation(foreign)
            wrong_oracle = Path(raw)/'oracle.json'
            wrong_oracle.write_text(json.dumps({'schema': 1, 'contract': tui.OBS_NAME, 'goos': tui.obs.host_goos(),
                                                'oracle_commit': 'e'*40, 'observations': {}, 'material': {}}))
            with self.assertRaises(tui.obs.MissingObservation): tui.load_observation(wrong_oracle)

    def test_committed_observation_for_this_host_is_complete_when_present(self):
        path = tui.obs.path(tui.OBS_NAME)
        if not path.is_file():
            if tui.obs.host_goos() == 'linux':
                self.fail(f'missing recorded Go observation {tui.obs.rel(path)}')
            self.skipTest('this OS runs the harness checks only; its Go observation needs a disposable host')
        document = tui.load_observation(path)
        rows = document['observations']['rows']
        self.assertEqual([row['case'] for row in rows], tui.CASES)
        self.assertEqual(set(document['material']['seeds']), {'0', '2'})
        for row in rows:
            self.assertIs(row['passed'], True)
            self.assertIs(row['capture_policy_checked_at_capture'], True)
            self.assertNotIn('capture_artifact', row)


class FixtureDriverTests(unittest.TestCase):
    """The Python console driver on a real private pty: never a clipboard, a credential store or Go."""

    def run_on_pty(self, argv, env, timeout=20, steer=None):
        import pty, select, subprocess
        master, slave = pty.openpty()
        child = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True)
        os.close(slave)
        end = time.monotonic() + timeout
        output = b''
        try:
            while time.monotonic() < end:
                ready, _, _ = select.select([master], [], [], 0.05)
                if ready:
                    try:
                        data = os.read(master, 4096)
                    except OSError:
                        break
                    if not data:
                        break
                    output += data
                if steer is not None:
                    steer()
                if child.poll() is not None and not ready:
                    break
            child.wait(timeout=5)
        finally:
            if child.poll() is None:
                child.kill(); child.wait()
            os.close(master)
        return child.returncode, output

    def launcher(self, base):
        return tui.build_driver(base)

    def test_console_wrapper_reports_exit_code_and_restored_modes_then_waits_for_release(self):
        with tempfile.TemporaryDirectory(prefix='tui-driver-') as raw:
            base = Path(raw); helper = self.launcher(base)
            cli = base/'cli'; cli.write_text('#!/bin/sh\nexit 3\n'); cli.chmod(0o755)
            receipt = base/'console.json'
            def steer():
                if receipt.is_file():
                    Path(str(receipt)+'.release').write_text('release\n')
            code, _ = self.run_on_pty([str(helper), '--root', str(base/'vault'), '--console-binary', str(cli),
                                       '--console-receipt', str(receipt)], dict(os.environ), steer=steer)
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(receipt.read_bytes()), {'exit_code': 3, 'input_restored': True, 'output_restored': True})
            before = json.loads(Path(str(receipt)+'.before').read_bytes())
            self.assertEqual(set(before), {'input', 'output'})
            self.assertEqual(set(before['input']), {'Iflag', 'Oflag', 'Cflag', 'Lflag', 'Ispeed', 'Ospeed', 'Cc'})

    def test_console_wrapper_detects_a_child_that_leaves_the_terminal_raw(self):
        with tempfile.TemporaryDirectory(prefix='tui-driver-') as raw:
            base = Path(raw); helper = self.launcher(base)
            cli = base/'cli'; cli.write_text('#!/bin/sh\nstty raw -echo\nexit 0\n'); cli.chmod(0o755)
            receipt = base/'console.json'
            def steer():
                if receipt.is_file():
                    Path(str(receipt)+'.release').write_text('release\n')
            code, _ = self.run_on_pty([str(helper), '--root', str(base/'vault'), '--console-binary', str(cli),
                                       '--console-receipt', str(receipt)], dict(os.environ), steer=steer)
            self.assertEqual(code, 0)
            observed = json.loads(receipt.read_bytes())
            self.assertIs(observed['input_restored'], False); self.assertIs(observed['output_restored'], False)

    def test_fixture_editor_modes_and_filtered_environment(self):
        for mode, expected_after, expected_code in [('invalid', b'invalid-json', 0), ('empty', b'', 0),
                                                    ('failure', b'{"data":null}', 23),
                                                    ('valid', b'public-tui-edited-secret-782a', 0)]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='tui-driver-') as raw:
                base = Path(raw); helper = self.launcher(base)
                editor = base/'fixture-editor'; editor.write_bytes(helper.read_bytes()); editor.chmod(0o755)
                ready, release, console = base/'ready.json', base/'release', base/'console.json.before'
                console.write_bytes(b'x')
                Path(str(editor)+'.editor.json').write_text(json.dumps({'Mode': mode, 'Ready': str(ready), 'Release': str(release),
                                                                       'Console': str(console)}))
                document = base/'document.json'; document.write_text('{"data":null}'); document.chmod(0o600)
                env = {k: v for k, v in os.environ.items() if not k.startswith(('SYMVAULT_', 'TUI_'))}
                def steer():
                    if ready.is_file():
                        release.write_text('release\n')
                code, output = self.run_on_pty([str(editor), str(document)], env, steer=steer)
                self.assertEqual(code, expected_code)
                self.assertIn(b'TUI_EDITOR_READY', output)
                observed = json.loads(ready.read_bytes())
                self.assertEqual({k: observed[k] for k in ['input_is_terminal', 'output_is_terminal', 'mode', 'document_bytes',
                                                           'environment_filtered']},
                                 {'input_is_terminal': True, 'output_is_terminal': True, 'mode': 0o600, 'document_bytes': 13,
                                  'environment_filtered': True})
                self.assertIs(observed['foreground_terminal_restored'], False)  # the .before stand-in is not this terminal's state
                self.assertIn(expected_after, document.read_bytes())

    def test_snapshot_forwards_to_the_rust_tool_only(self):
        with tempfile.TemporaryDirectory(prefix='tui-driver-') as raw:
            base = Path(raw); helper = self.launcher(base)
            tool = base/'tui-snapshot'; tool.write_text('#!/bin/sh\necho "[\\"$*\\"]"\n'); tool.chmod(0o755)
            env = dict(os.environ, TUI_SNAPSHOT_BIN=str(tool))
            out = tui.checked([helper, '--root', '/vault', '--snapshot', '--config-receipt', '/receipt.json'], env=env)
            self.assertEqual(json.loads(out), ['--root /vault --config-receipt /receipt.json'])
            env.pop('TUI_SNAPSHOT_BIN')
            with self.assertRaises(AssertionError): tui.checked([helper, '--root', '/vault', '--snapshot'], env=env)
            with self.assertRaises(AssertionError): tui.checked([helper, '--root', '/vault'], env=env)  # seeding is a recording


class FakeWin32:
    """Scripted user32/kernel32 stand-in; records call order. No real Win32."""
    def __init__(self, opens, closes=(True,), text='secret', handle=1, pointer=2, error=0):
        self.opens, self.closes = list(opens), list(closes)
        self.text, self.handle, self.pointer, self.error = text, handle, pointer, error
        self.calls = []
        self.OpenClipboard = lambda hwnd: self._pop('open', self.opens)
        self.CloseClipboard = lambda: self._pop('close', self.closes)
        self.GetClipboardData = lambda fmt: self._log('get', self.handle)
        self.GlobalLock = lambda handle: self._log('lock', self.pointer)
        self.GlobalUnlock = lambda handle: self._log('unlock', True)
    def _log(self, name, value):
        self.calls.append(name)
        return value
    def _pop(self, name, queue):
        self.calls.append(name)
        ok, error = queue.pop(0) if isinstance(queue[0], tuple) else (queue.pop(0), 0)
        self.error = error
        return ok
    def read(self):
        return tui.windows_clipboard_once(self, self, lambda: self.error, lambda pointer: self.text)


class WindowsClipboardTests(unittest.TestCase):
    def test_open_denied_is_busy_then_retry_succeeds_without_close(self):
        fake = FakeWin32(opens=[(False, tui.ERROR_ACCESS_DENIED), True])
        with self.assertRaises(tui.ClipboardBusy):
            fake.read()
        self.assertEqual(fake.calls, ['open'], 'CloseClipboard must not follow a failed OpenClipboard')
        fake.calls.clear()
        self.assertEqual(fake.read(), b'secret')
        self.assertEqual(fake.calls, ['open', 'get', 'lock', 'unlock', 'close'])

    def test_open_other_error_is_real_failure_with_code(self):
        fake = FakeWin32(opens=[(False, 1400)])
        with self.assertRaises(AssertionError) as caught:
            fake.read()
        self.assertNotIsInstance(caught.exception, tui.ClipboardBusy)
        self.assertEqual(caught.exception.args[0], ('native clipboard did not open', 1400))
        self.assertEqual(fake.calls, ['open'])

    def test_close_only_after_successful_open_and_empty_clipboard(self):
        fake = FakeWin32(opens=[True], handle=0)
        self.assertEqual(fake.read(), b'')
        self.assertEqual(fake.calls, ['open', 'get', 'close'])

    def test_close_failure_surfaces_error_code(self):
        fake = FakeWin32(opens=[True], closes=[(False, 87)])
        with self.assertRaises(AssertionError) as caught:
            fake.read()
        self.assertNotIsInstance(caught.exception, tui.ClipboardBusy)
        self.assertEqual(caught.exception.args[0], ('native clipboard did not close', 87))

    def test_close_not_open_is_retryable_busy(self):
        fake = FakeWin32(opens=[True], closes=[(False, tui.ERROR_CLIPBOARD_NOT_OPEN)])
        with self.assertRaises(tui.ClipboardBusy):
            fake.read()

    def test_primary_failure_is_not_masked_by_close(self):
        fake = FakeWin32(opens=[True], closes=[(False, 87)], pointer=0, error=6)
        with self.assertRaises(AssertionError) as caught:
            fake.read()
        self.assertEqual(caught.exception.args[0][0], 'native clipboard handle did not lock')
        self.assertEqual(fake.calls, ['open', 'get', 'lock', 'close'])

    def test_clipboard_retries_busy_then_reads(self):
        fake = FakeWin32(opens=[(False, tui.ERROR_ACCESS_DENIED), True])
        with self.fake_windows(fake):
            self.assertEqual(tui.clipboard({}), b'secret')
        self.assertEqual(fake.calls.count('open'), 2)

    def test_clipboard_zero_timeout_raises_busy_immediately(self):
        fake = FakeWin32(opens=[(False, tui.ERROR_ACCESS_DENIED)])
        with self.fake_windows(fake), self.assertRaises(tui.ClipboardBusy):
            tui.clipboard({}, busy_timeout=0)
        self.assertEqual(fake.calls, ['open'])

    def test_clipboard_persistent_busy_fails_after_timeout(self):
        fake = FakeWin32(opens=[(False, tui.ERROR_ACCESS_DENIED)]*2000000)
        with self.fake_windows(fake), self.assertRaises(tui.ClipboardBusy) as caught:
            tui.clipboard({}, busy_timeout=0.05)
        self.assertEqual(caught.exception.args[0][0], 'native clipboard remained busy')

    def fake_windows(self, fake):
        import contextlib, sys, types
        wintypes = types.SimpleNamespace(HWND=object, BOOL=object, UINT=object, HANDLE=object, HGLOBAL=object)
        stub = types.SimpleNamespace(
            WinDLL=lambda name, use_last_error=False: fake, c_void_p=object, wintypes=wintypes,
            get_last_error=lambda: fake.error, wstring_at=lambda pointer: fake.text)
        @contextlib.contextmanager
        def manager():
            with patch.object(tui.platform, 'system', return_value='Windows'), \
                 patch.dict(sys.modules, {'ctypes': stub, 'ctypes.wintypes': wintypes}), \
                 patch.object(tui.time, 'sleep'):
                # `from ctypes import wintypes` resolves the attribute on the stub.
                yield
        return manager()

    def test_wait_treats_busy_as_not_yet_satisfied(self):
        browser = object.__new__(tui.Browser)
        browser.pump = lambda seconds=0.12: None
        browser.alive = lambda: True
        browser.view = lambda: ''
        results = [tui.ClipboardBusy(('busy', 5)), b'', ]
        def poll():
            result = results.pop(0)
            if isinstance(result, Exception): raise result
            return not result
        browser.wait(poll, 'expiry', timeout=5)
        self.assertEqual(results, [])

    def test_wait_busy_is_not_empty_or_populated(self):
        browser = object.__new__(tui.Browser)
        browser.pump = lambda seconds=0.12: time.sleep(0.01)
        browser.alive = lambda: True
        browser.view = lambda: ''
        def busy(): raise tui.ClipboardBusy(('busy', 5))
        with self.assertRaises(AssertionError) as caught:
            browser.wait(lambda: not busy(), 'actual native clipboard expiry', timeout=0.05)
        self.assertIn('last clipboard state=', str(caught.exception))

    def test_wait_other_predicates_and_errors_unchanged(self):
        browser = object.__new__(tui.Browser)
        browser.pump = lambda seconds=0.12: None
        browser.alive = lambda: True
        browser.view = lambda: ''
        calls = []
        browser.wait(lambda: calls.append(1) or len(calls) == 3, 'plain')
        self.assertEqual(len(calls), 3)
        def real(): raise AssertionError('real failure')
        with self.assertRaisesRegex(AssertionError, 'real failure'):
            browser.wait(real, 'x')


class DarwinSourceRebuildTests(unittest.TestCase):
    """Darwin links LC_UUID from the output path: the rebuild must reuse the
    binary's own absolute target path, stay byte-exact and restore the original."""

    exe_name = 'symvault'

    def setUp(self):
        # The binary name is os.name-dependent (symvault.exe on Windows); the
        # Darwin branch is exercised on every host with either name.
        patcher = patch.object(tui, 'rust_exe_name', return_value=self.exe_name)
        patcher.start(); self.addCleanup(patcher.stop)

    def run_rebuild(self, built, fail=False, layout=True):
        real_checked = tui.checked
        seen = {}
        with tempfile.TemporaryDirectory(prefix='tui-darwin-rebuild-') as raw:
            base = Path(raw)
            target = base/'target/tui-candidate'
            (target/'debug').mkdir(parents=True)
            binary = target/'debug'/(self.exe_name if layout else 'other')
            binary.write_bytes(b'original-bytes')
            (target/'debug/deps-marker').write_bytes(b'kept')

            def fake(argv, **kwargs):
                if argv[:2] != ['cargo', 'build']:
                    return real_checked(argv, **kwargs)
                seen['target'] = Path(kwargs['env']['CARGO_TARGET_DIR'])
                seen['original_moved_aside'] = not binary.exists()
                if fail:
                    raise RuntimeError('simulated build failure')
                (seen['target']/'debug').mkdir(parents=True)
                (seen['target']/'debug'/self.exe_name).write_bytes(built)
            receipt = {}
            error = None
            with patch.object(tui.platform, 'system', return_value='Darwin'), \
                    patch.object(tui, 'checked', side_effect=fake):
                try:
                    tui.build_source_bound_rust(binary.resolve(), base/'unused', receipt)
                except (AssertionError, RuntimeError) as caught:
                    error = caught
            restored = (binary.read_bytes() == b'original-bytes'
                        and (target/'debug/deps-marker').read_bytes() == b'kept')
            leftovers = sorted(p.name for p in target.parent.iterdir())
            return seen, receipt, error, restored, leftovers, target.resolve()

    def test_identical_bytes_at_the_same_target_path_verify_and_restore(self):
        seen, receipt, error, restored, leftovers, target = self.run_rebuild(b'original-bytes')
        self.assertIsNone(error)
        self.assertEqual(seen['target'], target)
        self.assertTrue(seen['original_moved_aside'])
        self.assertIs(receipt['binary_source_verified'], True)
        self.assertEqual(receipt['rebuilt_rust_executable_sha256'], hashlib.sha256(b'original-bytes').hexdigest())
        self.assertTrue(restored); self.assertEqual(leftovers, ['tui-candidate'])

    def test_different_bytes_still_fail_exactly_and_restore_the_original(self):
        seen, receipt, error, restored, leftovers, _ = self.run_rebuild(b'original-bytes-with-other-uuid')
        self.assertIsInstance(error, AssertionError); self.assertEqual(str(error), 'source/binary mismatch')
        self.assertNotIn('binary_source_verified', receipt)
        self.assertEqual(receipt['rebuilt_rust_executable_sha256'],
                         hashlib.sha256(b'original-bytes-with-other-uuid').hexdigest())
        self.assertTrue(restored); self.assertEqual(leftovers, ['tui-candidate'])

    def test_build_failure_restores_the_original_target(self):
        _, receipt, error, restored, leftovers, _ = self.run_rebuild(b'', fail=True)
        self.assertIsInstance(error, RuntimeError); self.assertNotIn('binary_source_verified', receipt)
        self.assertTrue(restored); self.assertEqual(leftovers, ['tui-candidate'])

    def test_binary_outside_a_cargo_layout_is_rejected_before_any_move(self):
        _, receipt, error, restored, leftovers, _ = self.run_rebuild(b'', layout=False)
        self.assertIsInstance(error, AssertionError); self.assertNotIn('binary_source_verified', receipt)
        self.assertTrue(restored); self.assertEqual(leftovers, ['tui-candidate'])


class DarwinSourceRebuildWindowsNameTests(DarwinSourceRebuildTests):
    """Same Darwin-branch contract with the .exe binary name."""
    exe_name = 'symvault.exe'


class NonDarwinSourceRebuildTests(unittest.TestCase):
    """Linux/Windows keep the pre-#1409 behaviour: rebuild into a separate
    run-owned target, never touch the binary's own target tree."""

    def run_rebuild(self, system, exe_name, built):
        real_checked = tui.checked
        seen = {}
        with tempfile.TemporaryDirectory(prefix='tui-nondarwin-rebuild-') as raw:
            base = Path(raw)
            target = base/'target/tui-candidate'
            (target/'debug').mkdir(parents=True)
            binary = target/'debug'/exe_name
            binary.write_bytes(b'original-bytes')

            def fake(argv, **kwargs):
                if argv[:2] != ['cargo', 'build']:
                    return real_checked(argv, **kwargs)
                seen['target'] = Path(kwargs['env']['CARGO_TARGET_DIR'])
                seen['original_untouched'] = binary.read_bytes() == b'original-bytes'
                (seen['target']/'debug').mkdir(parents=True)
                (seen['target']/'debug'/exe_name).write_bytes(built)
            receipt = {}
            error = None
            with patch.object(tui.platform, 'system', return_value=system), \
                    patch.object(tui, 'rust_exe_name', return_value=exe_name), \
                    patch.object(tui, 'checked', side_effect=fake):
                try:
                    tui.build_source_bound_rust(binary, base, receipt)
                except AssertionError as caught:
                    error = caught
            return seen, receipt, error, base/'rust-source-build', binary.read_bytes(), sorted(p.name for p in target.parent.iterdir())

    def test_separate_target_and_exact_bytes_for_each_platform_name(self):
        for system, exe_name in [('Linux', 'symvault'), ('Windows', 'symvault.exe')]:
            with self.subTest(system=system):
                seen, receipt, error, expected, original, leftovers = self.run_rebuild(system, exe_name, b'original-bytes')
                self.assertIsNone(error)
                self.assertEqual(seen['target'], expected); self.assertTrue(seen['original_untouched'])
                self.assertIs(receipt['binary_source_verified'], True)
                self.assertEqual(original, b'original-bytes'); self.assertEqual(leftovers, ['tui-candidate'])

    def test_different_bytes_fail_exactly_for_each_platform_name(self):
        for system, exe_name in [('Linux', 'symvault'), ('Windows', 'symvault.exe')]:
            with self.subTest(system=system):
                _, receipt, error, _, original, _ = self.run_rebuild(system, exe_name, b'other')
                self.assertIsInstance(error, AssertionError); self.assertEqual(str(error), 'source/binary mismatch')
                self.assertNotIn('binary_source_verified', receipt); self.assertEqual(original, b'original-bytes')


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
