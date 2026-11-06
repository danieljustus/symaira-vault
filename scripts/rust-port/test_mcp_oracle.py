#!/usr/bin/env python3
"""Fail-closed controls of the Go-free MCP fixture replay (mcp_fixture_contract.py) and the oracle identity module.

Constructed metadata here is not native evidence; the positive controls replay the real committed observation.
"""
import base64
import copy
import gzip
import hashlib
import io
import json
import contextlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import mcp_fixture_contract as fixtures
import mcp_oracle as oracle
import mcp_process_contract as process


def run_replay(output, *extra, load=None):
    argv = ['mcp_fixture_contract.py', '--approval-generator', 'approval-lifetime-v1', '--output', str(output), *extra]
    stdout = io.StringIO()
    with patch.object(sys, 'argv', argv), contextlib.redirect_stdout(stdout):
        if load is None:
            fixtures.main()
        else:
            with patch.object(fixtures, 'load_go_observations', side_effect=load):
                fixtures.main()
    return stdout.getvalue()


class OracleIdentity(unittest.TestCase):
    def test_pins_are_full_lowercase_commits(self):
        for pin in (oracle.HISTORICAL, oracle.ORDERED, fixtures.PRODUCT_SOURCE, fixtures.FIXTURE_BASE):
            self.assertRegex(pin, r'^[0-9a-f]{40}$')
        self.assertEqual(oracle.CONTRACT, 'mcp-anomaly-ordered-v1')

    def test_tool_environment_drops_ambient_credentials(self):
        env = {'PATH': '/bin', 'HOME': '/h', 'GITHUB_TOKEN': 'x', 'SSH_AUTH_SOCK': '/s', 'HTTPS_PROXY': 'p', 'LANG': 'C',
               'GOFLAGS': '-p=2', 'GOCACHE': '/c'}
        self.assertEqual(oracle.tool_environment(env), {'PATH': '/bin', 'HOME': '/h', 'LANG': 'C'})

    def test_module_has_no_toolchain_or_git_entry_points(self):
        for name in ('pinned_go', 'validate_reference', 'git'):
            self.assertFalse(hasattr(oracle, name), name)


class FixtureAnchors(unittest.TestCase):
    def test_real_fixture_and_generator_anchors(self):
        fixtures.fixture_anchor(fixtures.ROOT, [*fixtures.FIXTURES, *fixtures.generator_paths()])
        self.assertEqual(len(fixtures.FIXTURES), 26)
        self.assertEqual(len(fixtures.archived_inputs()), fixtures.ARCHIVED_COUNT)
        # the generator sources that left with the Go tree are not claimed to be verified
        self.assertTrue(all(fixtures.held(fixtures.ROOT, name) for name in fixtures.generator_paths()))
        self.assertTrue(any(not fixtures.held(fixtures.ROOT, name) for name in json.loads(fixtures.ANCHOR.read_bytes())['files']))

    def test_frozen_fixture_cannot_self_baseline(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            name = 'testdata/port/mcp/tools-call.json'
            (root/name).parent.mkdir(parents=True)
            (root/name).write_bytes((fixtures.ROOT/name).read_bytes())
            fixtures.fixture_anchor(root, [name])
            changed = json.loads((root/name).read_bytes())
            changed['cases'][0]['output'][0]['jsonrpc'] = '9.0'
            (root/name).write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, 'anchor drift'):
                fixtures.fixture_anchor(root, [name])

    def test_unanchored_and_escaping_inputs_are_rejected(self):
        with self.assertRaises(ValueError):
            fixtures.fixture_anchor(fixtures.ROOT, ['testdata/port/mcp/not-anchored.json'])
        for bad in ('../x', '/etc/passwd', 'a\\b', 'a/../b', None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                fixtures.confined_file(fixtures.ROOT, bad)

    def test_approval_generator_source_is_pinned_and_carries_the_lifetime_close(self):
        data = fixtures.approval_generator_source(fixtures.ROOT)
        self.assertEqual(hashlib.sha256(data).hexdigest(), fixtures.APPROVAL_SHA256)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root/fixtures.APPROVAL_SOURCE
            target.parent.mkdir(parents=True)
            target.write_bytes(data + b'// edited\n')
            with self.assertRaisesRegex(ValueError, 'unreviewed'):
                fixtures.approval_generator_source(root)


class FixtureSemantics(unittest.TestCase):
    def test_fixture_semantics_types_inventory_and_reference_fail_closed(self):
        old = json.loads((fixtures.ROOT/'testdata/port/mcp/tools-call.json').read_bytes())
        new = copy.deepcopy(old)
        new['oracle']['commit_sha'] = oracle.ORDERED
        fixtures.compare_fixture(old, new, 4)  # structural positive control first
        fixtures.compare_fixture(old, dict(new, oracle=dict(new['oracle'], commit_sha=oracle.HISTORICAL)), 4, oracle.HISTORICAL)

        def changes(value):
            yield ('missing-null', lambda: value['cases'][0].pop('output'))
            yield ('extra-case', lambda: value['cases'].append(copy.deepcopy(value['cases'][0])))
            yield ('changed-response', lambda: value['cases'][0]['output'][0].update(jsonrpc='9.0'))
            yield ('type-substitution', lambda: value['cases'][0]['output'][0].update(id=True))
            yield ('source-inventory', lambda: value['oracle']['source_files'].pop())
            yield ('oracle', lambda: value['oracle'].update(commit_sha=oracle.HISTORICAL))
        for index in range(6):
            value = copy.deepcopy(new)
            name, mutate = list(changes(value))[index]
            mutate()
            with self.subTest(name=name), self.assertRaises(ValueError):
                fixtures.compare_fixture(old, value, 4)


class ReplayControls(unittest.TestCase):
    def test_replay_passes_without_go_git_or_any_child_process(self):
        import subprocess
        with tempfile.TemporaryDirectory() as raw, \
                patch.object(subprocess, 'Popen', side_effect=AssertionError('no child process may start')):
            out = run_replay(Path(raw) / 'run')
            self.assertIn('PASS recorded approval-lifetime-v1 generator executions', out)
            receipt = json.loads((Path(raw) / 'run/receipt.json').read_bytes())
        self.assertTrue(receipt['passed'])
        self.assertEqual([lane['lane'] for lane in receipt['lanes']], ['historical-approval-lifetime-v1', 'corrected-approval-lifetime-v1'])
        self.assertTrue(receipt['product_source_replay']['passed'] and receipt['product_replay']['passed'])
        self.assertTrue(all(lane['replayed_from_go_observations'] for lane in receipt['lanes']))

    def test_arguments_without_a_recording_are_refused_not_skipped(self):
        # Only the full approval-lifetime-v1 gate was recorded: a subset or the original mode has no observation.
        for extra, base in (('--generator', ['tools-call']), ('--approval-generator', ['original'])):
            with tempfile.TemporaryDirectory() as raw:
                argv = ['mcp_fixture_contract.py', '--output', str(Path(raw) / 'run')]
                argv += ['--generator', 'tools-call'] if extra == '--generator' else ['--approval-generator', 'original']
                with self.subTest(extra=extra), patch.object(sys, 'argv', argv), contextlib.redirect_stdout(io.StringIO()), \
                        self.assertRaisesRegex(AssertionError, 'observation contract args'):
                    fixtures.main()

    def mutated(self, mutate):
        real = process.load_go_observations

        def load(*args, **kwargs):
            document = real(*args, **kwargs)
            mutate(document['data'])
            return document
        return load

    def test_a_failed_recorded_step_fails_the_replay(self):
        def mutate(data):
            data['lanes']['corrected-approval-lifetime-v1']['steps'][0]['passed'] = False
        with tempfile.TemporaryDirectory() as raw, self.assertRaisesRegex(ValueError, 'recorded Go step failed'):
            run_replay(Path(raw) / 'run', load=self.mutated(mutate))

    def test_a_corrupt_recorded_capture_fails_the_replay(self):
        def mutate(data):
            entry = data['lanes']['corrected-approval-lifetime-v1']['captures']['testdata/port/mcp/tools-call.json']
            entry['sha256'] = '0' * 64
        with tempfile.TemporaryDirectory() as raw, self.assertRaisesRegex(ValueError, 'corrupt'):
            run_replay(Path(raw) / 'run', load=self.mutated(mutate))

    def test_a_drifted_corrected_capture_fails_the_replay(self):
        name = 'testdata/port/mcp/tools-call.json'

        def mutate(data):
            entry = data['lanes']['corrected-approval-lifetime-v1']['captures'][name]
            value = json.loads(gzip.decompress(base64.b64decode(entry['gzip_base64'])))
            value['cases'][0]['output'][0]['jsonrpc'] = '9.0'
            raw = json.dumps(value).encode()
            entry.update(sha256=hashlib.sha256(raw).hexdigest(), gzip_base64=base64.b64encode(gzip.compress(raw)).decode())
        with tempfile.TemporaryDirectory() as raw, self.assertRaisesRegex(ValueError, 'fixture value drift'):
            run_replay(Path(raw) / 'run', load=self.mutated(mutate))

    def test_a_changed_historical_digest_fails_the_replay(self):
        def mutate(data):
            data['lanes']['historical-approval-lifetime-v1']['captures']['testdata/port/mcp/tools-call.json']['sha256'] = '1' * 64
        with tempfile.TemporaryDirectory() as raw, self.assertRaisesRegex(ValueError, 'differs from the anchored bytes'):
            run_replay(Path(raw) / 'run', load=self.mutated(mutate))

    def test_a_lane_bound_to_the_wrong_commit_fails_the_replay(self):
        name = 'testdata/port/mcp/tools-call.json'

        def mutate(data):
            lanes = data['lanes']
            lanes['corrected-approval-lifetime-v1']['captures'][name] = copy.deepcopy(
                lanes['historical-approval-lifetime-v1']['captures'][name])
            lanes['corrected-approval-lifetime-v1']['captures'][name].setdefault('gzip_base64', base64.b64encode(
                gzip.compress((fixtures.ROOT/name).read_bytes())).decode())
        with tempfile.TemporaryDirectory() as raw, self.assertRaisesRegex(ValueError, 'not bound to its lane oracle'):
            run_replay(Path(raw) / 'run', load=self.mutated(mutate))

    def test_a_missing_or_foreign_observation_fails_instead_of_skipping(self):
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(AssertionError):
                process.load_go_observations(fixtures.OBSERVATION, dict(approval_generator='original', generator='tools-call'))
            saved = process.GO_OBS_DIR
            process.GO_OBS_DIR = Path(raw)
            try:
                with self.assertRaises(SystemExit):
                    process.load_go_observations(fixtures.OBSERVATION, dict(approval_generator='approval-lifetime-v1', generator=None))
            finally:
                process.GO_OBS_DIR = saved


if __name__ == '__main__':
    unittest.main()
