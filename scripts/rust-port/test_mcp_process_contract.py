#!/usr/bin/env python3
"""Focused controls for native MCP stdout record parsing."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

CONTRACT_PATH = Path(__file__).with_name('mcp_process_contract.py')
SPEC = importlib.util.spec_from_file_location('mcp_process_contract', CONTRACT_PATH)
assert SPEC is not None
CONTRACT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(CONTRACT)


class ProtocolBytesTests(unittest.TestCase):
    def parse(self, stdout, stderr=b''):
        result = SimpleNamespace(stdout=stdout, stderr=stderr)
        return CONTRACT.protocol_bytes(
            result, Path('__HOME__'), 'protocol-bytes-unit-control', 'rust', 'fixture')

    @staticmethod
    def frame(frame_id, text):
        value = {'jsonrpc': '2.0', 'id': frame_id, 'result': {'text': text}}
        return (json.dumps(value, ensure_ascii=False) + '\n').encode('utf-8')

    def test_ordinary_ascii_frame(self):
        raw, stderr, frames = self.parse(self.frame(1, 'ordinary'))
        self.assertEqual(raw, '{"jsonrpc": "2.0", "id": 1, "result": {"text": "ordinary"}}\n')
        self.assertEqual(stderr, '')
        self.assertEqual([frame['id'] for frame in frames], [1])

    def test_literal_line_separator_inside_json_string(self):
        _, _, frames = self.parse(self.frame(2, 'before\u2028after'))
        self.assertEqual(frames[0]['result']['text'], 'before\u2028after')

    def test_literal_paragraph_separator_inside_json_string(self):
        _, _, frames = self.parse(self.frame(3, 'before\u2029after'))
        self.assertEqual(frames[0]['result']['text'], 'before\u2029after')

    def test_two_lf_delimited_records_keep_unicode_values_and_count(self):
        stdout = self.frame(4, 'line\u2028value') + self.frame(5, 'paragraph\u2029value')
        _, _, frames = self.parse(stdout)
        self.assertEqual([frame['id'] for frame in frames], [4, 5])
        self.assertEqual(frames[0]['result']['text'], 'line\u2028value')
        self.assertEqual(frames[1]['result']['text'], 'paragraph\u2029value')

    def test_invalid_and_truncated_utf8_are_rejected_strictly(self):
        for invalid in (b'\xff', b'\xe2\x80'):
            with self.subTest(invalid=invalid):
                with self.assertRaises(UnicodeDecodeError):
                    self.parse(b'{"jsonrpc":"2.0","id":6,"result":{"text":"' + invalid + b'"}}\n')

    def test_missing_final_lf_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'unterminated stdout response'):
            self.parse(b'{"jsonrpc":"2.0","id":7,"result":{}}')

    def test_non_protocol_stdout_and_canary_stderr_remain_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'non-protocol stdout'):
            self.parse(b'[]\n')
        with self.assertRaisesRegex(AssertionError, 'credential in stderr'):
            self.parse(self.frame(8, 'ordinary'), b'public-mcp-secret-6af2\n')


def _row(**overrides):
    row = {'mode': 'stdio', 'state': 'idle', 'signal': 'SIGTERM', 'exit_code': 0, 'stdout': '',
           'stderr': '', 'delta': {'removed': [], 'added': [], 'changed': []}, 'orphans': [],
           'final_raw': {'vault/.lock': {'kind': 'file', 'bytes': 0, 'sha256': 'x'},
                         'vault/config.yaml': {'kind': 'file', 'bytes': 1, 'sha256': 'go'}}}
    row.update(overrides)
    return row


def _rust_twin(go, **overrides):
    twin = json.loads(json.dumps(go))
    twin['final_raw']['vault/config.yaml']['sha256'] = 'rust'   # pinned startup-only difference
    twin.update(overrides)
    return twin


class SignalNormalisationTests(unittest.TestCase):
    def test_only_pids_ports_timestamps_and_temp_paths_are_normalised(self):
        home = Path('/tmp/h')
        text = ('2026/10/21 18:14:29 WARN x remote=127.0.0.1:58882 pid=4242 at /tmp/h/vault\n'
                'MCP server listening on 127.0.0.1:60727\n')
        self.assertEqual(
            CONTRACT.normalise_process_text(text, home),
            '<TIMESTAMP> WARN x remote=127.0.0.1:<PORT> pid=<PID> at <HOME>/vault\n'
            'MCP server listening on 127.0.0.1:<PORT>\n')
        self.assertEqual(CONTRACT.normalise_process_text('exit status 7 bind 0.0.0.0:1', home),
                         'exit status 7 bind 0.0.0.0:1')

    def test_random_files_compare_by_existence_only(self):
        a = {'vault/mcp-server.key': {'kind': 'file', 'bytes': 1, 'sha256': 'a'},
             'vault/identity.age': {'kind': 'file', 'bytes': 1, 'sha256': 'a'}}
        b = json.loads(json.dumps(a))
        b['vault/mcp-server.key']['sha256'] = 'b'
        self.assertEqual(CONTRACT.comparable(a)['vault/mcp-server.key'], CONTRACT.comparable(b)['vault/mcp-server.key'])
        b['vault/identity.age']['sha256'] = 'b'
        self.assertNotEqual(CONTRACT.comparable(a), CONTRACT.comparable(b))

    def test_delta_reports_removed_added_and_changed(self):
        before = {'k': {'kind': 'file', 'sha256': '1'}, 'gone': {'kind': 'file', 'sha256': '1'}}
        after = {'k': {'kind': 'file', 'sha256': '2'}, 'new': {'kind': 'dir'}}
        self.assertEqual(CONTRACT.snapshot_delta(before, after),
                         {'removed': ['gone'], 'added': ['new'], 'changed': ['k']})


class SignalComparisonNegativeControls(unittest.TestCase):
    def setUp(self):
        self.go = _row()

    def test_identical_rows_with_only_the_pinned_startup_difference_pass(self):
        CONTRACT.compare_signal_rows(self.go, _rust_twin(self.go))

    def test_exit_code_mapping_mutation_is_rejected(self):
        for mutated in (1, -15, -2, 143):
            with self.subTest(exit_code=mutated), self.assertRaisesRegex(AssertionError, 'exit_code'):
                CONTRACT.compare_signal_rows(self.go, _rust_twin(self.go, exit_code=mutated))

    def test_stdout_stderr_and_side_effect_mutations_are_rejected(self):
        mutations = {'stdout': {'stdout': '{}\n'}, 'stderr': {'stderr': 'x'},
                     'delta': {'delta': {'removed': ['vault/.runtime-port'], 'added': [], 'changed': []}},
                     'orphans': {'orphans': [123]}}
        for field, mutation in mutations.items():
            with self.subTest(field=field), self.assertRaisesRegex(AssertionError, field):
                CONTRACT.compare_signal_rows(self.go, _rust_twin(self.go, **mutation))

    def test_unpinned_startup_differences_are_rejected(self):
        extra = _rust_twin(self.go)
        extra['final_raw']['vault/stray.tmp'] = {'kind': 'file', 'bytes': 0, 'sha256': 'x'}
        with self.assertRaisesRegex(AssertionError, 'unpinned startup difference'):
            CONTRACT.compare_signal_rows(self.go, extra)
        missing = _rust_twin(self.go)
        missing['final_raw']['vault/config.yaml']['sha256'] = 'go'   # difference vanished -> stale pin
        with self.assertRaisesRegex(AssertionError, 'unpinned startup difference'):
            CONTRACT.compare_signal_rows(self.go, missing)


@unittest.skipIf(os.name == 'nt', 'the signal engine uses Unix process groups')
class SyntheticSignalEngineControls(unittest.TestCase):
    """The engine itself, driven by tiny synthetic stdio servers (not product evidence)."""
    SERVER = """#!{python}
import os, signal, subprocess, sys, time
from pathlib import Path
mode = {mode!r}
Path('vault').mkdir(exist_ok=True)
if mode == 'orphan':
    subprocess.Popen(['sleep', '30'])
def handler(number, frame):
    if mode == 'die':
        signal.signal(number, signal.SIG_DFL)
        os.kill(os.getpid(), number)
    sys.exit(0)
if mode != 'die':
    signal.signal(signal.SIGTERM, handler)
Path('vault/audit-fixture.log').write_bytes(b'')
sys.stdin.readline()
time.sleep(30)
"""

    def run_server(self, mode):
        with tempfile.TemporaryDirectory(prefix='synthetic-signal-') as raw:
            home = Path(raw)
            (home / 'vault').mkdir()
            script = home / 'server.py'
            script.write_text(self.SERVER.format(python=sys.executable, mode=mode), encoding='utf-8')
            script.chmod(script.stat().st_mode | stat.S_IXUSR)
            return CONTRACT.run_signal_case(script, home, dict(os.environ), 'stdio', 'idle',
                                            'SIGTERM', signal.SIGTERM)

    def test_clean_exit_zero_is_observed(self):
        row = self.run_server('exit')
        self.assertEqual((row['exit_code'], row['orphans'], row['stdout'], row['stderr']), (0, [], '', ''))

    def test_death_by_the_signal_is_observed_as_a_negative_status(self):
        self.assertEqual(self.run_server('die')['exit_code'], -signal.SIGTERM)

    def test_orphaned_group_member_fails_the_case_and_is_reaped(self):
        with self.assertRaisesRegex(AssertionError, 'orphaned process group members'):
            self.run_server('orphan')

    def test_group_members_sees_only_the_owned_group(self):
        child = subprocess.Popen(['sleep', '30'], start_new_session=True)
        try:
            self.assertEqual(CONTRACT.group_members(child.pid), [child.pid])
        finally:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        self.assertEqual(CONTRACT.group_members(child.pid), [])


class DiagnosticEvidenceControls(unittest.TestCase):
    """The narrow anomaly-diagnostic stderr allowance (rust-mcp-process.yml)."""

    PLAIN = ('2026/10/05 01:24:19 WARN anomaly detected type=off_hours severity=low agent=fixture '
             'description="Entry access during off-hours by agent fixture"')
    CONTEXTUAL = PLAIN.replace(' description=', ' path=public/fixture request_id=0000000000000001 description=')

    @staticmethod
    def check(line, implementation='go'):
        CONTRACT.protocol_bytes(SimpleNamespace(stdout=b'', stderr=(line + '\n').encode()), Path('__HOME__'),
                                'diagnostic-unit-control', implementation, 'fixture')

    def test_accepted_diagnostics(self):
        for line in [self.PLAIN, self.CONTEXTUAL, self.CONTEXTUAL.replace('public/fixture', 'public/missing')]:
            with self.subTest(line=line):
                self.check(line)

    def test_rust_emits_the_same_off_hours_diagnostics_as_go(self):
        # PLATFORM-002: the Rust detector writes Go's line; this used to be rejected.
        for line in [self.PLAIN, self.CONTEXTUAL]:
            with self.subTest(line=line):
                self.check(line, 'rust')

    def test_rejected_diagnostics(self):
        rejected = [
            (self.CONTEXTUAL.replace('severity=low', 'severity=high'), 'go'),
            (self.CONTEXTUAL.replace('type=off_hours', 'type=tool_chain'), 'go'),
            (self.CONTEXTUAL.replace('agent=fixture', 'agent=other'), 'go'),
            (self.CONTEXTUAL.replace('public/fixture', 'private/other'), 'go'),
            (self.CONTEXTUAL.replace('0000000000000001', 'invalid'), 'go'),
            (self.PLAIN + '\naudit log write failed err="audit logger is closed"', 'go'),
            (self.CONTEXTUAL.replace('type=off_hours', 'type=tool_chain'), 'rust'),
            (self.CONTEXTUAL.replace('severity=low', 'severity=high'), 'rust'),
            (self.PLAIN + '\naudit log write failed err="audit logger is closed"', 'rust'),
            (self.CONTEXTUAL, 'java'),
        ]
        for line, implementation in rejected:
            with self.subTest(line=line, implementation=implementation):
                with self.assertRaises(AssertionError):
                    self.check(line, implementation)


class ReceiptFinalizationControls(unittest.TestCase):
    """The post-output receipt finalization of the actual main() (rust-mcp-process.yml)."""

    def test_finalization_records_a_dirty_tree_after_output(self):
        import ast
        tree = ast.parse(CONTRACT_PATH.read_text())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        final = next(n for n in main.body if isinstance(n, ast.Try)).finalbody
        code = compile(ast.Module(body=final, type_ignores=[]), '<actual receipt finalization>', 'exec')
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        for location, expected_clean in [('target/control.json', True), ('root-control.json', False)]:
            with self.subTest(location=location), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                subprocess.run(['git', 'init', '-q', str(root)], env=env, check=True)
                (root / '.git/info/exclude').write_text('target/\n')
                receipt_path = root / location
                receipt_path.parent.mkdir(parents=True, exist_ok=True)
                # Algorithm unit state only, never native process observations.
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
                self.assertEqual(result['candidate_worktree_clean_at_end'], expected_clean)
                self.assertEqual(result['passed'], expected_clean)
                self.assertNotEqual(rejected, expected_clean)


def _observation_files():
    return sorted(CONTRACT.GO_OBS_DIR.glob('*.json'))


class ObservationHygieneTests(unittest.TestCase):
    """The committed Go observations carry no operator path and are keyed to fixed oracles."""

    def test_the_scan_finds_a_path_in_plain_text_base64_nested_base64_and_gzip(self):
        import base64
        import gzip
        for path in (b'/Volumes/Dev/x', b'/Users/someone/x', b'/var/folders/7v/abc/T/x', b'/private/var/folders/7v/x',
                     b'/private/tmp/x', b'/tmp/symvault-go-capture-abc12345/seed/vault'):
            text = b'vaultDir: ' + path + b'\n'
            packed = base64.b64encode(text)
            for label, data in (('plain', text), ('base64', b'{"a": "' + packed + b'"}'),
                                ('nested', b'{"a": "' + base64.b64encode(packed) + b'"}'),
                                ('gzip', b'{"a": "' + base64.b64encode(gzip.compress(text)) + b'"}'),
                                ('gzip-nested', b'{"a": "' + base64.b64encode(base64.b64encode(gzip.compress(text))) + b'"}')):
                with self.subTest(path=path, form=label):
                    self.assertTrue(CONTRACT.operator_paths(data), (label, path))
        self.assertEqual(CONTRACT.operator_paths(b'{"a": "vaultDir: /observation/vault", "b": "/tmp"}'), [])

    def test_committed_observations_and_blobs_have_no_operator_path(self):
        files = _observation_files() + sorted((CONTRACT.GO_OBS_DIR / 'blobs').glob('*'))
        self.assertTrue(files, 'no committed Go observations found')
        for file in files:
            with self.subTest(file=file.name):
                self.assertEqual(CONTRACT.operator_paths(file.read_bytes()), [])

    def test_pack_tree_rewrites_the_capture_home_in_place(self):
        with tempfile.TemporaryDirectory(prefix='symvault-hygiene-') as raw:
            home = Path(raw) / 'seed'
            vault = home / 'vault'
            vault.mkdir(parents=True)
            (vault / 'config.yaml').write_text(f'a: 1\nvaultDir: {vault}\nb: 2\n')
            packed = CONTRACT.pack_tree(vault)
            import base64
            expected = b'a: 1\nvaultDir: /observation/vault\nb: 2\n'
            self.assertEqual(base64.b64decode(packed['config.yaml']), expected)
            self.assertEqual((vault / 'config.yaml').read_bytes(), expected, 'the working copy is what is recorded')

    def test_pack_tree_refuses_an_operator_path_it_cannot_scrub(self):
        with tempfile.TemporaryDirectory(prefix='symvault-hygiene-') as raw:
            vault = Path(raw) / 'seed' / 'vault'
            vault.mkdir(parents=True)
            (vault / 'note').write_text('log: /Users/someone/project\n')
            with self.assertRaisesRegex(ValueError, 'operator paths'):
                CONTRACT.pack_tree(vault)

    def test_save_refuses_an_operator_path_hidden_in_a_packed_value(self):
        import base64
        with tempfile.TemporaryDirectory(prefix='symvault-hygiene-') as raw:
            saved = CONTRACT.GO_OBS_DIR
            CONTRACT.GO_OBS_DIR = Path(raw)
            try:
                hidden = base64.b64encode(b'x: /var/folders/7v/abc/T/y').decode()
                with self.assertRaisesRegex(ValueError, 'operator paths'):
                    CONTRACT.save_go_observations('hygiene', {'tree': {'f': hidden}}, {}, [], 'go1.26.6')
                self.assertEqual(list(Path(raw).iterdir()), [], 'nothing is written on refusal')
            finally:
                CONTRACT.GO_OBS_DIR = saved

    def test_every_committed_observation_loads_with_its_pinned_oracle(self):
        import re
        seen = set()
        for file in _observation_files():
            contract, goos = file.name[:-len('.json')].rsplit('.', 1)
            with self.subTest(file=file.name):
                document = CONTRACT.load_go_observations(contract, goos=goos)   # no oracle argument: the generic loader
                oracle = document['oracle_commit']
                self.assertEqual(oracle, CONTRACT.pinned_oracle(contract))
                self.assertTrue(re.fullmatch(r'[0-9a-f]{40}|go_timestamp_oracle\.go\.txt:[0-9a-f]{64}', oracle), oracle)
                seen.add(contract)
        self.assertTrue({'mcp-process', 'timestamp-fixtures', 'toolhash-process'} <= seen, seen)

    def test_a_wrong_oracle_is_rejected(self):
        with self.assertRaises(AssertionError):
            CONTRACT.load_go_observations('mcp-process', goos='darwin', oracle=CONTRACT.HISTORICAL)

    def test_the_toolhash_capture_pin_is_the_registered_oracle(self):
        source = Path(__file__).with_name('toolhash_process_contract.py').read_text()
        self.assertIn(f"GO_SOURCE_COMMIT = '{CONTRACT.TOOLHASH_ORACLE}'", source)

    def test_no_oracle_identity_is_derived_from_git_history_of_go_sources(self):
        import re
        for script in sorted(Path(__file__).parent.glob('*contract*.py')) + [Path(__file__).with_name('go_timestamp_fixtures.py')]:
            if script.name.startswith('test_'):
                continue
            text = script.read_text()
            with self.subTest(script=script.name):
                self.assertIsNone(re.search(r"['\"](?:log|rev-list|describe)['\"]\s*,\s*['\"]-", text) or
                                  re.search(r"git\([^)]*['\"](?:log|rev-list)['\"]", text))


if __name__ == '__main__':
    unittest.main()
