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


if __name__ == '__main__':
    unittest.main()
