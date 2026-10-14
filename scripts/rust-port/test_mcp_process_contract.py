#!/usr/bin/env python3
"""Focused controls for native MCP stdout record parsing."""
import importlib.util
import json
from pathlib import Path
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


if __name__ == '__main__':
    unittest.main()
