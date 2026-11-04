#!/usr/bin/env python3
"""Controls for the interpreter-independent token-file structure of http_token_contract.py (no live processes)."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

import http_token_contract as driver


def nested(depth):
    return b'{"version":2,"tokens":' + b'[' * depth + b']' * depth + b'}'


class TokenFilesDepth(unittest.TestCase):
    def structure(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'mcp-tokens.json').write_bytes(raw)
            return driver.token_files(Path(directory))['mcp-tokens.json']

    def test_depth_is_counted_outside_strings_only(self):
        self.assertEqual(driver.json_nesting_depth(b'{"a":[[1]],"b":"[[[[{{{"}'), 3)
        self.assertEqual(driver.json_nesting_depth(b'{"a":"\\"[[[","b":[]}'), 2)
        self.assertEqual(driver.json_nesting_depth(b']]]'), 0)

    def test_deep_files_are_recorded_by_bytes_whatever_the_interpreter_can_parse(self):
        # 9997 is the depth Go accepts; it is a RecursionError on CPython 3.13 and parses on 3.14: the same row on both
        raw = nested(9997)
        self.assertEqual(self.structure(raw), 'too-deep:' + hashlib.sha256(raw).hexdigest())
        self.assertEqual(self.structure(raw), self.structure(raw))
        self.assertNotEqual(self.structure(raw), self.structure(nested(9998)))

    def test_the_guard_does_not_depend_on_a_recursion_error(self):
        # forcing the interpreter limit up must not change the row
        raw = nested(driver.STRUCTURE_DEPTH_LIMIT + 1)
        before = self.structure(raw)
        limit = sys.getrecursionlimit()
        sys.setrecursionlimit(limit * 20)
        try:
            self.assertEqual(self.structure(raw), before)
        finally:
            sys.setrecursionlimit(limit)
        self.assertTrue(before.startswith('too-deep:'))

    def test_timestamps_are_masked_in_deep_files(self):
        one = nested(200).replace(b'"version"', b'"at":"2026-11-04T01:02:03Z","version"')
        two = nested(200).replace(b'"version"', b'"at":"2031-01-02T03:04:05Z","version"')
        self.assertEqual(self.structure(one), self.structure(two))

    def test_an_ordinary_registry_is_parsed_structurally(self):
        raw = json.dumps({'version': 2, 'tokens': {'t': {'label': 'a', 'agent_name': 'x', 'allowed_tools': ['*'], 'hash': 'h' * 64,
                                                             'prefix': 'abcd', 'expires_at': 'z'}}}).encode()
        value = self.structure(raw)
        self.assertEqual(value['version'], 2)
        self.assertEqual(len(value['entries']), 1)
        self.assertEqual(self.structure(b'{"tokens": '), 'unparseable')


if __name__ == '__main__':
    unittest.main()
