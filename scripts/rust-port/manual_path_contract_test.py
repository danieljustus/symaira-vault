#!/usr/bin/env python3
"""Focused escaping/normalization unit controls; real binaries have a separate gate."""
from pathlib import Path
import tempfile
import unittest

from cli_artifacts_contract import literal_roff_text, normalized_man
from manual_path_contract import CASES


class LiteralManualTests(unittest.TestCase):
    def test_literal_paths_and_controls(self):
        self.assertEqual(literal_roff_text(r'C:\ordinary\config.yaml'), r'C:\\ordinary\\config.yaml')
        self.assertEqual(literal_roff_text('.request'), r'\&.request')
        self.assertEqual(literal_roff_text("'request"), r"\&'request")
        self.assertEqual(literal_roff_text('a\n.PS\r\t\0\a\b\v\f\x1b\x7f\u0085\u2028\u2029'),
                         r'a\\n.PS\\r\\t\\x00\\a\\b\\v\\f\\x1b\\x7f\\u0085\\u2028\\u2029')
        for path in ['/a__b__c', '/a`b`c', '/a![b](c)d', '/a<b>c', '/a&amp;b', '/é space']:
            self.assertEqual(literal_roff_text(path), path)

    def test_normalization_does_not_hide_legacy_markdown_or_changed_bytes(self):
        path = '/a__b__c/config.yaml'
        with tempfile.TemporaryDirectory() as temporary:
            page = Path(temporary) / 'page.1'
            page.write_bytes(('prefix ' + path + ' suffix').encode())
            self.assertEqual(normalized_man(page, path), 'prefix __CONFIG_PATH__ suffix')
            # A decorated legacy path is NOT silently accepted as the new path.
            legacy = r'prefix /a\fBb\fPc/config.yaml suffix'
            page.write_bytes(legacy.encode())
            self.assertEqual(normalized_man(page, path), legacy)
            page.write_bytes(('CHANGED ' + path + ' suffix').encode())
            self.assertNotEqual(normalized_man(page, path), 'prefix __CONFIG_PATH__ suffix')

    def test_every_declared_native_case_is_required(self):
        self.assertEqual(len(CASES), 18)
        self.assertEqual(len(set(CASES)), 18)
        self.assertIn('s__b0nk_', CASES)
        self.assertIn('a\n.PS\r\t\x1b', CASES)
        self.assertIn('a<b>c', CASES)


if __name__ == '__main__':
    unittest.main()
