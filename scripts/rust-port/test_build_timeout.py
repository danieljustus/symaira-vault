#!/usr/bin/env python3
"""Controls for the shared oracle compile budget and worktree cleanup retry."""
import io
import os
from pathlib import Path
import re
import sys
import unittest
from contextlib import redirect_stderr
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_timeout


class BuildTimeoutTests(unittest.TestCase):
    def test_default_is_generous(self):
        self.assertEqual(build_timeout.oracle_build_timeout({}), 900)
        self.assertEqual(build_timeout.oracle_build_timeout({build_timeout.BUILD_TIMEOUT_ENV: ''}), 900)

    def test_environment_override(self):
        key = build_timeout.BUILD_TIMEOUT_ENV
        self.assertEqual(build_timeout.oracle_build_timeout({key: '1800'}), 1800)
        self.assertEqual(build_timeout.oracle_build_timeout({key: '12.5'}), 12.5)

    def test_malformed_override_never_falls_back(self):
        key = build_timeout.BUILD_TIMEOUT_ENV
        for bad in ('abc', '0', '-5', 'nan', 'inf'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                build_timeout.oracle_build_timeout({key: bad})

    def test_reads_process_environment_by_default(self):
        key = build_timeout.BUILD_TIMEOUT_ENV
        old = os.environ.get(key)
        os.environ[key] = '77'
        try:
            self.assertEqual(build_timeout.oracle_build_timeout(), 77)
        finally:
            if old is None:
                del os.environ[key]
            else:
                os.environ[key] = old


class RemoveWorktreeTests(unittest.TestCase):
    def test_transient_failure_is_retried(self):
        action = Mock(side_effect=[PermissionError('go.exe locked'), PermissionError('go.exe locked'), None])
        sleep = Mock()
        self.assertTrue(build_timeout.remove_worktree(action, 'tree', attempts=5, sleep=sleep))
        self.assertEqual(action.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_persistent_failure_without_primary_raises(self):
        action = Mock(side_effect=PermissionError('go.exe locked'))
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(PermissionError):
            build_timeout.remove_worktree(action, 'tree', attempts=3, sleep=Mock())
        self.assertEqual(action.call_count, 3)
        self.assertRegex(stderr.getvalue(), re.compile('could not remove tree after 3 attempts'))

    def test_persistent_failure_keeps_primary_exception(self):
        action = Mock(side_effect=PermissionError('go.exe locked'))
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaisesRegex(RuntimeError, '^original build failure$'):
            try:
                raise RuntimeError('original build failure')
            finally:
                self.assertFalse(build_timeout.remove_worktree(action, 'tree', attempts=2, sleep=Mock()))
        self.assertIn('PermissionError', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
