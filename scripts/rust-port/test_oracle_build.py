#!/usr/bin/env python3
"""Synthetic failure-retention controls; native process ownership is tested in Go."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import oracle_build


class OracleBuildTests(unittest.TestCase):
    def test_primary_failure_survives_cleanup_failure(self):
        report: dict = {'passed': True}
        with self.assertRaisesRegex(RuntimeError, '^original build failure$'):
            try:
                raise RuntimeError('original build failure')
            finally:
                oracle_build.remove_oracle_worktree(Path('synthetic'), report,
                    Mock(side_effect=PermissionError('synthetic cleanup failure')))
        self.assertFalse(report['passed'])
        self.assertEqual(report['primary_failure']['type'], 'RuntimeError')
        self.assertEqual(report['cleanup_failure']['type'], 'PermissionError')

    def test_cleanup_only_failure_cannot_leave_passed_receipt(self):
        report: dict = {'passed': True}
        with self.assertRaises(PermissionError):
            oracle_build.remove_oracle_worktree(Path('synthetic'), report,
                Mock(side_effect=PermissionError('synthetic cleanup failure')))
        self.assertFalse(report['passed'])
        self.assertNotIn('primary_failure', report)

    def test_build_failures_retain_timeout_and_identity(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            runner = root / 'synthetic-runner'
            runner.write_bytes(b'synthetic runner, never executed')
            for result in (subprocess.CompletedProcess([], 124, b'', b'synthetic deadline'),
                           subprocess.TimeoutExpired('synthetic runner', 620)):
                rows = []
                with patch.dict(oracle_build.os.environ, {'SYMVAULT_ORACLE_BUILD_RUNNER': str(runner)}), \
                     patch.object(oracle_build, 'pinned_go', return_value=(Path('/synthetic/go'), {}, {'version': 'synthetic'})), \
                     patch.object(oracle_build.subprocess, 'run', side_effect=[result]):
                    with self.assertRaises((RuntimeError, subprocess.TimeoutExpired)):
                        oracle_build.build_go(root, root / 'output', '.', rows)
                self.assertEqual(len(rows), 1)
                self.assertFalse(rows[0]['passed'])
                self.assertTrue(rows[0]['timed_out'])
                self.assertEqual(rows[0]['compiler'], {'version': 'synthetic'})
                self.assertIn('elapsed_seconds', rows[0])
                self.assertIn('runner_sha256', rows[0])


if __name__ == '__main__':
    unittest.main()
