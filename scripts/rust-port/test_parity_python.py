#!/usr/bin/env python3
"""Subprocess controls for the shared parity driver's assertion boundary."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


class ParityPythonTests(unittest.TestCase):
    def test_driver_entrypoints_reject_disabled_assertions(self):
        for driver in ('mcp_process_contract.py', 'http_process_contract.py'):
            for flag, optimize in (('', ''), ('-O', ''), ('-OO', ''), ('', '1'), ('', '2')):
                with self.subTest(driver=driver, flag=flag, optimize=optimize):
                    env = os.environ.copy()
                    env.pop('PYTHONOPTIMIZE', None)
                    env['PYTHONDONTWRITEBYTECODE'] = '1'
                    if optimize:
                        env['PYTHONOPTIMIZE'] = optimize
                    command = [sys.executable, '-B']
                    if flag:
                        command.append(flag)
                    command.extend([str(Path(__file__).with_name(driver)), '--help'])
                    result = subprocess.run(command, env=env, capture_output=True, timeout=10)
                    if flag or optimize:
                        self.assertEqual(result.returncode, 1)
                        self.assertEqual(result.stdout, b'')
                        self.assertEqual(result.stderr, b'Parity acceptance requires unoptimized Python; remove -O / PYTHONOPTIMIZE.\n')
                    else:
                        self.assertEqual(result.returncode, 0)
                        self.assertIn(b'usage:', result.stdout)
                        self.assertEqual(result.stderr, b'')


if __name__ == '__main__':
    unittest.main()
