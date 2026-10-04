#!/usr/bin/env python3
"""Pure harness checks and an explicit real-editor regression; never clipboard.

python tui_harness_test.py --go-cli /path/go-cli --go-helper /path/go-fixture
executes the pinned binaries. Without those arguments only pure checks execute.
"""
import argparse
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import tui_contract as tui


class HarnessTests(unittest.TestCase):
    def test_wait_rechecks_predicate_after_process_exit_transition(self):
        browser = object.__new__(tui.Browser)
        browser.pump = lambda seconds=0.12: None
        browser.alive = lambda: False
        observations = iter([False, True])
        browser.wait(lambda: next(observations), 'exit between observations')

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
