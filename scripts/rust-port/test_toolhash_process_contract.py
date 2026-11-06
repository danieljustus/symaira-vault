#!/usr/bin/env python3
"""Negative controls for toolhash_process_contract.py's audit comparison (no live processes)."""
import unittest

import toolhash_process_contract as driver

SESS = 'a' * 32


LABELS = {'tok-20261103-aaaaaaaa': 'go_current', 'tok-20261103-bbbbbbbb': 'go_stale'}
TOK = 'tok-20261103-aaaaaaaa'


def row(action, req, **extra):
    return {'ts': 't', 'action': action, 'sess_id': SESS, 'req_id': req, 'token_id': TOK, 'hmac': 'h', 'kid': 'k', **extra}


ROWS = [row('tool_call', '0' * 16, path='health'), row('tool_denied', '1' * 16, path='x'),
        row('tool_registry_drift', '2' * 16, path='symaira_search')]


class AuditMask(unittest.TestCase):
    def test_random_ids_and_clock_are_masked(self):
        other = [dict(r, ts='later', sess_id='b' * 32, req_id=r['req_id'][::-1]) for r in ROWS]
        self.assertEqual(driver.mask_audit(ROWS, LABELS), driver.mask_audit(other, LABELS))
        masked = dict(driver.mask_audit(ROWS, LABELS)[0])
        self.assertEqual((masked['sess_id'], masked['req_id'], masked['token_id']), ('<sess>', '<req>', '<token:go_current>'))
        self.assertNotIn('hmac', masked)

    def test_rows_attributed_to_different_tokens_differ(self):
        # the review's hole: a Rust server crediting a row to the wrong token must not compare equal
        wrong = [dict(r) for r in ROWS]
        wrong[1]['token_id'] = 'tok-20261103-bbbbbbbb'
        self.assertNotEqual(driver.mask_audit(ROWS, LABELS), driver.mask_audit(wrong, LABELS))
        self.assertEqual(dict(driver.mask_audit(wrong, LABELS)[1])['token_id'], '<token:go_stale>')

    def test_token_id_outside_the_registry_is_rejected(self):
        unknown = [dict(r) for r in ROWS]
        unknown[0]['token_id'] = 'tok-20261103-cccccccc'
        with self.assertRaises(AssertionError):
            driver.mask_audit(unknown, LABELS)

    def test_token_labels_come_from_the_registry_and_must_be_unique(self):
        import json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as raw:
            def write(tokens):
                Path(raw, 'mcp-tokens.json').write_text(json.dumps({'tokens': tokens}))
            write({'tok-1': {'label': 'a'}, 'tok-2': {'label': 'b'}})
            self.assertEqual(driver.token_labels(raw), {'tok-1': 'a', 'tok-2': 'b'})
            write({'tok-1': {'label': 'a'}, 'tok-2': {'label': 'a'}})
            with self.assertRaises(AssertionError):
                driver.token_labels(raw)

    def test_dropped_ids_make_the_comparison_fail(self):
        self.assertNotEqual(driver.mask_audit(ROWS, LABELS), driver.mask_audit(ROWS, LABELS, drop_ids=True))

    def test_missing_malformed_or_split_ids_are_rejected(self):
        for mutant in (lambda r: r.pop('sess_id'), lambda r: r.pop('req_id'), lambda r: r.update(req_id='xyz'),
                       lambda r: r.update(sess_id='Z' * 32)):
            rows = [dict(r) for r in ROWS]
            mutant(rows[0])
            with self.assertRaises(AssertionError):
                driver.mask_audit(rows, LABELS)
        split = [dict(r) for r in ROWS]
        split[1]['sess_id'] = 'b' * 32
        with self.assertRaises(AssertionError):
            driver.mask_audit(split, LABELS)

    def test_anomaly_rows_are_skipped_but_must_not_carry_request_ids(self):
        anomaly = {'action': 'anomaly_off_hours', 'sess_id': SESS}
        self.assertEqual(driver.mask_audit(ROWS + [anomaly], LABELS), driver.mask_audit(ROWS, LABELS))
        with self.assertRaises(AssertionError):
            driver.mask_audit(ROWS + [dict(anomaly, req_id='3' * 16)], LABELS)

    def test_scenario_table_is_the_receipt_contract(self):
        pairs = [(name, token) for name, _, _, who in driver.SCENARIOS for token in who]
        self.assertEqual(len(pairs), 14)
        self.assertEqual(len(set(pairs)), 14)
        self.assertEqual(driver.EXPECTED_AUDIT_ROWS, 8)


if __name__ == '__main__':
    unittest.main()
