#!/usr/bin/env python3
"""Negative controls for toolhash_process_contract.py's audit comparison (no live processes)."""
import unittest

import toolhash_process_contract as driver

SESS = 'a' * 32


def row(action, req, **extra):
    return {'ts': 't', 'action': action, 'sess_id': SESS, 'req_id': req, 'token_id': 'tok-1', 'hmac': 'h', 'kid': 'k', **extra}


ROWS = [row('tool_call', '0' * 16, path='health'), row('tool_denied', '1' * 16, path='x'),
        row('tool_registry_drift', '2' * 16, path='symaira_search')]


class AuditMask(unittest.TestCase):
    def test_random_ids_and_clock_are_masked(self):
        other = [dict(r, ts='later', sess_id='b' * 32, req_id=r['req_id'][::-1]) for r in ROWS]
        self.assertEqual(driver.mask_audit(ROWS), driver.mask_audit(other))
        masked = dict(driver.mask_audit(ROWS)[0])
        self.assertEqual((masked['sess_id'], masked['req_id'], masked['token_id']), ('<sess>', '<req>', 'tok-1'))
        self.assertNotIn('hmac', masked)

    def test_dropped_ids_make_the_comparison_fail(self):
        self.assertNotEqual(driver.mask_audit(ROWS), driver.mask_audit(ROWS, drop_ids=True))

    def test_missing_malformed_or_split_ids_are_rejected(self):
        for mutant in (lambda r: r.pop('sess_id'), lambda r: r.pop('req_id'), lambda r: r.update(req_id='xyz'),
                       lambda r: r.update(sess_id='Z' * 32)):
            rows = [dict(r) for r in ROWS]
            mutant(rows[0])
            with self.assertRaises(AssertionError):
                driver.mask_audit(rows)
        split = [dict(r) for r in ROWS]
        split[1]['sess_id'] = 'b' * 32
        with self.assertRaises(AssertionError):
            driver.mask_audit(split)

    def test_anomaly_rows_are_skipped_but_must_not_carry_request_ids(self):
        anomaly = {'action': 'anomaly_off_hours', 'sess_id': SESS}
        self.assertEqual(driver.mask_audit(ROWS + [anomaly]), driver.mask_audit(ROWS))
        with self.assertRaises(AssertionError):
            driver.mask_audit(ROWS + [dict(anomaly, req_id='3' * 16)])

    def test_scenario_table_is_the_receipt_contract(self):
        pairs = [(name, token) for name, _, _, who in driver.SCENARIOS for token in who]
        self.assertEqual(len(pairs), 14)
        self.assertEqual(len(set(pairs)), 14)
        self.assertEqual(driver.EXPECTED_AUDIT_ROWS, 8)


if __name__ == '__main__':
    unittest.main()
