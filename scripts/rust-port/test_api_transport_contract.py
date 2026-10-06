#!/usr/bin/env python3
"""Structural rejection controls consuming an unchanged real Darwin TLS capture."""
import copy
import hashlib
import json
from pathlib import Path
import unittest

from api_transport_contract import assert_pair

FIXTURE = Path(__file__).resolve().parents[2] / 'testdata/api-darwin-trust/untrusted-root.json'
HOST = 'dns-api.example.test'


class CertificateTrustContractTests(unittest.TestCase):
    def setUp(self):
        raw = FIXTURE.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), 'ef614edb01152105e8093fd7d7685b86369930c8d712beb96a8db497b26269c9')
        self.capture = json.loads(raw)

    def validate(self, go=None, rust=None, native_os='Darwin', host=HOST):
        return assert_pair('untrusted-root', self.capture['go'] if go is None else go,
                           self.capture['rust'] if rust is None else rust, host, native_os)

    def test_real_native_darwin_rejection_is_preserved(self):
        before = copy.deepcopy(self.capture)
        self.assertIs(self.capture['source']['original_receipt_passed'], False)
        self.assertEqual(self.capture['source']['candidate_commit'], '373f7712e1aad53d61adbb460e433b22a5143519')
        self.assertEqual(self.capture['source']['original_receipt_sha256'], 'b38baad84f7f7f086104127ec0a5292ecd01d0a22a6020542329195775a7bed5')
        result = self.validate()
        assert result is not None
        self.assertEqual(result['decision'], 'opaque-transport-diagnostic')
        self.assertEqual(result['go'], self.capture['go']['result'])
        self.assertEqual(result['rust'], self.capture['rust']['result'])
        for implementation in ['go', 'rust']:
            self.assertEqual(self.capture[implementation]['exit_code'], 0)
            self.assertTrue(self.capture[implementation]['upstream'])
            self.assertTrue(all(set(event) == {'tls_rejection'} for event in self.capture[implementation]['upstream']))
        self.assertEqual(self.capture, before)

    def test_generic_trust_suffix_is_still_supported(self):
        # Explicitly synthetic isolation control, not another native capture.
        go = copy.deepcopy(self.capture['go'])
        go['result']['text'] = 'request failed: Get "https://dns-api.example.test:1234/v1/status": tls: failed to verify certificate: x509: certificate signed by unknown authority'
        for native_os in ['Linux', 'Windows', 'Darwin']:
            with self.subTest(native_os=native_os):
                result = self.validate(go=go, native_os=native_os)
                assert result is not None
                self.assertEqual(result['go'], go['result'])

    def test_native_suffix_requires_correct_platform_and_host(self):
        self.validate()
        for native_os in ['Linux', 'Windows', '', None, True, 1]:
            with self.subTest(native_os=native_os), self.assertRaises(AssertionError):
                self.validate(native_os=native_os)
        for host in ['wrong-api.example.test', HOST + '.evil', '']:
            with self.subTest(host=host), self.assertRaises(AssertionError):
                self.validate(host=host)

    def test_error_flags_are_actual_booleans(self):
        self.validate()
        for side in ['go', 'rust']:
            for field, invalid in [('is_error', [False, None, 1, 'true']), ('handler_error', [True, None, 0, 'false'])]:
                for value in invalid:
                    with self.subTest(side=side, field=field, value=value):
                        changed = copy.deepcopy(self.capture[side])
                        changed['result'][field] = value
                        with self.assertRaises(AssertionError):
                            self.validate(**{side: changed})
                changed = copy.deepcopy(self.capture[side])
                del changed['result'][field]
                with self.subTest(side=side, field=field, missing=True), self.assertRaises(KeyError):
                    self.validate(**{side: changed})

    def test_other_failures_and_modified_suffixes_are_not_trust_evidence(self):
        self.validate()
        original = self.capture['go']['result']['text']
        for text in [original + ' extra', original + '\n', original.replace('not trusted', 'expired'),
                     original.replace('“', '"').replace('”', '"'), original.replace('request failed: ', 'request completed: '),
                     'request failed: context deadline exceeded', 'request failed: connection refused']:
            with self.subTest(text=text):
                changed = copy.deepcopy(self.capture['go'])
                changed['result']['text'] = text
                with self.assertRaises(AssertionError):
                    self.validate(go=changed)
        changed = copy.deepcopy(self.capture['rust'])
        changed['result']['text'] = 'request failed: upstream request timed out'
        with self.assertRaises(AssertionError):
            self.validate(rust=changed)


if __name__ == '__main__':
    unittest.main()
