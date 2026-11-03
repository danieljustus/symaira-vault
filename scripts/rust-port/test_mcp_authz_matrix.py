#!/usr/bin/env python3
"""Regression controls for the MCP authz matrix recorder (no Go build needed).

The flake: generate_password's text passes through the MCP output sanitizer
(Go render.go sanitizeBytes) which rewrites `-->` to `-- >` and `</x...>` to
`</ x... >`, so a random 16-character password occasionally came back longer
than 16 and two otherwise identical Go observations masked to different lengths.
"""
import json
import random
import unittest

import mcp_authz_matrix as matrix

PASSWORD_ALPHABET = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789' + '!@#$%^&*()-_=+[]{}|;:,.<>?/~'


def reference_sanitize(text):
    """ASCII-only port of internal/mcp/server/render.go sanitizeBytes."""
    out, i = [], 0
    while i < len(text):
        ch = text[i]
        if ch == '<' and i + 2 < len(text) and text[i + 1] == '/' and (text[i + 2].isalpha() or text[i + 2] == '_'):
            end = text.find('>', i)
            if end - i > 2:
                out.append('</ ' + text[i + 2:end] + ' >')
                i = end + 1
                continue
        if text[i:i + 3] == '-->':
            out.append('-- >')
            i += 3
            continue
        out.append(ch)
        i += 1
    return ''.join(out)


def ok_response(text, tool='generate_password'):
    return {'jsonrpc': '2.0', 'id': 134, 'result': {'content': [{'type': 'text', 'text': text}], 'isError': False}}


def masked_length(text, tool='generate_password'):
    response = matrix.mask(tool, matrix.normalize(ok_response(text), '/tmp/home'))
    return response['result']['content'][0]['text']


class PasswordMaskIgnoresSanitizer(unittest.TestCase):
    # Recorded from the pinned Go oracle (24acdb08): sanitizeMCPText(input).
    GO_RECORDED = [
        ('Ab3-->kLmN9pQrSt', 'Ab3-- >kLmN9pQrSt'),
        ('x</ab>Zk3mNpQrStU', 'x</ ab >Zk3mNpQrStU'),
        ('q</_x2345678923>9', 'q</ _x2345678923 >9'),
        ('plainPassw0rd234', 'plainPassw0rd234'),
    ]

    def test_reference_sanitizer_matches_recorded_go_output(self):
        for original, sanitized in self.GO_RECORDED:
            with self.subTest(original=original):
                self.assertEqual(reference_sanitize(original), sanitized)

    def test_flake_inputs_mask_to_original_length(self):
        for original, sanitized in self.GO_RECORDED:
            with self.subTest(original=original):
                self.assertEqual(masked_length(sanitized), {'masked': 'random_password', 'length': len(original)})

    def test_control_the_naive_length_was_the_flake(self):
        sanitized = 'Ab3-- >kLmN9pQrSt'
        self.assertEqual((len('Ab3-->kLmN9pQrSt'), len(sanitized)), (16, 17))
        self.assertEqual(masked_length(sanitized)['length'], 16)

    def test_every_generated_password_masks_to_its_length(self):
        rng = random.Random(0x5eed)
        hostile = '-->-->-<</>>/abz_'
        rewritten = 0
        for trial in range(20000):
            alphabet = hostile if trial % 2 else PASSWORD_ALPHABET
            original = ''.join(rng.choice(alphabet) for _ in range(rng.choice([1, 8, 16, 17, 40])))
            sanitized = reference_sanitize(original)
            rewritten += sanitized != original
            self.assertEqual(matrix.undo_mcp_sanitizer(sanitized), original, original)
            self.assertEqual(masked_length(sanitized)['length'], len(original), original)
        self.assertGreater(rewritten, 1000, 'the property test must exercise rewrites')

    def test_wrong_length_or_foreign_space_is_still_a_difference(self):
        self.assertEqual(masked_length('abcdefghjkmnpqrs')['length'], 16)
        self.assertEqual(masked_length('abcdefghjkmnpqrst')['length'], 17)
        # A space that is not part of a sanitizer rewrite is not removed: it counts.
        self.assertEqual(masked_length('abcdefghjkmnpqrs ')['length'], 17)
        self.assertEqual(masked_length('abcdefghjk-- mnpq')['length'], 17)
        self.assertEqual(masked_length('abcdefghjk-- >mnpq')['length'], 17)  # rewrite undone: 17 original characters

    def test_error_and_other_tools_are_not_rewritten(self):
        error = {'jsonrpc': '2.0', 'id': 1, 'result': {'content': [{'type': 'text', 'text': 'Ab3-- >x'}], 'isError': True}}
        self.assertIs(matrix.mask('generate_password', error), error)
        other = ok_response('Ab3-- >x')
        self.assertIs(matrix.mask('get_entry', other), other)


class NondeterminismReport(unittest.TestCase):
    def test_differing_rows_name_tool_token_and_both_values(self):
        first = [{'tool': 'a', 'token': 'none', 'response': {'x': 1}},
                 {'tool': 'generate_password', 'token': 'including', 'response': {'text': {'length': 16}}}]
        second = [{'tool': 'a', 'token': 'none', 'response': {'x': 1}},
                  {'tool': 'generate_password', 'token': 'including', 'response': {'text': {'length': 17}}}]
        rows = matrix.differing_rows(first, second)
        self.assertEqual(rows, [{'tool': 'generate_password', 'token': 'including',
                                 'first': json.dumps({'text': {'length': 16}}), 'second': json.dumps({'text': {'length': 17}})}])
        self.assertEqual(matrix.differing_rows(first, first), [])
        self.assertEqual(len(matrix.differing_rows(first, second, limit=5)[0]['first']), 5)


if __name__ == '__main__':
    unittest.main()
