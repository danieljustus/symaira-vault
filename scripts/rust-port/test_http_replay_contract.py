#!/usr/bin/env python3
"""Negative controls for the replay/SSE/framing and token-matrix checkers (no live processes)."""
import base64
import copy
import hashlib
import json
import time
import unittest

import http_replay_contract as replay
import http_token_contract as tokens

PORT = 4242
TOKENS = {'full': 'public-token'}


def wire(code, body=b'', headers=(), reason='X'):
    fields = list(headers) + [('Content-Length', str(len(body)))]
    return (f'HTTP/1.1 {code} {reason}\r\n' + ''.join(f'{k}: {v}\r\n' for k, v in fields) + '\r\n').encode() + body


def health(offset=0):
    stamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + offset))
    return wire(200, json.dumps(dict(port=PORT, status='healthy', timestamp=stamp, version='dev'), sort_keys=True).encode() + b'\n',
                [('Content-Type', 'application/json')])


def row(name, raw, request=b'x', head=False):
    return dict(case=name, request_sha256=hashlib.sha256(request).hexdigest(), request_base64=base64.b64encode(request).decode(),
                raw_base64=base64.b64encode(raw).decode(), reset=None, responses=replay.parse_stream(raw, head))


def synthetic():
    """A self-consistent Go/Rust corpus that satisfies the policy table exactly."""
    go, rust = [], []
    for name, data, _, head in replay.cases(PORT, {'full': 'public-token', 'health': 'h', 'metadata': 'm', 'other': 'o', 'expired': 'e', 'revoked': 'r'}):
        request = data
        if name in replay.HEALTH_CASES:
            raw_go = raw_rust = health() if name != 'route-head-health' else wire(200, b'', [('Content-Type', 'application/json')])
            if name == 'route-head-health':
                raw_go = raw_rust = b'HTTP/1.1 200 OK\r\nContent-Length: 85\r\nContent-Type: application/json\r\n\r\n'
        elif name in replay.INTERIM_ONLY:
            raw_go = b'HTTP/1.1 100 Continue\r\n\r\n' + wire(200, b'same-' + name.encode())
            raw_rust = wire(200, b'same-' + name.encode())
        elif name in replay.DECLARED:
            _, go_code, rust_code = replay.DECLARED[name]
            raw_go = wire(go_code, b'go-' + name.encode())
            raw_rust = wire(rust_code, b'rust-' + name.encode()) if rust_code is not None else b''
        else:
            raw_go = raw_rust = wire(replay.EXPECT.get(name, 200), b'same-' + name.encode())
        if head:
            raw_go, raw_rust = (raw.split(b'\r\n\r\n')[0] + b'\r\n\r\n' if raw else raw for raw in (raw_go, raw_rust))
        go.append(row(name, raw_go, request, head))
        rust.append(row(name, raw_rust, request, head))
    return go, rust


class ReplayContract(unittest.TestCase):
    def test_synthetic_policy_passes(self):
        go, rust = synthetic()
        identical, declared, semantic, interim_only = replay.compare(go, rust, PORT)
        self.assertEqual(len(declared), len(replay.DECLARED))
        self.assertEqual(sorted(c['case'] for c in interim_only), sorted(replay.INTERIM_ONLY))
        self.assertEqual(len(semantic), len(replay.HEALTH_CASES) - 1)
        self.assertGreater(len(identical), 100)

    def test_undeclared_difference_is_rejected(self):
        go, rust = synthetic()
        index = next(i for i, r in enumerate(go) if r['case'] == 'method-GET')
        rust[index] = row('method-GET', wire(405, b'different'), base64.b64decode(go[index]['request_base64']))
        with self.assertRaisesRegex(AssertionError, 'undeclared difference'):
            replay.compare(go, rust, PORT)

    def test_interim_only_cases_assert_the_interim_line_and_identical_final(self):
        # Rust starting to send the interim line makes the declaration stale.
        go, rust = synthetic()
        index = next(i for i, r in enumerate(go) if r['case'] == 'expect-100')
        rust[index] = copy.deepcopy(go[index])
        with self.assertRaisesRegex(AssertionError, 'interim line set'):
            replay.compare(go, rust, PORT)
        # A final response that differs beyond the interim line is rejected.
        go, rust = synthetic()
        rust[index] = row('expect-100', wire(200, b'different'), base64.b64decode(go[index]['request_base64']))
        with self.assertRaisesRegex(AssertionError, 'final response differs'):
            replay.compare(go, rust, PORT)
        # Go without the interim line is also a change of the measured class.
        go, rust = synthetic()
        go[index] = copy.deepcopy(rust[index])
        with self.assertRaisesRegex(AssertionError, 'interim line set'):
            replay.compare(go, rust, PORT)

    def test_stale_declaration_is_rejected(self):
        go, rust = synthetic()
        index = next(i for i, r in enumerate(go) if r['case'] == 'line-empty')
        rust[index] = copy.deepcopy(go[index])
        with self.assertRaisesRegex(AssertionError, 'no longer observed'):
            replay.compare(go, rust, PORT)

    def test_declared_status_must_match_hand_written_codes(self):
        go, rust = synthetic()
        index = next(i for i, r in enumerate(go) if r['case'] == 'env-two-obj')
        rust[index] = row('env-two-obj', wire(200, b'rust-mutated'), base64.b64decode(go[index]['request_base64']))
        with self.assertRaisesRegex(AssertionError, 'complete-json-body-required'):
            replay.compare(go, rust, PORT)

    def test_both_wrong_is_rejected_by_hand_written_expectation(self):
        go, rust = synthetic()
        index = next(i for i, r in enumerate(go) if r['case'] == 'method-GET')
        wrong = wire(200, b'both-wrong')
        go[index] = row('method-GET', wrong, base64.b64decode(go[index]['request_base64']))
        rust[index] = copy.deepcopy(go[index])
        with self.assertRaisesRegex(AssertionError, 'method-GET'):
            replay.compare(go, rust, PORT)

    def test_event_stream_response_is_rejected(self):
        go, rust = synthetic()
        index = next(i for i, r in enumerate(go) if r['case'] == 'post-accept-sse-first')
        stream = wire(200, b'data: {}\n\n', [('Content-Type', 'text/event-stream')])
        go[index] = row('post-accept-sse-first', stream, base64.b64decode(go[index]['request_base64']))
        rust[index] = copy.deepcopy(go[index])
        with self.assertRaisesRegex(AssertionError, 'no event stream'):
            replay.compare(go, rust, PORT)

    def test_session_or_replay_response_headers_are_rejected(self):
        go, rust = synthetic()
        index = next(i for i, r in enumerate(go) if r['case'] == 'post-session-id')
        marked = wire(200, b'ok', [('Mcp-Session-Id', 'abc')])
        go[index] = row('post-session-id', marked, base64.b64decode(go[index]['request_base64']))
        rust[index] = copy.deepcopy(go[index])
        with self.assertRaisesRegex(AssertionError, 'session/replay header'):
            replay.compare(go, rust, PORT)

    def test_missing_declared_case_and_reordering_are_rejected(self):
        go, rust = synthetic()
        with self.assertRaisesRegex(AssertionError, 'declared case missing'):
            replay.compare([r for r in go if r['case'] != 'te-dup'], [r for r in rust if r['case'] != 'te-dup'], PORT)
        with self.assertRaisesRegex(AssertionError, 'same case inventory'):
            replay.compare(go, list(reversed(rust)), PORT)

    def test_health_semantic_control(self):
        go, rust = synthetic()
        index = next(i for i, r in enumerate(go) if r['case'] == 'route-get-health')
        wrong_port = wire(200, b'{"port":1,"status":"healthy","timestamp":"2026-01-01T00:00:00Z","version":"dev"}\n', [('Content-Type', 'application/json')])
        rust[index] = row('route-get-health', wrong_port, base64.b64decode(go[index]['request_base64']))
        with self.assertRaises(AssertionError):
            replay.compare(go, rust, PORT)
        go, rust = synthetic()
        rust[index] = row('route-get-health', health(offset=3600), base64.b64decode(go[index]['request_base64']))
        with self.assertRaisesRegex(AssertionError, 'health clocks'):
            replay.compare(go, rust, PORT)

    def test_truncated_response_is_rejected_unless_declared(self):
        go, rust = synthetic()
        index = next(i for i, r in enumerate(go) if r['case'] == 'method-GET')
        cut = wire(405, b'abcdef')[:-3]
        go[index] = row('method-GET', cut, base64.b64decode(go[index]['request_base64']))
        rust[index] = copy.deepcopy(go[index])
        with self.assertRaisesRegex(AssertionError, 'truncated'):
            replay.compare(go, rust, PORT)

    def test_response_framing_parser(self):
        chunked = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n'
        parsed = replay.parse_stream(chunked)
        self.assertEqual(base64.b64decode(parsed[0]['body_base64']), b'abcde')
        interim = replay.parse_stream(b'HTTP/1.1 100 Continue\r\n\r\n' + wire(200, b'ok'))
        self.assertEqual([r['interim'] for r in interim], [True, False])
        closed = replay.parse_stream(b'HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n400 Bad Request')
        self.assertEqual(base64.b64decode(closed[0]['body_base64']), b'400 Bad Request')
        self.assertTrue(replay.parse_stream(b'HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc')[0]['truncated'])
        head = replay.parse_stream(b'HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n', head=True)
        self.assertEqual(base64.b64decode(head[0]['body_base64']), b'')


def token_row(name, code, body=b'', request=b'x'):
    return row(name, wire(code, body, [('Content-Type', 'application/json')]), request)


class TokenContract(unittest.TestCase):
    def rows(self, mutate=None):
        out = []
        for name, (_, _, status, denied) in tokens.TOKENS.items():
            for step, _ in tokens.STEPS:
                body = b''
                if step == 'health' and status == 200:
                    result = {'content': [{'text': 'tool registry has changed since this token was issued' if name == 'stale-hash' else 'ok'}], 'isError': bool(denied)}
                    body = json.dumps({'jsonrpc': '2.0', 'id': 3, 'result': result}).encode()
                out.append(token_row(f'{name}:{step}', status, body, f'{name}{step}'.encode()))
        for label in ['lower', 'double-space', 'trailing-space', 'upper-token', 'basic', 'no-space', 'empty', 'tab', 'token-only', 'query-token']:
            out.append(token_row('bearer:' + label, 200 if label == 'trailing-space' else 401, b'', label.encode()))
        out += [token_row(f'failure-{i}', 401, b'', str(i).encode()) for i in range(25)]
        out.append(token_row('after-failures', 200, b'', b'after'))
        return out

    def test_matrix_passes_and_mutations_fail(self):
        tokens.check_token_rows(self.rows(), self.rows())
        mutated = self.rows()
        index = next(i for i, r in enumerate(mutated) if r['case'] == 'past1s:ping')
        mutated[index] = token_row('past1s:ping', 200, b'', f'past1sping'.encode())
        with self.assertRaisesRegex(AssertionError, 'undeclared token-state difference'):
            tokens.check_token_rows(self.rows(), mutated)
        both_wrong_go, both_wrong_rust = self.rows(), self.rows()
        for rows in (both_wrong_go, both_wrong_rust):
            index = next(i for i, r in enumerate(rows) if r['case'] == 'revoked:init')
            rows[index] = token_row('revoked:init', 200, b'', b'revokedinit')
        with self.assertRaises(AssertionError):
            tokens.check_token_rows(both_wrong_go, both_wrong_rust)

    def test_lockout_and_scope_controls(self):
        locked = self.rows()
        index = next(i for i, r in enumerate(locked) if r['case'] == 'after-failures')
        locked[index] = token_row('after-failures', 429, b'', b'after')
        with self.assertRaisesRegex(AssertionError, 'lockout'):
            tokens.check_token_rows(locked, copy.deepcopy(locked))
        scoped = self.rows()
        index = next(i for i, r in enumerate(scoped) if r['case'] == 'tools-empty:health')
        body = json.dumps({'jsonrpc': '2.0', 'id': 3, 'result': {'content': [], 'isError': False}}).encode()
        scoped[index] = token_row('tools-empty:health', 200, body, b'toolsemptyhealth')
        with self.assertRaisesRegex(AssertionError, 'scope/drift denial'):
            tokens.check_token_rows(scoped, copy.deepcopy(scoped))

    def test_startup_policy(self):
        never = tokens.entry('never')[1]
        body = json.dumps({'version': 2, 'tokens': {'tok-never': never, 'tok-future1h': {'expires_at': '2999-01-01T00:00:00Z'}}}, indent=2) + '\n'
        scenarios = {s[0]: s for s in tokens.startup_scenarios({}, body)}
        observed = dict(state='exited', exit=1, disposal='exited', before={}, after={}, responses=[], stderr_has_legacy_warning=False)
        tokens.check_startup(scenarios['registry-array'], observed, copy.deepcopy(observed))
        with self.assertRaisesRegex(AssertionError, 'startup state'):
            tokens.check_startup(scenarios['registry-array'], dict(observed, state='listening'), copy.deepcopy(observed))
        with self.assertRaisesRegex(AssertionError, 'resulting token files'):
            tokens.check_startup(scenarios['registry-array'], dict(observed, after={'mcp-tokens.json': 'x'}), copy.deepcopy(observed))
        with self.assertRaisesRegex(AssertionError, 'fatal registry exit status'):
            tokens.check_startup(scenarios['registry-array'], dict(observed, exit=2), dict(observed, exit=2))

    def test_duplicate_key_documents_are_held_to_go(self):
        _, body = tokens.token_registry()
        documents = tokens.duplicate_documents(body)
        scenarios = {s[0]: s for s in tokens.startup_scenarios({}, body)}
        for name in ('dup-revoked-typeerr-then-false', 'dup-version-typeerr-then-int', 'dup-root-tokens-typeerr-first',
                     'dup-root-tokens-merge', 'dup-root-tokens-null-resets', 'utf8-invalid-label'):
            assert name in documents and name in scenarios, name
        # Go rejects a bad value that a later duplicate would override; a Rust that serves it is the old folding.
        go = dict(state='exited', exit=1, disposal='exited', before={}, after={}, responses=[], stderr_has_legacy_warning=False)
        old_rust = dict(go, state='listening', exit=None)
        scenario = scenarios['dup-revoked-typeerr-then-false']
        tokens.check_startup(scenario, go, copy.deepcopy(go))
        with self.assertRaisesRegex(AssertionError, 'startup state'):
            tokens.check_startup(scenario, go, old_rust)
        # the documents are real JSON-with-duplicates and invalid UTF-8 only where declared
        for name, (data, _, _) in documents.items():
            if name.startswith('utf8-invalid'):
                with self.assertRaises(UnicodeDecodeError):
                    data.decode('utf-8')
            else:
                data.decode('utf-8')
        assert documents['dup-root-tokens-merge'][0].count(b'"tokens"') == 2, 'the merge document repeats the root tokens key'
        # the live-reload comparison rejects a Rust that diverges from Go
        steps = [('baseline', 200), ('revoked-typeerr-then-false', 401)]
        with self.assertRaises(AssertionError):
            tokens.check_duplicate_reload(steps, [('baseline', 200), ('revoked-typeerr-then-false', 200)])

    def test_dynamic_policy(self):
        good = dict(live_before_expiry=200, live_expiry_epoch=100.0, live_detected_epoch=101.0, added_latency=2.1, revoke_latency=2.2, recovered_latency=2.0)
        tokens.check_dynamic(dict(good, after_corruption=200), dict(good, after_corruption=200))
        with self.assertRaisesRegex(AssertionError, 'last-good'):
            tokens.check_dynamic(dict(good, after_corruption=200), dict(good, after_corruption=401))
        with self.assertRaisesRegex(AssertionError, 'actual elapsed expiry'):
            tokens.check_dynamic(dict(good, after_corruption=200, live_detected_epoch=99.0), dict(good, after_corruption=200))
        with self.assertRaisesRegex(AssertionError, 'poll bound'):
            tokens.check_dynamic(dict(good, after_corruption=200, revoke_latency=9.0), dict(good, after_corruption=200))


if __name__ == '__main__':
    unittest.main()
