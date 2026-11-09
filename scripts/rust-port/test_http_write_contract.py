#!/usr/bin/env python3
"""Synthetic socket-error controls, not native deadline acceptance evidence."""
import base64
import copy
import io
import platform
import ssl
import subprocess
import unittest
from unittest import mock

import http_write_contract as contract
import http_tls_contract
import http_framing_contract
import http_process_contract


class WriteDeadlineSocketErrors(unittest.TestCase):
    def test_receiver_observation_decodes_fixed_width_abi_and_fails_closed(self):
        # Synthetic ABI/failure checks only; this is not native Windows evidence.
        self.assertEqual(contract.TCP_INFO_V0.size, 88)
        values = list(range(len(contract.TCP_INFO_FIELDS)))
        values[0], values[3], values[12] = 7, True, 25613736
        payload = contract.TCP_INFO_V0.pack(*values)
        stream = mock.MagicMock()
        stream.fileno.return_value = 123
        stream.getsockname.return_value = ('127.0.0.1', 40000)
        stream.getpeername.return_value = ('127.0.0.1', 30000)
        stream.getsockopt.side_effect = lambda level, option: 4096 if option == contract.socket.SO_RCVBUF else 65536
        for code, returned in [(0, 88), (-1, 0), (0, 87), (0, 89)]:
            with self.subTest(code=code, returned=returned):
                ws2 = mock.MagicMock()
                ws2.WSAGetLastError.return_value = 10022
                def ioctl(handle, command, version, size, output, capacity, length, overlapped, completion):
                    self.assertEqual((handle, command, size, capacity), (123, 0xC0000000 | 0x18000000 | 39, 4, 88))
                    self.assertIsNone(overlapped)
                    self.assertIsNone(completion)
                    self.assertEqual(contract.ctypes.cast(version, contract.ctypes.POINTER(contract.ctypes.c_uint32))[0], 0)
                    contract.ctypes.memmove(output, payload, len(payload))
                    contract.ctypes.cast(length, contract.ctypes.POINTER(contract.ctypes.c_uint32))[0] = returned
                    return code
                ws2.WSAIoctl.side_effect = ioctl
                with mock.patch.object(contract.os, 'name', 'nt'), \
                     mock.patch.object(contract.ctypes, 'WinDLL', create=True, return_value=ws2), \
                     mock.patch.object(contract.time, 'monotonic', return_value=1.25):
                    if code:
                        with self.assertRaises(OSError):
                            contract.socket_observation(stream, 1)
                    elif returned != 88:
                        with self.assertRaises(ValueError):
                            contract.socket_observation(stream, 1)
                    else:
                        row = contract.socket_observation(stream, 1)
                        self.assertEqual(row['client_endpoint'], ('127.0.0.1', 40000))
                        self.assertEqual(row['server_endpoint'], ('127.0.0.1', 30000))
                        self.assertEqual(row['client_so_rcvbuf'], 4096)
                        self.assertEqual(row['client_so_sndbuf'], 65536)
                        self.assertEqual(row['started_seconds'], .25)
                        self.assertEqual(row['completed_seconds'], .25)
                        self.assertEqual(row['windows_tcp_info_v0'], dict(zip(contract.TCP_INFO_FIELDS, values, strict=True)))

    def test_diagnostic_failure_retains_peer_bytes_and_terminal_classification(self):
        # Synthetic lifecycle controls, not a native timeout/backpressure proof.
        outcomes = [(b'', 'eof'), (ConnectionResetError(104, 'synthetic reset'), 'connection-reset'),
                    (ConnectionAbortedError(10053, 'synthetic abort'), 'connection-aborted'),
                    (PermissionError(13, 'synthetic nonterminal error'), None)]
        for diagnostic in [None, OSError(10022, 'synthetic telemetry error'), ValueError('synthetic incomplete ABI')]:
            for outcome, terminal in outcomes:
                with self.subTest(diagnostic=type(diagnostic).__name__, terminal=terminal):
                    stream = mock.MagicMock()
                    stream.__enter__.return_value = stream
                    stream.getsockopt.return_value = 4096
                    data = b'public-received-bytes' if diagnostic and terminal else b''
                    stream.recv.side_effect = ([data] if data else []) + [outcome]
                    row = {}
                    with mock.patch.object(contract.socket, 'socket', return_value=stream), \
                         mock.patch.object(contract, 'socket_observation', side_effect=diagnostic,
                                           return_value={'completed_seconds': 0}) as observe, \
                         mock.patch.object(contract.time, 'monotonic', return_value=0), \
                         mock.patch.object(contract.time, 'time_ns', side_effect=[100, 120, 200, 220]), \
                         mock.patch.object(contract.time, 'sleep'), \
                         mock.patch.object(contract, 'request', return_value=b'public-request'):
                        if terminal is None:
                            with self.assertRaises(PermissionError):
                                contract.slow_output(1, {}, row)
                        elif diagnostic:
                            with self.assertRaises(type(diagnostic)):
                                contract.slow_output(1, {}, row)
                        else:
                            contract.slow_output(1, {}, row)
                    self.assertIs(row['peer_terminal_observed'], terminal is not None)
                    self.assertEqual([row[k] for k in ['request_start_wall_ns_before', 'request_start_wall_ns_after',
                                                      'receive_end_wall_ns_before', 'receive_end_wall_ns_after']],
                                     [100, 120, 200, 220])
                    self.assertIs(row['forced_client_close'], terminal is None)
                    if terminal:
                        self.assertEqual(row['peer_terminal_kind'], terminal)
                    self.assertEqual(contract.base64.b64decode(row['received_base64']), data)
                    self.assertEqual(len(row['socket_observation_errors']), int(diagnostic is not None))
                    self.assertEqual(observe.call_count, 1 if diagnostic else 2)
                    stream.setsockopt.assert_called_once_with(contract.socket.SOL_SOCKET, contract.socket.SO_RCVBUF, 4096)

    def test_tls_output_requires_verified_handshake_and_real_peer_closure(self):
        # Synthetic resource/error controls, not native backpressure evidence.
        for failure in (None, ssl.SSLCertVerificationError(1, 'synthetic certificate'),
                        ssl.SSLError(1, 'synthetic record error')):
            raw, stream, tls = mock.MagicMock(), mock.MagicMock(), mock.MagicMock()
            raw.__enter__.return_value = raw
            stream.__enter__.return_value = stream
            raw.getsockopt.return_value = 4096
            stream.getpeercert.return_value = b'synthetic-public-certificate'
            stream.version.return_value = 'TLSv1.3'
            stream.recv.return_value = b''
            tls.wrap_socket.return_value = stream
            certificate_failure = isinstance(failure, ssl.SSLCertVerificationError)
            if certificate_failure:
                tls.wrap_socket.side_effect = failure
            elif failure:
                stream.recv.side_effect = failure
            row = {}
            with mock.patch.object(contract.socket, 'socket', return_value=raw), \
                 mock.patch.object(contract, 'request', return_value=b'synthetic-request'), \
                 mock.patch.object(contract, 'socket_observation', return_value={}), \
                 mock.patch.object(contract.time, 'monotonic', return_value=0):
                if failure:
                    with self.assertRaises(type(failure)):
                        contract.slow_output(1, {}, row, tls)
                else:
                    contract.slow_output(1, {}, row, tls)
            raw.__exit__.assert_called_once()
            tls.wrap_socket.assert_called_once_with(raw, server_hostname='localhost')
            self.assertIs(row['peer_terminal_observed'], failure is None)
            if not certificate_failure:
                stream.__exit__.assert_called_once()
                self.assertEqual(row['tls_version'], 'TLSv1.3')
                self.assertEqual(row['server_certificate_sha256'], contract.hashlib.sha256(b'synthetic-public-certificate').hexdigest())

    def test_raw_tls_observer_requires_a_terminal_socket_outcome(self):
        outcomes = [
            (b'', 'eof'),
            (ConnectionResetError(104, 'synthetic reset'), 'connection-reset'),
            (ConnectionAbortedError(10053, 'synthetic Windows abort'), 'connection-aborted'),
            (PermissionError(13, 'synthetic nonterminal error'), None),
        ]
        for outcome, terminal in outcomes:
            with self.subTest(outcome=type(outcome).__name__):
                raw = mock.MagicMock()
                raw.__enter__.return_value = raw
                stream = mock.MagicMock()
                stream.version.return_value = 'TLSv1.2'
                stream.getpeercert.return_value = b'public-synthetic-certificate'
                tls_error = ssl.SSLError(1, 'synthetic record error')
                tls_error.reason = 'SYNTHETIC_RECORD_ERROR'
                stream.recv.side_effect = tls_error
                tls = mock.MagicMock()
                tls.wrap_socket.return_value = stream
                observer = mock.MagicMock()
                observer.__enter__.return_value = observer
                observer.recv.side_effect = [outcome]
                row = {}
                with mock.patch.object(contract.socket, 'create_connection', return_value=raw), \
                     mock.patch.object(contract.socket, 'socket', return_value=observer), \
                     mock.patch.object(contract.time, 'sleep'), \
                     mock.patch.object(contract.time, 'monotonic', return_value=0), \
                     mock.patch.object(contract, 'request', return_value=b'public-prefix-and-sixteen-final-bytes'):
                    if terminal is None:
                        with self.assertRaises(PermissionError):
                            contract.late_body(1, {}, tls, row)
                    else:
                        contract.late_body(1, {}, tls, row)
                self.assertIs(row['peer_terminal_observed'], terminal is not None)
                self.assertIs(row['forced_client_close'], terminal is None)
                if terminal is not None:
                    self.assertEqual(row['peer_terminal_kind'], terminal)
                    self.assertEqual(row['post_tls_error_wire_base64'], '')
                self.assertEqual(len(row['tls_read_errors']), 1)
                stream.detach.assert_called_once()

    def test_other_observers_keep_abort_narrow_and_validate_received_bytes(self):
        response = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'
        outcomes = [b'', ConnectionResetError(104, 'synthetic reset'),
                    ConnectionAbortedError(10053, 'synthetic Windows abort'),
                    PermissionError(13, 'synthetic unrelated error'), TimeoutError('synthetic timeout')]
        for observer in [http_framing_contract, http_process_contract]:
            for outcome in outcomes:
                for data in [response, response[:-1]]:
                    with self.subTest(observer=observer.__name__, outcome=type(outcome).__name__, complete=data==response):
                        stream = mock.MagicMock()
                        stream.__enter__.return_value = stream
                        stream.recv.side_effect = [data, outcome]
                        with mock.patch.object(observer.socket, 'create_connection', return_value=stream):
                            if isinstance(outcome, (PermissionError, TimeoutError)):
                                with self.assertRaises(type(outcome)):
                                    observer.exchange(1, b'GET / HTTP/1.1\r\n\r\n', {})
                            elif data!=response:
                                with self.assertRaises(AssertionError):
                                    observer.exchange(1, b'GET / HTTP/1.1\r\n\r\n', {})
                            else:
                                self.assertEqual(observer.exchange(1, b'GET / HTTP/1.1\r\n\r\n', {})['status_line'], 'HTTP/1.1 200 OK')
        for outcome in outcomes[1:]:
            for received in ['', 'eA==']:
                with self.subTest(denial=type(outcome).__name__, application_bytes=bool(received)):
                    row = {'received_base64': received}
                    with mock.patch.object(http_tls_contract, 'exchange', side_effect=outcome):
                        if isinstance(outcome, (PermissionError, TimeoutError)):
                            with self.assertRaises(type(outcome)):
                                http_tls_contract.denied(1, b'public-fixture', None, row)
                        elif received:
                            with self.assertRaises(AssertionError):
                                http_tls_contract.denied(1, b'public-fixture', None, row)
                        else:
                            http_tls_contract.denied(1, b'public-fixture', None, row)
                            self.assertIs(row['rejected'], True)


DECLARED_CELLS = [(implementation, profile, native_os)
                  for implementation in ('go', 'rust') for profile in ('tcp-output', 'tls-output', 'tcp-five')
                  for native_os in ('Linux', 'Darwin', 'Windows')]


class WindowsGoTcpOutputDeclaredDifference(unittest.TestCase):
    """#1470 exemption: synthetic predicate/validator controls, never native Windows evidence."""

    OUTPUT = {'received_chunk_bytes': 25613743, 'declared_chunk_length': 25613736}

    def test_only_the_go_windows_tcp_output_cell_is_exempt(self):
        exempt = [cell for cell in DECLARED_CELLS
                  if contract.declared_write_difference(*cell, self.OUTPUT) is not None]
        self.assertEqual(exempt, [('go', 'tcp-output', 'Windows')])
        entry = contract.declared_write_difference('go', 'tcp-output', 'Windows', self.OUTPUT)
        assert entry is not None
        self.assertEqual(entry, dict(
            implementation='go', profile='tcp-output', native_os='Windows', received_chunk_bytes=25613743,
            declared_chunk_length=25613736, decision=contract.WINDOWS_GO_TCP_OUTPUT_DECISION, reason=entry['reason']))
        self.assertIn('#1470', entry['reason'])

    def test_strict_assertion_message_is_unchanged_and_not_reachable_for_rust(self):
        source = contract.Path(contract.__file__).read_text(encoding='utf-8')
        self.assertEqual(source.count("'expired write resumed after fast client drain'"), 1)
        self.assertIn("else:assert output['received_chunk_bytes']<output['declared_chunk_length'],", source)

    VALIDATOR = 'python3 scripts/rust-port/gate_area_check.py receipt target/native-http-write.json --profile http-write'

    def validator(self):
        """The hosted workflow validates the receipt with the local gate's http-write profile."""
        text = (contract.ROOT / '.github/workflows/rust-http-write.yml').read_text(encoding='utf-8')
        self.assertIn(self.VALIDATOR, text)
        return [contract.sys.executable, '-B', str(contract.ROOT / 'scripts/rust-port/gate_area_check.py'),
                'receipt', 'target/native-http-write.json', '--profile', 'http-write']

    def receipt(self, native_os, commit, declared, rust_complete=False):
        profiles = ['tcp-five', 'tcp-short', 'tls12-short', 'tls13-short', 'tcp-output', 'tls-output']
        def observed(implementation, profile):
            row = {'case': 'ping-after', 'response': {'status_line': 'HTTP/1.1 200 OK'}}
            data = dict(rows=[row] * 3, processes=[dict(output_capture_complete=True, output_capture_errors=[],
                                                        forced_cleanup_not_graceful_evidence=True)],
                        late_body=dict(peer_terminal_observed=True, forced_client_close=False,
                                       sent_body_suffix_bytes=16, body_completed_seconds=3),
                        handshake_peer={}, slow_output={})
            if profile in {'tls12-short', 'tls13-short'}:
                data['handshake_peer'] = dict(sender_joined=True, peer_terminal_observed=True, forced_client_close=False,
                                              sent_hello_bytes=10, client_hello_length=100, elapsed_seconds=1)
            if profile in {'tcp-output', 'tls-output'}:
                complete = (implementation == 'go' and profile == 'tcp-output' and native_os == 'Windows') \
                    or (rust_complete and implementation == 'rust' and profile == 'tcp-output')
                data['slow_output'] = dict(peer_terminal_observed=True, forced_client_close=False, slow_read_calls=5,
                                           slow_received_bytes=8192, fast_drain_started_seconds=35,
                                           declared_chunk_length=self.OUTPUT['declared_chunk_length'],
                                           received_chunk_bytes=self.OUTPUT['received_chunk_bytes'] if complete else 245760)
            return data
        return dict(passed=True, candidate_worktree_clean=True, candidate_worktree_clean_at_end=True, scope='full',
                    candidate_commit=commit, native_os=native_os, differences=[], declared_differences=declared,
                    profiles={name: {} for name in profiles},
                    go={name: observed('go', name) for name in profiles},
                    rust={name: observed('rust', name) for name in profiles})

    def run_validator(self, native_os, declared, rust_complete=False):
        with contract.tempfile.TemporaryDirectory() as raw:
            base = contract.Path(raw)
            git = ['git', '-c', 'user.name=t', '-c', 'user.email=t@example.invalid']
            contract.checked(['git', 'init', '-q'], base)
            contract.checked(git + ['commit', '-q', '--allow-empty', '-m', 'x'], base)
            commit = contract.checked(['git', 'rev-parse', 'HEAD'], base).decode().strip()
            (base / 'target').mkdir()
            (base / 'target/native-http-write.json').write_text(contract.json.dumps(
                self.receipt(native_os, commit, declared, rust_complete)), encoding='utf-8')
            return subprocess.run(self.validator(), cwd=base, capture_output=True, text=True).returncode

    def test_workflow_validator_is_platform_correct_and_never_exempts_rust(self):
        entry = contract.declared_write_difference('go', 'tcp-output', 'Windows', self.OUTPUT)
        assert entry is not None
        # The receipt must come from the host that validates it (the http-write profile checks native_os).
        host = platform.system()
        other = 'Darwin' if host == 'Linux' else 'Linux'
        self.assertEqual(self.run_validator(host, []), 0)
        self.assertNotEqual(self.run_validator(other, []), 0)
        # The Windows legs are dropped (ADR 0036): the hosted validator accepts Linux and Darwin only, so a Windows
        # receipt fails with or without the recorded declared difference.
        self.assertNotEqual(self.run_validator('Windows', [entry]), 0)
        self.assertNotEqual(self.run_validator('Windows', []), 0)
        self.assertNotEqual(self.run_validator(host, [entry]), 0)
        self.assertNotEqual(self.run_validator('Windows', [entry, entry]), 0)
        self.assertNotEqual(self.run_validator('Windows', [{**entry, 'implementation': 'rust'}]), 0)
        self.assertNotEqual(self.run_validator('Windows', [{**entry, 'profile': 'tls-output'}]), 0)
        self.assertNotEqual(self.run_validator('Windows', [{**entry, 'reason': 'no reference'}]), 0)
        self.assertNotEqual(self.run_validator('Windows', [{**entry, 'received_chunk_bytes': 1}]), 0)
        self.assertNotEqual(self.run_validator('Windows', [entry], rust_complete=True), 0)
        self.assertNotEqual(self.run_validator(host, [], rust_complete=True), 0)


class StarvedOutputPrecondition(unittest.TestCase):
    """The slow-read probe needs bytes before the write budget ends; a starved host may not deliver any."""

    def test_budgets_escalate_and_are_whole_seconds(self):
        seconds = [contract.budget_seconds(budget) for budget in contract.OUTPUT_BUDGETS]
        self.assertEqual(seconds[0], 30)
        self.assertEqual(seconds, sorted(set(seconds)))
        self.assertGreaterEqual(contract.EXCHANGE_TIMEOUT, 30)
        # Only the two output profiles are retried; every other profile keeps its fixed budget.
        self.assertEqual({name for name, _, _ in contract.PROFILES if name.endswith('-output')},
                         {'tls-output', 'tcp-output'})

    def test_progress_needs_four_reads_and_4096_bytes(self):
        self.assertTrue(contract.output_progressing(dict(slow_read_calls=4, slow_received_bytes=4096)))
        self.assertFalse(contract.output_progressing(dict(slow_read_calls=3, slow_received_bytes=4096)))
        self.assertFalse(contract.output_progressing(dict(slow_read_calls=4, slow_received_bytes=4095)))
        # The observed starved-host failures: no byte at all, or a late trickle (13 reads, 98 bytes).
        self.assertFalse(contract.output_progressing(dict(slow_read_calls=0, slow_received_bytes=0)))
        self.assertFalse(contract.output_progressing(dict(slow_read_calls=13, slow_received_bytes=98)))

    def observe(self, progress):
        calls = []
        def starved_or_progressing(port, tokens, row, tls, budget):
            calls.append(budget)
            row.update(progress)
        server = mock.Mock()
        server.child.pid = 1
        exchanged = mock.Mock(return_value={'status_line': 'HTTP/1.1 200 OK', 'raw_base64': ''})
        result = dict(rows=[], processes=[], late_body={'received_base64': ''}, handshake_peer={}, slow_output={})
        with mock.patch.object(contract, 'Server', return_value=server), \
                mock.patch.object(contract, 'request', return_value=b'GET'), \
                mock.patch.object(contract, 'tcp_exchange', exchanged), \
                mock.patch.object(contract, 'late_body'), \
                mock.patch.object(contract, 'slow_output', starved_or_progressing), \
                mock.patch.object(contract, 'assert_response'):
            try:
                contract.observe('bin', 'home', 1, {}, None, 'tcp-output', None, result, 60)
            except BaseException as error:
                return error, calls, exchanged, server
        return None, calls, exchanged, server

    def test_starved_output_stops_before_the_next_exchange_and_closes_the_server(self):
        error, calls, exchanged, server = self.observe(dict(slow_read_calls=0, slow_received_bytes=0))
        self.assertIsInstance(error, contract.OutputPreconditionUnmet)
        self.assertEqual(calls, [60], 'the attempt budget must reach the slow-read phase')
        self.assertEqual(exchanged.call_count, 2, 'ping-after must not wait on a server still busy with the bulk response')
        server.close.assert_called_once()

    def test_progressing_output_reaches_the_expiry_verdict_unchanged(self):
        error, calls, exchanged, _ = self.observe(dict(slow_read_calls=5, slow_received_bytes=8192, received_base64=''))
        self.assertIsNone(error)
        self.assertEqual(exchanged.call_count, 3)

    def test_listener_wait_tolerates_a_starved_host(self):
        import http_oauth_contract
        self.assertGreaterEqual(http_oauth_contract.LISTEN_DEADLINE, 120)
        self.assertGreaterEqual(http_tls_contract.LISTEN_DEADLINE, 120)

    def test_exchanges_use_the_load_tolerant_timeout(self):
        _, _, exchanged, _ = self.observe(dict(slow_read_calls=5, slow_received_bytes=8192, received_base64=''))
        for call in exchanged.call_args_list:
            self.assertEqual(call.kwargs['timeout'], contract.EXCHANGE_TIMEOUT)


class StarvedExchange(unittest.TestCase):
    """A live server closing a plain exchange before any response byte is a starved attempt, nothing else is."""

    def server(self, alive=True):
        server = mock.Mock()
        server.child.pid = 1
        server.child.poll.return_value = None if alive else 1
        return server

    def classify(self, error, row, alive=True):
        def exchange():
            raise error
        try:
            contract.starved_exchange(self.server(alive), '/x/bin/symvault', 'tls12-short', 'initialize', row, exchange)
        except BaseException as caught:
            return caught
        self.fail('exchange error was swallowed')

    def test_reset_before_any_byte_by_a_live_server_is_starved(self):
        for error in [ConnectionResetError(104, 'reset'), ssl.SSLEOFError(8, 'eof'), http_tls_contract.EmptyTLSResponse('empty'),
                      ValueError('not enough values to unpack')]:
            caught = self.classify(error, dict(raw_base64=''))
            self.assertIsInstance(caught, contract.ExchangeStarved, error)
            self.assertEqual(caught.details['binary'], 'symvault')
            self.assertEqual(caught.details['profile'], 'tls12-short')
            self.assertEqual(caught.details['case'], 'initialize')
            self.assertEqual(caught.details['error_type'], type(error).__name__)

    def test_partial_response_dead_server_and_other_errors_still_fail(self):
        partial = dict(raw_base64=base64.b64encode(b'HTTP/1.1 200 OK\r\n').decode())
        reset = ConnectionResetError(104, 'reset')
        self.assertIs(self.classify(reset, partial), reset)
        self.assertIs(self.classify(reset, dict(raw_base64=''), alive=False), reset)
        tls_partial = dict(received_base64=base64.b64encode(b'x').decode())
        self.assertIs(self.classify(reset, tls_partial), reset)
        other = AssertionError('status')
        self.assertIs(self.classify(other, dict(raw_base64='')), other)

    def test_successful_exchange_is_returned_unchanged(self):
        response = {'status_line': 'HTTP/1.1 200 OK'}
        self.assertIs(contract.starved_exchange(self.server(), 'b', 'p', 'c', {}, lambda: response), response)

    def test_attempts_are_bounded_and_repeat_the_same_budget(self):
        self.assertGreaterEqual(contract.EXCHANGE_ATTEMPTS, 2)
        self.assertLessEqual(contract.EXCHANGE_ATTEMPTS, 3)

    def test_observe_reports_a_starved_plain_exchange(self):
        server = self.server()
        reset = mock.Mock(side_effect=ConnectionResetError(104, 'reset'))
        result = dict(rows=[], processes=[], late_body={'received_base64': ''}, handshake_peer={}, slow_output={})
        with mock.patch.object(contract, 'Server', return_value=server), \
                mock.patch.object(contract, 'request', return_value=b'GET'), \
                mock.patch.object(contract, 'tcp_exchange', reset):
            with self.assertRaises(contract.ExchangeStarved) as caught:
                contract.observe('bin', 'home', 1, {}, None, 'tcp-short', None, result, 1)
        self.assertEqual(caught.exception.details['case'], 'initialize')
        server.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
