#!/usr/bin/env python3
"""Synthetic socket-error controls, not native deadline acceptance evidence."""
import ssl
import unittest
from unittest import mock

import http_write_contract as contract
import http_tls_contract
import http_framing_contract
import http_process_contract


class WriteDeadlineSocketErrors(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
