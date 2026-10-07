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
    def test_receiver_observation_decodes_fixed_width_abi_and_fails_closed(self):
        # Synthetic ABI/failure checks only; this is not native Windows evidence.
        self.assertEqual(contract.TCP_INFO_V0.size, 88)
        values = list(range(len(contract.TCP_INFO_FIELDS)))
        values[0], values[3], values[12] = 7, True, 25613736
        payload = contract.TCP_INFO_V0.pack(*values)
        stream = mock.MagicMock()
        stream.fileno.return_value = 123
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
                        with self.assertRaises(AssertionError):
                            contract.socket_observation(stream, 1)
                    else:
                        row = contract.socket_observation(stream, 1)
                        self.assertEqual(row['client_so_rcvbuf'], 4096)
                        self.assertEqual(row['client_so_sndbuf'], 65536)
                        self.assertEqual(row['started_seconds'], .25)
                        self.assertEqual(row['completed_seconds'], .25)
                        self.assertEqual(row['windows_tcp_info_v0'], dict(zip(contract.TCP_INFO_FIELDS, values, strict=True)))

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
