#!/usr/bin/env python3
"""Synthetic socket-error controls, not native deadline acceptance evidence."""
import ssl
import unittest
from unittest import mock

import http_write_contract as contract


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


if __name__ == '__main__':
    unittest.main()
