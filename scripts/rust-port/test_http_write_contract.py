#!/usr/bin/env python3
"""Synthetic socket-error controls, not native deadline acceptance evidence."""
import copy
import io
import ssl
import unittest
from unittest import mock

import http_write_contract as contract
import http_tls_contract
import http_framing_contract
import http_process_contract
import http_winsock_metadata as winsock


class WriteDeadlineSocketErrors(unittest.TestCase):
    def test_winsock_export_is_scoped_numeric_and_fails_closed(self):
        # Synthetic privacy/identity checks only, not actual ETW or Windows evidence.
        canary = 'synthetic-authorization-canary'
        root = winsock.ET.Element('Events')
        receipt = {name: {'tcp-output': {'server_process_id': pid}}
                   for name, pid in [('go', 101), ('rust', 102)]}
        def event(process, endpoint, fields, creation=False):
            node = winsock.ET.SubElement(root, winsock.NAMESPACE + 'Event')
            system = winsock.ET.SubElement(node, winsock.NAMESPACE + 'System')
            winsock.ET.SubElement(system, winsock.NAMESPACE + 'Provider', Name=winsock.PROVIDER)
            winsock.ET.SubElement(system, winsock.NAMESPACE + 'TimeCreated', SystemTime='2026-10-07T14:00:00.1234567Z')
            winsock.ET.SubElement(system, winsock.NAMESPACE + 'Execution', ProcessID='4')
            for key in ('EventID', 'Version', 'Level', 'Task', 'Opcode'):
                winsock.ET.SubElement(system, winsock.NAMESPACE + key).text = '18' if key == 'EventID' and not creation else '1'
            data = winsock.ET.SubElement(node, winsock.NAMESPACE + 'EventData')
            values = {'Process': process, 'Endpoint': endpoint, **fields}
            if creation:
                values.update(SocketType=1, Protocol=6)
            for key, value in values.items():
                winsock.ET.SubElement(data, winsock.NAMESPACE + 'Data', Name=key).text = str(value)
            winsock.ET.SubElement(node, winsock.NAMESPACE + 'RenderingInfo').text = canary
            return node
        event('0x111', '0x777', {'UserModePid': 101}, True)
        event('0x111', '0x777', {'BufferLength': 123, 'Buffer': canary, 'Payload': canary})
        event('0x111', '0x777', {'UserModePid': 101}, True)  # Reused address, distinct lifetime.
        event('0x222', '0x888', {'UserModePid': 102}, True)
        event('0x222', '0x888', {'BufferLength': 456})
        event('0x111', '0x999', {'UserModePid': 999}, True)  # Reused kernel process address.
        event('0x111', '0x999', {'BufferLength': 789})
        def export(tree=root, summary='Events Lost: 0\nBuffers Lost: 0\n' + canary):
            return winsock.metadata(io.BytesIO(winsock.ET.tostring(tree)), receipt, summary)
        report = export()
        with self.subTest(boundary='unrelated unknown fields cannot affect report'):
            unrelated = copy.deepcopy(root)
            winsock.ET.SubElement(next(unrelated[-1].iter(winsock.NAMESPACE + 'EventData')),
                                 winsock.NAMESPACE + 'Data', Name='UnrelatedPayload').text = canary
            self.assertEqual(export(unrelated), report)
            self.assertNotIn('discarded_field_count', report)
        with self.subTest(boundary='non-creation identity fields cannot remap or reset'):
            spoofed = copy.deepcopy(root)
            fake_creation = copy.deepcopy(root[0])
            next(fake_creation.iter(winsock.NAMESPACE + 'EventID')).text = '18'
            next(node for node in fake_creation.iter(winsock.NAMESPACE + 'Data') if node.get('Name') == 'UserModePid').text = '999'
            spoofed.insert(2, fake_creation)
            checked = export(spoofed)
            self.assertEqual(checked['events'][2]['pid'], 101)
            self.assertEqual(checked['events'][2]['endpoint_id'], checked['events'][0]['endpoint_id'])
            self.assertNotEqual(checked['events'][3]['endpoint_id'], checked['events'][0]['endpoint_id'])
        with contract.tempfile.TemporaryDirectory(prefix='symvault-winsock-privacy-') as raw:
            base = contract.Path(raw)
            trace, receipt_path, summary_path, output = [base / name for name in ('trace.xml', 'receipt.json', 'summary.txt', 'metadata.json')]
            trace.write_bytes(winsock.ET.tostring(root))
            receipt_path.write_text(contract.json.dumps(receipt), encoding='utf-8')
            summary_path.write_text('Events Lost: 0\nBuffers Lost: 0\n' + canary, encoding='utf-16')
            contract.checked([contract.sys.executable, contract.Path(winsock.__file__), '--trace', trace,
                              '--receipt', receipt_path, '--summary', summary_path, '--output', output])
            self.assertEqual(contract.json.loads(output.read_text(encoding='utf-8')), report)
            invalid_cli = copy.deepcopy(root)
            next(node for node in invalid_cli[1].iter(winsock.NAMESPACE + 'Data') if node.get('Name') == 'BufferLength').text = canary
            trace.write_bytes(winsock.ET.tostring(invalid_cli))
            rejected_output = base / 'rejected.json'
            with self.assertRaises(RuntimeError) as failure:
                contract.checked([contract.sys.executable, contract.Path(winsock.__file__), '--trace', trace,
                                  '--receipt', receipt_path, '--summary', summary_path, '--output', rejected_output])
            self.assertFalse(rejected_output.exists())
            self.assertNotIn(canary, str(failure.exception))
            self.assertIn('unsupported Winsock integer field: BufferLength', str(failure.exception))
        encoded = contract.json.dumps(report)
        self.assertNotIn(canary, encoded)
        self.assertNotIn('0x111', encoded)
        self.assertNotIn('0x777', encoded)
        self.assertEqual({row['pid'] for row in report['events']}, {101, 102})
        self.assertEqual([row['data']['BufferLength'] for row in report['events'] if 'BufferLength' in row['data']], [123, 456])
        self.assertNotEqual(report['events'][0]['endpoint_id'], report['events'][2]['endpoint_id'])
        self.assertTrue(report['loss_verified'])
        self.assertFalse(export(summary=canary)['loss_verified'])
        self.assertFalse(export(summary='Events Lost: 1\nBuffers Lost: 0')['loss_verified'])
        for value in [canary, str(1 << 64), '1.2', '']:
            invalid = copy.deepcopy(root)
            field = next(node for node in invalid[1].iter(winsock.NAMESPACE + 'Data') if node.get('Name') == 'BufferLength')
            field.text = value
            with self.assertRaises(ValueError) as failure:
                export(invalid)
            self.assertNotIn(canary, str(failure.exception))
            self.assertEqual(str(failure.exception), 'unsupported Winsock integer field: BufferLength')
        duplicate = copy.deepcopy(root)
        winsock.ET.SubElement(next(duplicate[1].iter(winsock.NAMESPACE + 'EventData')), winsock.NAMESPACE + 'Data', Name='BufferLength').text = '123'
        with self.assertRaises(ValueError):
            export(duplicate)
        missing = copy.deepcopy(root)
        next(node for node in missing[1].iter(winsock.NAMESPACE + 'Data') if node.get('Name') == 'Endpoint').text = '0x999'
        with self.assertRaises(ValueError):
            export(missing)
        one_server = copy.deepcopy(root)
        one_server.remove(one_server[4])
        one_server.remove(one_server[3])
        with self.assertRaises(ValueError):
            export(one_server)
        incomplete_creation = copy.deepcopy(root)
        fields = next(incomplete_creation[0].iter(winsock.NAMESPACE + 'EventData'))
        fields.remove(next(node for node in fields if node.get('Name') == 'Protocol'))
        with self.assertRaises(ValueError):
            export(incomplete_creation)

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
