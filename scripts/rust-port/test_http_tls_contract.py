#!/usr/bin/env python3
"""Negative controls of the ALPN pin in http_tls_contract.py (ADR 0034 item 20).

The contract run itself needs a Go oracle and a Rust CLI. These controls need
neither: a small stand-in TLS server negotiates a configurable ALPN list, and
the contract's own observation function (`alpn_offer`) and pin (`alpn_check`,
`alpn_compare`) run against it over a real socket. A Rust that started to offer
`h2` must fail the pin, a Go-like server must pass it, and a tampered
observation must fail it.
"""
import copy
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
import http_tls_contract as c

PING = b'POST /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'
OK = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
SETTINGS = bytes([0, 0, 0, 4, 0, 0, 0, 0, 0])
VERSIONS = {'tls12': ssl.TLSVersion.TLSv1_2, 'tls13': ssl.TLSVersion.TLSv1_3}


class StandInServer:
    """TLS listener with a fixed ALPN list; speaks h2 (a SETTINGS frame) when it selected h2, else HTTP/1.1."""

    def __init__(self, directory, version, alpn):
        cert, key = directory / 'cert.pem', directory / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
                        '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost'], check=True, capture_output=True)
        self.server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server.minimum_version = self.server.maximum_version = VERSIONS[version]
        self.server.load_cert_chain(cert, key)
        if alpn:
            self.server.set_alpn_protocols(alpn)
        self.cafile = str(cert)
        self.client = ssl.create_default_context(cafile=self.cafile)
        self.client.minimum_version = self.client.maximum_version = VERSIONS[version]
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        self.stop = False
        self.worker = threading.Thread(target=self.serve, daemon=True)
        self.worker.start()

    def serve(self):
        while not self.stop:
            try:
                raw, _ = self.listener.accept()
            except OSError:
                return
            try:
                raw.settimeout(5)
                with self.server.wrap_socket(raw, server_side=True) as stream:
                    if stream.selected_alpn_protocol() == 'h2':
                        data = b''
                        while len(data) < len(c.H2_PREFACE):
                            part = stream.recv(4096)
                            if not part:
                                break
                            data += part
                        stream.sendall(SETTINGS)
                    else:
                        data = b''
                        while b'\r\n\r\n' not in data:
                            part = stream.recv(4096)
                            if not part:
                                break
                            data += part
                        stream.sendall(OK)
            except (OSError, ssl.SSLError):
                pass

    def close(self):
        self.stop = True
        self.listener.close()
        self.worker.join(timeout=5)

    def offers(self):
        rows = []
        for case, offered in c.ALPN_OFFERS:
            row = {}
            rows.append(row)
            c.alpn_offer(self.port, self._context(offered), case, offered, row, PING)
        return rows

    def _context(self, offered):
        ctx = ssl.create_default_context(cafile=self.cafile)
        ctx.minimum_version, ctx.maximum_version = self.client.minimum_version, self.client.maximum_version
        ctx.set_alpn_protocols(offered)
        return ctx

def stand_in(test, version, alpn):
    directory = Path(tempfile.mkdtemp(prefix='alpn-stand-in-'))
    test.addCleanup(shutil.rmtree, directory, True)
    server = StandInServer(directory, version, alpn)
    test.addCleanup(server.close)
    return server


class AlpnPin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A skipped negative control is not a pass: fail when openssl is missing.
        if not shutil.which('openssl'):
            raise RuntimeError('openssl is needed to mint the stand-in certificate')

    def test_rust_without_alpn_passes_on_every_profile(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                rows = stand_in(self, version, None).offers()
                self.assertEqual([r['selected'] for r in rows], [None, None, None])
                c.alpn_check('rust', version, rows)

    def test_go_like_plain_tls_selects_h2_and_serves_it(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                rows = stand_in(self, version, ['h2', 'http/1.1']).offers()
                self.assertEqual([r['selected'] for r in rows], ['h2', 'http/1.1', 'h2'])
                self.assertEqual([r['h2_settings_frame'] for r in rows], [True, None, True])
                c.alpn_check('go', version, rows)

    def test_go_like_mtls_selects_nothing(self):
        rows = stand_in(self, 'tls13', None).offers()
        c.alpn_check('go', 'mtls13', rows)

    def test_rust_that_offers_h2_fails_the_pin(self):
        for version in VERSIONS:
            with self.subTest(version=version):
                rows = stand_in(self, version, ['h2', 'http/1.1']).offers()
                with self.assertRaisesRegex(AssertionError, "negotiated 'h2'"):
                    c.alpn_check('rust', version, rows)

    def test_rust_that_offers_only_http11_fails_the_pin(self):
        rows = stand_in(self, 'tls13', ['http/1.1']).offers()
        self.assertEqual([r['selected'] for r in rows], ['http/1.1', 'http/1.1', None])
        with self.assertRaises(AssertionError):
            c.alpn_check('rust', 'tls13', rows)

    def test_go_that_stopped_offering_h2_fails_the_pin(self):
        rows = stand_in(self, 'tls12', None).offers()
        with self.assertRaisesRegex(AssertionError, 'negotiated None'):
            c.alpn_check('go', 'tls12', rows)

    def test_go_that_started_offering_h2_on_mtls_fails_the_pin(self):
        rows = stand_in(self, 'tls13', ['h2', 'http/1.1']).offers()
        with self.assertRaises(AssertionError):
            c.alpn_check('go', 'mtls13', rows)

    def test_h2_selected_without_h2_service_fails_the_pin(self):
        rows = stand_in(self, 'tls13', ['h2', 'http/1.1']).offers()
        rows[0]['h2_settings_frame'] = False
        with self.assertRaisesRegex(AssertionError, 'h2 service'):
            c.alpn_check('go', 'tls13', rows)

    def test_http11_service_must_answer_200(self):
        rows = stand_in(self, 'tls13', None).offers()
        rows[1]['http1_status_line'] = 'HTTP/1.1 500 X'
        with self.assertRaisesRegex(AssertionError, 'HTTP/1.1 service'):
            c.alpn_check('rust', 'tls13', rows)

    def test_wrong_offer_list_fails_the_pin(self):
        rows = stand_in(self, 'tls13', None).offers()
        rows[0]['offered'] = ['http/1.1']
        with self.assertRaisesRegex(AssertionError, 'offer'):
            c.alpn_check('rust', 'tls13', rows)


class AlpnCompare(unittest.TestCase):
    @staticmethod
    def rows(selected):
        return [{'case': case, 'selected': value} for (case, _), value in zip(c.ALPN_OFFERS, selected)]

    def test_go_selection_against_no_rust_selection_is_the_declared_difference(self):
        declared, undeclared = c.alpn_compare('tls13', self.rows(['h2', 'http/1.1', 'h2']), self.rows([None] * 3))
        self.assertEqual(undeclared, [])
        self.assertEqual([(d['case'], d['go_selected'], d['rust_selected'], d['decision']) for d in declared],
                         [('h2-and-http11', 'h2', None, 'alpn-http11-only'),
                          ('http11-only', 'http/1.1', None, 'alpn-http11-only'),
                          ('h2-only', 'h2', None, 'alpn-http11-only')])

    def test_identical_selection_is_no_difference(self):
        self.assertEqual(c.alpn_compare('mtls13', self.rows([None] * 3), self.rows([None] * 3)), ([], []))

    def test_equal_selection_is_left_to_the_pin(self):
        # Rust 'h2' equal to Go 'h2' is no difference between the two; `alpn_check('rust', ...)` rejects it.
        declared, undeclared = c.alpn_compare('tls13', self.rows(['h2', 'http/1.1', 'h2']),
                                              self.rows(['h2', None, None]))
        self.assertEqual([d['case'] for d in declared], ['http11-only', 'h2-only'])
        self.assertEqual(undeclared, [])

    def test_rust_selecting_a_different_protocol_than_go_is_undeclared(self):
        declared, undeclared = c.alpn_compare('tls13', self.rows(['h2', None, None]), self.rows(['http/1.1', None, None]))
        self.assertEqual(declared, [])
        self.assertEqual([(u['case'], u['go_selected'], u['rust_selected']) for u in undeclared],
                         [('h2-and-http11', 'h2', 'http/1.1')])

    def test_pin_tables(self):
        self.assertEqual(c.RUST_ALPN, None)
        self.assertEqual([case for case, _ in c.ALPN_OFFERS], ['h2-and-http11', 'http11-only', 'h2-only'])
        for case, _ in c.ALPN_OFFERS:
            self.assertIsNone(c.alpn_expected('rust', 'tls12', case))
            self.assertIsNone(c.alpn_expected('go', 'mtls12', case))
        self.assertEqual([c.alpn_expected('go', 'tls13', case) for case, _ in c.ALPN_OFFERS], ['h2', 'http/1.1', 'h2'])


if __name__ == '__main__':
    unittest.main()
