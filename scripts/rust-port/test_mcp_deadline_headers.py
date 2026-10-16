#!/usr/bin/env python3
"""Compile and exercise the frozen diagnostic header reader with real loopback IO.

Stdlib-only helper regression, NOT the owning suite or a Linux observation.
Run separately before admission; never add a test to the diagnostic owning suite.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap

import mcp_deadline_diagnostic as diagnostic


PROBE = r'''
use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{atomic::AtomicBool, mpsc};
use std::thread;
use std::time::{Duration, Instant};

struct ObservedReader(BufReader<TcpStream>, mpsc::Sender<usize>);
impl Read for ObservedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.0.read(buf) }
}
impl BufRead for ObservedReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> { self.0.fill_buf() }
    fn consume(&mut self, n: usize) { self.0.consume(n); }
    fn read_line(&mut self, line: &mut String) -> io::Result<usize> {
        let result = self.0.read_line(line);
        if result.as_ref().is_err_and(|e| matches!(e.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)) {
            let _ = self.1.send(line.len());
        }
        result
    }
}

#[test]
fn real_read_timeouts_preserve_partial_headers_and_byte_limit() {
    for oversized in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (timeout_tx, timeout_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            let mut reader = ObservedReader(BufReader::new(stream), timeout_tx);
            diagnostic_read_headers(&mut reader, &AtomicBool::new(false),
                                    Instant::now() + Duration::from_secs(5))
        });
        let mut client = TcpStream::connect(address).unwrap();
        client.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        // Synchronize on a REAL socket timeout, not a guessed scheduling delay.
        assert_eq!(timeout_rx.recv_timeout(Duration::from_secs(2)).unwrap(), 0);
        let partial = if oversized { vec![b'x'; 10000] } else { b"GET / HTTP/1.1\r\nX: partial".to_vec() };
        client.write_all(&partial).unwrap();
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            let length = timeout_rx.recv_timeout(until.saturating_duration_since(Instant::now())).unwrap();
            if length > 0 { break; }
        }
        if oversized {
            client.write_all(&vec![b'y'; 7000]).unwrap();
            client.write_all(b"\r\n\r\n").unwrap();
        } else {
            client.write_all(b"\r\n").unwrap();
            // Finishing the partial header must NOT be mistaken for an empty line.
            let until = Instant::now() + Duration::from_secs(2);
            loop {
                let length = timeout_rx.recv_timeout(until.saturating_duration_since(Instant::now())).unwrap();
                if length == 0 { break; }
            }
            client.write_all(b"\r\n").unwrap();
        }
        assert_eq!(server.join().unwrap(), !oversized);
    }
}

#[test]
fn eof_stop_and_deadline_do_not_admit_incomplete_headers() {
    for input in [b"".as_slice(), b"X: truncated".as_slice()] {
        assert!(!diagnostic_read_headers(&mut io::Cursor::new(input),
            &AtomicBool::new(false), Instant::now() + Duration::from_secs(1)));
    }
    assert!(!diagnostic_read_headers(&mut io::Cursor::new(b"\r\n"),
        &AtomicBool::new(true), Instant::now() + Duration::from_secs(1)));
    assert!(!diagnostic_read_headers(&mut io::Cursor::new(b"\r\n"),
        &AtomicBool::new(false), Instant::now()));
}
'''


def main():
    patch = diagnostic.ROOT / diagnostic.PATCH
    diagnostic.require(diagnostic.digest(patch) == diagnostic.PATCH_SHA, 'patch digest mismatch')
    text = patch.read_text()
    marker = '+    fn diagnostic_read_headers('
    diagnostic.require(text.count(marker) == 1, 'ambiguous frozen header reader')
    diagnostic.require(text.count('+            if !diagnostic_read_headers(&mut reader, &stop, deadline) {') == 1,
                       'diagnostic server must use the tested reader')
    frozen = marker + text.split(marker, 1)[1].split('+    struct TraceSession', 1)[0]
    diagnostic.require(all(line.startswith('+') for line in frozen.splitlines()), 'unexpected patch context')
    helper = textwrap.dedent(''.join(line[1:] for line in frozen.splitlines(keepends=True)))
    rustc = os.environ.get('RUSTC', 'rustc')
    version = subprocess.check_output([rustc, '--version'], text=True)
    diagnostic.require(version.startswith('rustc 1.98.0 '), 'pinned Rust 1.98.0 required')
    with tempfile.TemporaryDirectory(prefix='deadline-headers-', dir=os.environ['TMPDIR']) as raw:
        root = Path(raw)
        source = root / 'headers.rs'
        source.write_text('use std::io::BufRead;\n' + helper + PROBE)
        binary = root / ('headers.exe' if os.name == 'nt' else 'headers')
        subprocess.run([rustc, '--edition=2024', '--test', '-D', 'warnings', str(source), '-o', str(binary)],
                       check=True, timeout=60)
        subprocess.run([str(binary)], check=True, timeout=20)
    print('PASS actual frozen header reader; host-only helper regression, not native-suite acceptance')


if __name__ == '__main__':
    main()
