//! Explicit transport cancellation. This does not roll back dispatched tool calls.

use std::{
    collections::HashMap,
    io,
    net::{Shutdown, TcpStream},
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

#[derive(Default)]
struct State {
    cancelled: bool,
    next_id: usize,
    sockets: HashMap<usize, TcpStream>,
}

/// Cancels socket I/O and wakes the HTTP accept loop.
///
/// This is transport cancellation, not graceful draining or cancellation of an
/// executing application callback. The server still joins its scoped workers.
#[derive(Clone, Default)]
pub struct HttpShutdown {
    state: Arc<(Mutex<State>, Condvar)>,
}

fn close_transport(socket: &TcpStream) -> io::Result<()> {
    match socket.shutdown(Shutdown::Both) {
        Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(()),
        result => result,
    }
}

impl HttpShutdown {
    // Windows shutdown does not wake a blocking recv/send (Rust 1.98's
    // std/net/tcp/tests.rs, close_read_wakes_up). Cancellable sockets use
    // nonblocking I/O, retaining the caller's full per-operation timeout.
    pub(super) fn socket_io<T>(
        &self,
        timeout: Option<Duration>,
        mut operation: impl FnMut() -> io::Result<T>,
    ) -> io::Result<T> {
        let started = Instant::now();
        loop {
            if self.is_cancelled()? {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "HTTP transport cancelled",
                ));
            }
            match operation() {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if timeout.is_some_and(|timeout| started.elapsed() >= timeout) {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "HTTP socket timeout",
                        ));
                    }
                    self.wait_for_activity()?;
                }
                result => return result,
            }
        }
    }

    /// Prevents new admissions and interrupts every registered transport.
    pub fn cancel(&self) -> io::Result<()> {
        let (lock, changed) = &*self.state;
        let mut state = lock
            .lock()
            .map_err(|_| io::Error::other("HTTP shutdown state poisoned"))?;
        state.cancelled = true;
        changed.notify_all();
        let mut first_error = None;
        for socket in state.sockets.values() {
            if let Err(error) = close_transport(socket)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(super) fn is_cancelled(&self) -> io::Result<bool> {
        self.state
            .0
            .lock()
            .map(|state| state.cancelled)
            .map_err(|_| io::Error::other("HTTP shutdown state poisoned"))
    }

    pub(super) fn wait_for_activity(&self) -> io::Result<()> {
        let (lock, changed) = &*self.state;
        let state = lock
            .lock()
            .map_err(|_| io::Error::other("HTTP shutdown state poisoned"))?;
        // ponytail: bounded nonblocking socket polling avoids another reactor;
        // replace with the platform event loop if measured idle cost warrants it.
        let _state = changed
            .wait_timeout_while(state, Duration::from_millis(10), |state| !state.cancelled)
            .map_err(|_| io::Error::other("HTTP shutdown state poisoned"))?;
        Ok(())
    }

    pub(super) fn register(&self, socket: &TcpStream) -> io::Result<Option<ConnectionGuard>> {
        let mut state = self
            .state
            .0
            .lock()
            .map_err(|_| io::Error::other("HTTP shutdown state poisoned"))?;
        if state.cancelled {
            close_transport(socket)?;
            return Ok(None);
        }
        let id = state.next_id;
        state.next_id = state
            .next_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("HTTP connection identity exhausted"))?;
        state.sockets.insert(id, socket.try_clone()?);
        Ok(Some(ConnectionGuard {
            shutdown: self.clone(),
            id,
        }))
    }
}

pub(super) struct ConnectionGuard {
    shutdown: HttpShutdown,
    id: usize,
}

pub(super) struct CancelOnDrop(pub(super) HttpShutdown);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        let _ = self.0.cancel();
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        // Cleanup must also release sockets after a worker panic poisons state.
        let mut state = self
            .shutdown
            .state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.sockets.remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        thread,
        time::Instant,
    };

    struct ServerProbe {
        shutdown: HttpShutdown,
        worker: Option<thread::JoinHandle<io::Result<()>>>,
    }

    impl Drop for ServerProbe {
        fn drop(&mut self) {
            let _ = self.shutdown.cancel();
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn start(listener: TcpListener, registry: std::path::PathBuf) -> ServerProbe {
        let shutdown = HttpShutdown::default();
        let worker_shutdown = shutdown.clone();
        let worker = thread::spawn(move || {
            super::super::serve_loopback_until_cancelled(
                listener,
                registry,
                |_| panic!("unauthenticated discovery must not create an agent runtime"),
                worker_shutdown,
            )
        });
        ServerProbe {
            shutdown,
            worker: Some(worker),
        }
    }

    fn discovery(stream: &mut TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bounded response read");
        let address = stream.peer_addr().expect("server address");
        write!(
            stream,
            "GET /.well-known/oauth-protected-resource HTTP/1.1\r\nHost: {address}\r\n\r\n"
        )
        .expect("send real discovery request");
        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        reader.read_line(&mut status).expect("read status");
        assert_eq!(status, "HTTP/1.1 200 OK\r\n");
        let mut content_length = None;
        loop {
            let mut line = String::new();
            assert_ne!(
                reader.read_line(&mut line).expect("read header"),
                0,
                "peer closed before completing discovery headers"
            );
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.strip_prefix("Content-Length: ") {
                content_length = Some(value.trim().parse::<usize>().expect("body length"));
            }
        }
        let mut body = vec![0; content_length.expect("content length")];
        reader.read_exact(&mut body).expect("read discovery body");
        let body: serde_json::Value = serde_json::from_slice(&body).expect("discovery JSON");
        assert_eq!(body["resource"], format!("http://{address}/mcp"));
    }

    fn socket_cancellation_case(keep_alive: bool) {
        let root = tempfile::tempdir().expect("isolated registry root");
        let registry = root.path().join("tokens.json");
        std::fs::write(&registry, br#"{"tokens":{}}"#).expect("empty synthetic registry");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
        let address = listener.local_addr().expect("listener address");
        let mut server = start(listener, registry.clone());
        let mut client = TcpStream::connect(address).expect("connect client");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound reads before peer can reset the socket");
        if keep_alive {
            discovery(&mut client);
        } else {
            client
                .write_all(b"GET /mcp HTTP/1.1\r\nHost: ")
                .expect("incomplete request");
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while server
            .shutdown
            .state
            .0
            .lock()
            .expect("state")
            .sockets
            .is_empty()
        {
            assert!(
                Instant::now() < deadline,
                "server never registered the real client"
            );
            thread::yield_now();
        }
        server.shutdown.cancel().expect("cancel transports");
        let deadline = Instant::now() + Duration::from_secs(2);
        while !server.worker.as_ref().expect("worker").is_finished() {
            assert!(
                Instant::now() < deadline,
                "server failed to join canceled I/O"
            );
            thread::yield_now();
        }
        server
            .worker
            .take()
            .expect("worker")
            .join()
            .expect("server join")
            .expect("server result");
        let mut byte = [0];
        match client.read(&mut byte) {
            Ok(0) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            outcome => panic!("expected EOF or peer reset, not timeout/data: {outcome:?}"),
        }
        assert!(
            server
                .shutdown
                .state
                .0
                .lock()
                .expect("state")
                .sockets
                .is_empty()
        );
        server.shutdown.cancel().expect("idempotent cancellation");

        let listener = TcpListener::bind(address).expect("rebind exact endpoint after join");
        let mut replacement = start(listener, registry);
        let mut follow_up = TcpStream::connect(address).expect("reconnect replacement");
        discovery(&mut follow_up);
        replacement.shutdown.cancel().expect("cancel replacement");
        replacement
            .worker
            .take()
            .expect("replacement worker")
            .join()
            .expect("join replacement")
            .expect("replacement result");
    }

    #[test]
    fn cancellation_joins_idle_keep_alive_and_rebinds_real_endpoint() {
        socket_cancellation_case(true);
    }

    #[test]
    fn cancellation_joins_incomplete_request_and_rebinds_real_endpoint() {
        socket_cancellation_case(false);
    }

    #[test]
    fn cancellation_before_start_does_not_accept_a_request() {
        let root = tempfile::tempdir().expect("registry root");
        let registry = root.path().join("tokens.json");
        std::fs::write(&registry, br#"{"tokens":{}}"#).expect("registry");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let shutdown = HttpShutdown::default();
        shutdown.cancel().expect("pre-cancel");
        super::super::serve_loopback_until_cancelled(
            listener,
            registry,
            |_| panic!("pre-canceled server cannot dispatch"),
            shutdown,
        )
        .expect("server returns");
        let _rebound = TcpListener::bind(address).expect("listener released");
    }

    #[test]
    fn registration_after_cancellation_closes_socket_without_admission() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let mut client =
            TcpStream::connect(listener.local_addr().expect("address")).expect("connect");
        let (socket, _) = listener.accept().expect("accept");
        let shutdown = HttpShutdown::default();
        shutdown.cancel().expect("cancel before registration");
        assert!(
            shutdown
                .register(&socket)
                .expect("register canceled socket")
                .is_none()
        );
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read bound");
        assert_eq!(client.read(&mut [0]).expect("peer closure"), 0);
        assert!(shutdown.state.0.lock().expect("state").sockets.is_empty());
    }

    #[test]
    fn already_disconnected_transport_is_benign_in_both_cancellation_paths() {
        for before_registration in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let _client =
                TcpStream::connect(listener.local_addr().expect("address")).expect("connect");
            let (socket, _) = listener.accept().expect("accept");
            let shutdown = HttpShutdown::default();
            let guard = if before_registration {
                shutdown.cancel().expect("cancel before registration");
                None
            } else {
                shutdown.register(&socket).expect("register live transport")
            };
            socket
                .shutdown(Shutdown::Both)
                .expect("disconnect actual transport");
            let repeated_shutdown = socket.shutdown(Shutdown::Both);
            eprintln!(
                "native repeated shutdown: {:?}",
                repeated_shutdown.as_ref().err().map(io::Error::kind)
            );
            #[cfg(target_os = "macos")]
            assert_eq!(
                repeated_shutdown
                    .expect_err("Darwin reports an already shut socket")
                    .kind(),
                io::ErrorKind::NotConnected
            );
            if before_registration {
                assert!(
                    shutdown
                        .register(&socket)
                        .expect("benign disconnected registration")
                        .is_none()
                );
            } else {
                shutdown
                    .cancel()
                    .expect("benign disconnected registered socket");
            }
            drop(guard);
            assert!(shutdown.state.0.lock().expect("state").sockets.is_empty());
        }
    }

    #[test]
    fn cancellable_io_preserves_timeout_and_wakes_without_socket_shutdown() {
        let shutdown = HttpShutdown::default();
        let started = Instant::now();
        let result: io::Result<()> = shutdown.socket_io(Some(Duration::from_millis(20)), || {
            Err(io::ErrorKind::WouldBlock.into())
        });
        assert_eq!(
            result.expect_err("retained operation deadline").kind(),
            io::ErrorKind::TimedOut
        );
        assert!(started.elapsed() >= Duration::from_millis(20));

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker_shutdown = shutdown.clone();
        let worker = thread::spawn(move || {
            let mut ready = Some(ready_tx);
            let result: io::Result<()> = worker_shutdown.socket_io(None, || {
                if let Some(ready) = ready.take() {
                    ready.send(()).expect("notify pending I/O");
                }
                Err(io::ErrorKind::WouldBlock.into())
            });
            done_tx.send(result).expect("notify completed I/O");
        });
        ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("I/O started");
        // No registered socket: cancellation must wake the retry wait itself,
        // independent of whether the native shutdown syscall wakes recv/send.
        shutdown.cancel().expect("cancel pending I/O");
        let result = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("bounded cancellation");
        worker.join().expect("join completed I/O");
        assert_eq!(
            result.expect_err("cancelled I/O").kind(),
            io::ErrorKind::ConnectionAborted
        );
        let _: io::Result<()> = shutdown.socket_io(None, || panic!("cancelled I/O must not retry"));
    }

    fn saturation_case(abort_peers: bool) {
        let root = tempfile::tempdir().expect("registry root");
        let registry = root.path().join("tokens.json");
        std::fs::write(&registry, br#"{"tokens":{}}"#).expect("registry");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let mut server = start(listener, registry);
        let clients: Vec<_> = (0..super::super::MAX_HTTP_CONNECTIONS)
            .map(|_| TcpStream::connect(address).expect("occupy connection"))
            .collect();
        let deadline = Instant::now() + Duration::from_secs(2);
        while server.shutdown.state.0.lock().expect("state").sockets.len() != clients.len() {
            assert!(
                Instant::now() < deadline,
                "not all connections were registered"
            );
            thread::yield_now();
        }
        if abort_peers {
            // Abort after the first reply byte, while later response writes
            // may still be pending. Every following peer must still be served.
            for _ in 0..64 {
                let mut peer = TcpStream::connect(address).expect("aborting excess peer");
                peer.set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("aborting peer bound");
                peer.read_exact(&mut [0]).expect("busy reply started");
            }
            assert!(
                !server.shutdown.is_cancelled().expect("listener state"),
                "an overflow peer abort must not cancel admitted transports"
            );
        }
        let excess = TcpStream::connect(address).expect("excess connection");
        excess
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("response bound");
        // Consume the complete reply before closing the peer. Dropping after
        // only the status line can reset the socket during the remaining
        // writes on Windows, testing a peer abort rather than cancellation.
        // One-byte buffering exercises fragmented reads; cap the transcript.
        let response: Vec<u8> = BufReader::with_capacity(1, excess)
            .bytes()
            .take(256)
            .collect::<io::Result<_>>()
            .expect("busy response");
        assert_eq!(
            response,
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-Length: 12\r\nConnection: close\r\n\r\nserver busy\n"
        );
        server
            .shutdown
            .cancel()
            .expect("cancel saturated transports");
        let deadline = Instant::now() + Duration::from_secs(2);
        while !server.worker.as_ref().expect("worker").is_finished() {
            assert!(Instant::now() < deadline, "saturated server did not finish");
            thread::yield_now();
        }
        server
            .worker
            .take()
            .expect("worker")
            .join()
            .expect("join")
            .expect("clean cancellation");
    }

    #[test]
    fn saturated_connections_keep_busy_response_and_cancel_cleanly() {
        saturation_case(false);
    }

    #[test]
    fn saturated_peer_aborts_do_not_terminate_listener() {
        saturation_case(true);
    }

    #[test]
    fn discovery_negative_control_rejects_truncated_headers_without_eof_loop() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind malformed peer");
        let address = listener.local_addr().expect("address");
        let peer = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read bound");
            let mut reader = BufReader::new(socket.try_clone().expect("clone"));
            loop {
                let mut line = String::new();
                assert_ne!(reader.read_line(&mut line).expect("request line"), 0);
                if line == "\r\n" {
                    break;
                }
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n")
                .expect("truncated response");
            socket.shutdown(Shutdown::Write).expect("close response");
        });
        let mut client = TcpStream::connect(address).expect("connect");
        let rejected =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| discovery(&mut client)));
        peer.join().expect("join malformed peer");
        assert!(
            rejected.is_err(),
            "helper must reject EOF before header terminator"
        );
    }
}
