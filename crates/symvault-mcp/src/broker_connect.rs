//! Owned, bounded CONNECT passthrough. Full broker interception is #1237.

use crate::http::{HttpShutdown, shutdown::ConnectionGuard};
use std::{
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const WORKERS: usize = 4;
const QUEUED: usize = 4;
const HEADER_LIMIT: usize = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// Serve explicitly allowlisted CONNECT tunnels, retaining every worker and
/// relay until it finishes. `allow_private` is a test/application seam; the CLI
/// broker must keep it false, matching Go's production SSRF policy.
pub fn serve_connect_passthrough(
    listener: TcpListener,
    passthrough: Vec<String>,
    strict: bool,
    stopping: &AtomicBool,
    allow_private: bool,
) -> Result<(), String> {
    if passthrough.is_empty() || passthrough.len() > 256 {
        return Err("CONNECT requires 1..256 passthrough hosts".into());
    }
    listener
        .set_nonblocking(true)
        .map_err(|_| "configure broker listener")?;
    let cancellation = HttpShutdown::default();
    thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel::<(TcpStream, ConnectionGuard)>(QUEUED);
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..WORKERS {
            let receiver = receiver.clone();
            let cancellation = cancellation.clone();
            let passthrough = &passthrough;
            scope.spawn(move || {
                while !stopping.load(Ordering::Acquire) {
                    let next = receiver
                        .lock()
                        .expect("CONNECT queue")
                        .recv_timeout(Duration::from_millis(25));
                    match next {
                        Ok((client, _ownership)) => {
                            let _ = handle_client(
                                client,
                                passthrough,
                                strict,
                                allow_private,
                                &cancellation,
                            );
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            });
        }
        let result = (|| {
            while !stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((client, _)) => {
                        configure_accepted_client(&client)
                            .map_err(|_| "configure broker client")?;
                        let Some(ownership) = cancellation
                            .register(&client)
                            .map_err(|_| "own broker client")?
                        else {
                            break;
                        };
                        // A full admission queue owns no additional worker or
                        // payload allocation. Dropping the socket rejects it.
                        let _ = sender.try_send((client, ownership));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10))
                    }
                    Err(_) => return Err("accept broker connection".into()),
                }
            }
            Ok(())
        })();
        drop(sender);
        cancellation
            .cancel()
            .map_err(|_| "cancel broker transport")?;
        result
    })
}

pub(super) fn configure_accepted_client(client: &TcpStream) -> io::Result<()> {
    // macOS accepted sockets inherit the nonblocking listener's mode. Reset
    // before ordinary blocking header reads or relay I/O can see WouldBlock.
    client.set_nonblocking(false)?;
    client.set_read_timeout(Some(IO_TIMEOUT))?;
    client.set_write_timeout(Some(IO_TIMEOUT))
}

pub(super) struct Socket {
    pub(super) stream: TcpStream,
    cancellation: HttpShutdown,
}

impl Socket {
    pub(super) fn new(stream: TcpStream, cancellation: &HttpShutdown) -> io::Result<Self> {
        #[cfg(windows)]
        stream.set_nonblocking(true)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        Ok(Self {
            stream,
            cancellation: cancellation.clone(),
        })
    }
    pub(super) fn duplicate(&self) -> io::Result<Self> {
        Self::new(self.stream.try_clone()?, &self.cancellation)
    }
}

impl Read for Socket {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        #[cfg(windows)]
        {
            self.cancellation
                .socket_io(self.stream.read_timeout()?, || self.stream.read(buffer))
        }
        #[cfg(not(windows))]
        self.stream.read(buffer)
    }
}
impl Write for Socket {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        #[cfg(windows)]
        {
            self.cancellation
                .socket_io(Some(IO_TIMEOUT), || self.stream.write(buffer))
        }
        #[cfg(not(windows))]
        self.stream.write(buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn handle_client(
    client: TcpStream,
    passthrough: &[String],
    strict: bool,
    allow_private: bool,
    cancellation: &HttpShutdown,
) -> Result<(), String> {
    let mut client = Socket::new(client, cancellation).map_err(|_| "configure CONNECT I/O")?;
    let mut header = Vec::with_capacity(1024);
    let started = Instant::now();
    while header.len() < HEADER_LIMIT && started.elapsed() < Duration::from_secs(30) {
        client
            .stream
            .set_read_timeout(Some(
                Duration::from_secs(30)
                    .saturating_sub(started.elapsed())
                    .max(Duration::from_millis(1)),
            ))
            .map_err(|_| "configure CONNECT header deadline")?;
        let mut byte = [0];
        client
            .read_exact(&mut byte)
            .map_err(|_| "read CONNECT header")?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !header.ends_with(b"\r\n\r\n") {
        return Err("CONNECT headers exceed limits".into());
    }
    let header = std::str::from_utf8(&header).map_err(|_| "invalid CONNECT header")?;
    let parts = header
        .lines()
        .next()
        .unwrap_or_default()
        .split(' ')
        .collect::<Vec<_>>();
    if parts.len() != 3 || parts[0] != "CONNECT" || parts[2] != "HTTP/1.1" {
        write_proxy_error(&mut client, 400, "invalid proxy request")?;
        return Ok(());
    }
    let Some((host, addresses)) =
        resolve_connect_target(parts[1], allow_private, cancellation, None)
    else {
        write_proxy_error(&mut client, 403, "CONNECT target is blocked")?;
        return Ok(());
    };
    if !passthrough.iter().any(|entry| host_matches(entry, &host)) {
        let (status, message) = if strict {
            (403, "host is outside the passthrough allowlist")
        } else {
            (
                501,
                "TLS interception is not supported by this CONNECT slice",
            )
        };
        write_proxy_error(&mut client, status, message)?;
        return Ok(());
    }
    let Some(upstream) = connect_checked_addresses(&addresses, cancellation) else {
        write_proxy_error(&mut client, 502, "cannot reach upstream")?;
        return Ok(());
    };
    let Some(_upstream_ownership) = cancellation
        .register(&upstream)
        .map_err(|_| "own CONNECT upstream")?
    else {
        return Ok(());
    };
    let mut upstream = Socket::new(upstream, cancellation).map_err(|_| "configure upstream I/O")?;
    client
        .stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|_| "configure tunnel timeout")?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|_| "write CONNECT response")?;
    let mut client_reader = client.duplicate().map_err(|_| "duplicate client")?;
    let mut upstream_writer = upstream.duplicate().map_err(|_| "duplicate upstream")?;
    thread::scope(|scope| {
        scope.spawn(move || {
            let _ = io::copy(&mut client_reader, &mut upstream_writer);
            let _ = upstream_writer.stream.shutdown(Shutdown::Write);
        });
        let _ = io::copy(&mut upstream, &mut client);
        let _ = client.stream.shutdown(Shutdown::Write);
    });
    Ok(())
}

pub(super) fn resolve_connect_target(
    authority: &str,
    allow_private: bool,
    cancellation: &HttpShutdown,
    dns_server: Option<SocketAddr>,
) -> Option<(String, Vec<SocketAddr>)> {
    if authority.is_empty()
        || authority.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || byte.is_ascii_control()
                || matches!(byte, b'/' | b'@' | b'\\')
        })
    {
        return None;
    }
    let (raw_host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest.split_once("]:")?;
        (host, port)
    } else {
        let (host, port) = authority.rsplit_once(':')?;
        if host.contains(':') {
            return None;
        }
        (host, port)
    };
    if raw_host.is_empty() {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    let host = canonical_host(raw_host);
    if host.is_empty() || host.contains('%') {
        return None;
    }
    let addresses = resolve_destination(&host, port, allow_private, cancellation, dns_server)?;
    Some((host, addresses))
}

pub(super) fn resolve_destination(
    host: &str,
    port: u16,
    allow_private: bool,
    cancellation: &HttpShutdown,
    dns_server: Option<SocketAddr>,
) -> Option<Vec<SocketAddr>> {
    let context = cancellation
        .request_context()
        .with_timeout(Duration::from_secs(10));
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?
        .block_on(super::resolve_host_addresses(
            host,
            port,
            allow_private,
            &context,
            dns_server,
        ))
        .ok()
}

pub(super) fn connect_checked_addresses(
    addresses: &[SocketAddr],
    cancellation: &HttpShutdown,
) -> Option<TcpStream> {
    let context = cancellation
        .request_context()
        .with_timeout(Duration::from_secs(10));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    let stream = runtime
        .block_on(context.wait(async {
            for address in addresses {
                if let Ok(stream) = tokio::net::TcpStream::connect(address).await {
                    return Ok(stream);
                }
            }
            Err("cannot reach upstream".to_owned())
        }))
        .ok()?;
    let stream = stream.into_std().ok()?;
    // Tokio sockets remain nonblocking on conversion, including macOS. The
    // existing transport adapter selects its own cancellable platform mode.
    stream.set_nonblocking(false).ok()?;
    Some(stream)
}

pub(super) fn canonical_host(value: &str) -> String {
    let value = value.trim_start_matches('[').trim_end_matches(']');
    value
        .parse::<IpAddr>()
        .map_or_else(|_| value.to_ascii_lowercase(), |ip| ip.to_string())
}

pub(super) fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    if pattern.starts_with('[')
        && let Some((host_pattern, _)) = pattern.split_once(']')
    {
        return host == canonical_host(host_pattern.trim_start_matches('['));
    }
    let pattern = pattern
        .rsplit_once(':')
        .filter(|(host, _)| !host.contains(':'))
        .map_or(pattern, |(host, _)| host);
    let pattern = canonical_host(pattern);
    if pattern.is_empty() {
        return false;
    }
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

fn write_proxy_error(stream: &mut impl Write, status: u16, message: &str) -> Result<(), String> {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        501 => "Not Implemented",
        _ => "Bad Gateway",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{message}\n",
        message.len() + 1
    )
    .map_err(|error| format!("write proxy error response: {error}"))
}

pub(super) fn private_or_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            ip.to_ipv4_mapped()
                .is_some_and(|mapped| private_or_local(IpAddr::V4(mapped)))
                || ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    fn server() -> (SocketAddr, Arc<AtomicBool>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stopping = Arc::new(AtomicBool::new(false));
        let stop = stopping.clone();
        let worker = thread::spawn(move || {
            serve_connect_passthrough(listener, vec!["127.0.0.1".into()], true, &stop, true)
                .unwrap();
        });
        (address, stopping, worker)
    }

    fn connect(address: SocketAddr, target: SocketAddr) -> BufReader<TcpStream> {
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        write!(
            client,
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
        )
        .unwrap();
        let mut reader = BufReader::new(client);
        let mut status = String::new();
        reader.read_line(&mut status).unwrap();
        assert_eq!(status, "HTTP/1.1 200 Connection Established\r\n");
        let mut blank = String::new();
        reader.read_line(&mut blank).unwrap();
        assert_eq!(blank, "\r\n");
        reader
    }

    #[test]
    fn accepted_socket_reset_preserves_delayed_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            // Make the macOS inherited mode explicit on every native OS so
            // removing the production reset fails this regression everywhere.
            client.set_nonblocking(true).unwrap();
            configure_accepted_client(&client).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut bytes = [0; 4];
            client.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"ping");
        });
        let mut client = TcpStream::connect(address).unwrap();
        thread::sleep(Duration::from_millis(200));
        client.write_all(b"ping").unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn connect_passthrough_tunnels_only_allowlisted_loopback_hosts() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = upstream.local_addr().unwrap();
        let responder = thread::spawn(move || {
            let (mut client, _) = upstream.accept().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut bytes = [0; 4];
            client.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"ping");
            client.write_all(b"pong").unwrap();
        });
        let (address, stopping, worker) = server();
        let mut client = connect(address, target);
        thread::sleep(Duration::from_millis(200));
        client.get_mut().write_all(b"ping").unwrap();
        let mut bytes = [0; 4];
        client.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"pong");
        drop(client);
        responder.join().unwrap();
        stopping.store(true, Ordering::Release);
        worker.join().unwrap();
    }

    #[test]
    fn stopping_joins_idle_relay_and_closes_upstream() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = upstream.local_addr().unwrap();
        let responder = thread::spawn(move || {
            let (mut client, _) = upstream.accept().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut byte = [0];
            assert_eq!(client.read(&mut byte).unwrap(), 0);
        });
        let (address, stopping, worker) = server();
        let _client = connect(address, target);
        let started = Instant::now();
        stopping.store(true, Ordering::Release);
        worker.join().unwrap();
        responder.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn private_and_unlisted_targets_do_not_connect_upstream() {
        let cancellation = HttpShutdown::default();
        assert!(resolve_connect_target("127.0.0.1:443", false, &cancellation, None).is_none());
        assert!(
            resolve_connect_target("[::ffff:127.0.0.1]:443", false, &cancellation, None).is_none()
        );
        assert!(resolve_connect_target("localhost:443", false, &cancellation, None).is_none());
        assert!(host_matches("example.com", "api.example.com"));
        assert!(!host_matches("example.com", "notexample.com"));
        assert!(!host_matches("example.com", "example.com.evil"));
        assert!(host_matches("[::1]:443", "::1"));
        assert!(!host_matches("", "example.com."));
        assert!(!host_matches(":443", "example.com."));
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        upstream.set_nonblocking(true).unwrap();
        let target = upstream.local_addr().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = thread::spawn(move || {
            let (client, _) = listener.accept().unwrap();
            configure_accepted_client(&client).unwrap();
            handle_client(
                client,
                &["different.example".into()],
                true,
                true,
                &HttpShutdown::default(),
            )
            .unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        write!(
            client,
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        worker.join().unwrap();
        assert_eq!(
            upstream.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
