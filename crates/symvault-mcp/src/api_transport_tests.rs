use super::*;
use hickory_resolver::proto::{
    op::Message,
    rr::{
        RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Instant,
};

struct DnsFixture {
    address: SocketAddr,
    stopped: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    observed: mpsc::Receiver<SocketAddr>,
}

impl DnsFixture {
    fn new(addresses: Vec<IpAddr>, stall: bool) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopped);
        let (send, observed) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut bytes = [0u8; 4096];
            while !stop.load(Ordering::Acquire) {
                let (count, peer) = match socket.recv_from(&mut bytes) {
                    Ok(value) => value,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(error) => panic!("fixture DNS read: {error}"),
                };
                let request = Message::from_vec(&bytes[..count]).unwrap();
                send.send(peer).unwrap();
                if stall {
                    continue;
                }
                let mut response = Message::response(request.metadata.id, request.metadata.op_code);
                response.metadata.authoritative = true;
                response.metadata.recursion_available = true;
                response.metadata.recursion_desired = request.metadata.recursion_desired;
                response.edns = request.edns.clone();
                for query in request.queries {
                    response.add_query(query.clone());
                    for address in &addresses {
                        let data = match (query.query_type(), address) {
                            (RecordType::A, IpAddr::V4(ip)) => Some(RData::A(A(*ip))),
                            (RecordType::AAAA, IpAddr::V6(ip)) => Some(RData::AAAA(AAAA(*ip))),
                            _ => None,
                        };
                        if let Some(data) = data {
                            response.add_answer(Record::from_rdata(query.name().clone(), 0, data));
                        }
                    }
                }
                socket.send_to(&response.to_vec().unwrap(), peer).unwrap();
            }
        });
        Self {
            address,
            stopped,
            worker: Some(worker),
            observed,
        }
    }
}

impl Drop for DnsFixture {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn template(base: String, private: bool) -> ApiTemplate {
    ApiTemplate {
        base_url: base,
        allowed_endpoints: vec!["/safe/*".into()],
        allowed_methods: vec!["GET".into()],
        default_headers: BTreeMap::new(),
        allow_private: private,
    }
}

#[test]
fn actual_dns_accepts_public_answers_and_rejects_mixed_private_and_oversize() {
    for (answers, expected) in [
        (
            vec!["192.0.2.7".parse().unwrap(), "2001:db8::7".parse().unwrap()],
            None,
        ),
        (
            vec!["192.0.2.7".parse().unwrap(), "::1".parse().unwrap()],
            Some("blocked private or local upstream host"),
        ),
        (
            vec!["::ffff:127.0.0.1".parse().unwrap()],
            Some("blocked private or local upstream host"),
        ),
        (
            (1..=33)
                .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
                .collect(),
            Some("invalid upstream address set"),
        ),
    ] {
        let dns = DnsFixture::new(answers.clone(), false);
        let target =
            Target::parse("https://public-api.example.test:443", "/safe/item", false).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(resolve_addresses(
            &target,
            false,
            &RequestContext::default().with_timeout(Duration::from_secs(2)),
            Some(dns.address),
        ));
        if let Some(error) = expected {
            assert_eq!(result.unwrap_err(), error);
        } else {
            let actual = result.unwrap();
            for ip in answers {
                assert!(actual.contains(&SocketAddr::new(ip, 443)));
            }
        }
        assert!(
            dns.observed.try_iter().count() >= 2,
            "both DNS families must execute"
        );
    }
}

#[test]
fn cancelled_dns_releases_the_actual_owned_udp_socket() {
    let dns = DnsFixture::new(Vec::new(), true);
    let server = dns.address;
    let context = RequestContext::default();
    let request_context = context.clone();
    let worker = thread::spawn(move || {
        let target =
            Target::parse("https://waiting-api.example.test", "/safe/item", false).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(resolve_addresses(
                &target,
                false,
                &request_context,
                Some(server),
            ))
    });
    let peer = dns.observed.recv_timeout(Duration::from_secs(2)).unwrap();
    let started = Instant::now();
    context.cancel();
    assert_eq!(
        worker.join().unwrap().unwrap_err(),
        "upstream request cancelled"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    let reclaimed =
        UdpSocket::bind(peer).expect("cancelled owned resolver must release its real UDP port");
    drop(reclaimed);
}

#[test]
fn stopping_egress_during_dns_joins_workers_and_releases_socket() {
    use symvault_store::Store;
    for connect_request in [false, true] {
        let dns = DnsFixture::new(Vec::new(), true);
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("entries")).unwrap();
        std::fs::create_dir(root.path().join("templates")).unwrap();
        std::fs::write(
            root.path().join("config.yaml"),
            "vault:\n  format_version: 2\n",
        )
        .unwrap();
        std::fs::write(root.path().join("identity.age"), b"test layout marker").unwrap();
        // A credential read before completed DNS preflight would return 500
        // without ever sending the actual DNS packet required below.
        std::fs::write(root.path().join("templates/fixture.yaml"),
            "base_url: https://waiting-broker.example.test\nauth_type: bearer\nentry_ref: missing-entry\nallowed_methods: [GET]\nallowed_endpoints: [/safe/*]\n").unwrap();
        let identity = symvault_crypto::generate_identity();
        let store = Store::open(root.path(), &identity).unwrap();
        let broker = EgressBroker::new(root.path(), &store, &identity, EgressOptions::default())
            .unwrap()
            .with_dns_server(dns.address);
        let stop = broker.shutdown();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut stopped_at = None;
        let mut dns_peer = None;
        broker
            .with_running(listener, || {
                let mut client = std::net::TcpStream::connect(address).unwrap();
                client
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let first = if connect_request {
                    "CONNECT waiting-broker.example.test:443 HTTP/1.1"
                } else {
                    "GET https://waiting-broker.example.test/safe/item HTTP/1.1"
                };
                write!(
                    client,
                    "{first}\r\nHost: waiting-broker.example.test\r\n\r\n"
                )
                .unwrap();
                dns_peer = Some(dns.observed.recv_timeout(Duration::from_secs(2)).unwrap());
                stopped_at = Some(Instant::now());
                stop.cancel().unwrap();
                let mut byte = [0];
                match client.read(&mut byte) {
                    Ok(0) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ) => {}
                    other => panic!("cancelled DNS client remained live: {other:?}"),
                }
                Ok(())
            })
            .unwrap();
        assert!(stopped_at.unwrap().elapsed() < Duration::from_secs(1));
        let reclaimed = UdpSocket::bind(dns_peer.unwrap())
            .expect("joined broker resolver must release its UDP port");
        drop(reclaimed);
        assert!(
            std::net::TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err()
        );
        let reclaimed_listener =
            TcpListener::bind(address).expect("stopped broker must release its listener");
        drop(reclaimed_listener);
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request = String::new();
    for _ in 0..64 {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        request.push_str(&line);
        if line == "\r\n" {
            return request;
        }
    }
    panic!("fixture request header bound");
}

#[test]
fn cancelling_pending_api_headers_closes_upstream_and_joins() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (send, observed) = mpsc::channel();
    let upstream = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        assert!(request.contains("authorization: Bearer public-cancel-canary\r\n"));
        send.send(()).unwrap();
        assert_eq!(
            stream.read(&mut [0u8]).unwrap(),
            0,
            "owned upstream must receive EOF"
        );
    });
    let context = RequestContext::default();
    let child_context = context.clone();
    let worker = thread::spawn(move || {
        execute_http_with_context(
            &template(format!("http://{address}"), true),
            "GET",
            "/safe/item",
            &BTreeMap::new(),
            b"",
            Some("public-cancel-canary"),
            &child_context,
            &ApiTransportOptions::default(),
        )
    });
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    let started = Instant::now();
    context.cancel();
    let error = worker.join().unwrap().unwrap_err();
    assert_eq!(error, "upstream request cancelled");
    assert!(!error.contains("public-cancel-canary"));
    upstream.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn progressing_api_body_still_reaches_absolute_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        stream
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
            .unwrap();
        let started = Instant::now();
        let mut sent = 0;
        while started.elapsed() < Duration::from_secs(2) {
            if stream.write_all(b"x").is_err() {
                return sent;
            }
            sent += 1;
            match stream.read(&mut [0u8]) {
                Ok(0) => return sent,
                // Dropping a response while unread body bytes arrive can
                // close TCP with RST rather than FIN. Both prove that the
                // owned connection has ended; a live idle socket does not.
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => return sent,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                value => panic!("unexpected client bytes: {value:?}"),
            }
        }
        panic!("deadline did not close upstream");
    });
    let started = Instant::now();
    let error = execute_http_with_context(
        &template(format!("http://{address}"), true),
        "GET",
        "/safe/item",
        &BTreeMap::new(),
        b"",
        None,
        &RequestContext::default().with_timeout(Duration::from_millis(150)),
        &ApiTransportOptions::default(),
    )
    .unwrap_err();
    assert_eq!(error, "upstream request timed out");
    assert!(
        upstream.join().unwrap() >= 2,
        "response must make progress before timing out"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn actual_dns_https_verifies_chain_hostname_and_redacts_positive_control() {
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["dns-api.example.test".into()]).unwrap();
    params.use_authority_key_identifier_extension = true;
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = params.signed_by(&key, &ca).unwrap();
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone(), ca.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap(),
    );
    for (host, trusted, expected_request) in [
        ("dns-api.example.test", true, true),
        ("wrong-api.example.test", true, false),
        ("dns-api.example.test", false, false),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_config = Arc::clone(&config);
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut stream = rustls::StreamOwned::new(
                rustls::ServerConnection::new(server_config).unwrap(),
                socket,
            );
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") && request.len() < 16384 {
                let mut byte = [0];
                match stream.read(&mut byte) {
                    Ok(1) => request.push(byte[0]),
                    _ => return false,
                }
            }
            assert!(
                String::from_utf8_lossy(&request)
                    .contains("authorization: Bearer public-TLS-canary\r\n")
            );
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nX-Echo: public-TLS-canary\r\nConnection: close\r\n\r\npublic-TLS-canary").unwrap();
            stream.flush().unwrap();
            true
        });
        let dns = DnsFixture::new(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)], false);
        let options = ApiTransportOptions {
            dns_server: Some(dns.address),
            upstream_root_certificates: if trusted {
                vec![reqwest::Certificate::from_pem(ca.pem().as_bytes()).unwrap()]
            } else {
                vec![]
            },
        };
        let result = execute_http_with_context(
            &template(format!("https://{host}:{}", address.port()), true),
            "GET",
            "/safe/item",
            &BTreeMap::new(),
            b"",
            Some("public-TLS-canary"),
            &RequestContext::default().with_timeout(Duration::from_secs(2)),
            &options,
        );
        assert_eq!(server.join().unwrap(), expected_request);
        assert!(dns.observed.try_iter().count() >= 2);
        if expected_request {
            let response = result.unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.body, b"***");
            assert_eq!(response.headers["X-Echo"], "***");
            assert!(!response.headers.contains_key("Connection"));
            assert!(response.sanitized);
        } else {
            assert_eq!(result.unwrap_err(), "upstream request failed");
        }
    }
}
