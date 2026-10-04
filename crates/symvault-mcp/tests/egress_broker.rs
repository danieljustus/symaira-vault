//! Real encrypted entries, TCP/TLS peers and service cancellation; no network mocks.
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use symvault_mcp::broker::{EgressBroker, EgressOptions};
use symvault_store::{Entry, Store};

fn vault(root: &std::path::Path) -> (symvault_crypto::Identity, Store) {
    fs::create_dir(root.join("entries")).unwrap();
    fs::create_dir(root.join("templates")).unwrap();
    fs::write(root.join("config.yaml"), "vault:\n  format_version: 2\n").unwrap();
    fs::write(root.join("identity.age"), b"test layout marker").unwrap();
    let identity = symvault_crypto::generate_identity();
    let store = Store::open(root, &identity).unwrap();
    store
        .write_entry(
            "fixture",
            &Entry {
                data: BTreeMap::from([
                    ("credential".into(), json!("public-fixture-secret-9f31")),
                    ("username".into(), json!("public-fixture-user")),
                    (
                        "nested".into(),
                        json!({"token":"public-nested-secret-c771"}),
                    ),
                ]),
                ..Entry::default()
            },
            &identity,
        )
        .unwrap();
    (identity, store)
}

fn raw_request(address: std::net::SocketAddr, request: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
}

#[test]
fn egress_preflight_denies_before_credential_read_or_upstream_contact() {
    let root = tempfile::tempdir().unwrap();
    let (identity, store) = vault(root.path());
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let target = upstream.local_addr().unwrap();
    // Missing credentials would produce 500 if preflight incorrectly decrypted.
    fs::write(root.path().join("templates/fixture.yaml"), format!(
        "base_url: https://{target}\nauth_type: bearer\nentry_ref: missing-entry\nallowed_methods: [GET]\nallowed_endpoints: [/allowed]\nallow_private: true\n"
    )).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let broker =
        EgressBroker::new(root.path(), &store, &identity, EgressOptions::default()).unwrap();
    broker
        .with_running(listener, || {
            for target in [
                format!("https://{target}/allowed"),
                format!("http://{target}/allowed"),
                format!("https://{target}/denied"),
            ] {
                let response = raw_request(
                    address,
                    &format!("GET {target} HTTP/1.1\r\nHost: irrelevant.example\r\n\r\n"),
                );
                assert!(response.starts_with(b"HTTP/1.1 403"), "{response:?}");
                assert!(
                    !response
                        .windows(b"missing-entry".len())
                        .any(|b| b == b"missing-entry")
                );
            }
            assert_eq!(
                upstream.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            Ok(())
        })
        .unwrap();
    // The template's allow_private cannot override production destination denial.
}

#[test]
fn egress_decoded_path_acl_denies_before_entry_read_or_normalization() {
    let root = tempfile::tempdir().unwrap();
    let (identity, store) = vault(root.path());
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let target = upstream.local_addr().unwrap();
    let template = root.path().join("templates/fixture.yaml");
    let write_template = |pattern: &str| {
        fs::write(&template, format!(
            "base_url: http://{target}\nauth_type: bearer\nentry_ref: missing-entry\nallowed_methods: [GET]\nallowed_endpoints: ['{pattern}']\n"
        )).unwrap();
    };
    write_template("/v1/%61llowed");
    let broker = EgressBroker::new(
        root.path(),
        &store,
        &identity,
        EgressOptions {
            allow_private: true, // Explicit in-process fixture seam, never a CLI flag.
            ..EgressOptions::default()
        },
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    broker
        .with_running(listener, || {
            for (path, pattern, status) in [
                ("/v1/%61llowed", "/v1/%61llowed", "403"),
                ("/v1/../denied", "/denied", "403"),
                ("/v1/%2e%2e/denied", "/denied", "403"),
                ("/v1/%zz", "/v1/*", "400"),
                ("/v1/%ff", "/v1/*", "400"),
            ] {
                write_template(pattern);
                let response = raw_request(
                    address,
                    &format!("GET http://{target}{path} HTTP/1.1\r\nHost: {target}\r\n\r\n"),
                );
                // Touching the missing entry would produce 500. No authority can
                // be admitted using Url's normalized path or a lossy UTF-8 decode.
                assert!(
                    response.starts_with(format!("HTTP/1.1 {status}").as_bytes()),
                    "{response:?}"
                );
            }
            assert_eq!(
                upstream.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn egress_verified_mitm_injects_and_masks_real_encrypted_credentials() {
    let root = tempfile::tempdir().unwrap();
    let (identity, store) = vault(root.path());
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = upstream.local_addr().unwrap();
    fs::write(root.path().join("templates/fixture.yaml"), format!(
        "base_url: https://{target}\nauth_type: bearer\nentry_ref: fixture\nallowed_methods: [POST]\nallowed_endpoints: [/v1/*]\nsubstitutions:\n  - placeholder: __SECRET__\n    field: credential\n    in: [path, query, header, body]\n"
    )).unwrap();
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let tls = symvault_mcp::http::load_tls_server_config(
        fixture.join("tls-server.pem"),
        fixture.join("tls-server.key"),
        None,
    )
    .unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    thread::scope(|scope| {
        let accepted = accepted.clone();
        let peer = scope.spawn(move || {
            for _ in 0..2 {
                let (stream, _) = upstream.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut stream = rustls::StreamOwned::new(rustls::ServerConnection::new(tls.clone()).unwrap(), stream);
                let mut bytes = Vec::new();
                loop {
                    let mut byte = [0];
                    match stream.read(&mut byte) { Ok(1) => bytes.push(byte[0]), _ => break }
                    if bytes.ends_with(b"\r\n\r\n") { break; }
                }
                if bytes.is_empty() { continue; } // Closed CONNECT reachability probe.
                let headers = String::from_utf8(bytes).unwrap();
                assert!(headers.starts_with("POST /v1/public-fixture-secret-9f31?token=public-fixture-secret-9f31 HTTP/1.1"));
                assert!(headers.to_ascii_lowercase().contains("authorization: bearer public-fixture-secret-9f31"));
                assert!(headers.to_ascii_lowercase().contains("x-sub: public-fixture-secret-9f31"));
                let mut body = vec![0; "public-fixture-secret-9f31".len()]; stream.read_exact(&mut body).unwrap();
                assert_eq!(body, b"public-fixture-secret-9f31");
                accepted.fetch_add(1, Ordering::SeqCst);
                let body = b"public-fixture-secret-9f31 public-nested-secret-c771\x00\xff";
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Echo: public-fixture-secret-9f31\r\nSet-Cookie: a=public-fixture-secret-9f31\r\nSet-Cookie: b=public-nested-secret-c771\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(body).unwrap(); stream.flush().unwrap();
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let broker = EgressBroker::new(
            root.path(),
            &store,
            &identity,
            EgressOptions {
                allow_private: true,
                upstream_ca_pem: Some(fs::read(fixture.join("tls-ca.pem")).unwrap()),
                ..EgressOptions::default()
            },
        )
        .unwrap();
        broker
            .with_running(listener, || {
                let client = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .proxy(reqwest::Proxy::all(format!("http://{address}")).unwrap())
                    .add_root_certificate(
                        reqwest::Certificate::from_pem(broker.ca_pem().as_bytes()).unwrap(),
                    )
                    .build()
                    .unwrap();
                let response = client
                    .post(format!("https://{target}/v1/__SECRET__?token=__SECRET__"))
                    .header("X-Sub", "__SECRET__")
                    .body("__SECRET__")
                    .send()
                    .unwrap();
                assert_eq!(response.status(), 200);
                assert_eq!(response.headers()["x-echo"], "***");
                let cookies = response
                    .headers()
                    .get_all("set-cookie")
                    .iter()
                    .map(|v| v.to_str().unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(cookies, vec!["a=***", "b=***"]);
                assert_eq!(response.bytes().unwrap().as_ref(), b"*** ***\x00\xff");
                Ok(())
            })
            .unwrap();
        peer.join().unwrap();
    });
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

#[test]
fn egress_callback_error_joins_idle_clients_and_releases_listener() {
    let root = tempfile::tempdir().unwrap();
    let (identity, store) = vault(root.path());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let broker =
        EgressBroker::new(root.path(), &store, &identity, EgressOptions::default()).unwrap();
    let mut clients = Vec::new();
    let started = Instant::now();
    let result: Result<(), String> = broker.with_running(listener, || {
        for _ in 0..8 {
            let mut client = TcpStream::connect(address).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            client.write_all(b"GET ").unwrap();
            clients.push(client);
        }
        thread::sleep(Duration::from_millis(100));
        Err("foreground fixture failure".into())
    });
    assert_eq!(result.unwrap_err(), "foreground fixture failure");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err());
    for mut client in clients {
        let mut byte = [0];
        match client.read(&mut byte) {
            Ok(0) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {}
            other => panic!("client stayed live: {other:?}"),
        }
    }
}

#[test]
fn egress_stop_cancels_owned_upstream_request_without_waiting_for_network_timeout() {
    let root = tempfile::tempdir().unwrap();
    let (identity, store) = vault(root.path());
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = upstream.local_addr().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let broker = EgressBroker::new(
        root.path(),
        &store,
        &identity,
        EgressOptions {
            allow_private: true,
            ..EgressOptions::default()
        },
    )
    .unwrap();
    let (ready, received) = std::sync::mpsc::channel();
    let started = Instant::now();
    thread::scope(|scope| {
        let peer = scope.spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
                assert!(headers.len() < 65536);
            }
            ready.send(()).unwrap();
            // No reply. Cancellation must actually close the owned upstream.
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).unwrap(), 0);
        });
        let mut client = None;
        let result: Result<(), String> = broker.with_running(listener, || {
            client = Some(scope.spawn(move || {
                let mut socket = TcpStream::connect(address).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                write!(
                    socket,
                    "GET http://{target}/pending HTTP/1.1\r\nHost: {target}\r\n\r\n"
                )
                .unwrap();
                let mut byte = [0];
                let result = socket.read(&mut byte);
                assert!(
                    matches!(result, Ok(0))
                        || result.is_err_and(|e| matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ))
                );
            }));
            received.recv_timeout(Duration::from_secs(3)).unwrap();
            Err("child fixture ended while upstream was pending".into())
        });
        assert_eq!(
            result.unwrap_err(),
            "child fixture ended while upstream was pending"
        );
        client.unwrap().join().unwrap();
        peer.join().unwrap();
    });
    assert!(started.elapsed() < Duration::from_secs(2));
}
