// Focused PR1218 regressions through StoreReadOnlyRuntime::call.
thread_local! {
    pub(super) static API_REVIEW_REQUESTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static API_REVIEW_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn review_api_runtime(root: &Path, base: String) -> StoreReadOnlyRuntime {
    api_approval_runtime(
        root,
        ReadOnlyRuntimeConfig {
            agent_name: "review-agent".into(),
            approval_mode: "none".into(),
            can_run_commands: true,
            allowed_paths: vec!["*".into()],
            ..ReadOnlyRuntimeConfig::default()
        },
        RecordingApproval::new(false, false, false),
        true,
        base,
    )
}

// No blocking accept, bounded socket I/O, and a joined worker even on handler failure.
fn review_echo_server(listener: std::net::TcpListener) -> std::thread::JoinHandle<Option<String>> {
    review_echo_server_with(listener, str::to_owned)
}

fn review_echo_server_with(
    listener: std::net::TcpListener,
    echo: fn(&str) -> String,
) -> std::thread::JoinHandle<Option<String>> {
    review_echo_server_with_bytes(listener, move |target| echo(target).into_bytes())
}

fn review_echo_server_with_bytes(
    listener: std::net::TcpListener,
    echo: impl Fn(&str) -> Vec<u8> + Send + 'static,
) -> std::thread::JoinHandle<Option<String>> {
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        use std::io::{BufRead, Write};
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        // Darwin can inherit O_NONBLOCK from the listener; timeouts require a
        // blocking accepted socket, not a race against request arrival.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let target = line.split_whitespace().nth(1).unwrap().to_owned();
        // This seam receives only our bounded synthetic GET request.
        for _ in 0..64 {
            line.clear();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }
        let body = echo(&target);
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Echo: {}\r\nConnection: close\r\n\r\n",
            body.len(),
            String::from_utf8_lossy(&body)
        )
        .unwrap();
        stream.write_all(&body).unwrap();
        Some(target)
    })
}

#[test]
fn api_review_encoded_substitution_masks_handler_body_and_header() {
    review_assert_substitution_echo(
        "alpha:beta gamma",
        "none",
        "/v1/__TOKEN__?q=__TOKEN__",
        "/v1/alpha:beta%20gamma?q=alpha:beta%20gamma",
        "/v1/***?q=***",
    );
}

#[test]
fn api_review_suffix_substitution_masks_handler_body_and_header() {
    review_assert_substitution_echo(
        "alpha!? beta/..",
        "none",
        "/v1/__TOKEN__x",
        "/v1/alpha!%3F%20beta/..x",
        "/v1/***x",
    );
}

#[test]
fn api_review_query_auth_reencoding_masks_handler_body_and_header() {
    review_assert_substitution_echo(
        "alpha+beta gamma",
        "query_param",
        "/v1/status?q=__TOKEN__",
        "/v1/status?auth_token=separate-auth&q=alpha+beta+gamma",
        "/v1/status?***=***&q=***",
    );
}

#[test]
fn api_review_query_auth_percent_reencoding_masks_handler_body_and_header() {
    review_assert_substitution_echo(
        "alpha%2Fbeta gamma",
        "query_param",
        "/v1/status?q=__TOKEN__",
        "/v1/status?auth_token=separate-auth&q=alpha%2Fbeta+gamma",
        "/v1/status?***=***&q=***",
    );
}

#[test]
fn api_review_query_key_substitution_masks_handler_body_and_header() {
    review_assert_substitution_echo(
        "alpha=beta gamma",
        "query_param",
        "/v1/status?__TOKEN__=foo",
        "/v1/status?alpha=beta+gamma%3Dfoo&auth_token=separate-auth",
        "/v1/status?***=***&***=***",
    );
}

#[test]
fn api_review_query_boundary_substitution_masks_handler_body_and_header() {
    review_assert_substitution_echo(
        "alpha%",
        "query_param",
        "/v1/status?q=__TOKEN__41",
        "/v1/status?auth_token=separate-auth&q=alphaA",
        "/v1/status?***=***&q=***",
    );
}

#[test]
fn api_review_query_utf8_boundary_substitution_masks_handler_body_and_header() {
    review_assert_substitution_echo(
        "alpha%c3",
        "query_param",
        "/v1/status?q=__TOKEN__%bc",
        "/v1/status?auth_token=separate-auth&q=alpha%C3%BC",
        "/v1/status?***=***&q=***",
    );
}

#[test]
fn api_review_query_untainted_field_remains_public() {
    review_assert_substitution_echo(
        "alpha%",
        "query_param",
        "/v1/status?limit=50&q=__TOKEN__41",
        "/v1/status?auth_token=separate-auth&limit=50&q=alphaA",
        "/v1/status?***=***&limit=50&q=***",
    );
}

#[test]
fn api_review_path_dot_suffix_masks_surviving_credential_fragment() {
    review_assert_substitution_echo(
        "alpha!? beta/path/.",
        "none",
        "/v1/__TOKEN__.",
        "/v1/alpha!%3F%20beta/",
        "/v1/***",
    );
}

#[test]
fn api_review_path_multiple_substitutions_mask_surviving_fragment() {
    review_assert_substitution_echo(
        "alpha!? beta/path",
        "none",
        "/v1/__TOKEN__/__TAIL__",
        "/v1/alpha!%3F%20beta/",
        "/v1/***",
    );
}

#[test]
fn api_review_decoded_path_echo_masks_surviving_fragment() {
    review_assert_substitution_echo_with(
        "alpha!? beta/path/.",
        "none",
        "/v1/__TOKEN__.",
        "/v1/alpha!%3F%20beta/",
        "/v1/***",
        |target| {
            let mut url = reqwest::Url::parse(&format!("http://localhost{target}")).unwrap();
            // Independent form decoder, preserving path '+' and '&' literals.
            let path = url.path().replace('+', "%2B").replace('&', "%26");
            url.set_query(Some(&format!("q={path}")));
            url.query_pairs().next().unwrap().1.into_owned()
        },
    );
}

#[test]
fn api_review_decoded_query_echo_masks_boundary_fragment() {
    review_assert_substitution_echo_with(
        "alpha%c3",
        "query_param",
        "/v1/status?q=__TOKEN__%bc",
        "/v1/status?auth_token=separate-auth&q=alpha%C3%BC",
        "***",
        |target| {
            reqwest::Url::parse(&format!("http://localhost{target}"))
                .unwrap()
                .query_pairs()
                .find(|(key, _)| key == "q")
                .unwrap()
                .1
                .into_owned()
        },
    );
}

#[test]
fn api_review_decoded_query_without_query_auth_masks_substitutions() {
    for (credential, endpoint, wire) in [
        (
            "alpha+beta gamma",
            "/v1/status?limit=50&q=__TOKEN__",
            "/v1/status?limit=50&q=alpha+beta%20gamma",
        ),
        (
            "alpha%",
            "/v1/status?limit=50&q=__TOKEN__41",
            "/v1/status?limit=50&q=alpha%41",
        ),
        (
            "alpha%c3",
            "/v1/status?limit=50&q=__TOKEN__%bc",
            "/v1/status?limit=50&q=alpha%c3%bc",
        ),
    ] {
        review_assert_substitution_echo_with(
            credential,
            "none",
            endpoint,
            wire,
            "limit=50&q=***",
            |target| {
                let url = reqwest::Url::parse(&format!("http://localhost{target}")).unwrap();
                url.query_pairs()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect::<Vec<_>>()
                    .join("&")
            },
        );
    }
}

#[test]
fn api_review_decoded_path_with_malformed_percent_masks_surviving_fragment() {
    review_assert_substitution_echo_with(
        "alpha%zz beta/path/.",
        "none",
        "/v1/__TOKEN__.",
        "/v1/alpha%zz%20beta/",
        "/v1/***",
        |target| {
            let mut url = reqwest::Url::parse(&format!("http://localhost{target}")).unwrap();
            let path = url.path().replace('+', "%2B").replace('&', "%26");
            url.set_query(Some(&format!("q={path}")));
            url.query_pairs().next().unwrap().1.into_owned()
        },
    );
}

#[test]
fn api_review_raw_query_fields_mask_delimiter_split_credentials() {
    for (credential, endpoint, wire) in [
        (
            "alpha:beta gamma&next=ignored",
            "/v1/status?limit=50&q=__TOKEN__",
            "/v1/status?limit=50&q=alpha:beta%20gamma&next=ignored",
        ),
        (
            "alpha:beta gamma=hidden&next=ignored",
            "/v1/status?limit=50&__TOKEN__=public",
            "/v1/status?limit=50&alpha:beta%20gamma=hidden&next=ignored=public",
        ),
    ] {
        review_assert_substitution_echo_with(
            credential,
            "none",
            endpoint,
            wire,
            "limit=50&***",
            |target| {
                let query = target.split_once('?').unwrap().1;
                let field = query.split('&').nth(1).unwrap();
                let (key, value) = field.split_once('=').unwrap();
                format!("limit=50&{}", if key == "q" { value } else { key })
            },
        );
    }
}

#[test]
fn api_review_binary_decoded_path_masks_go_body_replacement() {
    review_assert_substitution_echo_with_bytes(
        "alpha%E2%82beta/path/.",
        "none",
        "/v1/__TOKEN__.",
        "/v1/alpha%E2%82beta/",
        "/v1/***",
        |target| {
            // Upstream independently decodes its received target into bytes,
            // without converting incomplete UTF-8 into text first.
            let mut bytes = target.as_bytes();
            let mut decoded = Vec::new();
            while !bytes.is_empty() {
                if bytes[0] == b'%' && bytes.len() >= 3 {
                    let hex = std::str::from_utf8(&bytes[1..3]).unwrap();
                    if let Ok(byte) = u8::from_str_radix(hex, 16) {
                        decoded.push(byte);
                        bytes = &bytes[3..];
                        continue;
                    }
                }
                decoded.push(bytes[0]);
                bytes = &bytes[1..];
            }
            decoded
        },
    );
}

#[test]
fn api_review_path_utf8_boundary_is_rejected_before_reads() {
    let root = tempdir().unwrap();
    let runtime = review_api_runtime(root.path(), "http://127.0.0.1:9".into());
    API_REVIEW_READS.with(|count| count.set(0));
    API_REVIEW_REQUESTS.with(|count| count.set(0));
    let result = runtime
        .call(
            "execute_api_request",
            &json!({"template":"fixture","endpoint":"/v1/__TOKEN__%bc","timeout":1}),
        )
        .unwrap();
    assert!(result.is_error);
    assert_eq!(result.text, "invalid endpoint path");
    assert_eq!(API_REVIEW_READS.with(|count| count.get()), 0);
    assert_eq!(API_REVIEW_REQUESTS.with(|count| count.get()), 0);
}

fn review_assert_substitution_echo(
    credential: &str,
    auth_type: &str,
    endpoint: &str,
    expected_wire: &str,
    expected_masked: &str,
) {
    review_assert_substitution_echo_with(
        credential,
        auth_type,
        endpoint,
        expected_wire,
        expected_masked,
        str::to_owned,
    );
}

fn review_assert_substitution_echo_with(
    credential: &str,
    auth_type: &str,
    endpoint: &str,
    expected_wire: &str,
    expected_masked: &str,
    echo: fn(&str) -> String,
) {
    review_assert_substitution_echo_with_bytes(
        credential,
        auth_type,
        endpoint,
        expected_wire,
        expected_masked,
        move |target| echo(target).into_bytes(),
    );
}

fn review_assert_substitution_echo_with_bytes(
    credential: &str,
    auth_type: &str,
    endpoint: &str,
    expected_wire: &str,
    expected_masked: &str,
    echo: impl Fn(&str) -> Vec<u8> + Send + 'static,
) {
    let echoed_is_ascii = echo(expected_wire).is_ascii();
    let root = tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    fs::create_dir_all(root.path().join("entries")).unwrap();
    fs::write(
        root.path().join("config.yaml"),
        b"vault:\n  format_version: 2\n",
    )
    .unwrap();
    fs::write(root.path().join("identity.age"), b"fixture marker").unwrap();
    fs::create_dir_all(root.path().join("templates")).unwrap();
    let tail_substitution = if endpoint.contains("__TAIL__") {
        "  - placeholder: __TAIL__\n    field: tail\n    in: [path]\n"
    } else {
        ""
    };
    fs::write(root.path().join("templates/fixture.yaml"), format!(
        "base_url: http://{}\nauth_type: {auth_type}\nentry_ref: api-fixture\nallowed_endpoints: [/v1/*]\nallowed_methods: [GET]\nallow_private: true\nsubstitutions:\n  - placeholder: __TOKEN__\n    field: credential\n    in: [path, query]\n{tail_substitution}",
        listener.local_addr().unwrap()
    )).unwrap();
    let identity = symvault_crypto::generate_identity();
    let store = Store::open(root.path(), &identity).unwrap();
    let mut data = BTreeMap::from([
        ("credential".into(), json!(credential)),
        ("param_name".into(), json!("auth_token")),
        ("param_value".into(), json!("separate-auth")),
    ]);
    if endpoint.contains("__TAIL__") {
        data.insert("tail".into(), json!(".."));
    }
    store
        .write_entry(
            "api-fixture",
            &Entry {
                path: "api-fixture".into(),
                data,
                ..Entry::default()
            },
            &identity,
        )
        .unwrap();
    let runtime = StoreReadOnlyRuntime::from_store(
        store,
        identity,
        ReadOnlyRuntimeConfig {
            agent_name: "review-agent".into(),
            approval_mode: "none".into(),
            can_run_commands: true,
            allowed_paths: vec!["*".into()],
            available_tools: vec!["execute_api_request".into()],
            ..ReadOnlyRuntimeConfig::default()
        },
        None,
        None,
    )
    .unwrap();
    let server = review_echo_server_with_bytes(listener, echo);
    let result = runtime.call(
        "execute_api_request",
        &json!({"template":"fixture","endpoint":endpoint,"timeout":1}),
    );
    let wire = server.join().unwrap();
    let result = result.unwrap();
    assert!(!result.is_error, "{}", result.text);
    assert_eq!(wire.as_deref(), Some(expected_wire));
    let payload: Value = serde_json::from_str(&result.text).unwrap();
    assert_eq!(payload["body"], expected_masked);
    // Existing broker projection drops non-ASCII HeaderValue::to_str failures.
    // Preserve that behavior; ASCII header echoes still require exact masking.
    let expected_header = if echoed_is_ascii {
        expected_masked
    } else {
        ""
    };
    assert_eq!(payload["headers"]["X-Echo"], expected_header);
}

#[test]
fn api_review_policy_denies_before_resolution_and_network() {
    use symvault_core::policy::{Action, Conditions, Engine, Policy, Rule};
    let root = tempdir().unwrap();
    // No listener is necessary: the denied route must never reach transport.
    let mut runtime = review_api_runtime(root.path(), "http://127.0.0.1:9".into());
    runtime.policy = Some(Engine::new([Policy {
        version: "1".into(),
        description: "API security hardening pending Go alignment".into(),
        rules: vec![Rule {
            name: "deny API use".into(),
            priority: 1,
            conditions: Conditions {
                agent_id: "review-agent".into(),
                path: "api-fixture".into(),
                action: "run".into(),
                ..Conditions::default()
            },
            action: Action::Deny,
        }],
    }]));
    API_REVIEW_READS.with(|count| count.set(0));
    API_REVIEW_REQUESTS.with(|count| count.set(0));
    let args = json!({"template":"fixture","endpoint":"/v1/status","timeout":1});
    runtime.authorize("execute_api_request", &args).unwrap();
    let result = runtime.call("execute_api_request", &args);
    assert_eq!(
        (
            API_REVIEW_READS.with(|count| count.get()),
            API_REVIEW_REQUESTS.with(|count| count.get())
        ),
        (0, 0),
        "denial must precede credential resolution and transport dispatch"
    );
    assert_eq!(
        API_REVIEW_REQUESTS.with(|count| count.get()),
        0,
        "no transport dispatch"
    );
    assert_eq!(
        result.unwrap_err(),
        "policy denied by rule \"deny API use\""
    );
}

#[test]
fn api_review_entry_policy_matches_corrected_go_observations() {
    use symvault_core::policy::{Action, Conditions, Engine, Policy, Rule};
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/execute-api-policy.json"
    ))
    .unwrap();
    assert_eq!(fixture["schema_version"], 1);
    assert_eq!(fixture["go_version"], "go1.26.6");
    assert_eq!(
        fixture["oracle"]["commit_sha"],
        "2269b3e4b92d2e3c8fbae41d71edd0dec3a67434"
    );
    assert_eq!(fixture["oracle"]["source_digest"].as_str().unwrap().len(), 64);
    assert_eq!(fixture["oracle"]["generator_hash"].as_str().unwrap().len(), 64);
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let denied = !case["error"].as_str().unwrap().is_empty();
        let root = tempdir().unwrap();
        let listener = (!denied).then(|| std::net::TcpListener::bind("127.0.0.1:0").unwrap());
        let base = listener.as_ref().map_or_else(
            || "http://127.0.0.1:9".to_owned(),
            |listener| format!("http://{}", listener.local_addr().unwrap()),
        );
        fs::create_dir_all(root.path().join("entries")).unwrap();
        fs::create_dir_all(root.path().join("templates")).unwrap();
        fs::write(root.path().join("config.yaml"), b"vault:\n  format_version: 2\n").unwrap();
        fs::write(root.path().join("identity.age"), b"fixture marker").unwrap();
        let identity = symvault_crypto::generate_identity();
        let store = Store::open(root.path(), &identity).unwrap();
        store.write_new_entry(
            "api-policy",
            &Entry {
                data: BTreeMap::from([("credential".into(), json!("synthetic-api-policy-credential"))]),
                ..Entry::default()
            },
            &identity,
        ).unwrap();
        drop(store);
        let mut runtime = StoreReadOnlyRuntime::open(
            root.path(),
            identity,
            ReadOnlyRuntimeConfig {
                agent_name: "policy-agent".into(),
                approval_mode: "none".into(),
                can_run_commands: true,
                allowed_paths: vec!["*".into()],
                available_tools: vec!["execute_api_request".into()],
                ..ReadOnlyRuntimeConfig::default()
            },
            None,
            None,
        ).unwrap();
        fs::write(
            root.path().join("templates/fixture.yaml"),
            format!("base_url: {base}\nauth_type: bearer\nentry_ref: {:?}\nallowed_endpoints: [/v1/*]\nallowed_methods: [GET]\nallow_private: true\n", case["entry_ref"].as_str().unwrap()),
        ).unwrap();
        let action = case["policy_action"].as_str().unwrap();
        if !action.is_empty() {
            let action = match action {
                "allow" => Action::Allow,
                "deny" => Action::Deny,
                "prompt" => Action::Prompt,
                "require_biometry" => Action::RequireBiometry,
                value => panic!("unknown frozen policy action {value}"),
            };
            runtime.policy = Some(Engine::new([Policy {
                version: "1".into(), description: String::new(),
                rules: vec![Rule {
                    name: "entry-policy".into(), priority: 0,
                    conditions: Conditions {
                        agent_id: "policy-agent".into(), path: "api-policy".into(),
                        action: case["policy_operation"].as_str().unwrap().into(),
                        ..Conditions::default()
                    }, action,
                }],
            }]));
        }
        let server = listener.map(review_echo_server);
        API_REVIEW_READS.with(|count| count.set(0));
        API_REVIEW_REQUESTS.with(|count| count.set(0));
        let result = runtime.call("execute_api_request", &json!({
            "template":"fixture", "endpoint":"/v1/status", "timeout":1,
            "path":"unrelated-allowed-entry",
        }));
        if let Some(server) = server {
            assert_eq!(server.join().unwrap().as_deref(), Some("/v1/status"), "{name}");
        }
        assert_eq!(result.is_err(), denied, "{name}");
        assert_eq!(API_REVIEW_READS.with(|count| count.get()) as u64, case["credential_reads"].as_u64().unwrap(), "{name}");
        assert_eq!(API_REVIEW_REQUESTS.with(|count| count.get()) as u64, case["requests"].as_u64().unwrap(), "{name}");
        if denied {
            // Go retains prompt/biometry-specific diagnostics. Rust denies all
            // non-allow actions; compare their denial and side effects above.
            if matches!(action, "deny" | "allow") {
                assert_eq!(result.unwrap_err(), case["error"].as_str().unwrap(), "{name}");
            }
        } else {
            let result = result.unwrap();
            assert!(!result.is_error, "{name}: {}", result.text);
            let body: Value = serde_json::from_str(&result.text).unwrap();
            assert_eq!(body["status_code"], 200, "{name}");
        }
    }
}

#[test]
fn api_review_ipv6_handler_allows_private_and_denies_controls() {
    let root = tempdir().unwrap();
    let listener = std::net::TcpListener::bind("[::1]:0").unwrap();
    let runtime = review_api_runtime(
        root.path(),
        format!("http://{}", listener.local_addr().unwrap()),
    );
    let server = review_echo_server(listener);
    let result = runtime.call(
        "execute_api_request",
        &json!({"template":"fixture","endpoint":"/v1/status","timeout":1}),
    );
    let wire = server.join().unwrap();
    let result = result.unwrap();
    assert!(!result.is_error, "{}", result.text);
    assert_eq!(wire.as_deref(), Some("/v1/status"));
    let payload: Value = serde_json::from_str(&result.text).unwrap();
    assert_eq!(payload["status_code"], 200);
    let template = root.path().join("templates/fixture.yaml");
    fs::write(
        &template,
        fs::read_to_string(&template)
            .unwrap()
            .replace("allow_private: true", "allow_private: false"),
    )
    .unwrap();
    API_REVIEW_READS.with(|count| count.set(0));
    API_REVIEW_REQUESTS.with(|count| count.set(0));
    let denied = runtime
        .call(
            "execute_api_request",
            &json!({"template":"fixture","endpoint":"/v1/status","timeout":1}),
        )
        .unwrap();
    assert!(denied.is_error, "{}", denied.text);
    assert_eq!(API_REVIEW_READS.with(|count| count.get()), 0);
}

#[test]
fn api_review_go_escape_contract() {
    // Captured from net/url using the repository's Go 1.26.6 toolchain.
    for (value, query, segment, path) in [
        (
            "alpha:beta gamma",
            "alpha%3Abeta+gamma",
            "alpha:beta%20gamma",
            "alpha:beta%20gamma",
        ),
        (
            "alpha:beta gamma/$&+=@",
            "alpha%3Abeta+gamma%2F%24%26%2B%3D%40",
            "alpha:beta%20gamma%2F$&+=@",
            "alpha:beta%20gamma/$&+=@",
        ),
        (
            "alpha!'()*[] gamma",
            "alpha%21%27%28%29%2A%5B%5D+gamma",
            "alpha%21%27%28%29%2A%5B%5D%20gamma",
            "alpha%21%27%28%29%2A%5B%5D%20gamma",
        ),
        (
            "alpha,;/?#% ü",
            "alpha%2C%3B%2F%3F%23%25+%C3%BC",
            "alpha%2C%3B%2F%3F%23%25%20%C3%BC",
            "alpha,;/%3F%23%25%20%C3%BC",
        ),
    ] {
        assert_eq!(super::api_query_escape(value), query);
        assert_eq!(super::api_path_escape(value), segment);
        assert_eq!(super::api_escaped_path(value), path);
        let known = super::api_substitution_redaction_values(value);
        for encoded in [
            query.to_owned(),
            segment.to_owned(),
            path.to_owned(),
            query.replace('+', "%20"),
        ] {
            assert_eq!(super::sanitize_api_value(&encoded, &known).0, "***");
        }
    }
}

#[test]
fn api_review_ipv6_handler_reaches_header_guard_without_network() {
    let root = tempdir().unwrap();
    let runtime = review_api_runtime(root.path(), "http://[::1]:9".into());
    let args = json!({"template":"fixture","endpoint":"/v1/status","headers":{"Host":"example.org"},"timeout":1});
    runtime.authorize("execute_api_request", &args).unwrap();
    let result = runtime.call("execute_api_request", &args).unwrap();
    assert!(result.is_error);
    assert_eq!(
        result.text,
        "request failed: request header is controlled by the broker"
    );
}

#[test]
fn api_review_serialized_substitution_is_masked() {
    let value = "alpha:beta gamma";
    let substitutions = vec![crate::broker::ApiSubstitution {
        placeholder: "__TOKEN__".into(),
        field: "credential".into(),
        surfaces: vec!["path".into(), "query".into()],
    }];
    let wire = super::api_request_url(
        "http://127.0.0.1",
        "/v1/__TOKEN__?q=__TOKEN__",
        &substitutions,
        &BTreeMap::from([("__TOKEN__".into(), value.into())]),
    )
    .unwrap();
    assert_eq!(
        wire,
        "http://127.0.0.1/v1/alpha:beta%20gamma?q=alpha:beta%20gamma"
    );
    let known = super::api_substitution_redaction_values(value);
    assert_eq!(
        super::sanitize_api_value(wire.strip_prefix("http://127.0.0.1").unwrap(), &known).0,
        "/v1/***?q=***"
    );
}

#[test]
fn api_review_serializer_variants_cover_path_and_query_punctuation() {
    for value in ["alpha!'()*[] gamma", "alpha,;/?#% ü", "alpha:beta gamma"] {
        let substitutions = vec![crate::broker::ApiSubstitution {
            placeholder: "__TOKEN__".into(),
            field: "credential".into(),
            surfaces: vec!["path".into(), "query".into()],
        }];
        let wire = super::api_request_url(
            "http://localhost",
            "/v1/__TOKEN__?q=__TOKEN__",
            &substitutions,
            &BTreeMap::from([("__TOKEN__".into(), value.into())]),
        )
        .unwrap();
        let known = super::api_substitution_redaction_values(value);
        assert_eq!(
            super::sanitize_api_value(wire.strip_prefix("http://localhost").unwrap(), &known).0,
            "/v1/***?q=***",
            "{value}"
        );
    }
}

#[test]
fn api_review_ipv6_authority_changes_are_denied() {
    let template = crate::broker::ApiTemplate {
        base_url: "http://[::1]:12345".into(),
        allowed_endpoints: vec!["/v1/*".into()],
        allowed_methods: vec!["GET".into()],
        default_headers: BTreeMap::new(),
        allow_private: true,
    };
    for url in [
        "https://[::1]:12345/v1/status",
        "http://[::1]:12346/v1/status",
        "http://[::2]:12345/v1/status",
        "http://127.0.0.1:12345/v1/status",
        "http://localhost:12345/v1/status",
        "http://user@[::1]:12345/v1/status",
        "http://user:pass@[::1]:12345/v1/status",
    ] {
        assert_eq!(
            crate::broker::execute_http_for_api(
                &template,
                "GET",
                "/v1/status",
                url,
                &BTreeMap::new(),
                b"",
                crate::broker::ApiResponseBounds {
                    timeout: Duration::from_secs(1),
                    response_limit: 1024,
                }
            )
            .unwrap_err(),
            "API request URL changed the validated upstream authority",
            "{url}"
        );
    }
}

#[test]
fn api_review_ipv6_private_and_non_loopback_controls_precede_resolution() {
    for (base, allow_private, expected) in [
        (
            "http://[::1]:9",
            false,
            "blocked private or local upstream host",
        ),
        (
            "http://[2001:db8::1]:9",
            true,
            "plain HTTP is restricted to loopback targets",
        ),
    ] {
        let root = tempdir().unwrap();
        let runtime = review_api_runtime(root.path(), base.into());
        let template = root.path().join("templates/fixture.yaml");
        if !allow_private {
            fs::write(
                &template,
                fs::read_to_string(&template)
                    .unwrap()
                    .replace("allow_private: true", "allow_private: false"),
            )
            .unwrap();
        }
        API_REVIEW_READS.with(|count| count.set(0));
        API_REVIEW_REQUESTS.with(|count| count.set(0));
        let result = runtime
            .call(
                "execute_api_request",
                &json!({"template":"fixture","endpoint":"/v1/status","timeout":1}),
            )
            .unwrap();
        assert!(result.is_error);
        assert_eq!(result.text, expected);
        assert_eq!(API_REVIEW_READS.with(|count| count.get()), 0);
        assert_eq!(API_REVIEW_REQUESTS.with(|count| count.get()), 0);
    }
}

#[test]
fn api_review_policy_default_deny_and_explicit_run_allow() {
    use symvault_core::policy::{Action, Conditions, Engine, Policy, Rule};
    for (action, allowed) in [("get", false), ("run", true)] {
        let root = tempdir().unwrap();
        let mut runtime = review_api_runtime(root.path(), "http://127.0.0.1:9".into());
        runtime.policy = Some(Engine::new([Policy {
            version: "1".into(),
            description: "API security hardening pending Go alignment".into(),
            rules: vec![Rule {
                name: "allow selected use".into(),
                priority: 1,
                conditions: Conditions {
                    agent_id: "review-agent".into(),
                    path: "api-fixture".into(),
                    action: action.into(),
                    allowed_tools: vec!["execute_api_request".into()],
                    ..Conditions::default()
                },
                action: Action::Allow,
            }],
        }]));
        API_REVIEW_READS.with(|count| count.set(0));
        API_REVIEW_REQUESTS.with(|count| count.set(0));
        let args = json!({"template":"fixture","endpoint":"/v1/status","headers":{"Host":"example.org"},"timeout":1});
        runtime.authorize("execute_api_request", &args).unwrap();
        let result = runtime.call("execute_api_request", &args);
        if allowed {
            assert_eq!(
                result.unwrap().text,
                "request failed: request header is controlled by the broker"
            );
            assert_eq!(API_REVIEW_READS.with(|count| count.get()), 1);
            assert_eq!(API_REVIEW_REQUESTS.with(|count| count.get()), 1);
        } else {
            assert_eq!(
                result.unwrap_err(),
                "policy: no matching rule (default deny)"
            );
            assert_eq!(API_REVIEW_READS.with(|count| count.get()), 0);
            assert_eq!(API_REVIEW_REQUESTS.with(|count| count.get()), 0);
        }
    }
}
