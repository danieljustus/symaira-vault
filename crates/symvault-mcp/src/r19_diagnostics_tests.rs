// ADR 0037 R19 (BROKER-002): replay of
// `testdata/port/mcp/execute-api-diagnostics.json`, recorded from the Go
// oracle (`scripts/rust-port/execute_api_diagnostics_record.go.txt`) through
// `Server.executeTool("execute_api_request", ...)`: approval diagnostics with
// the tool name, dispatcher-level policy/biometry behaviour and the
// template-open race. Included into `store_adapter::tests` like
// `api_review_tests.rs` so it can reuse `api_approval_runtime`.

const R19_RECORDING: &str =
    include_str!("../../../testdata/port/mcp/execute-api-diagnostics.json");

fn r19_case(id: &str) -> Value {
    let doc: Value = serde_json::from_str(R19_RECORDING).expect("parse R19 recording");
    assert_eq!(
        doc["oracle_commit"],
        "ce2390d748818a4beb413e97183b7795efa99411"
    );
    doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == id)
        .unwrap_or_else(|| panic!("recording has no case {id}"))
        .clone()
}

struct R19Approval {
    tty: bool,
    answer: symvault_platform::approval::ApprovalResult,
}

impl ApprovalSeam for R19Approval {
    fn is_tty_present(&self) -> bool {
        self.tty
    }

    fn request(
        &self,
        _request: &symvault_platform::approval::ApprovalRequest,
    ) -> symvault_platform::approval::ApprovalResult {
        self.answer.clone()
    }
}

fn r19_answer(
    approved: bool,
    error: Option<symvault_platform::approval::ApprovalError>,
) -> symvault_platform::approval::ApprovalResult {
    symvault_platform::approval::ApprovalResult {
        approved,
        remembered: false,
        error,
    }
}

fn r19_runtime(
    root: &Path,
    mode: &str,
    approval: R19Approval,
    base: String,
) -> StoreReadOnlyRuntime {
    api_approval_runtime(
        root,
        ReadOnlyRuntimeConfig {
            agent_name: "r19-agent".into(),
            approval_mode: mode.into(),
            approval_timeout: Duration::from_secs(1),
            can_run_commands: true,
            allowed_paths: vec!["*".into()],
            ..ReadOnlyRuntimeConfig::default()
        },
        Arc::new(approval),
        true,
        base,
    )
}

#[test]
fn execute_api_request_approval_diagnostics_match_the_go_recording() {
    use symvault_platform::approval::ApprovalError as E;
    let args = json!({"template": "fixture", "endpoint": "/v1/status"});
    // (case id, approval mode, tty present, answer)
    let table: Vec<(&str, &str, bool, symvault_platform::approval::ApprovalResult)> = vec![
        ("approval-deny-mode", "deny", true, r19_answer(true, None)),
        ("approval-prompt-no-tty", "prompt", false, r19_answer(true, None)),
        ("approval-prompt-user-denies", "prompt", true, r19_answer(false, None)),
        ("approval-prompt-user-approves", "prompt", true, r19_answer(true, None)),
        (
            "approval-prompt-tty-vanishes-before-prompt",
            "prompt",
            true,
            r19_answer(false, Some(E::NoTty)),
        ),
        (
            "approval-prompt-raw-mode-fails",
            "prompt",
            true,
            r19_answer(false, Some(E::RawMode("raw boom".into()))),
        ),
        (
            "approval-prompt-times-out",
            "prompt",
            true,
            r19_answer(false, Some(E::Timeout(Duration::from_secs(1)))),
        ),
        (
            "approval-prompt-read-fails",
            "prompt",
            true,
            r19_answer(false, Some(E::Read("read boom".into()))),
        ),
        ("approval-auto-mode", "auto", true, r19_answer(true, None)),
    ];
    for (id, mode, tty, answer) in table {
        let go = r19_case(id);
        let root = tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let go_requests = go["upstream_requests"].as_u64().unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let runtime = r19_runtime(root.path(), mode, R19Approval { tty, answer }, base);
        let server = (go_requests > 0).then(|| review_echo_server(listener));
        let result = runtime.call("execute_api_request", &args);
        if let Some(server) = server {
            assert_eq!(server.join().unwrap().as_deref(), Some("/v1/status"), "{id}");
        }
        match go["error"].as_str() {
            Some(error) => assert_eq!(result.unwrap_err(), error, "{id}"),
            None => {
                let result = result.unwrap_or_else(|error| panic!("{id}: {error}"));
                assert!(!result.is_error, "{id}: {}", result.text);
                let body: Value = serde_json::from_str(&result.text).unwrap();
                assert_eq!(
                    format!("<api response status_code={}>", body["status_code"]),
                    go["tool_text"].as_str().unwrap(),
                    "{id}"
                );
            }
        }
    }
}

/// Go's `default: return nil` lets an unrecognised approval mode through;
/// Rust fails closed. Config loading owns mode validation, so this is a
/// defence-in-depth stricter divergence on an input the CLI never produces.
#[test]
fn unknown_approval_mode_fails_closed_unlike_go() {
    let go = r19_case("approval-unknown-mode");
    assert_eq!(go["upstream_requests"], 1);
    assert_eq!(go["tool_text"], "<api response status_code=200>");
    let root = tempdir().unwrap();
    let runtime = r19_runtime(
        root.path(),
        "bogus",
        R19Approval {
            tty: true,
            answer: r19_answer(true, None),
        },
        "http://127.0.0.1:9".into(),
    );
    assert_eq!(
        runtime
            .call(
                "execute_api_request",
                &json!({"template": "fixture", "endpoint": "/v1/status"})
            )
            .unwrap_err(),
        "execute_api_request denied: unknown approval mode \"bogus\""
    );
}

struct R19Touch {
    available: bool,
    outcome: Result<(), symvault_core::platform::PlatformErrorKind>,
}

impl symvault_core::platform::TouchId for R19Touch {
    fn is_available(&self) -> bool {
        self.available
    }

    fn authenticate(
        &self,
        _reason: &str,
        _timeout: Duration,
    ) -> Result<(), symvault_core::platform::PlatformError> {
        self.outcome
            .map_err(|kind| symvault_core::platform::PlatformError {
                kind,
                message: "adapter detail must not reach the agent".into(),
            })
    }
}

fn r19_gate_policy(action: symvault_core::policy::Action) -> symvault_core::policy::Engine {
    use symvault_core::policy::{Action, Conditions, Engine, Policy, Rule};
    Engine::new([Policy {
        version: "1".into(),
        description: "R19".into(),
        rules: vec![
            Rule {
                name: "gate".into(),
                priority: 10,
                conditions: Conditions {
                    agent_id: "r19-agent".into(),
                    path: "gate".into(),
                    action: "run".into(),
                    ..Conditions::default()
                },
                action,
            },
            Rule {
                name: "entry".into(),
                priority: 1,
                conditions: Conditions {
                    agent_id: "r19-agent".into(),
                    path: "api-fixture".into(),
                    action: "run".into(),
                    ..Conditions::default()
                },
                action: Action::Allow,
            },
        ],
    }])
}

/// The challenge texts carry the tool name and are Go's byte for byte. Go's
/// dispatcher then ignores a failed or unavailable challenge and lets the tool
/// run (recorded: one upstream request in every `biometry-rule-*` case, also
/// for `prompt`/`deny` rules on the caller's `path`); Rust denies with the
/// challenge text. That stricter divergence predates this item and is pinned in
/// `policy_biometry_challenge` and `tests/authguard_require_biometry.rs`.
#[test]
fn biometry_diagnostics_carry_the_tool_name_like_go() {
    use symvault_core::platform::PlatformErrorKind;
    use symvault_core::policy::Action;
    let gated = json!({"template": "fixture", "endpoint": "/v1/status", "path": "gate"});
    let build = |action: Action, touch: R19Touch| {
        let root = tempdir().unwrap();
        let mut runtime = r19_runtime(
            root.path(),
            "none",
            R19Approval {
                tty: true,
                answer: r19_answer(true, None),
            },
            "http://127.0.0.1:9".into(),
        )
        .with_touch_id(Arc::new(touch));
        runtime.policy = Some(r19_gate_policy(action));
        (root, runtime)
    };
    for (id, touch, expected_error) in [
        (
            "challenge-text-unavailable",
            R19Touch {
                available: false,
                outcome: Ok(()),
            },
            true,
        ),
        (
            "challenge-text-failed",
            R19Touch {
                available: true,
                outcome: Err(PlatformErrorKind::Failed),
            },
            true,
        ),
        (
            "challenge-text-passed",
            R19Touch {
                available: true,
                outcome: Ok(()),
            },
            false,
        ),
    ] {
        let go = r19_case(id);
        let (_root, runtime) = build(Action::RequireBiometry, touch);
        let denied = runtime.authorize("execute_api_request", &gated);
        if expected_error {
            assert_eq!(denied.unwrap_err().text, go["error"].as_str().unwrap(), "{id}");
        } else {
            assert!(go.get("error").is_none());
            denied.expect("a passing challenge allows the call");
        }
    }
    // Go proceeds in all of these; Rust denies except for a passing challenge.
    for id in [
        "biometry-rule-unavailable",
        "biometry-rule-challenge-fails",
        "biometry-rule-challenge-passes",
        "policy-prompt-rule-on-path-argument",
        "policy-deny-rule-on-path-argument",
    ] {
        let go = r19_case(id);
        assert_eq!(go["upstream_requests"], 1, "{id}");
        assert_eq!(go["tool_text"], "<api response status_code=200>", "{id}");
    }
    let (_root, runtime) = build(
        Action::Deny,
        R19Touch {
            available: true,
            outcome: Ok(()),
        },
    );
    assert!(
        runtime
            .authorize("execute_api_request", &gated)
            .unwrap_err()
            .text
            .starts_with("policy denied tool \"execute_api_request\""),
    );
}

const R19_TEMPLATE: &str = "base_url: https://a.example.test\nauth_type: bearer\nentry_ref: a\nallowed_endpoints: [/v1/*]\nallowed_methods: [GET]\n";

#[test]
fn template_open_is_pinned_to_the_checked_file_unlike_go() {
    let go = r19_case("template-concurrent-swap");
    // Go: os.Stat then os.ReadFile by path; a file removed between the two
    // yields a read error instead of the builtin fallback.
    assert_eq!(go["notes"]["stat_then_read_window_reachable"], true);
    assert_eq!(go["notes"]["never_returns_a_non_template_value"], true);

    let root = tempdir().unwrap();
    fs::create_dir(root.path().join("templates")).unwrap();
    let target = root.path().join("templates/race.yaml");
    fs::write(&target, R19_TEMPLATE).unwrap();
    // control: no swap
    super::load_api_template_definition_with(root.path(), "race", || {}).expect("unswapped template");

    // rename another regular file over the checked path
    let swapped = super::load_api_template_definition_with(root.path(), "race", || {
        let other = root.path().join("templates/other.tmp");
        fs::write(&other, R19_TEMPLATE.replace("a.example", "b.example")).unwrap();
        fs::rename(&other, &target).unwrap();
    });
    assert_eq!(swapped.unwrap_err(), "template changed while loading");

    // replace the path by a symlink to a file elsewhere
    #[cfg(unix)]
    {
        let outside = root.path().join("outside.yaml");
        fs::write(&outside, R19_TEMPLATE.replace("a.example", "b.example")).unwrap();
        let relinked = super::load_api_template_definition_with(root.path(), "race", || {
            fs::remove_file(&target).unwrap();
            std::os::unix::fs::symlink(&outside, &target).unwrap();
        });
        assert_eq!(relinked.unwrap_err(), "template changed while loading");
    }
}

/// Go follows a symlink at the template path and a symlinked `templates`
/// directory to files outside the vault (both recorded as followed). Rust
/// refuses the first as non-regular and the second as an escape: stricter and
/// security-motivated, so a vault-local symlink cannot substitute a template
/// (and with it the credential entry and endpoint allowlist).
#[cfg(unix)]
#[test]
fn template_symlinks_are_refused_where_go_follows_them() {
    let go = r19_case("template-symlinks");
    assert_eq!(go["notes"]["file_symlink_followed"], true);
    assert_eq!(go["notes"]["directory_symlink_followed"], true);

    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(outside.path().join("linked.yaml"), R19_TEMPLATE).unwrap();
    fs::create_dir(root.path().join("templates")).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("linked.yaml"),
        root.path().join("templates/linked.yaml"),
    )
    .unwrap();
    assert_eq!(
        super::load_api_template_definition(root.path(), "linked").unwrap_err(),
        "template must be a regular file"
    );

    let vault = tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), vault.path().join("templates")).unwrap();
    fs::write(outside.path().join("dirlinked.yaml"), R19_TEMPLATE).unwrap();
    assert_eq!(
        super::load_api_template_definition(vault.path(), "dirlinked").unwrap_err(),
        "template directory escapes the vault root"
    );
}
