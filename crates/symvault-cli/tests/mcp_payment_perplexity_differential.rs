//! MCP-TOOLS-PP-001: `symvault mcp --stdio` Go-oracle vs native differential
//! for `prepare_payment`, `perplexity_search`, `perplexity_ask` and the
//! tool catalog. Every case here stops before any side effect: no autotype
//! keystroke, no approval dialog (`SYMVAULT_SECUREUI=none`, no controlling
//! TTY) and no network (the Perplexity base URL is rejected or the API key
//! is missing before a request is built). Success, upstream and autotype
//! paths are covered by the Go-recorded fixtures in
//! `crates/symvault-mcp/tests/{prepare_payment,perplexity}_contract.rs`.
//!
//! The Go answers (a `CGO_ENABLED=0` build of the pinned oracle) are replayed
//! from `testdata/port/cli-transcripts/mcp_payment_perplexity_differential.json`.

#![cfg(unix)]

#[path = "common/go_oracle.rs"]
mod go_oracle;

#[path = "support/temp_root.rs"]
mod test_temp_root;

use serde_json::{Value, json};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

/// Go oracle: the last commit that carries the Go sources (`CGO_ENABLED=0`
/// build, so no Touch ID); the tool catalog (`run_command` file inputs) of the
/// older config-cli oracle differs.
const ORACLE_COMMIT: &str = "c069d3f2b17d704525cedc1bd42840cc6a3e9896";

fn temporary_root(name: &str) -> test_temp_root::TempRoot {
    test_temp_root::TempRoot::missing(&format!("symvault-pp-differential-{name}-"))
}

fn base_command(binary: &Path, root: &Path, home: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_VAULT", root)
        .env("SYMVAULT_PASSPHRASE", "correct horse battery staple")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("SYMVAULT_SECUREUI", "none")
        .env("CI", "1")
        .env("NO_COLOR", "1");
    command
}

fn run(binary: &Path, args: &[&str], root: &Path, home: &Path) -> Output {
    go_oracle::output(base_command(binary, root, home).args(args)).expect("run CLI")
}

fn assert_success(output: &Output, label: &str) {
    assert!(
        output.status.success(),
        "{label} failed: {:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

const BITWARDEN_EXPORT: &str = r#"{"folders":[{"id":"f1","name":"payments"}],"items":[
{"id":"1","folderId":"f1","type":2,"name":"visa","card":{"cardholderName":"Jane Doe","brand":"Visa","number":"4111111111111111","expMonth":"12","expYear":"2030","code":"123"}},
{"id":"2","folderId":"f1","type":2,"name":"bank","card":{"cardholderName":"Jane Doe","number":"","expMonth":"","expYear":"","code":""},"fields":[{"name":"subtype","value":"bank_account"},{"name":"iban","value":"DE89370400440532013000"}]},
{"id":"3","folderId":"f1","type":1,"name":"login","login":{"username":"u","password":"pw"}}
]}"#;

const POLICIES: &str = "paymentPolicies:
  shop:
    instrument: payments/visa
    allowed_merchants: [Shop.Example]
    max_amount:
      per_transaction: \"75.00\"
      per_day: \"200.00\"
    currency: EUR
";

fn profile(name: &str, extra: &str) -> String {
    format!(
        "  {name}:\n    tier: admin\n    allowedPaths: ['*']\n    canWrite: false\n    canRunCommands: false\n    canUseAutotype: false\n    exposeValueTools: false\n{extra}"
    )
}

/// Prepares one disposable vault: Rust `init` (random keys: frozen as a seed),
/// Go `import` of payment cards (a recorded Go call whose vault delta is
/// replayed; the same cross-binary seeding `run_differential` relies on), then
/// a profile set covering every approval mode and a payment policy.
fn prepare_vault(
    oracle: &go_oracle::GoOracle,
    rust: &Path,
    go: &Path,
    root: &Path,
    home: &Path,
    perplexity: &str,
) {
    fs::create_dir_all(home).unwrap();
    for directory in ["config", "data", "cache"] {
        fs::create_dir_all(home.join(directory)).unwrap();
    }
    let vault = root.to_str().unwrap();
    if let Some(init) = oracle.seed("init", &[root, home], || {
        run(
            rust,
            &["--vault", vault, "init", "--auth", "passphrase"],
            root,
            home,
        )
    }) {
        assert_success(&init, "init");
    }
    let export = home.join("bitwarden.json");
    fs::write(&export, BITWARDEN_EXPORT).unwrap();
    assert_success(
        &run(
            go,
            &[
                "--vault",
                vault,
                "import",
                export.to_str().unwrap(),
                "--format",
                "bitwarden",
            ],
            root,
            home,
        ),
        "go import",
    );

    let config_path = root.join("config.yaml");
    let mut config: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    let agents = format!(
        "agents:\n{}{}{}{}{}{}",
        profile("deny", "    approvalMode: deny\n"),
        profile("prompt", "    approvalMode: prompt\n"),
        profile(
            "policy",
            "    approvalMode: deny\n    paymentPolicy: shop\n"
        ),
        profile("scoped", "    approvalMode: deny\n").replace("['*']", "['other/*']"),
        profile("readonly", "    approvalMode: deny\n").replace("tier: admin", "tier: read-only"),
        profile("standard", "    approvalMode: deny\n").replace("tier: admin", "tier: standard"),
    );
    let replacement: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&format!("{agents}{POLICIES}{perplexity}")).unwrap();
    let target = config.as_mapping_mut().unwrap();
    for (key, value) in replacement.as_mapping().unwrap() {
        target.insert(key.clone(), value.clone());
    }
    target.insert("defaultAgent".into(), "deny".into());
    fs::write(&config_path, serde_yaml_ng::to_string(&config).unwrap()).unwrap();
}

fn frames(calls: &[Value], include_all: bool) -> String {
    let mut lines = vec![
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"diff","version":"1"},"capabilities":{}}}"#.to_owned(),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_owned(),
    ];
    if include_all {
        lines.push(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"include_all_tools":true}}"#
                .into(),
        );
    }
    for (index, call) in calls.iter().enumerate() {
        lines.push(
            json!({"jsonrpc":"2.0","id":index + 10,"method":"tools/call","params":call})
                .to_string(),
        );
    }
    lines.join("\n") + "\n"
}

fn mcp(binary: &Path, root: &Path, home: &Path, agent: &str, input: &str) -> Output {
    let mut command = base_command(binary, root, home);
    command.args([
        "--vault",
        root.to_str().unwrap(),
        "mcp",
        "--stdio",
        "--agent",
        agent,
    ]);
    go_oracle::output_with_input(&mut command, Some(input.as_bytes())).expect("mcp output")
}

/// Audit actions as the audit log recorded them (timestamps/HMACs vary).
fn audit_actions(root: &Path) -> Vec<(String, String, bool)> {
    let mut names: Vec<PathBuf> = fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("audit-") && name.ends_with(".log"))
        })
        .collect();
    names.sort();
    let mut events = Vec::new();
    for name in names {
        for line in fs::read_to_string(name).unwrap().lines() {
            let value: Value = serde_json::from_str(line).unwrap();
            events.push((
                value["action"].as_str().unwrap_or_default().to_owned(),
                value["path"].as_str().unwrap_or_default().to_owned(),
                value["ok"].as_bool().unwrap_or(false),
            ));
        }
    }
    events
}

/// Every file below `dir`, relative, so side effects (tracker/state files)
/// are compared and not just stdout.
fn manifest(dir: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                out.push(
                    path.strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// Compares two stdio transcripts line by line so a mismatch names the exact
/// JSON-RPC frame instead of dumping both streams.
fn assert_same_frames(rust: &[u8], go: &[u8], label: &str) {
    let rust = String::from_utf8_lossy(rust);
    let go = String::from_utf8_lossy(go);
    let (rust_lines, go_lines): (Vec<&str>, Vec<&str>) =
        (rust.lines().collect(), go.lines().collect());
    assert_eq!(
        rust_lines.len(),
        go_lines.len(),
        "{label}: frame count differs"
    );
    for (index, (r, g)) in rust_lines.iter().zip(&go_lines).enumerate() {
        if r != g {
            let at = r
                .bytes()
                .zip(g.bytes())
                .position(|(a, b)| a != b)
                .unwrap_or(r.len().min(g.len()));
            let window = |text: &str| {
                text.chars()
                    .skip(at.saturating_sub(120))
                    .take(360)
                    .collect::<String>()
            };
            panic!(
                "{label}: frame {index} differs at byte {at}\ngo:   ...{}\nrust: ...{}",
                window(g),
                window(r)
            );
        }
    }
}

fn pay(agent: &str, arguments: Value) -> (String, Value) {
    (
        agent.to_owned(),
        json!({"name": "prepare_payment", "arguments": arguments}),
    )
}

fn search(agent: &str, arguments: Value) -> (String, Value) {
    (
        agent.to_owned(),
        json!({"name": "perplexity_search", "arguments": arguments}),
    )
}

fn ask(agent: &str, arguments: Value) -> (String, Value) {
    (
        agent.to_owned(),
        json!({"name": "perplexity_ask", "arguments": arguments}),
    )
}

fn visa(merchant: &str, amount: &str, currency: &str) -> Value {
    json!({"entry_path": "payments/visa", "merchant": merchant, "amount": amount, "currency": currency})
}

#[test]
fn prepare_payment_and_perplexity_match_go_for_non_interactive_cases() {
    let oracle = go_oracle::GoOracle::begin(
        "mcp_payment_perplexity_differential",
        "prepare_payment_and_perplexity_match_go_for_non_interactive_cases",
        Some(ORACLE_COMMIT),
    );
    let go = oracle.binary();
    let rust = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));

    // (config fragment, cases). Each group gets its own vault pair so the
    // Perplexity configuration (which Go reads at server start) differs.
    let groups: Vec<(&str, Vec<(String, Value)>)> = vec![
        (
            "",
            vec![
                pay("deny", visa("shop.example", "10", "EUR")),
                pay("deny", json!({})),
                pay("deny", json!({"entry_path": 3})),
                pay("deny", json!({"entry_path": "payments/visa"})),
                pay(
                    "deny",
                    json!({"entry_path": "payments/visa", "merchant": "m"}),
                ),
                pay(
                    "deny",
                    json!({"entry_path": "payments/visa", "merchant": "m", "amount": "1"}),
                ),
                pay(
                    "deny",
                    json!({"entry_path": "payments/visa", "merchant": "m", "amount": "1", "currency": 1}),
                ),
                pay(
                    "deny",
                    json!({"entry_path": "payments/bank", "merchant": "m", "amount": "1", "currency": "EUR"}),
                ),
                pay("prompt", visa("m", "1", "EUR")),
                pay("scoped", visa("m", "1", "EUR")),
                pay("readonly", visa("m", "1", "EUR")),
                pay("standard", visa("m", "1", "EUR")),
                pay(
                    "deny",
                    json!({"entry_path": "payments/login", "merchant": "m", "amount": "1", "currency": "EUR"}),
                ),
                pay(
                    "deny",
                    json!({"entry_path": "payments/missing", "merchant": "m", "amount": "1", "currency": "EUR"}),
                ),
                pay(
                    "deny",
                    json!({"entry_path": "", "merchant": "m", "amount": "1", "currency": "EUR"}),
                ),
                pay(
                    "deny",
                    json!({"entry_path": "../x", "merchant": "m", "amount": "1", "currency": "EUR"}),
                ),
                pay(
                    "deny",
                    json!({"entry_path": "/abs", "merchant": "m", "amount": "1", "currency": "EUR"}),
                ),
                pay(
                    "deny",
                    json!({"entry_path": "a//b", "merchant": "m", "amount": "1", "currency": "EUR"}),
                ),
                pay(
                    "deny",
                    json!({"entry_path": "a/./b", "merchant": "m", "amount": "1", "currency": "EUR"}),
                ),
                pay(
                    "deny",
                    json!({"entry_path": "a\u{1}b", "merchant": "m", "amount": "1", "currency": "EUR"}),
                ),
                pay("policy", visa("evil.example", "10", "EUR")),
                pay("policy", visa("shop.example", "10", "USD")),
                pay("policy", visa("shop.example", "75.01", "EUR")),
                pay("policy", visa(" SHOP.example ", "12abc", "EUR")),
                pay("policy", visa("shop.example", "1.2.3", "EUR")),
                pay("policy", visa("shop.example", "-", "EUR")),
                pay("policy", visa("shop.example", &"9".repeat(31), "EUR")),
                // Passes the policy, then the deny-mode profile stops it
                // before any autotype.
                pay("policy", visa("shop.example", "75.00", " eur ")),
                pay("policy", visa("shop.example", "010/2", "EUR")),
                pay("policy", visa("shop.example", "08/2", "EUR")),
                search("deny", json!({})),
                search("deny", json!({"query": 5})),
                search("deny", json!({"query": "q"})),
                ask("deny", json!({})),
                ask("deny", json!({"question": ["x"]})),
                ask("deny", json!({"question": "q", "context": "a\nb"})),
                search("readonly", json!({"query": "q"})),
            ],
        ),
        (
            "mcp:\n  perplexity:\n    api_key: cfg-key\n    base_url: http://api.example.invalid\n",
            vec![
                search("deny", json!({"query": "q"})),
                ask("deny", json!({"question": "q"})),
            ],
        ),
        (
            "mcp:\n  perplexity:\n    api_key: cfg-key\n    base_url: https://127.0.0.1:9\n    allow_private: true\n",
            vec![
                search("deny", json!({"query": "q <&>"})),
                ask("deny", json!({"question": "q", "context": "c"})),
            ],
        ),
        (
            "mcp:\n  perplexity:\n    api_key: cfg-key\n    base_url: https://localhost:9\n",
            vec![search("deny", json!({"query": "q"}))],
        ),
        (
            "mcp:\n  perplexity:\n    api_key: cfg-key\n    base_url: \"1a:b\"\n",
            vec![search("deny", json!({"query": "q"}))],
        ),
        (
            "mcp:\n  perplexity:\n    api_key: cfg-key\n    base_url: \"https://\"\n",
            vec![search("deny", json!({"query": "q"}))],
        ),
    ];

    let mut executed = 0_usize;
    let mut transcript = String::new();
    for (index, (perplexity, cases)) in groups.iter().enumerate() {
        let go_root = temporary_root(&format!("go-{index}"));
        let rust_root = temporary_root(&format!("rust-{index}"));
        let go_home = temporary_root(&format!("go-home-{index}"));
        let rust_home = temporary_root(&format!("rust-home-{index}"));
        prepare_vault(&oracle, &rust, &go, &go_root, &go_home, perplexity);
        prepare_vault(&oracle, &rust, &go, &rust_root, &rust_home, perplexity);

        // One stdio session per agent keeps the profile under test explicit.
        let mut agents: Vec<&str> = cases.iter().map(|(agent, _)| agent.as_str()).collect();
        agents.sort_unstable();
        agents.dedup();
        for agent in agents {
            let calls: Vec<Value> = cases
                .iter()
                .filter(|(name, _)| name == agent)
                .map(|(_, call)| call.clone())
                .collect();
            let include_all = index == 0;
            let input = frames(&calls, include_all);
            let go_output = mcp(&go, &go_root, &go_home, agent, &input);
            let rust_output = mcp(&rust, &rust_root, &rust_home, agent, &input);
            let label = format!("group {index} agent {agent}");
            assert_same_frames(&rust_output.stdout, &go_output.stdout, &label);
            assert_eq!(
                rust_output.status.code(),
                go_output.status.code(),
                "{label}: exit status differs"
            );
            let stdout = String::from_utf8_lossy(&go_output.stdout);
            for secret in ["4111111111111111", "DE89370400440532013000", "cfg-key"] {
                assert!(!stdout.contains(secret), "{label}: leaked {secret}");
            }
            // Each frame must have been answered (guards against both sides
            // silently printing nothing).
            let answered = stdout.lines().count();
            assert_eq!(
                answered,
                1 + usize::from(include_all) + calls.len(),
                "{label}: unexpected response count"
            );
            executed += calls.len();
            transcript.push_str(&stdout);
        }
        assert_eq!(
            audit_actions(&rust_root),
            audit_actions(&go_root),
            "group {index}: audit trail differs"
        );
        assert_eq!(
            manifest(&rust_home),
            manifest(&go_home),
            "group {index}: state files differ (payment tracker must not be created)"
        );
    }
    // The cases must really reach the behaviours they name, on the oracle.
    for marker in [
        "payment policy denied: merchant_not_allowed",
        "payment policy denied: currency_mismatch",
        "payment policy denied: over_per_transaction",
        "invalid amount: invalid amount",
        "prepare_payment denied: approval mode is 'deny'",
        "prepare_payment requires approval but no TTY or GUI dialog available",
        "is not a payment entry",
        "outside allowed scope",
        "Tool \\\"prepare_payment\\\" requires tier",
        "perplexity API key not found",
        "perplexity base URL must use HTTPS",
        "private or local network address",
        "URL host is required",
        "first path segment in URL cannot contain colon",
        "invalid path: path is empty",
    ] {
        assert!(
            transcript.contains(marker),
            "oracle transcript never produced {marker:?}"
        );
    }
    assert!(
        executed >= 44,
        "too few differential calls executed: {executed}"
    );
    eprintln!(
        "mcp_payment_perplexity: {} Go calls replayed",
        oracle.calls()
    );
}

#[test]
fn tools_list_with_all_tools_is_byte_identical_and_names_the_three_tools() {
    let oracle = go_oracle::GoOracle::begin(
        "mcp_payment_perplexity_differential",
        "tools_list_with_all_tools_is_byte_identical_and_names_the_three_tools",
        Some(ORACLE_COMMIT),
    );
    let go = oracle.binary();
    let rust = PathBuf::from(env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"));
    let go_root = temporary_root("list-go");
    let rust_root = temporary_root("list-rust");
    let go_home = temporary_root("list-go-home");
    let rust_home = temporary_root("list-rust-home");
    prepare_vault(&oracle, &rust, &go, &go_root, &go_home, "");
    prepare_vault(&oracle, &rust, &go, &rust_root, &rust_home, "");
    let input = frames(&[], true);
    for agent in ["deny", "readonly", "standard"] {
        let go_output = mcp(&go, &go_root, &go_home, agent, &input);
        let rust_output = mcp(&rust, &rust_root, &rust_home, agent, &input);
        assert_same_frames(
            &rust_output.stdout,
            &go_output.stdout,
            &format!("tools/list {agent}"),
        );
        let list: Value = serde_json::from_str(
            String::from_utf8_lossy(&go_output.stdout)
                .lines()
                .nth(1)
                .unwrap(),
        )
        .unwrap();
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert!(names.contains(&"perplexity_search"), "{agent}: {names:?}");
        assert!(names.contains(&"perplexity_ask"), "{agent}: {names:?}");
        assert_eq!(
            names.contains(&"prepare_payment"),
            agent != "readonly",
            "{agent}: prepare_payment visibility follows the tier block"
        );
    }
    assert_eq!(oracle.calls(), 2 + 3);
}
