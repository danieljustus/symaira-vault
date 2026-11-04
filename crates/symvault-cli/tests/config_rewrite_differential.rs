//! CONFIG-WRITER: commands that rewrite `config.yaml` leave the same bytes as
//! Go. The Go answers (status, streams and the rewritten `config.yaml`) are
//! replayed from `testdata/port/cli-transcripts/config_rewrite_differential.json`
//! (oracle 690647c5); a missing recording fails the test. The recorded verdict of
//! Go loading the file Rust wrote is bound to that file's sha256 (it is part of
//! the recorded request), so a changed Rust file cannot reuse it.
//!
//! Go's `SaveTo` drops the top-level `paymentPolicies` and `security`
//! sections; Rust keeps them on purpose (`docs/rust-port/upstream-go-bugs.md`).
//! Those two sections and the keys in [`KEPT`] (`mcp.oauth`, `mcp.perplexity`,
//! `mcp.approval_required`, `git.author`, `git.email`,
//! `clipboard.printByDefault`, all dropped by Go) are the declared differences
//! of these whole-file comparisons: the Rust file minus them must equal Go's
//! file byte for byte, the Rust file must still hold them, and both the Rust
//! and the Go loader must accept the file Rust wrote. (The per-case line
//! differences are pinned by `config_rewrite_contract` in `symvault-core`.)
//!
//! `agent_profile_show_is_unchanged_by_a_rewrite_for_every_tier` needs no
//! oracle: it compares the effective profile view before and after a rewrite.

#[path = "common/go_oracle.rs"]
mod go_oracle;

#[path = "support/temp_root.rs"]
mod test_temp_root;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use sha2::{Digest, Sha256};

/// Pinned Go oracle (`scripts/rust-port/check_config_rewrite.sh`).
const ORACLE_COMMIT: &str = "690647c5068a818a4b237738882bb20c865a134a";

const DECLARED: [&str; 2] = ["paymentPolicies", "security"];

/// Nested keys Go drops on rewrite and Rust keeps (indent 4 in the file).
const KEPT: [&str; 6] = [
    "oauth",
    "perplexity",
    "approval_required",
    "author",
    "email",
    "printByDefault",
];

const CONFIG: &str = "\
vaultDir: /fixture/vault
agents:
  bot:
    canWrite: true
    skillPath: /s/p
    skillVersion: \"3\"
    exposePaymentValues: true
    paymentPolicy: card
    allowed_tools: [vault_get]
    max_reads_per_hour: 7
    dynamicProviders:
      aws: [a]
  other:
    canWrite: true
paymentPolicies:
  card:
    instrument: cards/visa
    allowed_merchants: [acme]
    currency: EUR
security:
  disable_env_passphrase: true
audit:
  maxSizeMb: 10
  maxBackups: 2
logging:
  level: debug
scan_patterns:
  - name: aws
    pattern: '^AKIA'
    description: key
    severity: high
";

/// A multi-line description in a literal block, a multi-line list item and a
/// multi-line map key survive a rewrite (yaml.v3 block scalars).
const MULTILINE: &str = "\
vaultDir: /fixture/vault
agents:
  bot:
    canWrite: true
    allowedPaths: [\"a\\nb\", plain]
    perToolRedactFields:
      get: []
  other:
    canWrite: true
scan_patterns:
  - name: aws
    pattern: '^AKIA'
    description: |
      Matches AWS keys.
      Second line.
    severity: high
";

/// Every MCP field Go keeps (approval mTLS, the trusted-proxy allowlist,
/// OTLP), in a mix with `oauth`, which Go drops.
const MCP: &str = "\
vaultDir: /fixture/vault
agents:
  other:
    canWrite: true
mcp:
  port: 9091
  bind: 127.0.0.1
  httpTokenFile: /tmp/tok
  otlp_endpoint: localhost:4317
  stdio: true
  read_timeout: 1m30s
  trusted_proxy_ips: [10.0.0.1, 192.168.0.0/24]
  tls_cert_file: /c.pem
  tls_key_file: /k.pem
  approval_tls_cert_file: certs/approval-client.pem
  approval_tls_key_file: certs/approval-client.key
  mtls_enabled: true
  oauth:
    access_token_ttl: 2h
    refresh_token_ttl: 90m
";

/// The keys of [`KEPT`] other than `oauth`, next to the modelled ones.
const DROPPED_BY_GO: &str = "\
vaultDir: /fixture/vault
agents:
  other:
    canWrite: true
git:
  commit_template: msg
  author: Ann
  email: ann@example.test
mcp:
  port: 9096
  approval_required: true
  perplexity:
    api_key: pplx-secret
    base_url: https://api.perplexity.ai
    rate_limit_per_min: 7
    allow_private: true
clipboard:
  auto_clear_duration: 15
  copyByDefault: true
  printByDefault: true
";

/// `doctor --fix` repairs: zero audit size (fix 3) and a negative clipboard
/// timer (fix 4) next to a payment-bound agent.
const BROKEN: &str = "\
vaultDir: /fixture/vault
agents:
  bot:
    canWrite: true
    skillVersion: \"3\"
    paymentPolicy: card
paymentPolicies:
  card:
    instrument: cards/visa
    allowed_merchants: [acme]
audit:
  maxSizeMb: 0
  maxBackups: 4
clipboard:
  auto_clear_duration: -5
  copyByDefault: true
logging:
  format: json
";

struct Side {
    _root: test_temp_root::TempRoot,
    vault: PathBuf,
    home: PathBuf,
}

fn side(config: &str) -> Side {
    let root = test_temp_root::TempRoot::existing("symvault-config-rewrite-");
    let vault = root.join("vault");
    let home = root.join("home");
    fs::create_dir_all(&vault).expect("vault dir");
    fs::create_dir_all(&home).expect("home dir");
    fs::write(vault.join("config.yaml"), config).expect("write config");
    Side {
        _root: root,
        vault,
        home,
    }
}

fn run(binary: &Path, side: &Side, args: &[&str]) -> Output {
    run_with(binary, side, args, None)
}

/// `bound`: bytes the process reads from the starting vault that the request
/// does not otherwise name; their sha256 becomes part of the recorded request.
fn run_with(binary: &Path, side: &Side, args: &[&str], bound: Option<&str>) -> Output {
    let mut command = Command::new(binary);
    command
        .arg("--vault")
        .arg(&side.vault)
        .args(args)
        .env("HOME", &side.home)
        .env("USERPROFILE", &side.home)
        .env("XDG_CONFIG_HOME", side.home.join("config"))
        .env("XDG_DATA_HOME", side.home.join("data"))
        .env("XDG_CACHE_HOME", side.home.join("cache"))
        .env("CI", "1")
        .env("NO_COLOR", "1");
    if let Some(input) = bound {
        command.env(
            "SYMVAULT_ORACLE_INPUT_SHA256",
            hex::encode(Sha256::digest(input.as_bytes())),
        );
    }
    go_oracle::output(&mut command).expect("run CLI")
}

fn without_sections(yaml: &str, sections: &[&str]) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for line in yaml.split_inclusive('\n') {
        let top_level = !line.starts_with([' ', '\t', '-']) && !line.trim().is_empty();
        if top_level {
            skipping = sections
                .iter()
                .any(|section| line.starts_with(&format!("{section}:")));
        }
        if !skipping {
            out.push_str(line);
        }
    }
    out
}

/// Removes the [`KEPT`] keys (and their nested lines) that sit at indent 4.
fn without_kept(yaml: &str) -> String {
    let mut out = String::new();
    let mut skipping = false;
    for line in yaml.split_inclusive('\n') {
        if KEPT
            .iter()
            .any(|key| line.starts_with(&format!("    {key}:")))
        {
            skipping = true;
            continue;
        }
        if skipping && line.starts_with("        ") {
            continue;
        }
        skipping = false;
        out.push_str(line);
    }
    out
}

fn has_section(yaml: &str, section: &str) -> bool {
    yaml.lines()
        .any(|line| line.starts_with(&format!("{section}:")))
}

/// `tok-YYYYMMDD-<8 hex>` is a fresh random id on every run (the legacy-token
/// migration warning prints one on both sides).
fn mask_token_ids(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("tok-") {
        out.push_str(&rest[..at]);
        let id = &rest[at + 4..];
        let len = id
            .find(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
            .unwrap_or(id.len());
        out.push_str("tok-<id>");
        rest = &id[len..];
    }
    out.push_str(rest);
    out
}

fn config_of(side: &Side) -> String {
    fs::read_to_string(side.vault.join("config.yaml")).expect("read config")
}

/// Runs `args` on both binaries over the same starting config and compares the
/// resulting files and process output.
fn compare(test: &str, label: &str, config: &str, args: &[&str]) {
    let oracle =
        go_oracle::GoOracle::begin("config_rewrite_differential", test, Some(ORACLE_COMMIT));
    let go_binary = oracle.binary();
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let (go_side, rust_side) = (side(config), side(config));
    let go = run_with(&go_binary, &go_side, args, Some(config));
    let rust = run_with(&rust_binary, &rust_side, args, Some(config));
    assert_eq!(rust.status, go.status, "{label}: exit status");
    let normalise = |bytes: &[u8], side: &Side| {
        mask_token_ids(
            &String::from_utf8_lossy(bytes)
                .replace(side.vault.to_str().expect("utf-8 vault"), "__V__"),
        )
    };
    assert_eq!(
        normalise(&rust.stdout, &rust_side),
        normalise(&go.stdout, &go_side),
        "{label}: stdout"
    );
    assert_eq!(
        normalise(&rust.stderr, &rust_side),
        normalise(&go.stderr, &go_side),
        "{label}: stderr"
    );
    let (go_file, rust_file) = (config_of(&go_side), config_of(&rust_side));
    for section in DECLARED {
        assert!(
            !has_section(&go_file, section),
            "{label}: the Go oracle kept {section}; the declared difference is stale"
        );
        assert_eq!(
            has_section(&rust_file, section),
            has_section(config, section),
            "{label}: Rust must keep {section} exactly when the input had it"
        );
    }
    for key in KEPT {
        assert_eq!(
            rust_file.contains(&format!("\n    {key}:")),
            config.contains(&format!("\n  {key}:")),
            "{label}: Rust must keep {key} exactly when the input had it"
        );
    }
    assert_eq!(
        without_kept(&without_sections(&rust_file, &DECLARED)),
        go_file,
        "{label}: config.yaml bytes\n--- rust ---\n{rust_file}"
    );
    // The file Rust wrote loads in both implementations.
    for (name, binary) in [("rust", &rust_binary), ("go", &go_binary)] {
        let reload = side(&rust_file);
        // `config validate` reads the default config path, not `--vault`.
        let default_config = reload.home.join(".symvault").join("config.yaml");
        fs::create_dir_all(default_config.parent().expect("parent")).expect("config dir");
        fs::write(&default_config, &rust_file).expect("write default config");
        let output = run_with(binary, &reload, &["config", "validate"], Some(&rust_file));
        assert!(
            output.status.success(),
            "{label}: {name} cannot load the file Rust wrote: {}{}\n{rust_file}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            config_of(&reload),
            rust_file,
            "{label}: {name} validate rewrote the file"
        );
    }
    assert_eq!(oracle.calls(), 2, "{label}: recorded Go calls replayed");
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn agent_uninstall_rewrites_the_config_like_go() {
    compare(
        "agent_uninstall_rewrites_the_config_like_go",
        "agent uninstall",
        CONFIG,
        &["agent", "uninstall", "other", "--yes"],
    );
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn agent_uninstall_keeps_a_multi_line_description_like_go() {
    compare(
        "agent_uninstall_keeps_a_multi_line_description_like_go",
        "agent uninstall (multi-line)",
        MULTILINE,
        &["agent", "uninstall", "other", "--yes"],
    );
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn agent_uninstall_keeps_every_mcp_field_go_keeps() {
    compare(
        "agent_uninstall_keeps_every_mcp_field_go_keeps",
        "agent uninstall (mcp)",
        MCP,
        &["agent", "uninstall", "other", "--yes"],
    );
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn agent_uninstall_keeps_what_go_drops_and_nothing_else_differs() {
    compare(
        "agent_uninstall_keeps_what_go_drops_and_nothing_else_differs",
        "agent uninstall (dropped by Go)",
        DROPPED_BY_GO,
        &["agent", "uninstall", "other", "--yes"],
    );
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn agent_uninstall_of_the_payment_bound_agent_like_go() {
    compare(
        "agent_uninstall_of_the_payment_bound_agent_like_go",
        "agent uninstall bot",
        CONFIG,
        &["agent", "uninstall", "bot", "--yes"],
    );
}

#[test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "SKIP (darwin recording): replays on macOS only"
)]
fn doctor_fix_repairs_audit_and_clipboard_like_go() {
    const TEST: &str = "doctor_fix_repairs_audit_and_clipboard_like_go";
    const ARGS: [&str; 5] = [
        "doctor",
        "--only",
        "vault.config.validates",
        "--fix",
        "--no-network",
    ];
    compare(TEST, "doctor --fix", BROKEN, &ARGS);
    // The repair really ran on both sides: the file now validates. The second
    // Go session records the Go side of the same repair.
    let oracle = go_oracle::GoOracle::begin(
        "config_rewrite_differential",
        "doctor_fix_repairs_audit_and_clipboard_like_go.repair",
        Some(ORACLE_COMMIT),
    );
    let go_binary = oracle.binary();
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let rust_side = side(BROKEN);
    let _ = run(&rust_binary, &rust_side, &ARGS);
    let fixed = config_of(&rust_side);
    assert!(fixed.contains("maxSizeMb: 100\n"), "{fixed}");
    assert!(fixed.contains("auto_clear_duration: 0\n"), "{fixed}");
    assert!(fixed.contains("paymentPolicies:"), "{fixed}");
    let go_side = side(BROKEN);
    let _ = run_with(&go_binary, &go_side, &ARGS, Some(BROKEN));
    assert!(config_of(&go_side).contains("maxSizeMb: 100\n"));
    assert_eq!(oracle.calls(), 1);
}

const TIERS: [&str; 3] = ["read-only", "standard", "admin"];
const PRESET_BOOLS: [&str; 9] = [
    "canWrite",
    "canRunCommands",
    "canManageConfig",
    "canUseClipboard",
    "canUseAutotype",
    "canReadValues",
    "exposeValueTools",
    "autoUnseal",
    "requireApproval",
];

/// A tiered `bot` with `body` written explicitly, next to the `other` agent
/// the test uninstalls.
fn tiered_config(tier: &str, body: &str) -> String {
    format!(
        "vaultDir: /fixture/vault\nagents:\n  bot:\n    tier: {tier}\n{body}  other:\n    canWrite: true\n"
    )
}

fn profile_show(binary: &Path, side: &Side) -> (Option<i32>, String) {
    let output = run(
        binary,
        side,
        &["agent", "profile", "show", "bot", "--output", "json"],
    );
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// CONFIG-WRITER fix round 3 (HIGH), against the Rust CLI alone: for every
/// tier, every preset-backed field written explicitly as empty / false / zero /
/// null leaves `agent profile show bot --output json` unchanged by
/// `agent uninstall other --yes`. Go's rewrite drops an explicit empty
/// `allowedExecutables` and the next load hands `tier: standard` curl, git,
/// terraform, npm, node, python, python3, docker and kubectl.
#[test]
fn agent_profile_show_is_unchanged_by_a_rewrite_for_every_tier() {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let mut bodies: Vec<(String, String)> = Vec::new();
    for key in PRESET_BOOLS {
        for value in ["true", "false", "null"] {
            bodies.push((format!("{key}={value}"), format!("    {key}: {value}\n")));
        }
    }
    for (key, value) in [
        ("allowedExecutables", "[]"),
        ("allowedExecutables", "null"),
        ("allowedExecutables", "[git]"),
        ("approvalMode", "null"),
        ("approvalMode", "none"),
        ("approvalMode", "deny"),
        ("approvalMode", "prompt"),
        ("approvalTimeout", "0s"),
        ("approvalTimeout", "90s"),
    ] {
        bodies.push((format!("{key}={value}"), format!("    {key}: {value}\n")));
    }
    bodies.push((
        "every preset-backed field explicit".to_owned(),
        PRESET_BOOLS
            .iter()
            .map(|key| format!("    {key}: false\n"))
            .chain([
                "    approvalMode: null\n".to_owned(),
                "    allowedExecutables: []\n".to_owned(),
            ])
            .collect(),
    ));
    let mut failures = Vec::new();
    let mut checked = 0;
    for tier in TIERS {
        for (label, body) in &bodies {
            let side = side(&tiered_config(tier, body));
            let before = profile_show(&binary, &side);
            assert_eq!(before.0, Some(0), "{tier}/{label}: {}", before.1);
            let rewrite = run(&binary, &side, &["agent", "uninstall", "other", "--yes"]);
            assert!(
                rewrite.status.success(),
                "{tier}/{label}: uninstall: {}",
                String::from_utf8_lossy(&rewrite.stderr)
            );
            let after = profile_show(&binary, &side);
            checked += 1;
            if before != after {
                failures.push(format!(
                    "{tier}/{label}:\n--- before\n{}--- after\n{}--- config.yaml\n{}",
                    before.1,
                    after.1,
                    config_of(&side)
                ));
            }
        }
    }
    assert_eq!(checked, TIERS.len() * bodies.len());
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The control: the widened view really differs, so the test above can fail.
#[test]
fn agent_profile_show_sees_a_widened_tier_profile() {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let config = tiered_config(
        "standard",
        "    allowedExecutables: []\n    approvalMode: null\n",
    );
    let narrowed = side(&config);
    let (_, before) = profile_show(&binary, &narrowed);
    assert!(before.contains("\"AllowedExecutables\": null"), "{before}");
    // What Go's rewrite leaves behind: the two explicit keys are gone.
    let widened = tiered_config("standard", "");
    let widened_side = side(&widened);
    let (_, after) = profile_show(&binary, &widened_side);
    assert_ne!(before, after);
    assert!(after.contains("\"curl\""), "{after}");
    assert!(after.contains("\"kubectl\""), "{after}");
}
