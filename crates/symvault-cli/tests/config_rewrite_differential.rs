//! CONFIG-WRITER: commands that rewrite `config.yaml` leave the same bytes as
//! Go, against the live Go binary (`SYMVAULT_GO_BINARY`).
//!
//! Go's `SaveTo` drops the top-level `paymentPolicies` and `security`
//! sections; Rust keeps them on purpose (`docs/rust-port/upstream-go-bugs.md`).
//! Those two sections are the only declared difference: the Rust file minus
//! them must equal Go's file byte for byte, and the Rust file must still hold
//! them.

#[path = "support/temp_root.rs"]
mod test_temp_root;

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const DECLARED: [&str; 2] = ["paymentPolicies", "security"];

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
audit:
  maxSizeMb: 0
  maxBackups: 4
clipboard:
  auto_clear_duration: -5
  copyByDefault: true
logging:
  format: json
";

fn oracle() -> Option<PathBuf> {
    env::var_os("SYMVAULT_GO_BINARY").map(PathBuf::from)
}

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
    Command::new(binary)
        .arg("--vault")
        .arg(&side.vault)
        .args(args)
        .env("HOME", &side.home)
        .env("USERPROFILE", &side.home)
        .env("XDG_CONFIG_HOME", side.home.join("config"))
        .env("XDG_DATA_HOME", side.home.join("data"))
        .env("XDG_CACHE_HOME", side.home.join("cache"))
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run CLI")
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
fn compare(label: &str, config: &str, args: &[&str]) {
    let Some(go_binary) = oracle() else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let (go_side, rust_side) = (side(config), side(config));
    let go = run(&go_binary, &go_side, args);
    let rust = run(&rust_binary, &rust_side, args);
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
    assert_eq!(
        without_sections(&rust_file, &DECLARED),
        go_file,
        "{label}: config.yaml bytes\n--- rust ---\n{rust_file}"
    );
}

#[test]
fn agent_uninstall_rewrites_the_config_like_go() {
    compare(
        "agent uninstall",
        CONFIG,
        &["agent", "uninstall", "other", "--yes"],
    );
}

#[test]
fn agent_uninstall_of_the_payment_bound_agent_like_go() {
    compare(
        "agent uninstall bot",
        CONFIG,
        &["agent", "uninstall", "bot", "--yes"],
    );
}

#[test]
fn doctor_fix_repairs_audit_and_clipboard_like_go() {
    compare(
        "doctor --fix",
        BROKEN,
        &[
            "doctor",
            "--only",
            "vault.config.validates",
            "--fix",
            "--no-network",
        ],
    );
    // The repair really ran on both sides: the file now validates.
    if let Some(go_binary) = oracle() {
        let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
        let rust_side = side(BROKEN);
        let _ = run(
            &rust_binary,
            &rust_side,
            &[
                "doctor",
                "--only",
                "vault.config.validates",
                "--fix",
                "--no-network",
            ],
        );
        let fixed = config_of(&rust_side);
        assert!(fixed.contains("maxSizeMb: 100\n"), "{fixed}");
        assert!(fixed.contains("auto_clear_duration: 0\n"), "{fixed}");
        assert!(fixed.contains("paymentPolicies:"), "{fixed}");
        let go_side = side(BROKEN);
        let _ = run(
            &go_binary,
            &go_side,
            &[
                "doctor",
                "--only",
                "vault.config.validates",
                "--fix",
                "--no-network",
            ],
        );
        assert!(config_of(&go_side).contains("maxSizeMb: 100\n"));
    }
}
