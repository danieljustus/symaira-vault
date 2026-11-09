#![cfg(target_os = "macos")]
//! ADR 0037 R15 (CLI-003): the effective `unlock --ttl` against a persistent
//! session cache.
//!
//! With `CI` unset and no `SYMVAULT_TEST_KEYRING`, both implementations keep the
//! unlocked session in the macOS keychain (`/usr/bin/security`), the only
//! persistent backend. Every case therefore runs in a sandbox `HOME` with a
//! throw-away default keychain created by `security create-keychain`: the
//! search list is read from `$HOME/Library/Preferences`, so the user's login
//! keychain is neither read nor written (`sandbox` asserts that the sandbox
//! keychain is the default one before anything runs, and cleans up).
//!
//! An observation holds what `unlock` printed, and the TTL it stored: the
//! `ttl_ns` and `max_lifetime_ns` fields of the keychain items `session` and
//! `identity` (`go-keyring-base64:` JSON; timestamps and ciphertext only as
//! presence), plus `unlock --check` afterwards. Recorded from the Go oracle
//! (`legacy/go-oracle`, `ce2390d7`) into
//! `testdata/port/cli-observations/cli_unlock_ttl.json`. Recapture:
//! `SYMVAULT_ORACLE=capture SYMVAULT_GO_BINARY=<oracle> cargo test -p
//! symvault-cli --test cli_unlock_ttl`.

#[path = "common/go_oracle_ext.rs"]
mod go_oracle_ext;

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use go_oracle_ext::Observations;
use serde_json::{Map, Value, json};

const ORACLE: &str = "ce2390d748818a4beb413e97183b7795efa99411";
const PASSPHRASE: &str = "synthetic-r15-passphrase";
const SECURITY: &str = "/usr/bin/security";

struct Sandbox {
    _guard: tempfile::TempDir,
    home: PathBuf,
    vault: PathBuf,
    keychain: PathBuf,
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = security(
            &self.home,
            &["delete-keychain", self.keychain.to_str().unwrap()],
        );
    }
}

fn security(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(SECURITY)
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("security")
}

fn base_command(binary: &Path, sandbox: &Sandbox) -> Command {
    let home = &sandbox.home;
    let mut command = Command::new(binary);
    command
        .arg("--vault")
        .arg(&sandbox.vault)
        .current_dir(home)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("LANG", "C")
        .env("TZ", "UTC");
    command
}

/// A fresh `HOME` with its own default keychain and an initialized vault.
/// `config` is written to `config.yaml` after `init`.
fn sandbox(rust: &Path, config: Option<&str>) -> Sandbox {
    let guard = tempfile::Builder::new()
        .prefix("symvault-r15-")
        .tempdir()
        .expect("sandbox");
    let home = guard.path().join("home");
    let keychains = home.join("Library/Keychains");
    fs::create_dir_all(&keychains).expect("keychain dir");
    let keychain = keychains.join("login.keychain-db");
    let sandbox = Sandbox {
        _guard: guard,
        vault: home.join("vault"),
        home,
        keychain,
    };
    let keychain_text = sandbox.keychain.to_str().unwrap();
    for args in [
        &["create-keychain", "-p", "r15-keychain", keychain_text][..],
        &["default-keychain", "-s", keychain_text][..],
        &["set-keychain-settings", keychain_text][..],
    ] {
        let output = security(&sandbox.home, args);
        assert!(output.status.success(), "security {args:?}: {output:?}");
    }
    // The login keychain of the user must not be reachable from the sandbox.
    let listed =
        String::from_utf8_lossy(&security(&sandbox.home, &["list-keychains"]).stdout).into_owned();
    let default = String::from_utf8_lossy(&security(&sandbox.home, &["default-keychain"]).stdout)
        .into_owned();
    assert!(
        default.contains(keychain_text) && listed.contains(keychain_text),
        "sandbox keychain is not the default: {default:?} {listed:?}"
    );
    assert!(
        listed
            .lines()
            .filter(|line| line.contains("login.keychain"))
            .all(|line| line.contains(keychain_text)),
        "another login keychain is on the sandbox search list: {listed:?}"
    );
    let init = base_command(rust, &sandbox)
        .args(["init", "--auth", "passphrase"])
        .output()
        .expect("init");
    assert!(init.status.success(), "init: {init:?}");
    if let Some(config) = config {
        fs::write(sandbox.vault.join("config.yaml"), config).expect("config");
    }
    sandbox
}

fn text(bytes: &[u8], sandbox: &Sandbox) -> String {
    let mut out = String::from_utf8_lossy(bytes).into_owned();
    out = out.replace(&sandbox.home.to_string_lossy().into_owned(), "<HOME>");
    if let Ok(real) = fs::canonicalize(&sandbox.home) {
        out = out.replace(&real.to_string_lossy().into_owned(), "<HOME>");
    }
    out
}

fn outcome(output: &std::process::Output, sandbox: &Sandbox) -> Value {
    json!({
        "exit_code": output.status.code(),
        "stdout": text(&output.stdout, sandbox),
        "stderr": text(&output.stderr, sandbox),
    })
}

/// The stored session record of `account`, reduced to its TTL fields.
fn stored(sandbox: &Sandbox, account: &str) -> Value {
    let service = format!("symvault:{}", sandbox.vault.display());
    let found = security(
        &sandbox.home,
        &["find-generic-password", "-s", &service, "-a", account, "-w"],
    );
    if !found.status.success() {
        return Value::Null;
    }
    let raw = String::from_utf8_lossy(&found.stdout).trim().to_owned();
    let decoded = raw
        .strip_prefix("go-keyring-base64:")
        .map(|payload| B64.decode(payload).expect("keyring base64"))
        .unwrap_or_else(|| raw.clone().into_bytes());
    let record: Value = serde_json::from_slice(&decoded).expect("session record is JSON");
    let mut fields = Map::new();
    for (key, value) in record.as_object().expect("session record object") {
        let kept = if key == "ttl_ns" || key == "max_lifetime_ns" {
            value.clone()
        } else {
            Value::String(format!(
                "<{}>",
                if value.is_string() { "string" } else { "other" }
            ))
        };
        fields.insert(key.clone(), kept);
    }
    Value::Object(fields)
}

/// What `binary unlock <flags>` does in a fresh sandbox.
fn observe(binary: &Path, rust: &Path, case: &Case) -> Value {
    let (config, args) = (case.config, case.args);
    let sandbox = sandbox(rust, config);
    let before = base_command(binary, &sandbox)
        .args(["unlock", "--check"])
        .output()
        .expect("check before");
    let unlock = base_command(binary, &sandbox)
        .args(args)
        .output()
        .expect("unlock");
    // A session that lives a few seconds may be gone or not by the time it is
    // checked; only those whose answer is stable are asked.
    let after = if SHORT_LIVED.contains(&case.name) {
        Value::Null
    } else {
        let output = base_command(binary, &sandbox)
            .args(["unlock", "--check"])
            .output()
            .expect("check after");
        outcome(&output, &sandbox)
    };
    json!({
        "check_before": outcome(&before, &sandbox),
        "unlock": outcome(&unlock, &sandbox),
        "session": stored(&sandbox, "session"),
        "identity": stored(&sandbox, "identity"),
        "check_after": after,
    })
}

const NO_CONFIG: Option<&str> = None;

/// Cases whose TTL is within a second or two of the time the check takes
/// (`1ns` is always gone and stays in).
const SHORT_LIVED: &[&str] = &[
    "sub-second",
    "fraction",
    "one-second",
    "config-timeout-fraction",
];

struct Case {
    name: &'static str,
    config: Option<&'static str>,
    args: &'static [&'static str],
}

const fn case(name: &'static str, args: &'static [&'static str]) -> Case {
    Case {
        name,
        config: NO_CONFIG,
        args,
    }
}

const fn with_config(
    name: &'static str,
    config: &'static str,
    args: &'static [&'static str],
) -> Case {
    Case {
        name,
        config: Some(config),
        args,
    }
}

const CASES: &[Case] = &[
    case("default", &["unlock"]),
    case("minutes", &["unlock", "--ttl", "7m"]),
    case("equals-form", &["unlock", "--ttl=45m"]),
    case(
        "repeated-last-wins",
        &["unlock", "--ttl", "1m", "--ttl", "2m"],
    ),
    case("quiet", &["--quiet", "unlock", "--ttl", "7m"]),
    case("nanosecond", &["unlock", "--ttl", "1ns"]),
    case("sub-second", &["unlock", "--ttl", "999ms"]),
    case("fraction", &["unlock", "--ttl", "1.5s"]),
    case("one-second", &["unlock", "--ttl", "1s"]),
    case("ninety-seconds", &["unlock", "--ttl", "90s"]),
    case("compound", &["unlock", "--ttl", "1h2m3.5s"]),
    case("zero-bare", &["unlock", "--ttl", "0"]),
    case("zero-seconds", &["unlock", "--ttl", "0s"]),
    case("negative", &["unlock", "--ttl", "-5m"]),
    case("negative-nano", &["unlock", "--ttl", "-1ns"]),
    case("above-max-lifetime", &["unlock", "--ttl", "9h"]),
    case("huge", &["unlock", "--ttl", "100000h"]),
    case("max-hours", &["unlock", "--ttl", "2562047h"]),
    case("max-nanos", &["unlock", "--ttl", "9223372036854775807ns"]),
    case("overflow", &["unlock", "--ttl", "2562048h"]),
    case("unitless", &["unlock", "--ttl", "5"]),
    case("empty", &["unlock", "--ttl", ""]),
    case("days", &["unlock", "--ttl", "1d"]),
    case("exponent", &["unlock", "--ttl", "1e3s"]),
    case("check-only", &["unlock", "--check", "--ttl", "9m"]),
    with_config("config-timeout", "sessionTimeout: 2h\n", &["unlock"]),
    with_config(
        "config-timeout-flag-wins",
        "sessionTimeout: 2h\n",
        &["unlock", "--ttl", "3m"],
    ),
    with_config(
        "config-timeout-zero-flag",
        "sessionTimeout: 2h\n",
        &["unlock", "--ttl", "0"],
    ),
    with_config(
        "config-timeout-fraction",
        "sessionTimeout: 1500ms\n",
        &["unlock"],
    ),
    with_config(
        "config-max-lifetime",
        "sessionMaxLifetime: 1h\n",
        &["unlock", "--ttl", "10m"],
    ),
    with_config(
        "config-max-lifetime-below-ttl",
        "sessionMaxLifetime: 5m\n",
        &["unlock", "--ttl", "10m"],
    ),
    with_config(
        "config-both",
        "sessionTimeout: 20m\nsessionMaxLifetime: 2h\n",
        &["unlock"],
    ),
];

#[test]
fn unlock_ttl_matches_go_against_the_keychain() {
    let obs = Observations::begin(
        "cli_unlock_ttl",
        "unlock_ttl_matches_go_against_the_keychain",
        Some(ORACLE),
    );
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    for case in CASES {
        let go = obs.observe(case.name, |go_binary| observe(go_binary, &rust, case));
        if !obs.capturing() {
            let native = observe(&rust, &rust, case);
            assert_eq!(native, go, "unlock {}: {:?}", case.name, case.args);
        }
    }
    assert_eq!(obs.count(), CASES.len());
}
