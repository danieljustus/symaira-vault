//! Frozen productive Go output plus a mandatory live comparison in the port gate.
use sha2::{Digest, Sha256};

use std::{
    env,
    path::Path,
    process::{Command, Output},
};

const BINARY: &str = env!("CARGO_BIN_EXE_symvault");
const PAGES: [(&str, &[u8]); 4] = [
    ("update", include_bytes!("../src/help-update.txt")),
    ("check", include_bytes!("../src/help-update-check.txt")),
    ("apply", include_bytes!("../src/help-update-apply.txt")),
    ("info", include_bytes!("../src/help-update-info.txt")),
];

fn run(binary: &Path, args: &[&str], home: &Path) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env_remove("SYMVAULT_VAULT")
        .env_remove("SYMVAULT_PASSPHRASE")
        .env_remove("SYMVAULT_AGENT")
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run update help in disposable root")
}

#[test]
fn update_help_matches_frozen_and_actual_go_without_accessing_vault_or_updater() {
    let home = tempfile::tempdir().expect("disposable HOME/XDG root");
    let go = env::var_os("SYMVAULT_GO_BINARY");
    assert!(
        go.is_some() || env::var_os("SYMVAULT_HELP_REQUIRE_GO_ORACLE").is_none(),
        "live Go oracle required"
    );
    let mut count = 0;
    for ((topic, page), digest) in PAGES.into_iter().zip([
        "6edd6c16551d423a1246f50c721aba5794c1095e2837dfa08e0654096d8d46b3",
        "9e3735dd6ba38ee91c133eb57f8bff967140dc83d2e330f45fed2e65bd577f72",
        "42cb3811e6a102e077eb579fc1c17ba445d96f92e089f5ea0a94ce2ee3acb527",
        "ffd5d76a2a4879387aacc3597ea3a937a2216a4de0bea05e434af6b0bba35e33",
    ]) {
        assert_eq!(
            format!("{:x}", Sha256::digest(page)),
            digest,
            "retained actual Go page {topic}"
        );
        let command = if topic == "update" {
            vec!["update"]
        } else {
            vec!["update", topic]
        };
        let mut cases = Vec::new();
        for flag in ["--help", "-h", "--help=true"] {
            let mut args = command.clone();
            args.push(flag);
            cases.push(args);
        }
        let mut help = vec!["help"];
        help.extend_from_slice(&command);
        cases.push(help);
        let mut global = vec![
            "--quiet",
            "--output=json",
            "--vault",
            "missing-vault",
            "--profile",
            "missing-profile",
        ];
        global.extend_from_slice(&command);
        global.push("--help");
        cases.push(global);
        let mut after = command.clone();
        after.extend(["--vault", "missing-vault", "--output", "yaml", "--help"]);
        cases.push(after);
        let mut repeated = command.clone();
        repeated.extend(["--help=false", "--help"]);
        cases.push(repeated);
        if topic == "update" {
            cases.push(vec!["update"]);
            cases.push(vec!["update", "--json", "--help"]);
            cases.push(vec!["update", "unknown-topic", "--help"]);
            cases.push(vec!["help", "update", "unknown-topic"]);
        } else {
            let mut extra = command.clone();
            extra.extend(["extra", "--help"]);
            cases.push(extra);
            let mut json = command.clone();
            json.extend(["--json", "--help"]);
            cases.push(json);
        }
        if topic == "check" || topic == "apply" {
            let mut force = command.clone();
            force.extend(["--force", "--help"]);
            cases.push(force);
        }
        if topic == "apply" {
            cases.push(vec![
                "update",
                "apply",
                "--dry-run",
                "--force",
                "--json",
                "--help",
            ]);
        }
        for args in cases {
            let rust = run(Path::new(BINARY), &args, home.path());
            assert_eq!(rust.status.code(), Some(0), "{args:?}: {:?}", rust.stderr);
            assert_eq!(rust.stdout, page, "frozen stdout {args:?}");
            assert!(rust.stderr.is_empty(), "{args:?}: {:?}", rust.stderr);
            if let Some(go) = &go {
                let actual = run(Path::new(go), &args, home.path());
                assert_eq!(
                    actual.status.code(),
                    rust.status.code(),
                    "actual Go status {args:?}: {:?}",
                    actual.stderr
                );
                assert_eq!(actual.stdout, rust.stdout, "actual Go stdout {args:?}");
                assert_eq!(actual.stderr, rust.stderr, "actual Go stderr {args:?}");
            }
            count += 1;
        }
    }
    assert_eq!(count, 41, "all intended live help cases must execute");
    assert_eq!(
        std::fs::read_dir(home.path()).unwrap().count(),
        0,
        "help must not create vault, cache, session or installer files"
    );
}

#[test]
fn update_help_does_not_swallow_unknown_flags_or_argument_separator() {
    let home = tempfile::tempdir().expect("disposable HOME/XDG root");
    for args in [
        &["update", "check", "--bad", "--help"][..],
        &["update", "check", "--help", "--bad"][..],
        &["update", "apply", "--bad", "--help"][..],
        &["update", "apply", "--", "--help"][..],
        &["update", "check", "--", "--help"][..],
        &["update", "info", "--help=invalid"][..],
    ] {
        let output = run(Path::new(BINARY), args, home.path());
        assert!(!output.status.success(), "must reject {args:?}");
        assert!(
            output.stdout.is_empty(),
            "must not render help for {args:?}"
        );
        assert!(!output.stderr.is_empty(), "explicit error for {args:?}");
    }
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}
