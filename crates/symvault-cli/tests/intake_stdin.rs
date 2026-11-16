//! `intake --stdin-as <entry>` (danieljustus/symaira-vault#1605): one text
//! source read from stdin, staged under a chosen entry path. Covers the round
//! trip into a normal entry, the refusals that must not write, and the help and
//! manual lines of the Rust-only flag.
#![cfg(unix)]

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use serde_json::Value;

const BINARY: &str = env!("CARGO_BIN_EXE_symvault");
const PASSPHRASE: &str = "synthetic-1605-passphrase";
const USAGE: &str = "Read one text source from stdin instead of files and stage it for this entry path (refused if the entry exists)";
/// A selection as it is copied out of a mail or a chat: German labels, a
/// spaced separator, an `=` and a URL with its own `:` and `=`.
const SELECTION: &str = "Zugang zum Hosting:\nBenutzername: synthetic-user\nPasswort : Synthetic:Pass=1605\nAPI Key = sk-synthetic-1605\nURL: https://example.invalid/login?a=b\nPasswort: second-1605\n";

struct Sandbox {
    _guard: tempfile::TempDir,
    home: PathBuf,
    vault: PathBuf,
}

fn sandbox() -> Sandbox {
    let guard = tempfile::Builder::new()
        .prefix("symvault-1605-")
        .tempdir()
        .expect("sandbox");
    let home = guard.path().join("home");
    fs::create_dir_all(&home).expect("home");
    let vault = home.join("vault");
    let sandbox = Sandbox {
        _guard: guard,
        home,
        vault,
    };
    let init = run(&sandbox, &["init", "--auth", "passphrase"], "");
    assert!(init.status.success(), "init: {}", text(&init.stderr));
    sandbox
}

fn run(sandbox: &Sandbox, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(BINARY)
        .arg("--vault")
        .arg(&sandbox.vault)
        .args(args)
        .current_dir(&sandbox.home)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &sandbox.home)
        .env("TMPDIR", &sandbox.home)
        .env("XDG_CONFIG_HOME", sandbox.home.join("config"))
        .env("XDG_DATA_HOME", sandbox.home.join("data"))
        .env("XDG_CACHE_HOME", sandbox.home.join("cache"))
        .env("SYMVAULT_PASSPHRASE", PASSPHRASE)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("LANG", "C")
        .env("CI", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run symvault");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("{e}: {} {}", text(&output.stdout), text(&output.stderr)))
}

fn fields(result: &Value) -> Vec<(&str, &str)> {
    result["suggestions"]
        .as_array()
        .expect("suggestions")
        .iter()
        .map(|s| (s["path"].as_str().unwrap(), s["field"].as_str().unwrap()))
        .collect()
}

#[test]
fn stdin_text_becomes_a_normal_entry_under_the_chosen_path() {
    let sandbox = sandbox();
    let entry = "hosting/example";
    let expected = [
        (entry, "username"),
        (entry, "password"),
        (entry, "token"),
        (entry, "url"),
        // Reported, but the first value per field is the one that is stored.
        (entry, "password"),
    ];

    // Dry run: field names for the chosen entry, no value, nothing written.
    let preview = run(
        &sandbox,
        &["intake", "--stdin-as", entry, "--dry-run", "--json"],
        SELECTION,
    );
    assert_eq!(preview.status.code(), Some(0), "{}", text(&preview.stderr));
    let result = &json(&preview)["results"][0];
    assert_eq!(result["file"], "-");
    assert_eq!(result["status"], "ok");
    assert_eq!(result["provenance"]["source_path"], "-");
    assert_eq!(fields(result), expected);
    let printed = text(&preview.stdout);
    for secret in ["synthetic-user", "Synthetic:Pass", "sk-synthetic"] {
        assert!(!printed.contains(secret), "dry run printed {secret}");
    }
    let listed = run(&sandbox, &["list"], "");
    assert!(!text(&listed.stdout).contains("example"), "dry run wrote");

    // Stage, then promote the batch like any reviewed intake.
    let staged = run(
        &sandbox,
        &["intake", "--stdin-as", entry, "--json"],
        SELECTION,
    );
    assert_eq!(staged.status.code(), Some(0), "{}", text(&staged.stderr));
    let staged = json(&staged);
    assert_eq!(fields(&staged["results"][0]), expected);
    let import_id = staged["import_id"].as_str().expect("import id").to_owned();
    let promoted = run(&sandbox, &["import", "review", "promote", &import_id], "");
    assert_eq!(
        promoted.status.code(),
        Some(0),
        "{}",
        text(&promoted.stderr)
    );

    for (field, value) in [
        ("username", "synthetic-user"),
        ("password", "Synthetic:Pass=1605"),
        ("token", "sk-synthetic-1605"),
        ("url", "https://example.invalid/login?a=b"),
        // Prose and the repeated label are kept, not dropped.
        ("notes", "Zugang zum Hosting:\nPasswort: second-1605"),
    ] {
        let stored = run(
            &sandbox,
            &["get", &format!("{entry}.{field}"), "--print"],
            "",
        );
        assert_eq!(
            text(&stored.stdout).trim_end_matches('\n'),
            value,
            "{field}"
        );
    }
    // No unmasked copy of the selection next to the masked fields.
    let stored = text(&run(&sandbox, &["get", entry, "--output", "json"], "").stdout);
    assert!(stored.contains("\"password\":\"***\""), "{stored}");
    assert!(
        !stored.contains("attachment") && !stored.contains("Synthetic"),
        "{stored}"
    );
    let quarantine = run(&sandbox, &["import", "review", "list"], "");
    assert_eq!(text(&quarantine.stdout), "No quarantined imports found.\n");
    // The spool with the plaintext copy is gone.
    let leftovers: Vec<_> = fs::read_dir(&sandbox.home)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("symvault-intake-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    // The entry exists now: a second selection for it is refused before any write.
    let again = run(
        &sandbox,
        &["intake", "--stdin-as", entry, "--json"],
        "Passwort: other\n",
    );
    assert_eq!(again.status.code(), Some(9), "{}", text(&again.stdout));
    assert!(
        text(&again.stderr).contains("--stdin-as: entry \"hosting/example\" already exists"),
        "{}",
        text(&again.stderr)
    );
    let quarantine = run(&sandbox, &["import", "review", "list"], "");
    assert_eq!(text(&quarantine.stdout), "No quarantined imports found.\n");
}

/// Without a recognized label the text itself is the entry: it stays the
/// encrypted attachment, as for a file source.
#[test]
fn unlabelled_stdin_text_stays_an_attachment() {
    let sandbox = sandbox();
    let staged = run(
        &sandbox,
        &["intake", "--stdin-as", "misc/freeform", "--json"],
        "user a / pass b\n",
    );
    assert_eq!(staged.status.code(), Some(0), "{}", text(&staged.stderr));
    let staged = json(&staged);
    assert_eq!(
        fields(&staged["results"][0]),
        [("misc/freeform", "attachment")]
    );
    let import_id = staged["import_id"].as_str().expect("import id");
    let promoted = run(&sandbox, &["import", "review", "promote", import_id], "");
    assert_eq!(
        promoted.status.code(),
        Some(0),
        "{}",
        text(&promoted.stderr)
    );
    let stored = text(&run(&sandbox, &["get", "misc/freeform", "--output", "json"], "").stdout);
    // base64("user a / pass b\n")
    assert!(stored.contains("dXNlciBhIC8gcGFzcyBiCg=="), "{stored}");
}

#[test]
fn refusals_name_the_flag_and_write_nothing() {
    let sandbox = sandbox();
    for (args, stdin, code, message) in [
        (
            &["intake", "--stdin-as", "x", "--dry-run"][..],
            "",
            9,
            "--stdin-as: stdin is empty",
        ),
        (
            &["intake", "--stdin-as", "quarantine/x"][..],
            SELECTION,
            9,
            "--stdin-as needs an entry path outside quarantine/",
        ),
        (
            &["intake", "--stdin-as", "x", "some-file.txt"][..],
            SELECTION,
            9,
            "--stdin-as reads its only source from stdin",
        ),
        (
            &["intake", "--stdin-as", "../x"][..],
            SELECTION,
            9,
            "--stdin-as: ",
        ),
        // Without the flag (or with an empty value) the file rule still applies.
        (
            &["intake"][..],
            SELECTION,
            1,
            "requires at least 1 arg(s), only received 0",
        ),
        (
            &["intake", "--stdin-as="][..],
            SELECTION,
            1,
            "requires at least 1 arg(s), only received 0",
        ),
    ] {
        let output = run(&sandbox, args, stdin);
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(code), "{args:?}: {stderr}");
        assert!(stderr.contains(message), "{args:?}: {stderr}");
    }
    let listed = run(&sandbox, &["list", "--output", "json"], "");
    assert_eq!(
        text(&listed.stdout).trim(),
        "null",
        "a refusal wrote an entry"
    );
}

/// Lines of `rust` left after greedily matching every line of `go`; `None` when
/// `go` is not a subsequence of `rust`.
fn extra_lines(go: &str, rust: &str) -> Option<Vec<String>> {
    let mut go_lines = go.lines().peekable();
    let mut extra = Vec::new();
    for line in rust.lines() {
        if go_lines.peek() == Some(&line) {
            go_lines.next();
        } else {
            extra.push(line.to_owned());
        }
    }
    go_lines.peek().is_none().then_some(extra)
}

/// The frozen Go help and manual page gain exactly the declared flag, last in
/// cobra's sorted flag list.
#[test]
fn help_and_manual_add_exactly_the_rust_only_flag() {
    let sandbox = sandbox();
    let artifacts: Value =
        serde_json::from_str(include_str!("../../../testdata/port/cli/artifacts.json")).unwrap();

    let help = text(&run(&sandbox, &["intake", "--help"], "").stdout);
    let line = format!("      --stdin-as string   {USAGE}");
    assert_eq!(
        extra_lines(
            artifacts["help"]["symvault intake"].as_str().unwrap(),
            &help
        ),
        Some(vec![line.clone()])
    );
    let position = |needle: &str| help.find(needle).unwrap_or_else(|| panic!("{needle}"));
    assert!(
        position("--ocr-text") < position(&line) && position(&line) < position("\n\nGlobal Flags:")
    );

    let target = sandbox.home.join("man");
    let generated = run(
        &sandbox,
        &["generate", "manpages", target.to_str().unwrap()],
        "",
    );
    assert_eq!(
        generated.status.code(),
        Some(0),
        "{}",
        text(&generated.stderr)
    );
    let mask = |page: &str| -> String {
        page.lines()
            .map(|line| {
                if line.starts_with(".TH ") {
                    ".TH"
                } else if line.contains("Auto generated by spf13/cobra") {
                    "<HISTORY>"
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let name = "symvault-intake.1";
    let page = fs::read_to_string(target.join(name)).unwrap();
    let entry = "\\fB--stdin-as\\fP=\"\"";
    let usage_line = format!("\t{USAGE}");
    assert_eq!(
        extra_lines(
            &mask(artifacts["manpages"][name].as_str().unwrap()),
            &mask(&page)
        ),
        Some(vec![
            ".PP".to_owned(),
            entry.to_owned(),
            usage_line.clone(),
            String::new()
        ])
    );
    let committed = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/man")
            .join(name),
    )
    .unwrap();
    assert!(
        committed.contains(entry) && committed.contains(&usage_line),
        "docs/man/{name}"
    );
}
