#![cfg(unix)]
#![deny(unsafe_code)]

//! ADR 0037 R9 (PLATFORM-001): the prompts of Go's `resolveConfig` answered by a
//! script on stdin, for the vault-opening commands.
//!
//! `testdata/port/cli/config-prompts.json` holds what the archived Go binary
//! (`legacy/go-oracle`, `ce2390d7`) printed, exited with and left in
//! `config.yaml` for 225 runs: 23 commands, each given the invalid-clipboard
//! configuration of the frozen Go vault (`error-taxonomy.json`, `vault_seed`)
//! and a stdin script (EOF, `n`, `n n`, an empty line, `no`, `y`, `Y`, a padded
//! `y`, `yes`, `n` then `y`, `y` without a newline). The accepting scripts are
//! only run for the commands whose body is safe in a sandbox; the others
//! (`add`, `intake` file and directory, `broker`, `ui`, `mcp serve`, `generate --store`) get declining
//! scripts only. The recording is byte-identical on darwin and in the linux gate
//! container. The pre-existing `error-taxonomy.json` rows cover the same
//! prompts for a closed stdin on `device`, `list`, `verify`, `unlock`,
//! `migrate`, `dynamic generate`, `import <file>` (and non-interactive
//! `get`/`mcp serve --stdio`); this file adds the answers and the other
//! commands.

#[path = "support/temp_root.rs"]
mod test_temp_root;

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use serde::Deserialize;

const CLIPBOARD_INVALID_CONFIG_SUFFIX: &str = "clipboard:\n    auto_clear_duration: -5\n";
const SEED_PASSPHRASE: &str = "correct horse battery staple";
const ORACLE_COMMIT: &str = "ce2390d748818a4beb413e97183b7795efa99411";
const EXPECTED_CASES: usize = 225;

#[derive(Deserialize)]
struct Fixture {
    oracle: Oracle,
    configs: Vec<String>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Oracle {
    commit: String,
    go_version: String,
    program_sha256: String,
    recorded_goos: Vec<String>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    args: Vec<String>,
    stdin: String,
    #[serde(default)]
    files: BTreeMap<String, String>,
    exit_code: i32,
    stdout: String,
    stderr: String,
    config_after_id: usize,
    #[serde(default)]
    timed_out: bool,
}

#[derive(Deserialize)]
struct SeedHolder {
    vault_seed: Vec<SeedFile>,
}

#[derive(Deserialize)]
struct SeedFile {
    path: String,
    kind: String,
    mode: u32,
    #[serde(default)]
    data: String,
    #[serde(default)]
    base64: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(
        "../../../testdata/port/cli/config-prompts.json"
    ))
    .expect("decode the Go config prompt recording")
}

fn seed() -> Vec<SeedFile> {
    serde_json::from_str::<SeedHolder>(include_str!(
        "../../../testdata/port/cli/error-taxonomy.json"
    ))
    .expect("decode the frozen vault seed")
    .vault_seed
}

fn write_seed(root: &Path, seed: &[SeedFile]) {
    use base64::Engine as _;
    let root_text = root.to_string_lossy().into_owned();
    for entry in seed {
        let path = root.join(&entry.path);
        match entry.kind.as_str() {
            "dir" => fs::create_dir_all(&path).expect("create seed directory"),
            "file" => {
                let raw = if entry.base64.is_empty() {
                    let mut data = entry.data.clone();
                    if entry.path.ends_with("/config.yaml") {
                        data.push_str(CLIPBOARD_INVALID_CONFIG_SUFFIX);
                    }
                    data.replace("__ROOT__", &root_text).into_bytes()
                } else {
                    base64::engine::general_purpose::STANDARD
                        .decode(&entry.base64)
                        .expect("decode seed file")
                };
                fs::create_dir_all(path.parent().expect("seed parent")).expect("seed parent");
                fs::write(&path, raw).expect("write seed file");
            }
            other => panic!("seed entry {} has unknown kind {other}", entry.path),
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(entry.mode)).expect("seed mode");
    }
}

/// Replaces the sandbox root (in the spellings the platform renders) by `__ROOT__`.
fn normalize_root(root: &Path, raw: &str) -> String {
    let mut text = raw.to_owned();
    let mut forms = vec![root.to_string_lossy().into_owned()];
    if let Ok(real) = root.canonicalize() {
        forms.insert(0, real.to_string_lossy().into_owned());
    }
    for form in forms {
        text = text.replace(&form, "__ROOT__");
    }
    text
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    config_after: String,
}

fn run(case: &Case, seed: &[SeedFile]) -> Run {
    let root = test_temp_root::TempRoot::existing("symvault-config-prompts-");
    let home = root.join("home");
    fs::create_dir_all(&home).expect("create isolated home");
    let editor = root.join("editor.sh");
    fs::write(&editor, "#!/bin/sh\nexit 0\n").expect("write the editor stand-in");
    fs::set_permissions(&editor, fs::Permissions::from_mode(0o700)).expect("editor mode");
    write_seed(&root, seed);
    for (name, content) in &case.files {
        let path = root.join(name);
        fs::create_dir_all(path.parent().expect("file parent")).expect("file parent");
        fs::write(path, content).expect("write disposable file");
    }
    let config_path = seed
        .iter()
        .find(|entry| entry.kind == "file" && entry.path.ends_with("/config.yaml"))
        .map(|entry| root.join(&entry.path))
        .expect("seed holds a config.yaml");
    let mut command = Command::new(env!("CARGO_BIN_EXE_symvault"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("XDG_CONFIG_HOME", root.join("xdg-config"))
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_CACHE_HOME", root.join("xdg-cache"))
        .env("TMPDIR", &*root)
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .env("TZ", "UTC")
        .env("SYMVAULT_PASSPHRASE", SEED_PASSPHRASE)
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .env("EDITOR", &editor)
        .current_dir(&*root)
        .args(&case.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("run symvault");
    let mut stdin = child.stdin.take().expect("stdin pipe");
    let script = case.stdin.clone().into_bytes();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&script);
    });
    let mut stdout = child.stdout.take().expect("stdout pipe");
    let mut stderr = child.stderr.take().expect("stderr pipe");
    let out_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.read_to_end(&mut bytes);
        bytes
    });
    let err_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll symvault") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "{} did not finish within 60s",
            case.name
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let _ = writer.join();
    let stdout = out_reader.join().expect("stdout reader");
    let stderr = err_reader.join().expect("stderr reader");
    Run {
        code: status.code().unwrap_or(-1),
        stdout: normalize_root(&root, &String::from_utf8_lossy(&stdout)),
        stderr: normalize_root(&root, &String::from_utf8_lossy(&stderr)),
        config_after: normalize_root(&root, &fs::read_to_string(&config_path).unwrap_or_default()),
    }
}

#[test]
fn recording_is_pinned_to_the_archived_oracle() {
    let fixture = fixture();
    assert_eq!(fixture.oracle.commit, ORACLE_COMMIT);
    assert_eq!(fixture.oracle.go_version, "go1.26.6");
    assert_eq!(fixture.oracle.program_sha256.len(), 64);
    assert_eq!(fixture.oracle.recorded_goos, ["darwin", "linux"]);
    assert_eq!(fixture.cases.len(), EXPECTED_CASES);
    assert!(
        fixture.cases.iter().all(|case| !case.timed_out),
        "a recorded run timed out"
    );
    let stdins: std::collections::BTreeSet<&str> = fixture
        .cases
        .iter()
        .map(|case| case.stdin.as_str())
        .collect();
    assert_eq!(stdins.len(), 11, "eleven distinct stdin scripts");
}

#[test]
fn native_cli_matches_go_scripted_config_prompt_answers() {
    let fixture = fixture();
    let seed = seed();
    let mut differences = Vec::new();
    for case in &fixture.cases {
        let run = run(case, &seed);
        let mut check = |field: &str, native: &str, go: &str| {
            if native != go {
                differences.push(format!(
                    "{} [{field}]\n  native: {native:?}\n  go:     {go:?}",
                    case.name
                ));
            }
        };
        check("stdout", &run.stdout, &case.stdout);
        check("stderr", &run.stderr, &case.stderr);
        check(
            "exit code",
            &run.code.to_string(),
            &case.exit_code.to_string(),
        );
        check(
            "config.yaml after",
            &run.config_after,
            &fixture.configs[case.config_after_id],
        );
    }
    assert!(
        differences.is_empty(),
        "{} of {} recorded runs differ from Go:\n{}",
        differences.len(),
        fixture.cases.len(),
        differences.join("\n")
    );
}
