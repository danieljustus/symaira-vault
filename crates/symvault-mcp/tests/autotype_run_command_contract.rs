//! ADR 0037 R13 (MCP-003): the `autotype` and `run_command` tool results are
//! replayed from `testdata/port/mcp/autotype-run-command.json`, recorded from
//! the production Go handlers at legacy/go-oracle (every success, denied and
//! error branch). `autotype` runs against a fake backend; `run_command`
//! against a fake executor that returns the child outcome the Go generator
//! asserted its real subprocess produced.

use std::{collections::BTreeMap, fs, path::Path, sync::Arc, sync::Mutex, time::Duration};

use serde::Deserialize;
use serde_json::Value;
use symvault_core::platform::{Autotype, PlatformError};
use symvault_mcp::{
    CommandExecution, CommandExecutor, ReadOnlyRuntimeConfig, StoreReadOnlyRuntime, ToolCallRuntime,
};
use symvault_store::{Entry, Store};
use tempfile::tempdir;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    vault: VaultSpec,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Oracle {
    commit: String,
    program_sha256: String,
}

#[derive(Deserialize)]
struct VaultSpec {
    entry: String,
    data: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    tool: String,
    profile: Profile,
    input: Value,
    #[serde(default)]
    type_error: String,
    backend: Option<Backend>,
    output: Output,
    typed: Option<String>,
}

#[derive(Deserialize)]
struct Profile {
    can_use_autotype: bool,
    can_run_commands: bool,
    approval_mode: String,
    allowed_paths: Vec<String>,
    #[serde(default)]
    allowed_executables: Vec<String>,
}

#[derive(Deserialize, Clone)]
struct Backend {
    stdout: String,
    stderr: String,
    exit_code: i32,
    timed_out: bool,
    #[serde(default)]
    spawn_error: String,
}

#[derive(Deserialize)]
struct Output {
    text: String,
    is_error: bool,
    #[serde(default)]
    error: String,
}

#[derive(Default)]
struct Typer {
    error: String,
    typed: Mutex<Option<String>>,
}

impl Autotype for Typer {
    fn type_text(&self, text: &str) -> Result<(), PlatformError> {
        *self.typed.lock().unwrap() = Some(text.to_owned());
        if self.error.is_empty() {
            Ok(())
        } else {
            Err(PlatformError::unavailable(self.error.clone()))
        }
    }
}

struct Executor {
    backend: Backend,
    timeout: Duration,
}

impl CommandExecutor for Executor {
    fn run(
        &self,
        _command: &[String],
        _environment: &BTreeMap<String, String>,
        _files: &BTreeMap<String, Vec<u8>>,
        additional_redactions: &[Vec<u8>],
        _working_directory: Option<&Path>,
        timeout: Duration,
    ) -> Result<CommandExecution, String> {
        assert_eq!(timeout, self.timeout, "timeout handed to the executor");
        if !self.backend.spawn_error.is_empty() {
            return Err(format!(
                "failed to run command: {}",
                self.backend.spawn_error
            ));
        }
        // The real executor masks the redactions the handler resolved from the
        // vault (Go: secrets.RunCommand KnownSecrets); mirror that boundary.
        let mask = |text: &str| {
            additional_redactions
                .iter()
                .fold(text.to_owned(), |text, secret| {
                    text.replace(&*String::from_utf8_lossy(secret), "***")
                })
        };
        Ok(CommandExecution {
            stdout: mask(&self.backend.stdout),
            stderr: mask(&self.backend.stderr),
            exit_code: self.backend.exit_code,
            timed_out: self.backend.timed_out,
            duration: Duration::from_millis(3),
        })
    }
}

fn normalize(text: &str) -> String {
    // EmbedAsData draws a random hex marker; duration_ms is wall time.
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(b"DATA_") {
            let hex = bytes[i + 5..]
                .iter()
                .take_while(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                .count();
            if hex > 0 {
                out.push_str("DATA_MARKER");
                i += 5 + hex;
                continue;
            }
        }
        if bytes[i..].starts_with(b"\"duration_ms\":") {
            out.push_str("\"duration_ms\":0");
            i += "\"duration_ms\":".len();
            while bytes.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            continue;
        }
        let character = text[i..].chars().next().unwrap();
        out.push(character);
        i += character.len_utf8();
    }
    out
}

fn fixture() -> Fixture {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/autotype-run-command.json"
    ))
    .expect("decode Go recording");
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle.commit,
        "ce2390d748818a4beb413e97183b7795efa99411"
    );
    assert_eq!(fixture.oracle.program_sha256.len(), 64);
    fixture
}

fn run_case(fixture: &Fixture, case: &Case) {
    let directory = tempdir().expect("temporary vault");
    fs::create_dir(directory.path().join("entries")).unwrap();
    fs::write(
        directory.path().join("config.yaml"),
        b"vault:\n  format_version: 2\n",
    )
    .unwrap();
    fs::write(directory.path().join("identity.age"), b"fixture marker").unwrap();
    let identity = symvault_crypto::generate_identity();
    Store::open(
        symvault_store::data_safety::test_support_pre_marked(directory.path()),
        &identity,
    )
    .unwrap()
    .write_new_entry(
        &fixture.vault.entry,
        &Entry {
            path: fixture.vault.entry.clone(),
            data: fixture.vault.data.clone(),
            ..Entry::default()
        },
        &identity,
    )
    .unwrap();

    let profile = &case.profile;
    let config = ReadOnlyRuntimeConfig {
        agent_name: "fixture".into(),
        available_tools: vec![case.tool.clone()],
        can_use_autotype: profile.can_use_autotype,
        can_run_commands: profile.can_run_commands,
        approval_mode: profile.approval_mode.clone(),
        allowed_paths: profile.allowed_paths.clone(),
        allowed_executables: profile.allowed_executables.clone(),
        ..ReadOnlyRuntimeConfig::default()
    };
    let typer = Arc::new(Typer {
        error: case.type_error.clone(),
        ..Typer::default()
    });
    let mut runtime = StoreReadOnlyRuntime::open(directory.path(), identity, config, None, None)
        .expect("open runtime");
    if case.tool == "autotype" {
        runtime = runtime.with_autotype(typer.clone());
    } else {
        // A case without a scripted backend never reaches the child process:
        // Go rejects it first, so the executor must not run (exit_code -99 and
        // an unmatched text would fail the comparison below).
        let seconds = case
            .input
            .get("timeout")
            .and_then(Value::as_u64)
            .unwrap_or(30);
        let backend = case.backend.clone().unwrap_or(Backend {
            stdout: String::new(),
            stderr: "executor must not run".into(),
            exit_code: -99,
            timed_out: false,
            spawn_error: String::new(),
        });
        runtime = runtime.with_command_executor(Arc::new(Executor {
            backend,
            timeout: Duration::from_secs(seconds),
        }));
    }

    // Go's handler-level `error` can surface at authorization (the Rust gate
    // runs the same checks first) or from the dispatch itself.
    let outcome = match runtime.authorize(&case.tool, &case.input) {
        Ok(()) => runtime.call(&case.tool, &case.input),
        Err(rejection) if rejection.authorization_internal_error => Err(rejection.text),
        Err(rejection) => Ok(rejection),
    };
    match outcome {
        Ok(result) => {
            assert_eq!(case.output.error, "", "{}: Go returned an error", case.name);
            assert_eq!(result.is_error, case.output.is_error, "{} flag", case.name);
            assert_eq!(
                normalize(&result.text),
                normalize(&case.output.text),
                "{} text",
                case.name
            );
        }
        Err(error) => {
            assert_eq!(
                (error, ""),
                (case.output.error.clone(), case.output.text.as_str()),
                "{} handler error",
                case.name
            );
        }
    }
    if case.tool == "autotype" {
        assert_eq!(
            *typer.typed.lock().unwrap(),
            case.typed,
            "{} typed text",
            case.name
        );
    }
}

#[test]
fn go_autotype_tool_results_replay() {
    let fixture = fixture();
    let cases = fixture
        .cases
        .iter()
        .filter(|case| case.tool == "autotype")
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 11);
    for case in cases {
        run_case(&fixture, case);
    }
}

#[test]
fn go_run_command_tool_results_replay() {
    let fixture = fixture();
    let cases = fixture
        .cases
        .iter()
        .filter(|case| case.tool == "run_command")
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 28);
    // The branch that renders a timeout as a Go time.Duration must be present.
    assert!(cases.iter().any(|case| {
        case.output
            .text
            .starts_with("command timed out after 1m0s\n")
    }));
    for case in cases {
        run_case(&fixture, case);
    }
}
