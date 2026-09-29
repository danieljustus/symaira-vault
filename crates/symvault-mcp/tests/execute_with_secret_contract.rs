use std::{collections::BTreeMap, fs, path::Path, sync::Arc, time::Duration};

use serde::Deserialize;
use serde_json::{Value, json};
use symvault_mcp::{
    CommandExecution, CommandExecutor, ReadOnlyRuntimeConfig, StoreReadOnlyRuntime, ToolCallRuntime,
};
use symvault_store::{Entry, Store};
use tempfile::tempdir;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    oracle: Oracle,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Oracle {
    commit: String,
    commit_sha: String,
    source_files: Vec<String>,
    source_digest: String,
    generator_files: Vec<String>,
    generator_digest: String,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    input: Value,
    output: Expected,
}

#[derive(Deserialize)]
struct Expected {
    text: String,
    is_error: bool,
    #[serde(default)]
    error: String,
}

struct FixtureExecutor;

impl CommandExecutor for FixtureExecutor {
    fn run(
        &self,
        command: &[String],
        environment: &BTreeMap<String, String>,
        files: &BTreeMap<String, Vec<u8>>,
        additional_redactions: &[Vec<u8>],
        working_directory: Option<&Path>,
        timeout: Duration,
    ) -> Result<CommandExecution, String> {
        assert_eq!(command, ["go", "run", "<fixture-child-go-source>"]);
        assert_eq!(
            environment.get("GITHUB_PASSWORD").map(String::as_str),
            Some("testpass123")
        );
        assert!(files.is_empty());
        assert_eq!(additional_redactions, [b"testpass123".to_vec()]);
        assert!(working_directory.is_none());
        assert_eq!(timeout, Duration::from_secs(30));
        Ok(CommandExecution {
            stdout: "testpass123".into(),
            stderr: String::new(),
            exit_code: 0,
            timed_out: false,
            duration: Duration::ZERO,
        })
    }
}

#[test]
fn source_bound_go_execute_with_secret_contract() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../testdata/port/mcp/execute-with-secret.json"
    ))
    .expect("decode Go oracle fixture");
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(
        fixture.oracle.commit,
        "12d8c616ae98b954a9b906e0984af1613ca05fde"
    );
    assert_eq!(fixture.oracle.commit_sha, fixture.oracle.commit);
    assert!(!fixture.oracle.source_files.is_empty());
    assert_eq!(fixture.oracle.source_digest.len(), 64);
    assert_eq!(fixture.oracle.generator_files.len(), 3);
    assert_eq!(fixture.oracle.generator_digest.len(), 64);

    let directory = tempdir().expect("temporary vault");
    fs::create_dir(directory.path().join("entries")).expect("entries directory");
    fs::write(
        directory.path().join("config.yaml"),
        b"vault:\n  format_version: 2\n",
    )
    .expect("vault config");
    fs::write(directory.path().join("identity.age"), b"fixture marker").expect("identity marker");
    let identity = symvault_crypto::generate_identity();
    Store::open(directory.path(), &identity)
        .expect("open fixture vault")
        .write_new_entry(
            "github",
            &Entry {
                path: "github".into(),
                data: BTreeMap::from([("password".into(), json!("testpass123"))]),
                ..Entry::default()
            },
            &identity,
        )
        .expect("write synthetic secret");
    let config = ReadOnlyRuntimeConfig {
        available_tools: vec!["execute_with_secret".into()],
        can_run_commands: true,
        allowed_executables: vec!["go".into(), "true".into()],
        allowed_paths: vec!["*".into()],
        approval_mode: "none".into(),
        ..ReadOnlyRuntimeConfig::default()
    };
    let runtime = StoreReadOnlyRuntime::open(directory.path(), identity, config, None, None)
        .expect("open runtime")
        .with_command_executor(Arc::new(FixtureExecutor));

    for case in fixture.cases {
        runtime
            .authorize("execute_with_secret", &case.input)
            .unwrap_or_else(|error| panic!("{} authorization: {}", case.name, error.text));
        let expected_text = normalize_result_text(&case.output.text);
        match runtime.call("execute_with_secret", &case.input) {
            Ok(actual) => {
                assert_eq!(
                    actual.is_error, case.output.is_error,
                    "{} error flag",
                    case.name
                );
                assert_eq!(
                    normalize_result_text(&actual.text),
                    expected_text,
                    "{} text",
                    case.name
                );
                assert_eq!(
                    case.output.error, "",
                    "{} unexpected Go handler error",
                    case.name
                );
            }
            Err(actual_error) => {
                assert_eq!(
                    case.output.error, actual_error,
                    "{} handler error",
                    case.name
                );
                assert!(case.output.text.is_empty(), "{} expected text", case.name);
            }
        }
    }
}

fn normalize_result_text(text: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<Value>(text) else {
        return text.to_owned();
    };
    if let Some(object) = value.as_object_mut() {
        if object.contains_key("duration_ms") {
            object.insert("duration_ms".into(), Value::from(0));
        }
        for key in ["stdout", "stderr"] {
            if let Some(output) = object
                .get_mut(key)
                .and_then(|value| value.as_str())
                .map(str::to_owned)
            {
                object.insert(key.into(), Value::String(normalize_marker(&output)));
            }
        }
    }
    serde_json::to_string(&value).expect("encode normalized result")
}

fn normalize_marker(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"DATA_")
            && bytes.get(index + 5..index + 21).is_some_and(|marker| {
                marker.len() == 16 && marker.iter().all(u8::is_ascii_hexdigit)
            })
        {
            output.push_str("DATA_FIXTURE");
            index += 21;
        } else {
            let character = text[index..].chars().next().expect("valid UTF-8 boundary");
            output.push(character);
            index += character.len_utf8();
        }
    }
    output
}
