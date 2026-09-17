//! Secret environment construction and bounded process execution for `run`.
//!
//! Command policy and vault/session authorization remain with the caller. This
//! module parses mappings, resolves requested vault references, and provides a
//! shared process seam for `run` and attachment commands after authorization.

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
use symvault_core::redact::{EntropyDetector, ScanOptions, Scanner};
use symvault_crypto::Identity;
use symvault_store::{Entry, Store, StoreError};

/// Environment inherited by Go's `secrets.RunCommand` before caller-selected
/// passthrough names and resolved secret mappings are applied.
pub(crate) const RUN_ENV_WHITELIST: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "SHELL",
    "TERM",
    "COLORTERM",
    "DISPLAY",
    "XAUTHORITY",
    "GIT_ASKPASS",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_LAUNCHER",
    "GNUPGHOME",
];

const MAX_PROCESS_OUTPUT: usize = 100 * 1024;

/// Inputs shared by `run` and `file use` after each command has performed its
/// own policy and vault work. `whitelist` is deliberately supplied by the
/// caller because `run` has Go's broad safe set while attachment commands
/// retain their narrower legacy set.
pub(crate) struct ProcessOptions<'a> {
    pub(crate) command: &'a [String],
    pub(crate) environment: &'a BTreeMap<String, String>,
    /// Additional native environment assignments, used when a value is not
    /// guaranteed to be valid UTF-8 (for example a materialized file path).
    pub(crate) extra_environment: &'a [(OsString, OsString)],
    pub(crate) passthrough: &'a [String],
    pub(crate) working_directory: Option<&'a Path>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) redactions: &'a [Vec<u8>],
    /// Apply the shared generic redaction pass after exact known-value masks.
    /// Attachment commands leave this disabled to preserve their established
    /// byte-oriented output behavior.
    pub(crate) generic_redaction: bool,
    pub(crate) whitelist: &'a [&'a str],
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ProcessResult {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) exit_code: i32,
    pub(crate) timed_out: bool,
    pub(crate) duration: Duration,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
    pub(crate) rejected_env_vars: Vec<String>,
}

/// Resolved values to overlay on the child environment.  A caller that needs
/// output redaction can borrow or clone this map at the process boundary.
/// Values must never be formatted into an error or diagnostic by this module.
#[derive(Default, Eq, PartialEq)]
pub(crate) struct SecretEnvironment {
    pub(crate) values: BTreeMap<String, String>,
}

/// Parse and resolve all `--env` and `--env-file` mappings.
///
/// The order mirrors Go's `newRunCmd`: repeated `--env` flags are processed
/// first and the last value for a name wins; env-file names colliding with a
/// previous mapping are rejected.  Duplicate names within one env file keep
/// the last line because Go's parser stores them in a map before the caller
/// checks cross-source duplicates.
pub(crate) fn build_secret_environment<R>(
    env_flags: &[String],
    env_files: &[PathBuf],
    mut resolve: R,
) -> Result<SecretEnvironment, String>
where
    R: FnMut(&str) -> Result<String, String>,
{
    let mut environment = SecretEnvironment::default();

    for env_flag in env_flags {
        let (name, reference) = env_flag
            .split_once('=')
            .ok_or_else(|| invalid_env_format(env_flag))?;
        let value = resolve(reference)?;
        environment.values.insert(name.to_owned(), value);
    }

    for env_file in env_files {
        let mappings = read_env_file(env_file)?;
        for (name, reference) in mappings {
            if environment.values.contains_key(&name) {
                return Err(format!(
                    "duplicate env var {name:?}: defined in both --env and --env-file (or in multiple --env-file)"
                ));
            }
            let value = resolve(&reference)?;
            environment.values.insert(name, value);
        }
    }

    Ok(environment)
}

/// Resolves one environment reference using Go's path/field disambiguation.
///
/// A final dot is treated as a field separator only when the candidate entry
/// exists and contains that field. Otherwise the full reference is read as
/// an entry path, which permits dotted entry names. The Store and Identity
/// are borrowed so this helper performs no writes or session changes.
pub(crate) fn resolve_secret_ref(
    root: &Path,
    identity: &Identity,
    reference: &str,
) -> Result<String, String> {
    let store = Store::open(root, identity).map_err(|error| resolve_error(reference, error))?;
    let mut path = reference;
    let mut field = None;

    if let Some(index) = reference.rfind('.').filter(|index| *index > 0) {
        let candidate_path = &reference[..index];
        let candidate_field = &reference[index + 1..];
        if !candidate_field.is_empty()
            && let Ok(entry) = store.get(candidate_path, identity)
            && entry.data.contains_key(candidate_field)
        {
            path = candidate_path;
            field = Some(candidate_field);
            return format_resolved_value(path, field, &entry);
        }
    }

    let entry = store
        .get(path, identity)
        .map_err(|error| resolve_error(reference, error))?;
    format_resolved_value(path, field, &entry)
}

fn resolve_error(reference: &str, error: StoreError) -> String {
    match error {
        StoreError::EntryNotFound(path) => format!("secret ref not found: {path}"),
        error => format!("cannot resolve secret ref {reference}: {error}"),
    }
}

fn format_resolved_value(path: &str, field: Option<&str>, entry: &Entry) -> Result<String, String> {
    if let Some(field) = field {
        let value = entry
            .data
            .get(field)
            .ok_or_else(|| format!("field not found in secret ref {path}.{field}"))?;
        return Ok(format_go_value(value));
    }
    Ok(format_go_map(&entry.data))
}

fn format_go_map(values: &BTreeMap<String, Value>) -> String {
    let mut rendered = String::from("map[");
    for (index, (key, value)) in values.iter().enumerate() {
        if index > 0 {
            rendered.push(' ');
        }
        rendered.push_str(key);
        rendered.push(':');
        rendered.push_str(&format_go_value(value));
    }
    rendered.push(']');
    rendered
}

fn format_go_value(value: &Value) -> String {
    match value {
        Value::Null => "<nil>".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(values) => {
            let values = values.iter().map(format_go_value).collect::<Vec<_>>();
            format!("[{}]", values.join(" "))
        }
        Value::Object(values) => {
            let values = values
                .iter()
                .map(|(key, value)| format!("{key}:{}", format_go_value(value)))
                .collect::<Vec<_>>();
            format!("map[{}]", values.join(" "))
        }
    }
}

fn invalid_env_format(value: &str) -> String {
    format!("invalid --env format: {value:?} (expected NAME=path.field)")
}

fn read_env_file(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let bytes = fs::read(path).map_err(|error| format!("open env file {path:?}: {error}"))?;
    // Go's bufio.Scanner accepts arbitrary bytes.  The command's references
    // are text at the Rust API boundary, so retain the non-failing behavior
    // and replace invalid UTF-8 only at that boundary.
    let contents = String::from_utf8_lossy(&bytes);
    parse_env_file_contents(path, &contents)
}

fn parse_env_file_contents(
    path: &Path,
    contents: &str,
) -> Result<BTreeMap<String, String>, String> {
    let mut result = BTreeMap::new();
    for (index, raw_line) in contents.lines().enumerate() {
        let line_number = index + 1;
        if raw_line.len() >= 64 * 1024 {
            return Err(format!(
                "read env file {path:?}: bufio.Scanner: token too long"
            ));
        }
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, reference)) = line.split_once('=') else {
            return Err(format!(
                "invalid format in {}:{line_number}: {line:?} (expected NAME=path.field)",
                path.display()
            ));
        };
        let name = name.trim();
        let reference = reference.trim();
        if name.is_empty() || reference.is_empty() {
            return Err(format!(
                "empty name or ref in {}:{line_number}: {line:?}",
                path.display()
            ));
        }
        result.insert(name.to_owned(), reference.to_owned());
    }
    Ok(result)
}

/// Execute a command using the caller-selected environment policy.
///
/// The process itself is deliberately kept behind this small seam so `run`
/// and `file use` share bounded capture, timeout handling, and redaction. A
/// timeout returns a result with `timed_out` set, allowing a caller to retain
/// Go's result-plus-error semantics while attachment commands can keep their
/// existing string error API.
pub(crate) fn run_process(options: ProcessOptions<'_>) -> Result<ProcessResult, String> {
    if options.command.is_empty() {
        return Err("command must contain at least one element".to_owned());
    }

    let mut child_command = Command::new(&options.command[0]);
    child_command.args(&options.command[1..]);
    child_command.env_clear();
    for &key in options.whitelist {
        if let Some(value) = std::env::var_os(key) {
            child_command.env(key, value);
        }
    }

    let mut rejected_env_vars = Vec::new();
    for name in options.passthrough {
        if is_sensitive_env_name(name) {
            rejected_env_vars.push(name.clone());
            continue;
        }
        if let Some(value) = std::env::var_os(name) {
            child_command.env(name, value);
        }
    }
    rejected_env_vars.sort();

    for (name, value) in options.environment {
        child_command.env(name, value);
    }
    for (name, value) in options.extra_environment {
        child_command.env(name, value);
    }
    if let Some(directory) = options.working_directory {
        child_command.current_dir(directory);
    }
    child_command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = child_command
        .spawn()
        .map_err(|error| format!("failed to run command: {error}"))?;
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => return terminate_after_spawn_failure(&mut child, "failed to capture command stdout"),
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => return terminate_after_spawn_failure(&mut child, "failed to capture command stderr"),
    };
    let stdout_reader = thread::spawn(|| read_process_output(stdout));
    let stderr_reader = thread::spawn(|| read_process_output(stderr));
    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if options
                    .timeout
                    .is_some_and(|limit| started.elapsed() >= limit)
                {
                    timed_out = true;
                    let _ = child.kill();
                    break child
                        .wait()
                        .map_err(|error| format!("wait for timed out command: {error}"))?;
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("wait for command: {error}"));
            }
        }
    };
    let duration = started.elapsed();

    if timed_out {
        // A descendant may inherit a pipe and keep it open after the direct
        // child is killed. Detach bounded readers so timeout cleanup does not
        // wait for an unrelated descendant.
        drop(stdout_reader);
        drop(stderr_reader);
        return Ok(ProcessResult {
            stdout: String::new(),
            stderr: String::new(),
            // Go reports -1 for deadline cancellation regardless of the
            // platform-specific status produced after killing the child.
            exit_code: -1,
            timed_out: true,
            duration,
            stdout_truncated: false,
            stderr_truncated: false,
            rejected_env_vars,
        });
    }

    let ((stdout, stdout_truncated), (stderr, stderr_truncated)) =
        join_process_readers(stdout_reader, stderr_reader);
    let stdout = redact_process_output(&stdout, options.redactions, options.generic_redaction);
    let stderr = redact_process_output(&stderr, options.redactions, options.generic_redaction);
    Ok(ProcessResult {
        stdout,
        stderr,
        exit_code: status.code().unwrap_or(-1),
        timed_out: false,
        duration,
        stdout_truncated,
        stderr_truncated,
        rejected_env_vars,
    })
}

fn terminate_after_spawn_failure<T>(child: &mut std::process::Child, message: &str) -> Result<T, String> {
    let _ = child.kill();
    let _ = child.wait();
    Err(message.to_owned())
}

fn is_sensitive_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let normalized: String = upper
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect();
    let joined = normalized.replace('_', "");
    [
        "PASSPHRASE",
        "PASSWORD",
        "PASSWD",
        "SECRET",
        "TOKEN",
        "APIKEY",
        "CREDENTIAL",
        "CREDENTIALS",
        "PRIVATEKEY",
    ]
    .iter()
    .any(|token| joined.contains(token) || normalized.split('_').any(|part| part == *token))
}

fn join_process_readers(
    stdout_reader: thread::JoinHandle<(Vec<u8>, bool)>,
    stderr_reader: thread::JoinHandle<(Vec<u8>, bool)>,
) -> ((Vec<u8>, bool), (Vec<u8>, bool)) {
    let deadline = Instant::now() + Duration::from_millis(250);
    while (!stdout_reader.is_finished() || !stderr_reader.is_finished())
        && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(5));
    }
    let stdout = if stdout_reader.is_finished() {
        stdout_reader.join().unwrap_or_default()
    } else {
        drop(stdout_reader);
        (Vec::new(), false)
    };
    let stderr = if stderr_reader.is_finished() {
        stderr_reader.join().unwrap_or_default()
    } else {
        drop(stderr_reader);
        (Vec::new(), false)
    };
    (stdout, stderr)
}

fn read_process_output(mut reader: impl Read) -> (Vec<u8>, bool) {
    let mut captured = Vec::with_capacity(MAX_PROCESS_OUTPUT);
    let mut buffer = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                let remaining = MAX_PROCESS_OUTPUT.saturating_sub(captured.len());
                captured.extend_from_slice(&buffer[..count.min(remaining)]);
                truncated |= count > remaining;
            }
            Err(_) => break,
        }
    }
    (captured, truncated)
}

fn redact_process_output(
    output: &[u8],
    redactions: &[Vec<u8>],
    generic_redaction: bool,
) -> String {
    let mut output = output.to_vec();
    // Replace longer values first so a short secret that is a prefix of a
    // longer one cannot expose the longer value's suffix.
    let mut order: Vec<_> = (0..redactions.len()).collect();
    order.sort_by_key(|&index| std::cmp::Reverse(redactions[index].len()));
    for index in order {
        output = replace_bytes(&output, &redactions[index], b"***");
    }
    let output = String::from_utf8_lossy(&output).into_owned();
    if !generic_redaction {
        return output;
    }

    // The core scanner is the shared Rust redaction boundary. Its current
    // generic detector is the entropy heuristic; keeping the scan here makes
    // detector failures fail closed through ScanError::safe_result instead of
    // returning the unscanned child output.
    let mut scanner = Scanner::new(vec![Box::new(EntropyDetector::new())]);
    match scanner.scan(&output, &ScanOptions::default()) {
        Ok(result) => result.text,
        Err(error) => error.safe_result.text,
    }
}

fn replace_bytes(input: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return input.to_vec();
    }
    let mut result = Vec::with_capacity(input.len());
    let mut cursor = 0;
    while cursor < input.len() {
        if input[cursor..].starts_with(needle) {
            result.extend_from_slice(replacement);
            cursor += needle.len();
        } else {
            result.push(input[cursor]);
            cursor += 1;
        }
    }
    result
}

pub(crate) fn format_timeout(timeout: Duration) -> String {
    let nanos = timeout.as_nanos();
    if nanos == 0 {
        return "0s".to_owned();
    }
    if nanos < 1_000 {
        return format!("{nanos}ns");
    }
    if nanos < 1_000_000 {
        return format_go_decimal(nanos, 1_000, "µs");
    }
    if nanos < 1_000_000_000 {
        return format_go_decimal(nanos, 1_000_000, "ms");
    }

    let seconds = nanos / 1_000_000_000;
    let remainder = nanos % 1_000_000_000;
    let mut result = String::new();
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;
    if hours > 0 {
        result.push_str(&format!("{hours}h"));
    }
    if hours > 0 || minutes > 0 {
        result.push_str(&format!("{minutes}m"));
    }
    result.push_str(&format_decimal_component(seconds, remainder));
    result.push('s');
    result
}

fn format_go_decimal(value: u128, unit: u128, suffix: &str) -> String {
    let whole = value / unit;
    let remainder = value % unit;
    if remainder == 0 {
        return format!("{whole}{suffix}");
    }
    format!("{}{}", format_fraction(whole, remainder, unit), suffix)
}

fn format_decimal_component(whole: u128, nanos: u128) -> String {
    if nanos == 0 {
        return whole.to_string();
    }
    format_fraction(whole, nanos, 1_000_000_000)
}

fn format_fraction(whole: u128, fraction: u128, unit: u128) -> String {
    let mut digits = fraction.to_string();
    let width = match unit {
        1_000 => 3,
        1_000_000 => 6,
        _ => 9,
    };
    while digits.len() < width {
        digits.insert(0, '0');
    }
    while digits.ends_with('0') {
        digits.pop();
    }
    format!("{whole}.{digits}")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::json;
    use symvault_crypto::generate_identity;
    use symvault_store::Store;

    use super::*;

    static TEST_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TemporaryEnvFile(PathBuf);

    impl TemporaryEnvFile {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TemporaryEnvFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn temporary_env_file(contents: &[u8]) -> TemporaryEnvFile {
        let sequence = TEST_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "symvault-run-env-{}-{sequence}.env",
            std::process::id()
        ));
        fs::write(&path, contents).expect("temporary env file");
        TemporaryEnvFile(path)
    }

    struct TemporaryVault(PathBuf);

    impl TemporaryVault {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TemporaryVault {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temporary_vault() -> (TemporaryVault, Identity) {
        let sequence = TEST_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "symvault-run-resolver-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(path.join("entries")).expect("temporary vault entries");
        fs::write(path.join("config.yaml"), b"vault:\n  format_version: 2\n")
            .expect("temporary vault config");
        fs::write(path.join("identity.age"), b"synthetic identity marker")
            .expect("temporary vault identity marker");
        (TemporaryVault(path), generate_identity())
    }

    fn write_test_entry(
        root: &Path,
        identity: &Identity,
        path: &str,
        data: BTreeMap<String, Value>,
    ) {
        let store = Store::open(root, identity).expect("open temporary vault");
        store
            .write_new_entry(
                path,
                &Entry {
                    path: path.to_owned(),
                    data,
                    ..Entry::default()
                },
                identity,
            )
            .expect("write temporary entry");
    }

    fn resolver<'a>(
        values: &'a BTreeMap<&'a str, &'a str>,
    ) -> impl FnMut(&str) -> Result<String, String> + 'a {
        move |reference| {
            values
                .get(reference)
                .map(|value| (*value).to_owned())
                .ok_or_else(|| format!("secret ref not found: {reference}"))
        }
    }

    #[test]
    fn builds_mappings_with_go_order_and_last_flag_wins() {
        let values = BTreeMap::from([
            ("first.value", "one"),
            ("second.value", "two"),
            ("replacement.value", "three"),
        ]);
        let env_flags = vec![
            "VALUE=first.value".to_owned(),
            "VALUE=replacement.value".to_owned(),
        ];
        // File parsing is tested independently; this test only exercises the
        // resolver/overlay path without touching a filesystem.
        let parsed =
            parse_env_file_contents(Path::new(".env.one"), "# comment\nOTHER=second.value\n\n")
                .expect("env file contents");
        assert_eq!(parsed.get("OTHER"), Some(&"second.value".to_owned()));

        let mut resolve = resolver(&values);
        let direct =
            build_secret_environment(&env_flags, &[], &mut resolve).expect("direct mappings");
        assert_eq!(direct.values.get("VALUE"), Some(&"three".to_owned()));
    }

    #[test]
    fn rejects_cross_source_duplicate_without_resolving_or_disclosing_values() {
        let values = BTreeMap::from([("value", "secret-value")]);
        let env_file = temporary_env_file(b"TOKEN=value\n");
        let parsed = parse_env_file_contents(env_file.path(), "TOKEN=value\n").unwrap();
        assert_eq!(parsed.get("TOKEN"), Some(&"value".to_owned()));

        let env_flags = vec!["TOKEN=value".to_owned()];
        let mut resolve = resolver(&values);
        let error = build_secret_environment(
            &env_flags,
            &[env_file.path().to_path_buf()],
            &mut resolve,
        )
        .err()
        .expect("duplicate mapping");
        assert!(error.contains("duplicate env var"));
        assert!(!error.contains("secret-value"));
    }

    #[test]
    fn matches_env_file_validation_cases() {
        let path = Path::new(".env.symvault");
        assert!(parse_env_file_contents(path, "\n # comment\nNAME=work.value\r\n").is_ok());
        assert!(
            parse_env_file_contents(path, "NOEQUALSIGN\n")
                .expect_err("missing separator")
                .contains("invalid format")
        );
        assert!(
            parse_env_file_contents(path, "=work.value\n")
                .expect_err("empty name")
                .contains("empty name or ref")
        );
        assert!(
            parse_env_file_contents(path, "NAME=\n")
                .expect_err("empty reference")
                .contains("empty name or ref")
        );
        assert!(
            parse_env_file_contents(path, &"A".repeat(64 * 1024))
                .expect_err("overlong line")
                .contains("read env file")
        );
        let invalid_utf8 = temporary_env_file(b"NAME=work.\xFFvalue\n");
        assert!(read_env_file(invalid_utf8.path()).is_ok());
    }

    #[test]
    fn rejects_invalid_flag_syntax_without_resolving() {
        let mut called = false;
        let error = build_secret_environment(&["NOEQUALSIGN".to_owned()], &[], |reference| {
            called = true;
            Ok(reference.to_owned())
        })
        .err()
        .expect("invalid flag");
        assert!(error.contains("invalid --env format"));
        assert!(!called);
    }

    #[test]
    fn resolves_dotted_paths_and_scalar_values_like_go() {
        let (vault, identity) = temporary_vault();
        write_test_entry(
            vault.path(),
            &identity,
            "service",
            BTreeMap::from([
                (
                    "password".to_owned(),
                    Value::String("synthetic-secret".into()),
                ),
                ("count".to_owned(), json!(42)),
                ("enabled".to_owned(), json!(true)),
                ("unset".to_owned(), Value::Null),
                ("".to_owned(), Value::String("empty-field".into())),
            ]),
        );
        write_test_entry(
            vault.path(),
            &identity,
            "github.com",
            BTreeMap::from([("token".to_owned(), Value::String("dotted-secret".into()))]),
        );

        assert_eq!(
            resolve_secret_ref(vault.path(), &identity, "service.password").unwrap(),
            "synthetic-secret"
        );
        assert_eq!(
            resolve_secret_ref(vault.path(), &identity, "service.count").unwrap(),
            "42"
        );
        assert_eq!(
            resolve_secret_ref(vault.path(), &identity, "service.enabled").unwrap(),
            "true"
        );
        assert_eq!(
            resolve_secret_ref(vault.path(), &identity, "service.unset").unwrap(),
            "<nil>"
        );
        assert_eq!(
            resolve_secret_ref(vault.path(), &identity, "github.com.token").unwrap(),
            "dotted-secret"
        );
        assert_eq!(
            resolve_secret_ref(vault.path(), &identity, "service").unwrap(),
            "map[:empty-field count:42 enabled:true password:synthetic-secret unset:<nil>]"
        );
        assert_eq!(
            resolve_secret_ref(vault.path(), &identity, "service.").unwrap(),
            "map[:empty-field count:42 enabled:true password:synthetic-secret unset:<nil>]"
        );
    }

    #[test]
    fn missing_reference_reports_path_without_secret_value() {
        let (vault, identity) = temporary_vault();
        write_test_entry(
            vault.path(),
            &identity,
            "service",
            BTreeMap::from([(
                "password".to_owned(),
                Value::String("synthetic-secret".into()),
            )]),
        );

        let error = resolve_secret_ref(vault.path(), &identity, "missing.password")
            .expect_err("missing reference");
        assert_eq!(error, "secret ref not found: missing.password");
        assert!(!error.contains("synthetic-secret"));
    }

    #[test]
    fn process_redaction_replaces_each_known_value() {
        let redactions = vec![b"plain-secret".to_vec(), b"encoded-secret".to_vec()];
        assert_eq!(
            redact_process_output(b"plain-secret and encoded-secret", &redactions, false),
            "*** and ***"
        );
    }

    #[test]
    fn process_redaction_masks_overlapping_longer_value_first() {
        let redactions = vec![b"token".to_vec(), b"token-suffix".to_vec()];
        assert_eq!(
            redact_process_output(b"token-suffix", &redactions, false),
            "***"
        );
    }

    #[test]
    fn run_redaction_applies_shared_fail_closed_scanner_after_known_values() {
        let input = b"known-secret aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
        let redactions = vec![b"known-secret".to_vec()];
        assert_eq!(
            redact_process_output(input, &redactions, true),
            "*** [REDACTED]"
        );
    }

    #[test]
    fn process_passthrough_rejects_sensitive_names_without_disclosing_values() {
        assert!(is_sensitive_env_name("VAULT_PASS_PHRASE"));
        assert!(is_sensitive_env_name("api-key"));
        assert!(!is_sensitive_env_name("TERM_MODE"));
    }

    #[test]
    fn timeout_format_preserves_go_fractional_units() {
        assert_eq!(format_timeout(Duration::ZERO), "0s");
        assert_eq!(format_timeout(Duration::from_nanos(1)), "1ns");
        assert_eq!(format_timeout(Duration::from_micros(1_500)), "1.5ms");
        assert_eq!(format_timeout(Duration::from_millis(1_500)), "1.5s");
        assert_eq!(
            format_timeout(Duration::from_secs(60) + Duration::from_millis(1)),
            "1m0.001s"
        );
        assert_eq!(
            format_timeout(Duration::from_secs(3_661) + Duration::from_nanos(2)),
            "1h1m1.000000002s"
        );
    }
}
