//! Secret environment construction for the `run` command.
//!
//! This module deliberately stops before process creation.  The caller owns
//! command policy, environment filtering, and subprocess lifetime; this
//! module only parses mappings and resolves the requested vault references.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde_json::Value;
use symvault_crypto::Identity;
use symvault_store::{Entry, Store, StoreError};

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
        if let Ok(entry) = store.get(candidate_path, identity)
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
        let error =
            build_secret_environment(&env_flags, &[env_file.path().to_path_buf()], &mut resolve)
                .expect_err("duplicate mapping");
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
        .expect_err("invalid flag");
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
            "map[count:42 enabled:true password:synthetic-secret unset:<nil>]"
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
}
