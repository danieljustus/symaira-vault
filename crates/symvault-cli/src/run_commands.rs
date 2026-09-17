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
}
