//! Cobra's completion response protocol with a standalone Rust backend.
use crate::cli_artifacts as artifact;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

pub struct Completion {
    pub candidates: Vec<String>,
    pub directive: u8,
}

impl Completion {
    pub fn stdout(&self, descriptions: bool) -> String {
        let mut out = String::new();
        for candidate in &self.candidates {
            let row = if descriptions {
                candidate.as_str()
            } else {
                candidate.split('\t').next().unwrap_or_default()
            };
            out.push_str(row.split('\n').next().unwrap_or_default().trim());
            out.push('\n');
        }
        out.push_str(&format!(":{}\n", self.directive));
        out
    }
}

// Cobra first finds the final command, removing only command words. Discovery
// skips flag values even for flags not known until that final command is found.
fn command_args(args: &[String]) -> (&'static artifact::Command, Vec<&str>) {
    let mut command = artifact::root();
    let mut remaining: Vec<_> = args.iter().map(String::as_str).collect();
    loop {
        let mut i = 0;
        let mut next = None;
        while let Some(word) = remaining.get(i) {
            if *word == "--" {
                break;
            }
            if word.starts_with('-') {
                if !word.contains('=')
                    && (word.starts_with("--") || word.len() == 2)
                    && artifact::flag(command, word).is_none_or(|f| f.no_opt_default.is_empty())
                {
                    i += 1;
                }
            } else if !word.is_empty() {
                next = artifact::child(command, word).map(|child| (i, child));
                break;
            }
            i += 1;
        }
        let Some((index, child)) = next else {
            return (command, remaining);
        };
        remaining.remove(index);
        command = child;
    }
}

fn validate_value(flag: &artifact::Flag, value: &str) -> Result<(), String> {
    let cause = match flag.kind.as_str() {
        "bool" => crate::intake_commands::parse_bool(value).map(|_| ()),
        "int" | "int64" => validate_integer(value),
        "duration" => symvault_core::config::parse_go_duration(value).map(|_| ()),
        _ => Ok(()),
    };
    cause.map_err(|cause| {
        let name = if flag.shorthand.is_empty() {
            format!("--{}", flag.name)
        } else {
            format!("-{}, --{}", flag.shorthand, flag.name)
        };
        format!("invalid argument {value:?} for {name:?} flag: {cause}")
    })
}

// pflag's int and int64 both use strconv.ParseInt(value, 0, 64), not decimal
// Rust parsing. Preserve Go's base prefixes, underscore syntax and range error.
fn validate_integer(value: &str) -> Result<(), String> {
    let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
    let (radix, digits, prefixed) = if unsigned.starts_with("0x") || unsigned.starts_with("0X") {
        (16, &unsigned[2..], true)
    } else if unsigned.starts_with("0b") || unsigned.starts_with("0B") {
        (2, &unsigned[2..], true)
    } else if unsigned.starts_with("0o") || unsigned.starts_with("0O") {
        (8, &unsigned[2..], true)
    } else if unsigned.starts_with('0') {
        (8, unsigned, false)
    } else {
        (10, unsigned, false)
    };
    let digits = if prefixed {
        digits.strip_prefix('_').unwrap_or(digits)
    } else {
        digits
    };
    let mut previous_digit = false;
    let mut valid = !digits.is_empty();
    for character in digits.chars() {
        if character == '_' {
            valid &= previous_digit;
            previous_digit = false;
        } else {
            valid &= character.is_ascii() && character.is_digit(radix);
            previous_digit = true;
        }
    }
    valid &= previous_digit;
    let error = if !valid {
        Some("invalid syntax")
    } else {
        let magnitude = u64::from_str_radix(&digits.replace('_', ""), radix);
        let limit = if value.starts_with('-') {
            1_u64 << 63
        } else {
            i64::MAX as u64
        };
        match magnitude {
            Ok(magnitude) if magnitude <= limit => None,
            _ => Some("value out of range"),
        }
    };
    match error {
        Some(error) => Err(format!("strconv.ParseInt: parsing {value:?}: {error}")),
        None => Ok(()),
    }
}

pub fn complete(
    args: &[String],
    globals: &[String],
    dynamic: impl FnMut(&str, &str) -> Vec<String>,
) -> Result<Completion, String> {
    let Some((prefix, typed)) = args.split_last() else {
        return Ok(Completion {
            candidates: vec![],
            directive: 0,
        });
    };
    let (command, mut typed) = command_args(typed);
    let mut positionals = Vec::new();
    let mut used = BTreeSet::new();
    let mut local_changed = false;
    let mut separator = false;
    let mut pending = None;
    let mut value_prefix = prefix.as_str();
    let mut flag_error = None;
    if !command.disable_flag_parsing {
        let inline = prefix
            .starts_with('-')
            .then(|| prefix.split_once('='))
            .flatten();
        let previous = (!prefix.starts_with('-'))
            .then(|| typed.last().copied())
            .flatten()
            .filter(|word| {
                word.starts_with('-') && word.len() >= 2 && *word != "--" && !word.contains('=')
            });
        if let Some((word, value)) = inline.or_else(|| previous.map(|word| (word, prefix.as_str())))
        {
            let name = if let Some(name) = word.strip_prefix("--") {
                name
            } else {
                word.get(word.len() - 1..).unwrap_or(word)
            };
            let flag = artifact::flags(command)
                .into_iter()
                .find(|f| f.name == name || f.shorthand == name);
            if let Some(flag) = flag {
                if inline.is_some() || flag.no_opt_default.is_empty() {
                    pending = Some(flag);
                    value_prefix = value;
                    if inline.is_none() {
                        typed.pop();
                    }
                }
            } else {
                flag_error = Some(format!(
                    "Subcommand '{}' does not support flag '{name}'",
                    command.name
                ));
            }
        }
    }
    let parsed: Vec<_> = globals
        .iter()
        .map(String::as_str)
        .chain(typed.iter().copied())
        .collect();
    let parse_error = |error| {
        format!(
            "Error while parsing flags from args [{}]: {error}",
            parsed.join(" ")
        )
    };
    let mut parsing_flags = !command.disable_flag_parsing;
    let mut help = false;
    let mut i = 0;
    while let Some(word) = parsed.get(i) {
        if parsing_flags && *word == "--" {
            parsing_flags = false;
            separator = true;
        } else if parsing_flags && word.starts_with('-') && *word != "-" {
            let mut short = word.strip_prefix('-').unwrap_or_default();
            loop {
                let (flag, inline) = if word.starts_with("--") {
                    let flag = artifact::flag(command, word).ok_or_else(|| {
                        parse_error(format!(
                            "unknown flag: {}",
                            word.split('=').next().unwrap_or(word)
                        ))
                    })?;
                    (flag, word.split_once('=').map(|(_, value)| value))
                } else {
                    let name = short.get(..1).ok_or_else(|| {
                        parse_error(format!(
                            "unknown shorthand flag: {:?} in -{short}",
                            char::from(short.as_bytes()[0])
                        ))
                    })?;
                    let flag = artifact::flags(command)
                        .into_iter()
                        .find(|f| f.shorthand == name)
                        .ok_or_else(|| {
                            parse_error(format!("unknown shorthand flag: '{name}' in -{short}"))
                        })?;
                    short = &short[1..];
                    let inline = short.strip_prefix('=').or_else(|| {
                        flag.no_opt_default
                            .is_empty()
                            .then_some(short)
                            .filter(|v| !v.is_empty())
                    });
                    (flag, inline)
                };
                let value = if let Some(value) = inline {
                    value
                } else if !flag.no_opt_default.is_empty() {
                    &flag.no_opt_default
                } else {
                    i += 1;
                    parsed.get(i).copied().ok_or_else(|| {
                        parse_error(if word.starts_with("--") {
                            format!("flag needs an argument: --{}", flag.name)
                        } else {
                            format!("flag needs an argument: '{}' in {word}", flag.shorthand)
                        })
                    })?
                };
                validate_value(flag, value).map_err(&parse_error)?;
                used.insert(flag.name.as_str());
                local_changed |= command.local_flags.iter().any(|f| f.name == flag.name);
                if flag.name == "help" {
                    help = true;
                }
                if word.starts_with("--") || inline.is_some() || short.is_empty() {
                    break;
                }
            }
        } else {
            positionals.push(*word);
        }
        i += 1;
    }
    if !separator && let Some(error) = flag_error {
        return Err(error);
    }
    if help {
        return Ok(Completion {
            candidates: vec![],
            directive: 4,
        });
    }
    if separator {
        pending = None;
    }
    Ok(complete_resolved(
        Resolved {
            command,
            prefix,
            value_prefix,
            positionals,
            used,
            local_changed,
            separator,
            pending,
        },
        dynamic,
    ))
}

struct Resolved<'a> {
    command: &'static artifact::Command,
    prefix: &'a str,
    value_prefix: &'a str,
    positionals: Vec<&'a str>,
    used: BTreeSet<&'static str>,
    local_changed: bool,
    separator: bool,
    pending: Option<&'static artifact::Flag>,
}

fn complete_resolved(
    resolved: Resolved<'_>,
    mut dynamic: impl FnMut(&str, &str) -> Vec<String>,
) -> Completion {
    let Resolved {
        command,
        prefix,
        value_prefix,
        positionals,
        used,
        local_changed,
        separator,
        pending,
    } = resolved;
    if let Some(flag) = pending {
        if flag.name == "profile" {
            return Completion {
                candidates: dynamic("profiles", value_prefix),
                directive: 4,
            };
        }
        if let Some(annotations) = &flag.annotations {
            if let Some(exts) =
                annotations.get("cobra_annotation_bash_completion_filename_extensions")
                && !exts.is_empty()
            {
                return Completion {
                    candidates: exts.clone(),
                    directive: 8,
                };
            }
            if let Some(dirs) = annotations.get("cobra_annotation_bash_completion_subdirs_in_dir") {
                return Completion {
                    candidates: dirs.clone(),
                    directive: 16,
                };
            }
        }
        return Completion {
            candidates: vec![],
            directive: 0,
        };
    }
    let flags = artifact::flags(command);
    let required = |f: &&&artifact::Flag| {
        f.annotations
            .as_ref()
            .is_some_and(|a| a.contains_key("cobra_annotation_bash_completion_one_required_flag"))
            && !used.contains(f.name.as_str())
    };
    let mut candidates = Vec::new();
    if !separator && prefix.starts_with('-') {
        let required_flags: Vec<_> = flags
            .iter()
            .filter(required)
            .filter(|f| {
                format!("--{}", f.name).starts_with(prefix)
                    || (!f.shorthand.is_empty() && format!("-{}", f.shorthand).starts_with(prefix))
            })
            .collect();
        let selected = if required_flags.is_empty() {
            flags.iter().collect::<Vec<_>>()
        } else {
            required_flags
        };
        for flag in selected {
            let repeat = flag.kind.contains("Slice")
                || flag.kind.contains("Array")
                || flag.kind.starts_with("stringTo");
            if flag.hidden
                || !flag.deprecated.is_empty()
                || (used.contains(flag.name.as_str()) && !repeat)
            {
                continue;
            }
            for name in [format!("--{}", flag.name), format!("-{}", flag.shorthand)] {
                if name == "-" || !name.starts_with(prefix) {
                    continue;
                }
                candidates.push(format!("{name}\t{}", flag.usage));
            }
        }
        if !command.disable_flag_parsing {
            return Completion {
                candidates,
                directive: 4,
            };
        }
    }
    let mut directive = 0;
    if command.path == "symvault help" {
        let mut target = artifact::root();
        for part in &positionals {
            let Some(next) = artifact::child(target, part) else {
                return Completion {
                    candidates: vec![],
                    directive: 4,
                };
            };
            target = next;
        }
        let candidates = artifact::children(target)
            .filter(|c| {
                !c.hidden
                    && c.deprecated.is_empty()
                    && (c.available || c.name == "help")
                    && c.name.starts_with(prefix)
            })
            .map(|c| format!("{}\t{}", c.name, c.short))
            .collect();
        return Completion {
            candidates,
            directive: 4,
        };
    }
    if positionals.is_empty() && !local_changed {
        for child in artifact::children(command) {
            if !child.hidden
                && child.deprecated.is_empty()
                && (child.available || child.name == "help")
            {
                directive = 4;
                if child.name.starts_with(prefix) {
                    candidates.push(format!("{}\t{}", child.name, child.short));
                }
            }
        }
    }
    for flag in flags.iter().filter(required) {
        let name = format!("--{}", flag.name);
        if name.starts_with(prefix) {
            candidates.push(format!("{name}\t{}", flag.usage));
        }
    }
    if let Some(valid) = &command.valid_args
        && !valid.is_empty()
    {
        if positionals.is_empty() {
            candidates.extend(valid.iter().filter(|s| s.starts_with(prefix)).cloned());
            if candidates.is_empty()
                && let Some(aliases) = &command.arg_aliases
            {
                candidates.extend(aliases.iter().filter(|s| s.starts_with(prefix)).cloned());
            }
            directive = 4;
        }
    } else if !command.dynamic.is_empty() {
        directive = 4;
        if command.dynamic == "config" || positionals.is_empty() {
            candidates.extend(dynamic(&command.dynamic, value_prefix));
        }
    }
    Completion {
        candidates,
        directive,
    }
}

/// Only the first command word can select the hidden protocol entry point.
pub fn request_index(args: &[OsString]) -> Option<usize> {
    if !args
        .iter()
        .any(|a| a == "__complete" || a == "__completeNoDesc")
    {
        return None;
    }
    let mut i = 1;
    while let Some(word) = args.get(i).and_then(|s| s.to_str()) {
        if word.starts_with('-') {
            let flag = artifact::flag(artifact::root(), word)?;
            if !word.contains('=') && flag.no_opt_default.is_empty() {
                i += 1;
            }
        } else {
            return matches!(word, "__complete" | "__completeNoDesc").then_some(i);
        }
        i += 1;
    }
    None
}

pub fn run(args: &[OsString], index: usize) -> ExitCode {
    let raw: Option<Vec<String>> = args[index + 1..]
        .iter()
        .map(|a| a.to_str().map(str::to_owned))
        .collect();
    let Some(raw) = raw.filter(|a| !a.is_empty()) else {
        crate::print_error_like_go("requires at least 1 arg(s), only received 0");
        return ExitCode::from(1);
    };
    let globals: Vec<_> = args[1..index]
        .iter()
        .filter_map(|a| a.to_str().map(str::to_owned))
        .collect();
    let mut line = globals.clone();
    line.extend(raw.iter().cloned());
    let vault = option(&line, "--vault");
    let profile = option(&line, "--profile");
    let result = complete(&raw, &globals, |kind, prefix| match kind {
        "config" => artifact::DATA
            .config_keys
            .iter()
            .filter(|s| !s.contains('*') && s.starts_with(prefix))
            .cloned()
            .collect(),
        "profiles" => {
            // Go's os.UserHomeDir uses USERPROFILE on Windows and HOME on Unix.
            let Some(home) = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
                .filter(|home| !home.is_empty())
            else {
                return vec![];
            };
            match symvault_core::config::Config::load(
                PathBuf::from(home).join(".symvault/config.yaml"),
            ) {
                Ok(config) => config
                    .profiles
                    .unwrap_or_default()
                    .into_keys()
                    .filter(|name| name.starts_with(prefix))
                    .collect(),
                Err(_) => vec![],
            }
        }
        "entries" => entry_paths(vault.as_deref(), profile.as_deref(), prefix),
        _ => vec![],
    })
    .unwrap_or_else(|error| {
        eprintln!("[Debug] [Error] {error}");
        Completion {
            candidates: vec![],
            directive: 0,
        }
    });
    let descriptions = args[index] != "__completeNoDesc"
        && std::env::var("SYMVAULT_COMPLETION_DESCRIPTIONS")
            .ok()
            .and_then(|s| crate::intake_commands::parse_bool(&s).ok())
            != Some(false);
    if io::stdout()
        .lock()
        .write_all(result.stdout(descriptions).as_bytes())
        .is_err()
    {
        return ExitCode::FAILURE;
    }
    let label = match result.directive {
        4 => "ShellCompDirectiveNoFileComp",
        8 => "ShellCompDirectiveFilterFileExt",
        16 => "ShellCompDirectiveFilterDirs",
        _ => "ShellCompDirectiveDefault",
    };
    eprintln!("Completion ended with directive: {label}");
    ExitCode::SUCCESS
}

fn option(args: &[String], name: &str) -> Option<PathBuf> {
    args.iter().enumerate().rev().find_map(|(i, a)| {
        if a == name {
            args.get(i + 1).map(PathBuf::from)
        } else {
            a.strip_prefix(&format!("{name}=")).map(PathBuf::from)
        }
    })
}

fn entry_paths(
    vault: Option<&std::path::Path>,
    profile: Option<&std::path::Path>,
    prefix: &str,
) -> Vec<String> {
    let Ok(root) = crate::resolve_vault(vault, profile.and_then(|p| p.to_str())) else {
        return vec![];
    };
    let runtime = crate::runtime_session_manager();
    cached_entry_paths(&root, &runtime.manager, prefix)
}

fn cached_entry_paths(
    root: &std::path::Path,
    manager: &symvault_core::session::SessionManager,
    prefix: &str,
) -> Vec<String> {
    if crate::require_initialized(root).is_err() {
        return vec![];
    }
    let Some(root_text) = root.to_str() else {
        return vec![];
    };
    let Ok(key) = manager
        .load_identity(root_text, true)
        .map(zeroize::Zeroizing::new)
    else {
        return vec![];
    };
    let Ok(text) = std::str::from_utf8(&key) else {
        return vec![];
    };
    let Ok(identity) = symvault_crypto::parse_identity(text) else {
        return vec![];
    };
    let Ok(store) = symvault_store::Store::open(root, &identity) else {
        return vec![];
    };
    let Ok(paths) = store.read_session(&identity).list() else {
        return vec![];
    };
    paths
        .into_iter()
        .filter(|p| p.starts_with(prefix.trim()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, sync::Arc, time::Duration};
    use symvault_core::{
        config::Config,
        session::{MemoryKeyring, SessionManager},
    };
    use symvault_crypto::{
        SecretBytes, encrypt, generate_identity, identity_string, parse_recipient, recipient_string,
    };
    use symvault_store::{Entry, Store};

    #[test]
    fn actual_go_protocol_queries_replay_through_real_rust_sessions_and_store() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../testdata/port/cli/artifacts.json"))
                .unwrap();
        let cases = fixture["entry_completions"].as_array().unwrap();
        assert_eq!(cases.len(), 519);
        assert_eq!(
            cases
                .iter()
                .filter(|c| c["name"].as_str().unwrap().starts_with("parser/"))
                .count(),
            64
        );
        assert_eq!(
            cases
                .iter()
                .map(|c| c["name"].as_str().unwrap())
                .collect::<BTreeSet<_>>()
                .len(),
            cases.len()
        );
        for case in cases {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("vault");
            let manager = SessionManager::with_system_clock(Arc::new(MemoryKeyring::new()));
            let state = case["state"].as_str().unwrap();
            if state != "absent" {
                fs::create_dir_all(root.join("entries")).unwrap();
                let config = Config {
                    vault_dir: root.to_str().unwrap().to_owned(),
                    ..Config::default()
                };
                fs::write(root.join("config.yaml"), config.to_yaml_bytes().unwrap()).unwrap();
                let identity = generate_identity();
                fs::write(
                    root.join("identity.age"),
                    encrypt(
                        identity_string(&identity).as_bytes(),
                        &[parse_recipient(&recipient_string(&identity)).unwrap()],
                    )
                    .unwrap(),
                )
                .unwrap();
                let store = Store::open(&root, &identity).unwrap();
                for path in ["alpha/account", "alpha/token", "beta"] {
                    let mut entry = Entry::default();
                    entry
                        .data
                        .insert("password".into(), "public-fixture".into());
                    store
                        .write_entry_with_recipients_at(
                            path,
                            &entry,
                            &identity,
                            "2026-10-04T00:00:00Z",
                            None,
                        )
                        .unwrap();
                }
                if state != "locked" {
                    let key = if state == "malformed" {
                        SecretBytes::new(b"not-an-age-identity")
                    } else {
                        identity_string(&identity)
                    };
                    let ttl = if state == "expired" {
                        Duration::from_nanos(1)
                    } else {
                        Duration::from_secs(60)
                    };
                    manager
                        .save_identity(root.to_str().unwrap(), key.as_bytes(), ttl, Duration::ZERO)
                        .unwrap();
                }
            }
            let globals = vec![
                "--vault".to_owned(),
                if case["name"].as_str().unwrap().starts_with("parser/") {
                    "absent-vault".to_owned()
                } else {
                    root.to_str().unwrap().to_owned()
                },
            ];
            let mut args = Vec::new();
            args.extend(
                case["args"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| a.as_str().unwrap().to_owned()),
            );
            let actual = complete(&args, &globals, |kind, prefix| match kind {
                "entries" => cached_entry_paths(&root, &manager, prefix),
                "config" => artifact::DATA
                    .config_keys
                    .iter()
                    .filter(|s| !s.contains('*') && s.starts_with(prefix))
                    .cloned()
                    .collect(),
                _ => vec![],
            });
            let (actual, diagnostic) = match actual {
                Ok(actual) => (actual, String::new()),
                Err(error) => (
                    Completion {
                        candidates: vec![],
                        directive: 0,
                    },
                    format!("[Debug] [Error] {error}\n"),
                ),
            };
            assert_eq!(
                actual.stdout(true),
                case["stdout"].as_str().unwrap(),
                "{}",
                case["name"]
            );
            assert!(!actual.stdout(true).contains("public-fixture"));
            let label = match actual.directive {
                4 => "ShellCompDirectiveNoFileComp",
                8 => "ShellCompDirectiveFilterFileExt",
                16 => "ShellCompDirectiveFilterDirs",
                _ => "ShellCompDirectiveDefault",
            };
            assert_eq!(
                format!("{diagnostic}Completion ended with directive: {label}\n"),
                case["stderr"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
}
