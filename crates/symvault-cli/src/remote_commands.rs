//! Read-only remote configuration reporting.
//!
//! `remote status` only inspects the vault repository and the user's legacy
//! config file.  It deliberately does not unlock the vault or contact a
//! remote, matching the Go command's read-only behavior.

use std::{env, io::Write, path::Path};

use serde::Serialize;
use symvault_core::config::{Config, GitConfig};
use symvault_sync::GitRepository;

const REMOTE_NAME: &str = "origin";

/// Adds a named SSH remote and enables Git auto-push in the user's legacy
/// configuration, matching `remote init`. The command only edits the local
/// repository; `push` is an explicit opt-in and reports a failed initial push
/// as a warning, as the Go command does.
#[allow(clippy::too_many_arguments)] // Direct CLI arguments plus isolated output streams.
pub(crate) fn init(
    root: &Path,
    home: &Path,
    target: &str,
    name: &str,
    custom_path: Option<&str>,
    push: bool,
    quiet: bool,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("ssh-target must not be empty".to_owned());
    }
    if !root.join("config.yaml").is_file() || !root.join("identity.age").is_file() {
        return Err("vault not initialized. Run 'symvault init' first".to_owned());
    }
    let repository = GitRepository::open(root)
        .map_err(|error| format!("cannot check existing remotes: {error}"))?;
    if let Some(existing_url) = repository
        .remote_url(name)
        .map_err(|error| format!("cannot check existing remotes: {error}"))?
    {
        if existing_url.is_empty() {
            return Err(format!(
                "remote {name:?} already exists. Remove it first to reconfigure."
            ));
        }
        return Err(format!(
            "remote {name:?} already exists with URL {existing_url}. Remove it first to reconfigure."
        ));
    }

    let (user, host, repository_path) = parse_ssh_target(target, custom_path)?;
    let remote_url = build_ssh_url(&user, &host, &repository_path);
    repository
        .add_remote(name, &remote_url)
        .map_err(|error| format!("cannot add remote: {error}"))?;

    if let Err(error) = enable_auto_push(home)
        && !quiet
    {
        writeln!(
            stderr,
            "Warning: remote added but could not enable auto_push in config: {error}"
        )
        .map_err(|error| error.to_string())?;
    }

    if !quiet {
        writeln!(stdout, "Remote {name:?} added successfully.")
            .map_err(|error| error.to_string())?;
        write_hint(stderr, quiet, format_args!("SSH target: {target}"))?;
        write_hint(stderr, quiet, format_args!("Remote URL: {remote_url}"))?;
        write_hint(
            stderr,
            quiet,
            format_args!("Bare repo path: {repository_path}"),
        )?;
    }

    if push {
        if !quiet {
            writeln!(stdout, "Pushing vault to remote...").map_err(|error| error.to_string())?;
        }
        // Go's remote init delegates to git.Push(vaultDir), whose implementation
        // always selects the conventional origin remote after adding the named
        // remote. Keep that behavior when callers choose a different --name.
        let result = repository.push(REMOTE_NAME);
        if result.error.is_none() && result.success {
            if !quiet {
                writeln!(stdout, "Vault pushed successfully.")
                    .map_err(|error| error.to_string())?;
            }
        } else if !quiet {
            let error = result
                .error
                .unwrap_or_else(|| "push did not complete".to_owned());
            write_hint(
                stderr,
                quiet,
                format_args!("Warning: initial push failed: {error}"),
            )?;
            write_hint(
                stderr,
                quiet,
                format_args!(
                    "Make sure a bare git repository exists at {repository_path} on {host}"
                ),
            )?;
            write_hint(
                stderr,
                quiet,
                format_args!("Create it with: ssh {host} 'git init --bare {repository_path}'"),
            )?;
        }
    } else if !quiet {
        write_hint(
            stderr,
            quiet,
            format_args!("Create the bare repo on the remote with:"),
        )?;
        write_hint(
            stderr,
            quiet,
            format_args!("  ssh {host} 'git init --bare {repository_path}'"),
        )?;
        write_hint(
            stderr,
            quiet,
            format_args!("Then push with: symvault git push"),
        )?;
    }
    Ok(())
}

fn write_hint(
    stderr: &mut impl Write,
    quiet: bool,
    message: std::fmt::Arguments<'_>,
) -> Result<(), String> {
    if quiet {
        return Ok(());
    }
    writeln!(stderr, "{message}").map_err(|error| error.to_string())
}

fn parse_ssh_target(
    target: &str,
    custom_path: Option<&str>,
) -> Result<(String, String, String), String> {
    let mut user = String::new();
    let mut remainder = target.to_owned();
    if let Some(index) = remainder.rfind('@') {
        user = remainder[..index].to_owned();
        remainder = remainder[index + 1..].to_owned();
    }
    let (host, target_path) = if let Some(index) = remainder.rfind(':') {
        (
            remainder[..index].to_owned(),
            remainder[index + 1..].to_owned(),
        )
    } else {
        (remainder, String::new())
    };
    if host.is_empty() {
        return Err(format!(
            "invalid ssh-target: host must not be empty in ssh target {target:?}"
        ));
    }
    if user.is_empty() {
        user = env::var("USER")
            .or_else(|_| env::var("USERNAME"))
            .unwrap_or_default();
    }
    let repository_path = custom_path
        .filter(|path| !path.is_empty())
        .unwrap_or(&target_path);
    let repository_path = if repository_path.is_empty() {
        "~/symvault-remote.git"
    } else {
        repository_path
    };
    Ok((user, host, repository_path.to_owned()))
}

fn build_ssh_url(user: &str, host: &str, repository_path: &str) -> String {
    let without_tilde = repository_path.strip_prefix('~').unwrap_or(repository_path);
    let clean_path = without_tilde.strip_prefix('/').unwrap_or(without_tilde);
    if user.is_empty() {
        format!("ssh://{host}/~{clean_path}")
    } else {
        format!("ssh://{user}@{host}/~{clean_path}")
    }
}

fn enable_auto_push(home: &Path) -> Result<(), String> {
    let path = home.join(".symvault").join("config.yaml");
    let mut config = Config::load(&path).unwrap_or_default();
    config.git.get_or_insert_with(GitConfig::default).auto_push = true;
    config
        .save_to(path)
        .map_err(|error| format!("cannot save config: {error}"))
}

#[derive(Serialize)]
struct RemoteInfo<'a> {
    #[serde(rename = "autoPush")]
    auto_push: bool,
    name: &'a str,
    url: &'a str,
}

#[derive(Serialize)]
struct RemoteStatus<'a> {
    configured: bool,
    remote: RemoteInfo<'a>,
}

#[derive(Serialize)]
struct NoRemote {
    configured: bool,
    message: &'static str,
}

/// Report the configured `origin` remote in the selected output format.
///
/// `home` is passed by the dispatcher rather than read here so tests and
/// callers can keep HOME/XDG state isolated.  The Go command treats a broken
/// config as the default `auto_push: false` for this display, while a valid
/// config without a git section gets the default `true`.
pub(crate) fn status(
    root: &Path,
    home: &Path,
    format: &str,
    quiet: bool,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), String> {
    let repo =
        GitRepository::open(root).map_err(|error| format!("cannot get remote info: {error}"))?;
    let url = repo
        .remote_url(REMOTE_NAME)
        .map_err(|error| format!("cannot get remote info: {error}"))?;

    if quiet {
        if matches!(format, "text" | "") && url.as_deref().is_none_or(str::is_empty) {
            return write_unconfigured(format, &mut std::io::sink(), stderr);
        }
        return Ok(());
    }

    match url {
        None => write_unconfigured(format, stdout, stderr),
        Some(url) if url.is_empty() => write_unconfigured(format, stdout, stderr),
        Some(url) => {
            let auto_push = load_auto_push(home);
            match format {
                "text" | "" => write_text(stdout, url.as_str(), auto_push),
                "json" => write_json(stdout, &url, auto_push),
                "yaml" => write_yaml(stdout, &url, auto_push),
                other => Err(format!(
                    "unknown output format: {other:?} (valid: text, json, yaml)"
                )),
            }
        }
    }
}

fn load_auto_push(home: &Path) -> bool {
    let path = home.join(".symvault").join("config.yaml");
    let Ok(config) = Config::load(path) else {
        return false;
    };
    config.git.is_none_or(|git| git.auto_push)
}

fn write_unconfigured(
    format: &str,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), String> {
    match format {
        "text" | "" => {
            writeln!(stdout, "No remote configured.").map_err(|error| error.to_string())?;
            writeln!(
                stderr,
                "Use 'symvault remote init <ssh-target>' to configure a remote."
            )
            .map_err(|error| error.to_string())
        }
        "json" => {
            let encoded = NoRemote {
                configured: false,
                message: "No remote configured",
            };
            serde_json::to_writer(&mut *stdout, &encoded).map_err(|error| error.to_string())?;
            writeln!(stdout).map_err(|error| error.to_string())
        }
        "yaml" => {
            let encoded = serde_yaml_ng::to_string(&NoRemote {
                configured: false,
                message: "No remote configured",
            })
            .map_err(|error| error.to_string())?;
            write_go_yaml(stdout, &encoded)
        }
        other => Err(format!(
            "unknown output format: {other:?} (valid: text, json, yaml)"
        )),
    }
}

fn write_text(stdout: &mut impl Write, url: &str, auto_push: bool) -> Result<(), String> {
    writeln!(stdout, "Remote configuration for {REMOTE_NAME:?}:")
        .map_err(|error| error.to_string())?;
    writeln!(stdout, "  URL:      {url}").map_err(|error| error.to_string())?;
    write!(stdout, "  AutoPush: ").map_err(|error| error.to_string())?;
    writeln!(stdout, "{}", if auto_push { "enabled" } else { "disabled" })
        .map_err(|error| error.to_string())
}

fn write_json(stdout: &mut impl Write, url: &str, auto_push: bool) -> Result<(), String> {
    let encoded = RemoteStatus {
        configured: true,
        remote: RemoteInfo {
            auto_push,
            name: REMOTE_NAME,
            url,
        },
    };
    // Go's Encoder disables HTML escaping here but still escapes JS separators.
    let encoded = serde_json::to_string(&encoded)
        .map_err(|error| error.to_string())?
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    writeln!(stdout, "{encoded}").map_err(|error| error.to_string())
}

fn write_yaml(stdout: &mut impl Write, url: &str, auto_push: bool) -> Result<(), String> {
    let encoded = serde_yaml_ng::to_string(&RemoteStatus {
        configured: true,
        remote: RemoteInfo {
            auto_push,
            name: REMOTE_NAME,
            url,
        },
    })
    .map_err(|error| error.to_string())?;
    write_go_yaml(stdout, &encoded)
}

/// yaml.v3 uses four spaces for nested mappings, while serde_yaml_ng uses two.
/// This output has a fixed two-level shape: mapping fields use two spaces,
/// scalar continuations four. Adjust their structural indentation, including
/// YAML Unicode line breaks, while retaining additional scalar whitespace.
fn write_go_yaml(stdout: &mut impl Write, encoded: &str) -> Result<(), String> {
    for line in encoded.split_inclusive(['\n', '\u{85}', '\u{2028}', '\u{2029}']) {
        if line.starts_with("    ") {
            write!(stdout, "    {line}").map_err(|error| error.to_string())?;
        } else if line.starts_with("  ") {
            write!(stdout, "  {line}").map_err(|error| error.to_string())?;
        } else {
            stdout
                .write_all(line.as_bytes())
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}
