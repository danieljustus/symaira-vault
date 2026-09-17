//! Read-only remote configuration reporting.
//!
//! `remote status` only inspects the vault repository and the user's legacy
//! config file.  It deliberately does not unlock the vault or contact a
//! remote, matching the Go command's read-only behavior.

use std::{io::Write, path::Path};

use serde::Serialize;
use symvault_core::config::Config;
use symvault_sync::GitRepository;

const REMOTE_NAME: &str = "origin";

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
    config.git.map_or(true, |git| git.auto_push)
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
    write!(stdout, "Remote configuration for {REMOTE_NAME:?}:\n")
        .map_err(|error| error.to_string())?;
    writeln!(stdout, "  URL:      {url}").map_err(|error| error.to_string())?;
    writeln!(stdout, "  AutoPush: ").map_err(|error| error.to_string())?;
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
    serde_json::to_writer(&mut *stdout, &encoded).map_err(|error| error.to_string())?;
    writeln!(stdout).map_err(|error| error.to_string())
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
/// This output has a fixed two-level shape, so adjust only complete serialized
/// lines rather than changing scalar contents.
fn write_go_yaml(stdout: &mut impl Write, encoded: &str) -> Result<(), String> {
    for line in encoded.split_inclusive('\n') {
        if line.starts_with("  ") {
            write!(stdout, "  {line}").map_err(|error| error.to_string())?;
        } else {
            stdout
                .write_all(line.as_bytes())
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}
