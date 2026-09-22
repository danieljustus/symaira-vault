//! `symvault update` — bare help, `update info` installation-method report,
//! and the root output-format gate. `update check` / `update apply` stay
//! blocked on network/cosign and dispatch as unknown words until their
//! runtime is ported.
//!
//! Go references: `cmd/admin/update.go` (`newUpdateCmd`,
//! `newUpdateInfoCmd`), the output-format gate in `internal/cli/cli.go`
//! (`PersistentPreRunE` + `CommandSupportsJSON`), `internal/update/apply.go`
//! (`Info`), and corekit's `updatecheck/installmethod` detection heuristic
//! (pin recorded in the fixture). The byte contract lives in
//! `tests/fixtures/update-info/cases.json` (frozen oracle `d4aa2b13`);
//! `tests/cli_update_info.rs` replays every case against this code.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use serde::Serialize;

/// Install-method string values as published by corekit's `InstallMethod`.
pub(crate) mod method {
    pub(crate) const DIRECT_DOWNLOAD: &str = "direct-download";
    pub(crate) const HOMEBREW: &str = "homebrew";
    pub(crate) const GO_INSTALL: &str = "go-install";
    pub(crate) const PACKAGE_MANAGER: &str = "package-manager";
    pub(crate) const BUILD_FROM_SOURCE: &str = "build-from-source";
    pub(crate) const UNKNOWN: &str = "unknown";
}

use method::*;

pub(crate) struct InstallInfo {
    pub(crate) method: &'static str,
    pub(crate) binary_path: PathBuf,
    pub(crate) self_update_supported: bool,
    pub(crate) guidance: String,
}

/// `symvault update` dispatch — cobra Find semantics over the first word.
pub(crate) fn run(rest: &[OsString], output_format: &str, json_flag: bool) -> ExitCode {
    match rest.first() {
        // Cobra validates the parent's args before `PersistentPreRunE`, so
        // an unknown word reports the command error without the gate; a bare
        // `update` hits the gate first and only then falls through to help.
        None => {
            // The oracle prints the cobra help here; help rendering is a
            // documented non-goal (same class as `symvault help`).
            output_gate(output_format, json_flag).unwrap_or(ExitCode::SUCCESS)
        }
        Some(word) => {
            let word = word.to_string_lossy();
            if word == "info" {
                if let Some(extra) = rest.get(1) {
                    return unknown_command(
                        "symvault update info",
                        &extra.to_string_lossy(),
                        false,
                    );
                }
                return info(json_flag || output_format == "json");
            }
            unknown_command("symvault update", &word, true)
        }
    }
}

/// Go `PersistentPreRunE`: a non-text output format must be supported by the
/// command's JSON annotation. The bare `update` command has none, so every
/// non-text format fails with exit 9. Cobra prints the CLI error once and
/// `ExecuteRoot` prints it again (the repository's doubled-error dialect).
fn output_gate(output_format: &str, json_flag: bool) -> Option<ExitCode> {
    let format = if json_flag { "json" } else { output_format };
    if format == "text" {
        return None;
    }
    let message = format!(
        "Error: output format {format:?} is not supported by 'symvault update' (supported commands: admin config get, delete, device list, find, generate, get, list, mcp agent install, mcp agent list, recipients, remote, share, template generate)\n"
    );
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(message.as_bytes());
    let _ = stderr.write_all(message.as_bytes());
    Some(ExitCode::from(9))
}

/// `unknown command %q for %q`. Parent commands carry no `SilenceErrors`, so
/// cobra and `ExecuteRoot` both print; the info command silences cobra and
/// the error appears exactly once.
fn unknown_command(path: &str, word: &str, doubled: bool) -> ExitCode {
    let message = format!("Error: unknown command {word:?} for {path:?}\n");
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(message.as_bytes());
    if doubled {
        let _ = stderr.write_all(message.as_bytes());
    }
    ExitCode::from(1)
}

#[derive(Serialize)]
struct InfoJson<'a> {
    method: &'a str,
    binary_path: String,
    self_update_supported: bool,
    guidance: &'a str,
}

/// `symvault update info` — detect the installation method and report it.
/// The text report goes to stderr (cobra's `cmd.Printf` writes to
/// `OutOrStderr`); the JSON report goes to stdout like the oracle.
fn info(want_json: bool) -> ExitCode {
    let info = match install_info() {
        Ok(info) => info,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "Error: update info: {error}");
            return ExitCode::from(1);
        }
    };

    if want_json {
        let output = InfoJson {
            method: info.method,
            binary_path: info.binary_path.to_string_lossy().into_owned(),
            self_update_supported: info.self_update_supported,
            guidance: &info.guidance,
        };
        let Ok(mut text) = serde_json::to_string_pretty(&output) else {
            let _ = writeln!(
                std::io::stderr(),
                "Error: encode JSON output: serialize failed"
            );
            return ExitCode::from(1);
        };
        // Go's encoding/json escapes `&`, `<`, `>` and U+2028/U+2029 in
        // string values; serde_json does not. Structural JSON never contains
        // these characters outside strings, so the replacements are safe.
        text = text
            .replace('&', "\\u0026")
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029");
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(text.as_bytes());
        let _ = stdout.write_all(b"\n");
        return ExitCode::SUCCESS;
    }

    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "Installation method: {}", info.method);
    let _ = writeln!(stderr, "Binary path: {}", info.binary_path.display());
    let _ = writeln!(
        stderr,
        "Self-update: {}",
        if info.self_update_supported {
            "supported"
        } else {
            "not supported"
        }
    );
    let _ = writeln!(stderr, "Guidance: {}", info.guidance);
    ExitCode::SUCCESS
}

/// Go `updatepkg.Info`: executable path, detected method, support flag,
/// vault-specific guidance.
fn install_info() -> Result<InstallInfo, String> {
    let binary_path =
        std::env::current_exe().map_err(|error| format!("resolve binary path: {error}"))?;
    let raw = binary_path.to_string_lossy();
    if raw.is_empty() {
        return Err("binary path must not be empty".to_owned());
    }
    let method = detect(&raw);
    Ok(InstallInfo {
        method,
        self_update_supported: method == DIRECT_DOWNLOAD,
        guidance: guidance(method).to_owned(),
        binary_path,
    })
}

/// Corekit's layered heuristic: env vars, path patterns, receipt files,
/// Go module-cache markers, then directory writability.
fn detect(binary_path: &str) -> &'static str {
    // Go runs filepath.EvalSymlinks (falling back to the raw path) and then
    // filepath.Abs; executable paths are already absolute, so canonicalize
    // (which resolves symlinks) stands in for the pair.
    let abs_path = std::fs::canonicalize(binary_path)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| binary_path.to_owned());
    let abs_path = abs_path.as_str();

    detect_from_env(abs_path)
        .or_else(|| detect_from_path(abs_path))
        .or_else(|| detect_from_receipts(abs_path))
        .or_else(|| detect_from_go_cache(abs_path))
        .unwrap_or_else(|| detect_from_writability(abs_path))
}

/// Layer 1: `HOMEBREW_PREFIX`, `GOPATH/bin`, `GOMODCACHE` (prefixes resolve
/// symlinks best-effort, like Go's EvalSymlinks fallback).
fn detect_from_env(abs_path: &str) -> Option<&'static str> {
    if let Some(prefix) = env_resolved("HOMEBREW_PREFIX")
        && abs_path.starts_with(&prefix)
    {
        return Some(HOMEBREW);
    }
    if let Some(gopath) = env_resolved("GOPATH") {
        let bin_dir = PathBuf::from(&gopath).join("bin");
        if abs_path.starts_with(bin_dir.to_string_lossy().as_ref()) {
            return Some(GO_INSTALL);
        }
    }
    if let Some(mod_cache) = env_resolved("GOMODCACHE")
        && abs_path.starts_with(&mod_cache)
    {
        return Some(GO_INSTALL);
    }
    None
}

fn env_resolved(name: &str) -> Option<String> {
    let value = std::env::var(name).ok().filter(|value| !value.is_empty())?;
    Some(
        std::fs::canonicalize(&value)
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or(value),
    )
}

/// Layer 2: fixed path patterns, then GOPATH/home bin directories.
fn detect_from_path(abs_path: &str) -> Option<&'static str> {
    if abs_path.contains("/opt/homebrew/")
        || abs_path.contains("/usr/local/Cellar/")
        || abs_path.contains("/.linuxbrew/")
    {
        return Some(HOMEBREW);
    }
    if abs_path.starts_with("/usr/bin/") {
        return Some(PACKAGE_MANAGER);
    }
    if abs_path.starts_with("/usr/local/bin/") {
        return Some(DIRECT_DOWNLOAD);
    }
    let sep = std::path::MAIN_SEPARATOR_STR;
    if let Some(gopath) = env_resolved("GOPATH") {
        let bin_dir = PathBuf::from(&gopath).join("bin");
        if abs_path.starts_with(&format!("{}{sep}", bin_dir.to_string_lossy())) {
            return Some(GO_INSTALL);
        }
    }
    if let Some(home) = home_dir() {
        let go_bin = PathBuf::from(&home).join("go").join("bin");
        if abs_path.starts_with(&format!("{}{sep}", go_bin.to_string_lossy())) {
            return Some(GO_INSTALL);
        }
        for relative in ["bin", ".local/bin", ".cargo/bin"] {
            let user_bin = PathBuf::from(&home).join(relative);
            if abs_path.starts_with(&format!("{}{sep}", user_bin.to_string_lossy())) {
                return Some(DIRECT_DOWNLOAD);
            }
        }
    }
    None
}

fn home_dir() -> Option<String> {
    let name = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Layer 3: Homebrew Cellar markers and dpkg receipt files.
fn detect_from_receipts(abs_path: &str) -> Option<&'static str> {
    if abs_path.contains("/Cellar/") {
        return Some(HOMEBREW);
    }
    let base = abs_path
        .rsplit(['/', '\\'])
        .next()
        .filter(|base| !base.is_empty())
        .unwrap_or(abs_path);
    if std::fs::metadata(format!("/var/lib/dpkg/info/{base}.list")).is_ok() {
        return Some(PACKAGE_MANAGER);
    }
    None
}

/// Layer 4: Go module-cache markers in the path.
fn detect_from_go_cache(abs_path: &str) -> Option<&'static str> {
    if abs_path.contains('@') || abs_path.contains("/pkg/mod/") {
        return Some(GO_INSTALL);
    }
    None
}

/// Layer 5: Windows never claims a writability fallback; elsewhere a
/// user-writable parent directory means direct download.
#[cfg(windows)]
fn detect_from_writability(_abs_path: &str) -> &'static str {
    BUILD_FROM_SOURCE
}

#[cfg(unix)]
fn detect_from_writability(abs_path: &str) -> &'static str {
    use std::os::unix::fs::MetadataExt;
    // Platform-gated: `Path` is only used on unix (windows takes &str),
    // so the import lives inside this cfg to keep -D unused-imports green
    // on every target.
    use std::path::Path;

    let dir = Path::new(abs_path)
        .parent()
        .unwrap_or_else(|| Path::new("/"));
    let Ok(metadata) = std::fs::metadata(dir) else {
        return UNKNOWN;
    };
    let mode = metadata.mode();
    if mode & 0o200 != 0 || mode & 0o022 != 0 {
        return DIRECT_DOWNLOAD;
    }
    BUILD_FROM_SOURCE
}

/// Vault-specific guidance text (`internal/update/installmethod` keeps the
/// wording; corekit's generic strings differ and are not the contract).
fn guidance(method: &str) -> String {
    match method {
        DIRECT_DOWNLOAD => "Re-run the quick install script: curl -sSfL https://raw.githubusercontent.com/danieljustus/symaira-vault/main/scripts/install.sh | sh",
        HOMEBREW => "Update via Homebrew: brew update && brew upgrade symvault",
        GO_INSTALL => "Update via Go: go install github.com/danieljustus/symaira-vault@latest",
        PACKAGE_MANAGER => "Update via your system package manager (e.g., apt upgrade, yum update, pacman -Syu)",
        BUILD_FROM_SOURCE => "Rebuild from source: git pull && go build ./cmd/symvault",
        UNKNOWN => "Unable to determine installation method. Reinstall from https://github.com/danieljustus/symaira-vault/releases",
        _ => "",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn writability_reports_direct_download_for_writable_dirs() {
        let dir = std::env::temp_dir();
        let probe = dir.join("symvault-writability-probe");
        assert_eq!(
            detect_from_writability(&probe.to_string_lossy()),
            DIRECT_DOWNLOAD
        );
    }

    #[cfg(windows)]
    #[test]
    fn writability_is_build_from_source_on_windows() {
        assert_eq!(
            detect_from_writability("C:\\probe\\symvault"),
            BUILD_FROM_SOURCE
        );
    }
}
