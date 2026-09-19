//! MCP background-service installer (the darwin/launchd path).
//!
//! Mirrors the Go oracle's `internal/daemon` for macOS: the generated plist
//! bytes, the `launchctl` invocation order and the CLI text are byte-compatible
//! with the oracle (verified against `wave3-go-plist-com.symvault.mcp.plist`).
//!
//! `launchctl` is resolved through the parent `PATH` and then started with a
//! cleared environment (only `HOME`), so no secret-bearing variable reaches the
//! helper — the same intent as the oracle's filtered environment.

use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

use symvault_core::error::{CauseKind, CliError, ErrorCause, ExitCode};

const LABEL: &str = "com.symvault.mcp";
const PLIST_FILE: &str = "com.symvault.mcp.plist";
const LOG_FILE: &str = "symvault-mcp.log";
const ERR_LOG_FILE: &str = "symvault-mcp.error.log";

/// Installer inputs, mirroring Go's `daemon.Installer`.
pub struct Installer {
    binary_path: PathBuf,
    vault_dir: PathBuf,
    port: i64,
    bind: String,
    log_path: PathBuf,
    err_log_path: PathBuf,
}

impl Installer {
    /// Builds an installer for `vault_dir`; `port`/`bind` come from the config
    /// section and fall back to the oracle's defaults.
    pub fn new(vault_dir: &Path, port: Option<i64>, bind: Option<&str>) -> Result<Self, CliError> {
        let binary_path = env::current_exe().map_err(|err| {
            CliError::new(
                ExitCode::General,
                "create installer",
                Some(ErrorCause::new(CauseKind::Other, err.to_string())),
            )
        })?;
        let home = home_dir().ok_or_else(|| {
            CliError::new(
                ExitCode::General,
                "create installer",
                Some(ErrorCause::new(CauseKind::Other, "get home directory")),
            )
        })?;
        let port = match port {
            Some(value) if value > 0 => value,
            _ => 8080,
        };
        let bind = match bind {
            Some(value) if !value.is_empty() => value.to_string(),
            _ => "127.0.0.1".to_string(),
        };
        Ok(Installer {
            binary_path,
            vault_dir: vault_dir.to_path_buf(),
            port,
            bind,
            log_path: home.join("Logs").join(LOG_FILE),
            err_log_path: home.join("Logs").join(ERR_LOG_FILE),
        })
    }

    #[must_use]
    pub fn port(&self) -> i64 {
        self.port
    }

    #[must_use]
    pub fn bind(&self) -> &str {
        &self.bind
    }

    #[must_use]
    pub fn vault_dir(&self) -> &Path {
        &self.vault_dir
    }

    /// `~/LaunchAgents/com.symvault.mcp.plist` — the oracle does not use
    /// `~/Library/LaunchAgents` here.
    pub fn service_file_path(&self) -> Result<PathBuf, CliError> {
        let home = home_dir()
            .ok_or_else(|| CliError::new(ExitCode::General, "get home directory", None))?;
        Ok(home.join("LaunchAgents").join(PLIST_FILE))
    }
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

/// Characters rejected before any template rendering (oracle
/// `hasDisallowedChars`).
fn has_disallowed_chars(value: &str) -> bool {
    value.contains(['\n', '\r', '<', '>', '"', '\'', '$', '`', ';', '&', '|'])
}

fn validate_install_options(
    binary_path: &Path,
    vault_dir: &Path,
    bind: &str,
    port: i64,
) -> Result<(), CliError> {
    let mut errs: Vec<&str> = Vec::new();

    if !binary_path.is_absolute() {
        errs.push("binary path must be an absolute path");
    } else if has_disallowed_chars(&binary_path.to_string_lossy()) {
        errs.push("binary path contains disallowed characters (newlines, <>\"'$`;&|)");
    }

    if !vault_dir.is_absolute() {
        errs.push("vault directory must be an absolute path");
    } else if has_disallowed_chars(&vault_dir.to_string_lossy()) {
        errs.push("vault directory contains disallowed characters (newlines, <>\"'$`;&|)");
    }

    if bind.is_empty() {
        errs.push("bind address must not be empty");
    } else if has_disallowed_chars(bind) {
        errs.push("bind address contains disallowed characters (newlines, <>\"'$`;&|)");
    }

    if !(1..=65535).contains(&port) {
        errs.push("port must be between 1 and 65535");
    }

    if errs.is_empty() {
        return Ok(());
    }
    Err(CliError::new(
        ExitCode::General,
        format!("invalid installation options: {}", errs.join("; ")),
        None,
    ))
}

/// Go's `encoding/xml` text escaping for the five characters the oracle can
/// emit here.
fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            other => out.push(other),
        }
    }
    out
}

/// Renders the plist exactly as the oracle does: XML header, DOCTYPE, four-space
/// indentation, `<true></true>` for booleans.
#[must_use]
pub fn render_plist(installer: &Installer, home: &Path) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
    );
    out.push_str("<plist version=\"1.0\">\n");
    out.push_str("    <dict>\n");
    out.push_str(&format!(
        "        <key>Label</key>\n        <string>{}</string>\n",
        xml_escape(LABEL)
    ));
    out.push_str("        <key>ProgramArguments</key>\n        <array>\n");
    let arguments = [
        installer.binary_path.to_string_lossy().to_string(),
        "serve".to_string(),
        "--port".to_string(),
        installer.port.to_string(),
        "--bind".to_string(),
        installer.bind.clone(),
    ];
    for argument in arguments {
        out.push_str(&format!(
            "            <string>{}</string>\n",
            xml_escape(&argument)
        ));
    }
    out.push_str("        </array>\n");
    out.push_str("        <key>EnvironmentVariables</key>\n        <dict>\n");
    out.push_str(&format!(
        "            <key>SYMVAULT_VAULT</key>\n            <string>{}</string>\n",
        xml_escape(&installer.vault_dir.to_string_lossy())
    ));
    out.push_str("        </dict>\n");
    out.push_str("        <key>RunAtLoad</key>\n        <true></true>\n");
    out.push_str("        <key>KeepAlive</key>\n        <true></true>\n");
    out.push_str(&format!(
        "        <key>StandardOutPath</key>\n        <string>{}</string>\n",
        xml_escape(&installer.log_path.to_string_lossy())
    ));
    out.push_str(&format!(
        "        <key>StandardErrorPath</key>\n        <string>{}</string>\n",
        xml_escape(&installer.err_log_path.to_string_lossy())
    ));
    out.push_str("    </dict>\n</plist>\n");
    let _ = home;
    out
}

/// Resolves `launchctl` through the inherited `PATH` (Go's `exec.LookPath`).
fn launchctl_path() -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join("launchctl"))
        .find(|candidate| candidate.is_file())
}

/// Runs `launchctl` with a cleared environment; returns its combined output.
fn run_launchctl(args: &[&str]) -> io::Result<std::process::Output> {
    let Some(binary) = launchctl_path() else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "exec: \"launchctl\": executable file not found in $PATH",
        ));
    };
    let mut command = Command::new(binary);
    command.args(args);
    command.env_clear();
    if let Some(home) = home_dir() {
        command.env("HOME", home);
    }
    command.output()
}

impl Installer {
    /// Writes the plist, unloads any previous instance and loads the service.
    pub fn install(&self) -> Result<(), CliError> {
        validate_install_options(&self.binary_path, &self.vault_dir, &self.bind, self.port)?;

        let plist_path = self.service_file_path()?;
        let home = home_dir()
            .ok_or_else(|| CliError::new(ExitCode::General, "get home directory", None))?;

        if let Some(dir) = plist_path.parent() {
            fs::create_dir_all(dir).map_err(|err| {
                CliError::new(
                    ExitCode::General,
                    "create directory",
                    Some(ErrorCause::new(CauseKind::Other, err.to_string())),
                )
            })?;
        }
        if let Some(dir) = self.log_path.parent() {
            fs::create_dir_all(dir).map_err(|err| {
                CliError::new(
                    ExitCode::General,
                    "create log directory",
                    Some(ErrorCause::new(CauseKind::Other, err.to_string())),
                )
            })?;
        }

        let plist = render_plist(self, &home);
        fs::write(&plist_path, plist)
            .map_err(|_| CliError::permission_denied("failed to write launchd plist"))?;
        set_mode(&plist_path, 0o600);

        // Unload any existing instance first (errors are ignored).
        let _ = run_launchctl(&["unload", &plist_path.to_string_lossy()]);

        match run_launchctl(&["load", &plist_path.to_string_lossy()]) {
            Ok(output) => {
                let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
                combined.push_str(&String::from_utf8_lossy(&output.stderr));
                if output.status.success() {
                    Ok(())
                } else {
                    Err(CliError::new(
                        ExitCode::General,
                        format!("failed to load launchd service: {}", combined.trim()),
                        None,
                    ))
                }
            }
            Err(err) => Err(CliError::new(
                ExitCode::General,
                format!("failed to load launchd service: {}", err),
                Some(ErrorCause::new(CauseKind::Other, err.to_string())),
            )),
        }
    }

    /// Unloads the service (best effort) and removes the plist.
    pub fn uninstall(&self) -> Result<(), CliError> {
        let plist_path = self.service_file_path()?;
        let _ = run_launchctl(&["unload", &plist_path.to_string_lossy()]);

        match fs::remove_file(&plist_path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(CliError::permission_denied(
                "failed to remove launchd plist",
            )),
        }
    }

    /// Returns `running`, `stopped` or `not installed`.
    pub fn status(&self) -> Result<&'static str, CliError> {
        let plist_path = self.service_file_path()?;
        if !plist_path.exists() {
            return Ok("not installed");
        }

        let Ok(output) = run_launchctl(&["list", LABEL]) else {
            return Ok("stopped");
        };

        let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));
        if !output.status.success() {
            return Ok("stopped");
        }

        let trimmed = combined.trim();
        if trimmed.contains(LABEL) {
            let fields: Vec<&str> = trimmed.split_whitespace().collect();
            if fields.len() >= 2 && fields[0] != "-" {
                return Ok("running");
            }
        }
        Ok("stopped")
    }
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plist recorded from the pinned Go oracle in
    /// `target/resume-evidence/wave3-daemon-differential.json`, with the
    /// program's own path, the synthetic home and the vault replaced by
    /// placeholders (those are the only machine-dependent values).
    const ORACLE_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.symvault.mcp</string>
        <key>ProgramArguments</key>
        <array>
            <string>/opt/symvault/bin/symvault</string>
            <string>serve</string>
            <string>--port</string>
            <string>8080</string>
            <string>--bind</string>
            <string>127.0.0.1</string>
        </array>
        <key>EnvironmentVariables</key>
        <dict>
            <key>SYMVAULT_VAULT</key>
            <string>/data/vault</string>
        </dict>
        <key>RunAtLoad</key>
        <true></true>
        <key>KeepAlive</key>
        <true></true>
        <key>StandardOutPath</key>
        <string>/Users/tester/Logs/symvault-mcp.log</string>
        <key>StandardErrorPath</key>
        <string>/Users/tester/Logs/symvault-mcp.error.log</string>
    </dict>
</plist>
"#;

    const TEST_HOME: &str = "/Users/tester";
    const TEST_VAULT: &str = "/data/vault";

    fn fixture_installer() -> Installer {
        Installer {
            binary_path: PathBuf::from("/opt/symvault/bin/symvault"),
            vault_dir: PathBuf::from(TEST_VAULT),
            port: 8080,
            bind: "127.0.0.1".to_string(),
            log_path: PathBuf::from(format!("{TEST_HOME}/Logs/symvault-mcp.log")),
            err_log_path: PathBuf::from(format!("{TEST_HOME}/Logs/symvault-mcp.error.log")),
        }
    }

    #[test]
    fn render_plist_matches_the_go_oracle_byte_for_byte() {
        let installer = fixture_installer();
        let rendered = render_plist(&installer, Path::new(TEST_HOME));
        if rendered != ORACLE_PLIST {
            let left: Vec<&str> = rendered.lines().collect();
            let right: Vec<&str> = ORACLE_PLIST.lines().collect();
            for index in 0..left.len().max(right.len()) {
                let (a, b) = (
                    left.get(index).copied().unwrap_or("<missing>"),
                    right.get(index).copied().unwrap_or("<missing>"),
                );
                assert_eq!(a, b, "plist line {index} diverged");
            }
        }
        assert_eq!(rendered, ORACLE_PLIST);
    }

    #[test]
    fn validation_rejects_injected_values() {
        let installer = fixture_installer();
        assert!(
            validate_install_options(
                &installer.binary_path,
                &installer.vault_dir,
                &installer.bind,
                installer.port
            )
            .is_ok()
        );
        assert!(
            validate_install_options(
                Path::new("relative/symvault"),
                &installer.vault_dir,
                "127.0.0.1",
                8080
            )
            .is_err()
        );
        assert!(
            validate_install_options(
                &installer.binary_path,
                &installer.vault_dir,
                "127.0.0.1;rm -rf /",
                8080
            )
            .is_err()
        );
        assert!(
            validate_install_options(&installer.binary_path, &installer.vault_dir, "", 8080)
                .is_err()
        );
        assert!(
            validate_install_options(&installer.binary_path, &installer.vault_dir, "127.0.0.1", 0)
                .is_err()
        );
        assert!(
            validate_install_options(
                &installer.binary_path,
                &installer.vault_dir,
                "127.0.0.1",
                70000
            )
            .is_err()
        );
    }

    #[test]
    fn service_file_path_is_home_relative_not_library() {
        // The oracle writes `~/LaunchAgents/...`, not `~/Library/LaunchAgents/...`.
        let path = fixture_installer()
            .service_file_path()
            .expect("service path");
        assert!(path.ends_with("LaunchAgents/com.symvault.mcp.plist"));
        assert!(!path.to_string_lossy().contains("Library/LaunchAgents"));
    }
}
