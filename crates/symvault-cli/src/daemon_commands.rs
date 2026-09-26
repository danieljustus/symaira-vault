//! MCP background-service installer (the darwin/launchd path).
//!
//! Mirrors the Go oracle's `internal/daemon` for macOS: the generated plist
//! bytes, the `launchctl` invocation order and the CLI text are byte-compatible
//! with the oracle (verified against `wave3-go-plist-com.symvault.mcp.plist`).
//!
//! `launchctl` is resolved through the parent `PATH` and then started with a
//! cleared environment (only `HOME`), so no secret-bearing variable reaches the
//! helper — the same intent as the oracle's filtered environment.

// On Windows the module only ever produces the unsupported-platform error, so the
// helpers and fields the macOS/Linux branches need are intentionally unused there.
#![cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    allow(dead_code, unused_imports)
)]

use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

use symvault_core::error::{CauseKind, CliError, ErrorCause, ExitCode};

#[cfg(any(target_os = "macos", test))]
const LABEL: &str = "com.symvault.mcp";
#[cfg(target_os = "macos")]
const PLIST_FILE: &str = "com.symvault.mcp.plist";
#[cfg(any(target_os = "macos", test))]
#[cfg(any(target_os = "macos", test))]
const LOG_FILE: &str = "symvault-mcp.log";
#[cfg(any(target_os = "macos", test))]
const ERR_LOG_FILE: &str = "symvault-mcp.error.log";
#[cfg(target_os = "linux")]
const SYSTEMD_USER_DIR: &str = ".config/systemd/user";
#[cfg(target_os = "linux")]
const SYSTEMD_UNIT_NAME: &str = "symvault-mcp.service";
#[cfg(target_os = "linux")]
const SYSTEMD_UNIT_LABEL: &str = "symvault-mcp";

/// Installer inputs, mirroring Go's `daemon.Installer`.
pub struct Installer {
    binary_path: PathBuf,
    vault_dir: PathBuf,
    port: i64,
    bind: String,
    #[cfg(any(target_os = "macos", test))]
    log_path: PathBuf,
    #[cfg(any(target_os = "macos", test))]
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
                Some(ErrorCause::new(CauseKind::Other, home_dir_error_message())),
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
        // The home lookup must happen on every platform: the oracle reports a
        // missing home from `NewInstaller`, not from the platform branch.
        #[cfg(not(any(target_os = "macos", test)))]
        let _ = &home;

        Ok(Installer {
            binary_path,
            vault_dir: vault_dir.to_path_buf(),
            port,
            bind,
            #[cfg(any(target_os = "macos", test))]
            log_path: crate::agent_list_commands::clean_path(&home.join("Logs").join(LOG_FILE)),
            #[cfg(any(target_os = "macos", test))]
            err_log_path: crate::agent_list_commands::clean_path(
                &home.join("Logs").join(ERR_LOG_FILE),
            ),
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
        #[cfg(target_os = "linux")]
        let result = self.linux_service_file_path();
        #[cfg(target_os = "macos")]
        let result = self.plist_path();
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let result = Err(CliError::new(
            ExitCode::General,
            format!("unsupported platform: {}", std::env::consts::OS),
            None,
        ));
        result
    }
    /// The launchd plist path.
    #[cfg(any(target_os = "macos", test))]
    #[cfg(target_os = "macos")]
    fn plist_path(&self) -> Result<PathBuf, CliError> {
        let home = home_dir()
            .ok_or_else(|| CliError::new(ExitCode::General, home_dir_error_message(), None))?;
        Ok(crate::agent_list_commands::clean_path(
            &home.join("LaunchAgents").join(PLIST_FILE),
        ))
    }
}

/// The oracle's `os.UserHomeDir` error text, kept verbatim; the platform name in
/// the message follows Go's implementation.
fn home_dir_error_message() -> &'static str {
    if cfg!(windows) {
        "get home directory: %USERPROFILE% is not defined"
    } else {
        "get home directory: $HOME is not defined"
    }
}

/// Mirrors Go's `os.UserHomeDir`: `$HOME` on unix, `%USERPROFILE%` (with the
/// `HOMEDRIVE`+`HOMEPATH` fallback) on Windows.
fn home_dir() -> Option<PathBuf> {
    if let Some(home) = env::var_os("HOME").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(home));
    }
    #[cfg(windows)]
    {
        if let Some(profile) = env::var_os("USERPROFILE").filter(|value| !value.is_empty()) {
            return Some(PathBuf::from(profile));
        }
        if let (Some(drive), Some(path)) = (env::var_os("HOMEDRIVE"), env::var_os("HOMEPATH"))
            && !drive.is_empty()
            && !path.is_empty()
        {
            let mut joined = PathBuf::from(drive);
            joined.push(path);
            return Some(joined);
        }
    }
    None
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
#[cfg(any(target_os = "macos", test))]
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
#[cfg(any(target_os = "macos", test))]
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
#[cfg(target_os = "macos")]
fn launchctl_path() -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join("launchctl"))
        .find(|candidate| candidate.is_file())
}

/// Runs `launchctl` with a cleared environment; returns its combined output.
#[cfg(target_os = "macos")]
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

#[cfg(target_os = "linux")]
fn systemctl_path() -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join("systemctl"))
        .find(|candidate| candidate.is_file())
}

/// Runs `systemctl` with a cleared environment; returns its combined output.
#[cfg(target_os = "linux")]
fn run_systemctl(args: &[&str]) -> io::Result<std::process::Output> {
    let Some(binary) = systemctl_path() else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "exec: \"systemctl\": executable file not found in $PATH",
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

/// Escapes a value for a systemd unit file, mirroring the oracle's
/// `systemdEscape` (backslashes first, then quotes, then `$`).
#[cfg(any(target_os = "linux", test))]
fn systemd_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "$$")
}

#[cfg(any(target_os = "linux", test))]
const SYSTEMD_TEMPLATE: &str = r#"[Unit]
Description=Symaira Vault MCP Server

[Service]
Type=simple
ExecStart="{{BINARY}}" serve --port {{PORT}} --bind "{{BIND}}"
Environment="SYMVAULT_VAULT={{VAULT}}"
Restart=on-failure

[Install]
WantedBy=default.target
"#;

#[cfg(any(target_os = "linux", test))]
fn render_systemd_unit(installer: &Installer) -> String {
    SYSTEMD_TEMPLATE
        .replace(
            "{{BINARY}}",
            &systemd_escape(&installer.binary_path.to_string_lossy()),
        )
        .replace("{{PORT}}", &installer.port.to_string())
        .replace("{{BIND}}", &systemd_escape(&installer.bind))
        .replace(
            "{{VAULT}}",
            &systemd_escape(&installer.vault_dir.to_string_lossy()),
        )
}

impl Installer {
    /// Installs the background service for the running platform.
    pub fn install(&self) -> Result<(), CliError> {
        #[cfg(target_os = "linux")]
        let result = self.install_linux();
        #[cfg(target_os = "macos")]
        let result = self.install_darwin();
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let result = Err(CliError::new(
            ExitCode::General,
            format!(
                "unsupported platform: {}; service templates are available for macOS (launchd) and Linux (systemd)",
                std::env::consts::OS
            ),
            None,
        ));
        result
    }
    /// Writes the systemd user unit, reloads, enables and starts the service.
    #[cfg(any(target_os = "linux", test))]
    #[cfg(target_os = "linux")]
    fn install_linux(&self) -> Result<(), CliError> {
        let unit_path = self.linux_service_file_path()?;
        self.write_systemd_unit(&unit_path).map_err(|err| {
            CliError::new(
                ExitCode::PermissionDenied,
                "failed to write systemd service file",
                Some(ErrorCause::new(CauseKind::Other, err)),
            )
        })?;

        for (args, label) in [
            (
                vec!["--user", "daemon-reload"],
                "systemctl daemon-reload failed",
            ),
            (
                vec!["--user", "enable", SYSTEMD_UNIT_LABEL],
                "systemctl enable failed",
            ),
            (
                vec!["--user", "start", SYSTEMD_UNIT_LABEL],
                "systemctl start failed",
            ),
        ] {
            match run_systemctl(&args) {
                Ok(output) if output.status.success() => {}
                Ok(output) => {
                    return Err(CliError::new(
                        ExitCode::General,
                        format!("{}: {}", label, combined_output(&output).trim()),
                        None,
                    ));
                }
                Err(err) => {
                    return Err(CliError::new(
                        ExitCode::General,
                        format!("{}: {}", label, err),
                        Some(ErrorCause::new(CauseKind::Other, err.to_string())),
                    ));
                }
            }
        }
        Ok(())
    }

    #[cfg(any(target_os = "linux", test))]
    #[cfg(target_os = "linux")]
    fn linux_service_file_path(&self) -> Result<PathBuf, CliError> {
        let home = home_dir()
            .ok_or_else(|| CliError::new(ExitCode::General, home_dir_error_message(), None))?;
        Ok(crate::agent_list_commands::clean_path(
            &home.join(SYSTEMD_USER_DIR).join(SYSTEMD_UNIT_NAME),
        ))
    }

    #[cfg(any(target_os = "linux", test))]
    #[cfg(target_os = "linux")]
    fn write_systemd_unit(&self, path: &Path) -> Result<(), String> {
        validate_install_options(&self.binary_path, &self.vault_dir, &self.bind, self.port)
            .map_err(|err| err.message().to_string())?;

        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|err| format!("create directory: {err}"))?;
            set_mode(dir, 0o700);
        }
        fs::write(path, render_systemd_unit(self))
            .map_err(|err| format!("write service file: {err}"))?;
        set_mode(path, 0o600);
        Ok(())
    }

    /// Writes the plist, unloads any previous instance and loads the service.
    #[cfg(any(target_os = "macos", test))]
    #[cfg(target_os = "macos")]
    fn install_darwin(&self) -> Result<(), CliError> {
        validate_install_options(&self.binary_path, &self.vault_dir, &self.bind, self.port)?;

        let plist_path = self.plist_path()?;
        let home = home_dir()
            .ok_or_else(|| CliError::new(ExitCode::General, home_dir_error_message(), None))?;

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

    /// Removes the background service for the running platform.
    pub fn uninstall(&self) -> Result<(), CliError> {
        #[cfg(target_os = "linux")]
        let result = self.uninstall_linux();
        #[cfg(target_os = "macos")]
        let result = self.uninstall_darwin();
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let result = Err(CliError::new(
            ExitCode::General,
            format!("unsupported platform: {}", std::env::consts::OS),
            None,
        ));
        result
    }
    /// Stops and disables the unit (best effort), removes the file, reloads.
    #[cfg(any(target_os = "linux", test))]
    #[cfg(target_os = "linux")]
    fn uninstall_linux(&self) -> Result<(), CliError> {
        let _ = run_systemctl(&["--user", "stop", SYSTEMD_UNIT_LABEL]);
        let _ = run_systemctl(&["--user", "disable", SYSTEMD_UNIT_LABEL]);

        let unit_path = self.linux_service_file_path()?;
        match fs::remove_file(&unit_path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(CliError::new(
                    ExitCode::PermissionDenied,
                    "failed to remove systemd service file",
                    Some(ErrorCause::new(CauseKind::Other, err.to_string())),
                ));
            }
        }

        let _ = run_systemctl(&["--user", "daemon-reload"]);
        Ok(())
    }

    /// Unloads the service (best effort) and removes the plist.
    #[cfg(any(target_os = "macos", test))]
    #[cfg(target_os = "macos")]
    fn uninstall_darwin(&self) -> Result<(), CliError> {
        let plist_path = self.plist_path()?;
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
        #[cfg(target_os = "linux")]
        let result = self.status_linux();
        #[cfg(target_os = "macos")]
        let result = self.status_darwin();
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let result = Err(CliError::new(
            ExitCode::General,
            format!("unsupported platform: {}", std::env::consts::OS),
            None,
        ));
        result
    }
    #[cfg(any(target_os = "linux", test))]
    #[cfg(target_os = "linux")]
    fn status_linux(&self) -> Result<&'static str, CliError> {
        let unit_path = self.linux_service_file_path()?;
        if !unit_path.exists() {
            return Ok("not installed");
        }
        match run_systemctl(&["--user", "is-active", SYSTEMD_UNIT_LABEL]) {
            Ok(output)
                if output.status.success() && combined_output(&output).trim() == "active" =>
            {
                Ok("running")
            }
            _ => Ok("stopped"),
        }
    }

    #[cfg(any(target_os = "macos", test))]
    #[cfg(target_os = "macos")]
    fn status_darwin(&self) -> Result<&'static str, CliError> {
        let plist_path = self.plist_path()?;
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

/// Combined stdout+stderr of a finished command, like Go's `CombinedOutput`.
#[cfg(target_os = "linux")]
fn combined_output(output: &std::process::Output) -> String {
    let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    combined
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
        // Absolute paths look different per platform; `fixture_installer` keeps
        // Unix-style values because the plist fixture compares bytes.
        let (bin, vault) = if cfg!(windows) {
            ("C:\\opt\\symvault\\symvault", "C:\\data\\vault")
        } else {
            ("/opt/symvault/bin/symvault", "/data/vault")
        };
        let installer = Installer {
            binary_path: PathBuf::from(bin),
            vault_dir: PathBuf::from(vault),
            port: 8080,
            bind: "127.0.0.1".to_string(),
            log_path: PathBuf::from("log"),
            err_log_path: PathBuf::from("err"),
        };
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

    /// The launchd layout is macOS-only: on Linux the same call returns the
    /// systemd unit path, which the byte test for the unit file covers.
    #[cfg(target_os = "macos")]
    #[test]
    fn service_file_path_is_home_relative_not_library() {
        // The oracle writes `~/LaunchAgents/...`, not `~/Library/LaunchAgents/...`.
        let path = fixture_installer()
            .service_file_path()
            .expect("service path");
        assert!(path.ends_with("LaunchAgents/com.symvault.mcp.plist"));
        assert!(!path.to_string_lossy().contains("Library/LaunchAgents"));
    }

    /// The systemd unit recorded from the pinned Go oracle in
    /// `target/resume-evidence/wave3b-systemd-differential.json`; only the
    /// machine-dependent binary path is substituted.
    #[cfg(any(target_os = "linux", test))]
    const ORACLE_SYSTEMD_UNIT: &str = r#"[Unit]
Description=Symaira Vault MCP Server

[Service]
Type=simple
ExecStart="/opt/symvault/bin/symvault" serve --port 8080 --bind "127.0.0.1"
Environment="SYMVAULT_VAULT=/home/tester/vault"
Restart=on-failure

[Install]
WantedBy=default.target
"#;

    #[cfg(any(target_os = "linux", test))]
    fn linux_fixture_installer() -> Installer {
        Installer {
            binary_path: PathBuf::from("/opt/symvault/bin/symvault"),
            vault_dir: PathBuf::from("/home/tester/vault"),
            port: 8080,
            bind: "127.0.0.1".to_string(),
            log_path: PathBuf::from("log"),
            err_log_path: PathBuf::from("err"),
        }
    }

    #[cfg(any(target_os = "linux", test))]
    #[test]
    fn render_systemd_unit_matches_the_go_oracle_byte_for_byte() {
        let rendered = render_systemd_unit(&linux_fixture_installer());
        if rendered != ORACLE_SYSTEMD_UNIT {
            let left: Vec<&str> = rendered.lines().collect();
            let right: Vec<&str> = ORACLE_SYSTEMD_UNIT.lines().collect();
            for index in 0..left.len().max(right.len()) {
                let (a, b) = (
                    left.get(index).copied().unwrap_or("<missing>"),
                    right.get(index).copied().unwrap_or("<missing>"),
                );
                assert_eq!(a, b, "unit line {index} diverged");
            }
        }
        assert_eq!(rendered, ORACLE_SYSTEMD_UNIT);
    }

    #[cfg(any(target_os = "linux", test))]
    #[test]
    fn systemd_escape_matches_the_oracle() {
        assert_eq!(systemd_escape(r"C:\vault"), r"C:\\vault");
        assert_eq!(systemd_escape("a\"b"), "a\\\"b");
        assert_eq!(systemd_escape("$HOME"), "$$HOME");
    }

    /// Linux counterpart: the same call must return the systemd unit path.
    #[cfg(target_os = "linux")]
    #[test]
    fn service_file_path_is_the_systemd_unit_on_linux() {
        let path = fixture_installer()
            .service_file_path()
            .expect("service path");
        assert!(path.ends_with(".config/systemd/user/symvault-mcp.service"));
        assert!(!path.to_string_lossy().contains("LaunchAgents"));
    }
}
