//! `symvault update` — `update check`, `update info`, and the root
//! output-format gate. `update apply --dry-run` previews the checker result;
//! applying a downloaded release remains intentionally unavailable here.
//!
//! Go references: `cmd/admin/update.go`, `internal/update/checker.go`, and
//! corekit's `updatecheck/updatecheck.go` and install-method detector.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use symvault_core::config::Config;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use ureq::Agent;

const LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/danieljustus/symaira-vault/releases/latest";
const UPDATE_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const UPDATE_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RELEASE_BODY: u64 = 1 << 20;

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
pub(crate) fn run(
    rest: &[OsString],
    output_format: &str,
    json_flag: bool,
    quiet: bool,
) -> ExitCode {
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
            if matches!(word.as_ref(), "info" | "check" | "apply")
                && rest
                    .iter()
                    .skip(1)
                    .any(|arg| matches!(arg.to_string_lossy().as_ref(), "--help" | "-h"))
            {
                print_command_help(&word);
                return ExitCode::SUCCESS;
            }
            if word == "--json" && rest.len() == 1 {
                return output_gate(output_format, true).unwrap_or(ExitCode::SUCCESS);
            }
            if word == "info" {
                let mut local_json = json_flag || output_format == "json";
                let mut args = rest.iter().skip(1);
                while let Some(arg) = args.next() {
                    match arg.to_string_lossy().as_ref() {
                        "--json" => local_json = true,
                        "--output=json" => local_json = true,
                        "--output=text" | "--output=yaml" => {}
                        "--output" => {
                            let Some(value) = args.next() else {
                                return unknown_command("symvault update info", "--output", false);
                            };
                            local_json |= value == "json";
                        }
                        other => {
                            return unknown_command("symvault update info", other, false);
                        }
                    }
                }
                return info(local_json);
            }
            if word == "check" {
                let mut force = false;
                let mut local_json = json_flag || output_format == "json";
                let mut local_quiet = quiet;
                let mut args = rest.iter().skip(1);
                while let Some(arg) = args.next() {
                    match arg.to_string_lossy().as_ref() {
                        "--force" => force = true,
                        "--json" => local_json = true,
                        "--quiet" | "-q" => local_quiet = true,
                        "--output=json" => local_json = true,
                        "--output=text" | "--output=yaml" => {}
                        "--output" => {
                            let Some(value) = args.next() else {
                                return unknown_command("symvault update check", "--output", false);
                            };
                            local_json |= value == "json";
                        }
                        other => {
                            return unknown_command("symvault update check", other, false);
                        }
                    }
                }
                return check(
                    crate::VERSION,
                    force,
                    local_json || json_flag || output_format == "json",
                    local_quiet,
                );
            }
            if word == "apply" {
                let mut dry_run = false;
                let mut force = false;
                let mut local_json = json_flag || output_format == "json";
                let mut args = rest.iter().skip(1);
                while let Some(arg) = args.next() {
                    match arg.to_string_lossy().as_ref() {
                        "--dry-run" => dry_run = true,
                        "--force" => force = true,
                        "--json" => local_json = true,
                        "--output=json" => local_json = true,
                        "--output=text" | "--output=yaml" => {}
                        "--output" => {
                            let Some(value) = args.next() else {
                                return unknown_command("symvault update apply", "--output", false);
                            };
                            local_json |= value == "json";
                        }
                        other => {
                            return unknown_command("symvault update apply", other, false);
                        }
                    }
                }
                if !dry_run {
                    let _ = writeln!(
                        std::io::stderr(),
                        "Error: update apply currently requires --dry-run in the Rust CLI"
                    );
                    return ExitCode::from(1);
                }
                return apply_dry_run(
                    crate::VERSION,
                    force,
                    local_json || json_flag || output_format == "json",
                );
            }
            unknown_command("symvault update", &word, true)
        }
    }
}

#[derive(Debug, Serialize)]
struct CheckJson<'a> {
    current_version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    release_url: Option<&'a str>,
    checkable: bool,
    update_available: bool,
}

fn check(current_version: &str, force: bool, json: bool, quiet: bool) -> ExitCode {
    match check_result(current_version, force) {
        Ok(result) => report_check(result, json, quiet),
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "Error: check for updates: {error}");
            ExitCode::from(1)
        }
    }
}

fn check_result(current_version: &str, force: bool) -> Result<CheckResult, String> {
    let current_text = current_version.trim();
    let Some(current) = StableVersion::parse(current_text) else {
        return Ok(CheckResult {
            current_version: current_text.to_owned(),
            latest_version: None,
            release_url: None,
            checkable: false,
            update_available: false,
        });
    };

    check_result_with(
        current_text,
        current,
        force,
        LATEST_RELEASE_URL,
        &default_cache_path(),
        cache_ttl(),
        &agent(true),
    )
}

fn check_result_with(
    current_text: &str,
    current: StableVersion,
    force: bool,
    url: &str,
    cache_path: &Path,
    ttl: Duration,
    http: &Agent,
) -> Result<CheckResult, String> {
    check_latest(current_text, current, force, url, cache_path, ttl, http).map(|release| {
        let update_available = release.is_some();
        let latest_text = release
            .as_ref()
            .map(|release| release.tag_name.trim_start_matches('v').to_owned())
            .unwrap_or_else(|| current.to_string());
        CheckResult {
            current_version: current.to_string(),
            latest_version: Some(latest_text),
            release_url: release
                .map(|release| release.html_url)
                .filter(|url| !url.is_empty()),
            checkable: true,
            update_available,
        }
    })
}

#[derive(Serialize)]
struct ApplyDryRunJson<'a> {
    method: &'static str,
    old_version: &'a str,
    new_version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_path: Option<&'a str>,
    binary_path: &'static str,
    dry_run: bool,
}

fn apply_dry_run(current_version: &str, force: bool, json: bool) -> ExitCode {
    let result = match check_result(current_version, force) {
        Ok(result) => result,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "Error: check for updates: {error}");
            return ExitCode::from(1);
        }
    };
    match render_apply_dry_run(&result, json) {
        Ok(text) => {
            if json {
                print!("{text}");
            } else {
                let _ = std::io::stderr().lock().write_all(text.as_bytes());
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "Error: encode JSON output: {error}");
            ExitCode::from(1)
        }
    }
}

fn render_apply_dry_run(result: &CheckResult, json: bool) -> Result<String, serde_json::Error> {
    let new_version = if result.update_available {
        result.latest_version.as_deref().unwrap_or_default()
    } else {
        &result.current_version
    };
    if json {
        let output = ApplyDryRunJson {
            method: "",
            old_version: &result.current_version,
            new_version,
            backup_path: None,
            binary_path: "",
            dry_run: true,
        };
        return serde_json::to_string_pretty(&output)
            .map(|text| format!("{}\n", go_json_escape(&text)));
    }
    let text = if !result.checkable {
        format!(
            "Update checks are only available for stable release builds. Current version: {}\n",
            result.current_version
        )
    } else if result.update_available {
        format!(
            "Update available: {} -> {} (use --dry-run to preview)\n",
            result.current_version, new_version
        )
    } else {
        format!(
            "Symaira Vault is up to date ({}).\n",
            result.current_version
        )
    };
    Ok(text)
}

fn go_json_escape(text: &str) -> String {
    text.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

fn print_command_help(command: &str) {
    print!("{}", command_help(command).expect("known update command"));
}

fn command_help(command: &str) -> Option<&'static str> {
    Some(match command {
        "info" => {
            "Detects how Symaira Vault was installed and shows whether self-update\nis supported, along with upgrade guidance for the detected method.\n\nUsage:\n  symvault update info [flags]\n\nFlags:\n  -h, --help   help for info\n      --json   output info as JSON (deprecated: use --output=json)\n\nGlobal Flags:\n      --color string      When to emit ANSI color: auto, always, never (default \"auto\")\n      --no-pipe-warning   suppress 'reading from non-TTY' warning when piping secrets\n      --output string     Output format (text, json, yaml) (default \"text\")\n      --profile string    use a named vault profile\n      --quiet             suppress non-error output\n      --theme string      Color preset: default, highcontrast, colorblind (or SYMVAULT_THEME)\n      --vault string      path to the password vault (default \"~/.symvault\")\n"
        }
        "check" => {
            "Check GitHub for a newer Symaira Vault release\n\nUsage:\n  symvault update check [flags]\n\nFlags:\n      --force   bypass cache and force a fresh check\n  -h, --help    help for check\n      --json    output update check result as JSON (deprecated: use --output=json)\n      --quiet   suppress non-essential output (exit code 1 if update available)\n\nGlobal Flags:\n      --color string      When to emit ANSI color: auto, always, never (default \"auto\")\n      --no-pipe-warning   suppress 'reading from non-TTY' warning when piping secrets\n      --output string     Output format (text, json, yaml) (default \"text\")\n      --profile string    use a named vault profile\n      --theme string      Color preset: default, highcontrast, colorblind (or SYMVAULT_THEME)\n      --vault string      path to the password vault (default \"~/.symvault\")\n"
        }
        "apply" => {
            "Downloads, verifies, and applies the latest Symaira Vault release.\n\nSupports direct-download installations only. When run via Homebrew, go install,\nor a package manager, self-update is disabled and guidance is shown instead.\n\nUsage:\n  symvault update apply [flags]\n\nFlags:\n      --dry-run   preview update without applying\n      --force     bypass cache and force a fresh check\n  -h, --help      help for apply\n      --json      output apply result as JSON (deprecated: use --output=json)\n\nGlobal Flags:\n      --color string      When to emit ANSI color: auto, always, never (default \"auto\")\n      --no-pipe-warning   suppress 'reading from non-TTY' warning when piping secrets\n      --output string     Output format (text, json, yaml) (default \"text\")\n      --profile string    use a named vault profile\n      --quiet             suppress non-error output\n      --theme string      Color preset: default, highcontrast, colorblind (or SYMVAULT_THEME)\n      --vault string      path to the password vault (default \"~/.symvault\")\n"
        }
        _ => return None,
    })
}

#[derive(Debug, Eq, PartialEq)]
struct CheckResult {
    current_version: String,
    latest_version: Option<String>,
    release_url: Option<String>,
    checkable: bool,
    update_available: bool,
}

fn report_check(result: CheckResult, json: bool, quiet: bool) -> ExitCode {
    if json {
        let output = CheckJson {
            current_version: &result.current_version,
            latest_version: result.latest_version.as_deref(),
            release_url: result.release_url.as_deref(),
            checkable: result.checkable,
            update_available: result.update_available,
        };
        match serde_json::to_string_pretty(&output) {
            Ok(text) => {
                let text = text
                    .replace('&', "\\u0026")
                    .replace('<', "\\u003c")
                    .replace('>', "\\u003e")
                    .replace('\u{2028}', "\\u2028")
                    .replace('\u{2029}', "\\u2029");
                println!("{text}");
            }
            Err(error) => {
                let _ = writeln!(std::io::stderr(), "Error: encode JSON output: {error}");
                return ExitCode::from(1);
            }
        }
        return if result.update_available {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        };
    }

    if quiet {
        return if result.update_available {
            ExitCode::from(1)
        } else {
            ExitCode::SUCCESS
        };
    }
    if !result.checkable {
        println!(
            "Update checks are only available for stable release builds. Current version: {}",
            result.current_version
        );
    } else if result.update_available {
        println!(
            "Update available: {} -> {}",
            result.current_version,
            result.latest_version.as_deref().unwrap_or_default()
        );
        if let Some(url) = result.release_url.as_deref().filter(|url| !url.is_empty()) {
            println!("Download: {url}");
        }
    } else if result.latest_version.as_deref() == Some(result.current_version.as_str()) {
        println!("Symaira Vault is up to date ({}).", result.current_version);
    }
    if result.update_available {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct StableVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl StableVersion {
    fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim().strip_prefix('v').unwrap_or(raw.trim());
        if raw.is_empty() || raw.contains(['-', '+']) {
            return None;
        }
        let mut parts = raw.split('.');
        let version = Self {
            major: parts.next()?.parse().ok()?,
            minor: parts.next()?.parse().ok()?,
            patch: parts.next()?.parse().ok()?,
        };
        parts.next().is_none().then_some(version)
    }
}

impl std::fmt::Display for StableVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct ReleaseAsset {
    name: String,
    #[serde(rename = "BrowserDownloadURL")]
    browser_download_url: String,
    size: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Release {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    tag_name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    body: String,
    #[serde(
        rename = "HTMLURL",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    html_url: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    assets: Vec<ReleaseAsset>,
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Deserialize)]
struct GithubRelease {
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    tag_name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    body: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    html_url: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    assets: Vec<GithubAsset>,
}

#[derive(Deserialize)]
struct GithubAsset {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    browser_download_url: String,
    #[serde(default)]
    size: i64,
}

#[derive(Deserialize, Serialize)]
struct DiskCache {
    #[serde(rename = "timestamp")]
    timestamp: String,
    release: Release,
}

fn agent(https_only: bool) -> Agent {
    Agent::new_with_config(
        Agent::config_builder()
            .https_only(https_only)
            .max_redirects(0)
            .timeout_global(Some(UPDATE_REQUEST_TIMEOUT))
            .http_status_as_error(false)
            .build(),
    )
}

fn check_latest(
    current_text: &str,
    current: StableVersion,
    force: bool,
    url: &str,
    cache_path: &Path,
    ttl: Duration,
    http: &Agent,
) -> Result<Option<Release>, String> {
    if !force
        && let Some(entry) = read_cache(cache_path)
        && cache_is_fresh(&entry.timestamp, ttl)
    {
        let latest = StableVersion::parse(&entry.release.tag_name);
        if let Some(latest) = latest {
            if current >= latest || (current.major == 0 && latest.major > 0) {
                return Ok(None);
            }
            return Ok(Some(entry.release));
        }
    }

    let mut response = http
        .get(url)
        .header("Accept", "application/vnd.github+json")
        .header(
            "User-Agent",
            &format!("symaira-updatecheck/{}", current_text.trim()),
        )
        .call()
        .map_err(|error| format!("request latest release: {error}"))?;
    if response.status() != 200 {
        if response.status() == 403
            && response
                .headers()
                .get("X-RateLimit-Remaining")
                .is_some_and(|value| value == "0")
        {
            return Err("GitHub API rate limit exceeded".to_owned());
        }
        return Err(format!("GitHub API returned HTTP {}", response.status()));
    }
    let raw = response
        .body_mut()
        .with_config()
        .limit(MAX_RELEASE_BODY)
        .read_to_string()
        .map_err(|error| format!("decode latest release response: {error}"))?;
    let api: GithubRelease = serde_json::from_str(&raw)
        .map_err(|error| format!("decode latest release response: {error}"))?;
    if api.draft {
        return Err("latest release response returned a draft release".to_owned());
    }
    if api.prerelease {
        return Err("latest release response returned a prerelease".to_owned());
    }
    if api.tag_name.trim().is_empty() {
        return Err("latest release response did not include a tag name".to_owned());
    }
    let release = Release {
        tag_name: api.tag_name.trim().to_owned(),
        body: api.body,
        html_url: api.html_url.trim().to_owned(),
        assets: api
            .assets
            .into_iter()
            .map(|asset| ReleaseAsset {
                name: asset.name,
                browser_download_url: asset.browser_download_url,
                size: asset.size,
            })
            .collect(),
    };
    if StableVersion::parse(&release.tag_name).is_none() {
        return Err(format!(
            "latest release tag {:?} is not a stable semantic version",
            release.tag_name
        ));
    }
    write_cache(cache_path, &release);
    let latest = StableVersion::parse(&release.tag_name).expect("validated stable version");
    if current < latest && !(current.major == 0 && latest.major > 0) {
        Ok(Some(release))
    } else {
        Ok(None)
    }
}

fn cache_ttl() -> Duration {
    let Some(home) = home_dir().map(PathBuf::from) else {
        return UPDATE_CACHE_TTL;
    };
    Config::load(home.join(".symvault/config.yaml"))
        .ok()
        .and_then(|config| config.update.map(|update| update.cache_ttl))
        .filter(|ttl| *ttl > Duration::ZERO)
        .unwrap_or(UPDATE_CACHE_TTL)
}

fn default_cache_path() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".cache"))
        })
        .unwrap_or_else(|| PathBuf::from(".cache"));
    let hash = Sha256::digest(b"danieljustus\0symaira-vault");
    let hex = hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    base.join("symaira/updatecheck").join(format!("{hex}.json"))
}

fn read_cache(path: &Path) -> Option<DiskCache> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn cache_is_fresh(timestamp: &str, ttl: Duration) -> bool {
    let Ok(timestamp) = OffsetDateTime::parse(timestamp, &Rfc3339) else {
        return false;
    };
    let age = OffsetDateTime::now_utc() - timestamp;
    age.whole_nanoseconds() < ttl.as_nanos() as i128
}

fn write_cache(path: &Path, release: &Release) {
    let Ok(timestamp) = OffsetDateTime::now_utc().format(&Rfc3339) else {
        return;
    };
    let Ok(bytes) = serde_json::to_vec(&DiskCache {
        timestamp,
        release: release.clone(),
    }) else {
        return;
    };
    let Some(parent) = path.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).is_err() {
            return;
        }
    }
    let mut suffix = [0_u8; 8];
    if getrandom::fill(&mut suffix).is_err() {
        return;
    }
    let suffix = suffix
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let temp = parent.join(format!(".update-cache-{}-{suffix}.tmp", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let Ok(mut file) = options.open(&temp) else {
        return;
    };
    if file.write_all(&bytes).is_err() || file.sync_all().is_err() {
        let _ = std::fs::remove_file(&temp);
        return;
    }
    if std::fs::rename(&temp, path).is_err() {
        let _ = std::fs::remove_file(&temp);
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
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

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

    #[test]
    fn update_check_force_bypasses_persistent_cache_and_fetches_github_shape() {
        let temp = tempfile::tempdir().expect("cache temp dir");
        let cache = temp.path().join("cache.json");
        let timestamp = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        std::fs::write(
            &cache,
            format!(
                r#"{{"timestamp":"{timestamp}","release":{{"TagName":"v0.4.0","Body":"","HTMLURL":"","Assets":null}}}}"#
            ),
        )
        .unwrap();

        let body = r#"{"tag_name":"v0.5.0","html_url":"https://github.com/danieljustus/symaira-vault/releases/tag/v0.5.0","body":"","draft":false,"prerelease":false,"assets":[{"name":"symvault-macos-arm64.tar.gz","browser_download_url":"https://example.test/release.tar.gz","size":123}]}"#;
        let (url, request_rx, server) = local_oracle(body);
        let current = StableVersion::parse("0.4.0").unwrap();
        let http = Agent::new_with_config(
            Agent::config_builder()
                .https_only(false)
                .max_redirects(0)
                .timeout_global(Some(Duration::from_secs(2)))
                .http_status_as_error(false)
                .build(),
        );

        let cached = check_latest(
            "0.4.0",
            current,
            false,
            &url,
            &cache,
            UPDATE_CACHE_TTL,
            &http,
        )
        .expect("fresh cache hit");
        assert!(cached.is_none(), "cache contains current release");
        assert!(request_rx.try_recv().is_err(), "cache hit must skip HTTP");

        let forced = check_latest(
            "0.4.0",
            current,
            true,
            &url,
            &cache,
            UPDATE_CACHE_TTL,
            &http,
        )
        .expect("forced request");
        let forced = forced.unwrap();
        assert_eq!(forced.tag_name, "v0.5.0");
        assert_eq!(
            forced.assets[0].browser_download_url,
            "https://example.test/release.tar.gz"
        );
        let cached = std::fs::read_to_string(&cache).unwrap();
        assert!(cached.contains("\"HTMLURL\""));
        assert!(cached.contains("\"BrowserDownloadURL\""));
        let request = request_rx.recv().expect("oracle received HTTP request");
        assert!(request.starts_with("get /releases/latest http/1.1\r\n"));
        assert!(request.contains("accept: application/vnd.github+json\r\n"));
        assert!(request.contains("user-agent: symaira-updatecheck/0.4.0\r\n"));
        server.join().expect("oracle server thread");
    }

    #[test]
    fn update_apply_dry_run_force_previews_fresh_local_release() {
        let temp = tempfile::tempdir().expect("cache temp dir");
        let cache = temp.path().join("cache.json");
        let timestamp = OffsetDateTime::now_utc().format(&Rfc3339).unwrap();
        std::fs::write(
            &cache,
            format!(
                r#"{{"timestamp":"{timestamp}","release":{{"TagName":"v0.4.0","Body":"cached","HTMLURL":"https://example.test/old","Assets":[]}}}}"#
            ),
        )
        .unwrap();

        let body = r#"{"tag_name":"v0.5.0","html_url":"https://example.test/releases/v0.5.0","body":"local oracle","draft":false,"prerelease":false,"assets":[]}"#;
        let (url, request_rx, server) = local_oracle(body);
        let current = StableVersion::parse("0.4.0").unwrap();
        let http = Agent::new_with_config(
            Agent::config_builder()
                .https_only(false)
                .max_redirects(0)
                .timeout_global(Some(Duration::from_secs(2)))
                .http_status_as_error(false)
                .build(),
        );

        let preview = check_result_with(
            "0.4.0",
            current,
            true,
            &url,
            &cache,
            UPDATE_CACHE_TTL,
            &http,
        )
        .expect("forced local release check");
        assert!(preview.update_available);
        assert_eq!(preview.latest_version.as_deref(), Some("0.5.0"));
        assert_eq!(
            render_apply_dry_run(&preview, false).unwrap(),
            "Update available: 0.4.0 -> 0.5.0 (use --dry-run to preview)\n"
        );
        assert_eq!(
            render_apply_dry_run(&preview, true).unwrap(),
            "{\n  \"method\": \"\",\n  \"old_version\": \"0.4.0\",\n  \"new_version\": \"0.5.0\",\n  \"binary_path\": \"\",\n  \"dry_run\": true\n}\n"
        );
        let request = request_rx.recv().expect("local oracle received request");
        assert!(request.starts_with("get /releases/latest http/1.1\r\n"));
        assert!(request.contains("user-agent: symaira-updatecheck/0.4.0\r\n"));
        server.join().expect("local oracle thread");
    }

    fn local_oracle(body: &str) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local update oracle");
        let address = listener.local_addr().unwrap();
        let body = body.to_owned();
        let (request_tx, request_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept local request");
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let count = stream.read(&mut chunk).expect("read request");
                request.extend_from_slice(&chunk[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = request_tx.send(String::from_utf8_lossy(&request).to_ascii_lowercase());
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .expect("write local response");
        });
        (
            format!("http://{address}/releases/latest"),
            request_rx,
            server,
        )
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
