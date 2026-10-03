//! `symvault update` — bare help, `update info` installation-method report,
//! `update check` for stable releases and non-release builds, `update apply`
//! signed download/install for direct-download builds, plus stable and
//! non-release `update apply --dry-run` previews.
//!
//! Go references: `cmd/admin/update.go` (`newUpdateCmd`,
//! `newUpdateInfoCmd`), the output-format gate in `internal/cli/cli.go`
//! (`PersistentPreRunE` + `CommandSupportsJSON`), `internal/update/apply.go`
//! (`Info`), and corekit's `updatecheck/installmethod` detection heuristic
//! (pin recorded in the fixture). The byte contract lives in
//! `tests/fixtures/update-info/cases.json` (frozen oracle `d4aa2b13`);
//! `tests/cli_update_info.rs` replays every case against this code.

use std::ffi::OsString;
#[cfg(any(test, unix))]
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[path = "update_apply.rs"]
mod update_apply;

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
            if let Some(code) = output_gate(output_format, json_flag) {
                return code;
            }
            match crate::help_commands::write_nested("update", &mut std::io::stdout().lock()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("Error: help: {error}");
                    ExitCode::from(1)
                }
            }
        }
        Some(word) => {
            let word = word.to_string_lossy();
            if word == "info" {
                let mut info_json = json_flag || output_format == "json";
                let mut index = 1;
                while let Some(arg) = rest.get(index) {
                    match arg.to_string_lossy().as_ref() {
                        "--json" => info_json = true,
                        "--output" => {
                            let Some(format) = rest.get(index + 1) else {
                                return unknown_command("symvault update info", "--output", false);
                            };
                            info_json = format == "json";
                            index += 1;
                        }
                        value if value.starts_with("--output=") => {
                            info_json = value.trim_start_matches("--output=") == "json";
                        }
                        extra => {
                            return unknown_command("symvault update info", extra, false);
                        }
                    }
                    index += 1;
                }
                return info(info_json);
            }
            if word == "check" {
                return check(rest, output_format, json_flag, quiet);
            }
            if word == "apply" {
                return apply_dry_run(rest, output_format, json_flag);
            }
            unknown_command("symvault update", &word, true)
        }
    }
}

#[derive(Serialize)]
struct ApplyDryRunJson<'a> {
    method: &'static str,
    old_version: &'a str,
    new_version: &'a str,
    binary_path: &'static str,
    dry_run: bool,
}

/// Implements Go's `update apply --dry-run` metadata preview. Stable releases
/// use the existing hardened checker/cache path; non-release builds return
/// before any network or cache access. No artifact is downloaded or installed.
fn apply_dry_run(rest: &[OsString], output_format: &str, json_flag: bool) -> ExitCode {
    let mut want_json = json_flag;
    let mut output_json = output_format == "json";
    let mut dry_run = false;
    let mut force = false;
    let mut index = 1;
    while let Some(arg) = rest.get(index) {
        match arg.to_string_lossy().as_ref() {
            "--json" => want_json = true,
            "--dry-run" => dry_run = true,
            "--force" => force = true,
            "--output" => {
                let Some(format) = rest.get(index + 1) else {
                    return unknown_command("symvault update apply", "--output", false);
                };
                output_json = format == "json";
                index += 1;
            }
            value if value.starts_with("--output=") => {
                output_json = value.trim_start_matches("--output=") == "json";
            }
            flag if flag.starts_with('-') => {
                return unknown_command("symvault update apply", flag, false);
            }
            extra => return unknown_command("symvault update apply", extra, false),
        }
        index += 1;
    }

    if !dry_run {
        let info = match install_info() {
            Ok(info) => info,
            Err(error) => {
                return write_check_output(CheckOutput {
                    exit_code: ExitCode::from(1),
                    stdout: String::new(),
                    stderr: format!("Error: update apply: {error}\n"),
                });
            }
        };
        if !info.self_update_supported {
            return write_check_output(render_unsupported_apply(&info, want_json || output_json));
        }
        return apply_stable_update(&info, force, want_json || output_json);
    }

    let version = crate::VERSION.trim();
    let result = if let Some(current) = parse_stable_version(version) {
        match cached_check(current, force, OffsetDateTime::now_utc()) {
            Some(result) => Ok(result),
            None => fetch_latest_check(current, version),
        }
    } else {
        Ok(CheckResult {
            current_version: version.to_owned(),
            latest_version: String::new(),
            release_url: String::new(),
            checkable: false,
            update_available: false,
            release: None,
        })
    };
    let Ok(result) = result else {
        return ExitCode::from(1);
    };
    write_check_output(render_apply_dry_run(&result, want_json || output_json))
}

#[derive(Serialize)]
struct CheckJson<'a> {
    current_version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    release_url: Option<&'a str>,
    checkable: bool,
    update_available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CheckResult {
    current_version: String,
    latest_version: String,
    release_url: String,
    checkable: bool,
    update_available: bool,
    release: Option<CachedRelease>,
}

#[derive(Deserialize, Serialize)]
struct DiskCache {
    #[serde(rename = "timestamp", alias = "Timestamp")]
    timestamp: String,
    #[serde(rename = "release", alias = "Release")]
    release: Option<CachedRelease>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CachedRelease {
    #[serde(default, rename = "TagName", alias = "tag_name")]
    tag_name: String,
    #[serde(default, rename = "HTMLURL", alias = "html_url")]
    html_url: String,
    #[serde(default, rename = "Body", alias = "body")]
    body: String,
    #[serde(default, rename = "Assets", alias = "assets")]
    assets: Vec<CachedAsset>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CachedAsset {
    #[serde(default, rename = "Name", alias = "name")]
    name: String,
    #[serde(default, rename = "BrowserDownloadURL", alias = "browser_download_url")]
    browser_download_url: String,
    #[serde(default, rename = "Size", alias = "size")]
    size: i64,
}

#[derive(Debug, Deserialize)]
struct LatestRelease {
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    assets: Vec<CachedAsset>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StableVersion {
    major: i64,
    minor: i64,
    patch: i64,
}

const DEFAULT_UPDATE_CACHE_TTL_SECONDS: i64 = 24 * 60 * 60;
const LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/danieljustus/symaira-vault/releases/latest";
const MAX_RELEASE_RESPONSE_BYTES: u64 = 1 << 20;

/// Go's checker returns before creating its HTTP client when AppVersion is
/// not a stable semver. This is the complete local/dev-build path and cannot
/// consult the network or write the release cache.
fn check(rest: &[OsString], output_format: &str, json_flag: bool, root_quiet: bool) -> ExitCode {
    let mut want_json = json_flag || output_format == "json";
    let mut quiet = root_quiet;
    let mut force = false;
    for arg in rest.iter().skip(1) {
        match arg.to_string_lossy().as_ref() {
            "--json" => want_json = true,
            "--quiet" => quiet = true,
            "--force" => force = true,
            flag if flag.starts_with('-') => {
                return unknown_command("symvault update check", flag, false);
            }
            extra => return unknown_command("symvault update check", extra, false),
        }
    }

    let version = crate::VERSION.trim();
    let result = if let Some(current) = parse_stable_version(version) {
        match cached_check(current, force, OffsetDateTime::now_utc()) {
            Some(result) => Ok(result),
            None => fetch_latest_check(current, version),
        }
    } else {
        Ok(CheckResult {
            current_version: version.to_string(),
            latest_version: String::new(),
            release_url: String::new(),
            checkable: false,
            update_available: false,
            release: None,
        })
    };
    let Ok(result) = result else {
        return ExitCode::from(1);
    };
    write_check_output(render_check(&result, want_json, quiet))
}

fn parse_stable_version(raw: &str) -> Option<StableVersion> {
    let value = raw.trim().strip_prefix('v').unwrap_or(raw.trim());
    let mut parts = value.split('.');
    if value.contains(['-', '+']) {
        return None;
    }
    let (major, minor, patch) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let parse = |part: &str| {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        part.parse::<i64>().ok().filter(|value| *value >= 0)
    };
    Some(StableVersion {
        major: parse(major)?,
        minor: parse(minor)?,
        patch: parse(patch)?,
    })
}

fn cached_check(current: StableVersion, force: bool, now: OffsetDateTime) -> Option<CheckResult> {
    if force {
        return None;
    }
    let cache_path = default_cache_path();
    let raw =
        symvault_sync::safeio::read_bounded(&cache_path, MAX_RELEASE_RESPONSE_BYTES).ok()??;
    cached_check_bytes(&raw, current, now, update_cache_ttl())
}

fn cached_check_bytes(
    raw: &[u8],
    current: StableVersion,
    now: OffsetDateTime,
    ttl: time::Duration,
) -> Option<CheckResult> {
    let disk: DiskCache = serde_json::from_slice(raw).ok()?;
    let timestamp = OffsetDateTime::parse(&disk.timestamp, &Rfc3339).ok()?;
    if is_zero_timestamp(timestamp) {
        return None;
    }
    if now - timestamp >= ttl {
        return None;
    }
    let release = disk.release?;
    let latest = parse_stable_version(&release.tag_name)?;
    let update_available =
        compare_versions(current, latest).is_lt() && !(current.major == 0 && latest.major > 0);
    Some(CheckResult {
        current_version: current.to_string(),
        latest_version: if update_available {
            release
                .tag_name
                .strip_prefix('v')
                .unwrap_or(&release.tag_name)
                .to_string()
        } else {
            current.to_string()
        },
        release_url: if update_available {
            release.html_url.clone()
        } else {
            String::new()
        },
        checkable: true,
        update_available,
        release: Some(release),
    })
}

fn fetch_latest_check(current: StableVersion, version: &str) -> Result<CheckResult, ()> {
    let result = fetch_latest_check_at(current, version, LATEST_RELEASE_URL);
    match result {
        Ok(result) => Ok(result),
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "Error: check for updates: {error}");
            Err(())
        }
    }
}

fn fetch_latest_check_at(
    current: StableVersion,
    version: &str,
    url: &str,
) -> Result<CheckResult, String> {
    let release = fetch_latest_release_at(url, version)?;
    let (result, cached) = result_from_latest_release(current, release)?;
    let cache = DiskCache {
        timestamp: OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|error| format!("format release cache timestamp: {error}"))?,
        release: Some(cached),
    };
    persist_release_cache(&cache);
    Ok(result)
}

fn result_from_latest_release(
    current: StableVersion,
    release: LatestRelease,
) -> Result<(CheckResult, CachedRelease), String> {
    if release.draft {
        return Err("latest release response returned a draft release".to_owned());
    }
    if release.prerelease {
        return Err("latest release response returned a prerelease".to_owned());
    }
    let tag_name = release.tag_name.trim().to_owned();
    if tag_name.is_empty() {
        return Err("latest release response did not include a tag name".to_owned());
    }
    let latest = parse_stable_version(&tag_name).ok_or_else(|| {
        format!("latest release tag {tag_name:?} is not a stable semantic version")
    })?;
    let html_url = release.html_url.trim().to_owned();
    let cached = CachedRelease {
        tag_name,
        html_url: html_url.clone(),
        body: release.body,
        assets: release.assets,
    };
    let update_available =
        compare_versions(current, latest).is_lt() && !(current.major == 0 && latest.major > 0);
    let result = CheckResult {
        current_version: current.to_string(),
        latest_version: if update_available {
            latest.to_string()
        } else {
            current.to_string()
        },
        release_url: if update_available {
            html_url
        } else {
            String::new()
        },
        checkable: true,
        update_available,
        release: Some(cached.clone()),
    };
    Ok((result, cached))
}

fn fetch_latest_release_at(url: &str, version: &str) -> Result<LatestRelease, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .tls_backend_rustls()
        .tls_version_min(reqwest::tls::Version::TLS_1_3)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 10 {
                return attempt.error("stopped after 10 redirects");
            }
            if attempt.url().scheme() == "https"
                && github_host(attempt.url().host_str().unwrap_or_default())
            {
                attempt.follow()
            } else {
                attempt.error("refusing unsafe update-check redirect")
            }
        }))
        .build()
        .map_err(|error| format!("create update-check HTTP client: {error}"))?;
    let mut response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header(
            reqwest::header::USER_AGENT,
            format!("symaira-updatecheck/{}", version.trim()),
        )
        .send()
        .map_err(|error| {
            if error.is_redirect() {
                "request latest release: refusing unsafe update-check redirect".to_owned()
            } else if error.is_timeout() {
                "request latest release: request timed out".to_owned()
            } else if tls_certificate_error(&error) {
                format!("update check failed: TLS certificate verification error - {error}")
            } else {
                format!("request latest release: {error}")
            }
        })?;
    if response.status() != reqwest::StatusCode::OK {
        if response.status() == reqwest::StatusCode::FORBIDDEN
            && response
                .headers()
                .get("x-ratelimit-remaining")
                .is_some_and(|value| value == "0")
        {
            return Err("GitHub API rate limit exceeded".to_owned());
        }
        return Err(format!(
            "GitHub API returned HTTP {}",
            response.status().as_u16()
        ));
    }
    let mut body = Vec::new();
    response
        .by_ref()
        .take(MAX_RELEASE_RESPONSE_BYTES)
        .read_to_end(&mut body)
        .map_err(|error| format!("decode latest release response: {error}"))?;
    // Go decodes one value through an io.LimitReader; preserve that behavior
    // by ignoring any bytes after the first JSON object while never reading
    // more than the configured bound.
    let mut decoder = serde_json::Deserializer::from_slice(&body);
    LatestRelease::deserialize(&mut decoder)
        .map_err(|error| format!("decode latest release response: {error}"))
}

fn github_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "github.com"
        || host == "api.github.com"
        || host.ends_with(".github.com")
        || host.ends_with(".githubusercontent.com")
}

fn tls_certificate_error(error: &reqwest::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = source {
        let message = error.to_string().to_ascii_lowercase();
        if message.contains("certificate") || message.contains("cert error") {
            return true;
        }
        source = error.source();
    }
    false
}

fn persist_release_cache(cache: &DiskCache) {
    let path = default_cache_path();
    persist_release_cache_at(&path, cache);
}

fn persist_release_cache_at(path: &Path, cache: &DiskCache) {
    let Some(parent) = path.parent() else {
        return;
    };
    if create_cache_directories(parent).is_err() {
        return;
    }
    let Ok(encoded) = serde_json::to_string(cache) else {
        return;
    };
    let bytes = escape_go_json(&encoded).into_bytes();
    let _ = symvault_sync::safeio::write_atomic(path, &bytes);
}

/// Mirrors corekit `fsutil.SafeMkdirAll`: reject non-root symlinks and create
/// missing cache ancestors as private directories before the atomic cache write.
fn create_cache_directories(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        use std::path::Component;
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut components = Vec::new();
        for component in absolute.components() {
            match component {
                Component::Normal(name) => components.push(name.to_os_string()),
                Component::ParentDir => {
                    components.pop();
                }
                _ => {}
            }
        }
        let mut current = PathBuf::from("/");
        for component in components {
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    if metadata.uid() == 0 {
                        current = fs::canonicalize(&current)?;
                        continue;
                    }
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "refusing untrusted symlink in update cache path",
                    ));
                }
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotADirectory,
                        "update cache path component is not a directory",
                    ));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::DirBuilder::new().mode(0o700).create(&current)?;
                }
                Err(error) => return Err(error),
            }
        }
    }
    #[cfg(not(unix))]
    {
        symvault_sync::safeio::create_dir_all(path).map_err(std::io::Error::other)?;
    }
    Ok(())
}

fn is_zero_timestamp(value: OffsetDateTime) -> bool {
    value.year() == 1
        && value.month() == time::Month::January
        && value.day() == 1
        && value.hour() == 0
        && value.minute() == 0
        && value.second() == 0
        && value.nanosecond() == 0
}

fn compare_versions(left: StableVersion, right: StableVersion) -> std::cmp::Ordering {
    (left.major, left.minor, left.patch).cmp(&(right.major, right.minor, right.patch))
}

impl std::fmt::Display for StableVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

fn default_cache_path() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(".cache"));
    let hash = Sha256::digest(b"danieljustus\0symaira-vault");
    let filename = format!("{hash:x}.json");
    base.join("symaira").join("updatecheck").join(filename)
}

fn update_cache_ttl() -> time::Duration {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    update_cache_ttl_at(home.as_deref())
}

fn update_cache_ttl_at(home: Option<&Path>) -> time::Duration {
    let Some(home) = home else {
        return time::Duration::seconds(DEFAULT_UPDATE_CACHE_TTL_SECONDS);
    };
    let config_path = home.join(".symvault/config.yaml");
    let ttl = symvault_core::config::Config::load(config_path)
        .ok()
        .and_then(|config| config.update.map(|update| update.cache_ttl))
        .filter(|ttl| *ttl > std::time::Duration::ZERO);
    ttl.map_or(
        time::Duration::seconds(DEFAULT_UPDATE_CACHE_TTL_SECONDS),
        |ttl| {
            time::Duration::seconds(ttl.as_secs() as i64)
                + time::Duration::nanoseconds(ttl.subsec_nanos() as i64)
        },
    )
}

struct CheckOutput {
    exit_code: ExitCode,
    stdout: String,
    stderr: String,
}

#[derive(Serialize)]
struct UnsupportedApplyJson<'a> {
    error: String,
    guidance: &'a str,
}

/// Preserve Go's fail-closed refusal for package-managed and source-built
/// installs before the direct-download installer is available in Rust.
fn render_unsupported_apply(info: &InstallInfo, want_json: bool) -> CheckOutput {
    let error = format!(
        "self-update is not supported for {} installation",
        info.method
    );
    let generic_error = format!("Error: self-update not supported: {error}\n");
    if want_json {
        let output = UnsupportedApplyJson {
            error,
            guidance: &info.guidance,
        };
        let stdout = match serde_json::to_string_pretty(&output) {
            Ok(text) => format!("{}\n", escape_go_json(&text)),
            Err(_) => {
                return CheckOutput {
                    exit_code: ExitCode::from(1),
                    stdout: String::new(),
                    stderr: "Error: encode JSON output: serialize failed\n".into(),
                };
            }
        };
        return CheckOutput {
            exit_code: ExitCode::from(2),
            stdout,
            stderr: format!("{generic_error}Try: symvault find <search-term>\n"),
        };
    }

    CheckOutput {
        exit_code: ExitCode::from(2),
        stdout: String::new(),
        stderr: format!(
            "Error: {error}\nGuidance: {}\n{generic_error}Try: symvault find <search-term>\n",
            info.guidance
        ),
    }
}

#[derive(Serialize)]
struct ApplyResultJson<'a> {
    method: &'a str,
    old_version: &'a str,
    new_version: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_path: Option<&'a str>,
    binary_path: String,
    dry_run: bool,
}

fn apply_stable_update(info: &InstallInfo, force: bool, want_json: bool) -> ExitCode {
    let version = crate::VERSION.trim();
    let result = if let Some(current) = parse_stable_version(version) {
        match cached_check(current, force, OffsetDateTime::now_utc()) {
            Some(result) => Ok(result),
            None => fetch_latest_check_at(current, version, LATEST_RELEASE_URL)
                .map_err(|error| format!("check for updates: {error}")),
        }
    } else {
        Ok(CheckResult {
            current_version: version.to_owned(),
            latest_version: version.to_owned(),
            release_url: String::new(),
            checkable: false,
            update_available: false,
            release: None,
        })
    };
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            let _ = writeln!(std::io::stderr(), "Error: apply update: {error}");
            return ExitCode::from(1);
        }
    };
    let binary_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            let _ = writeln!(
                std::io::stderr(),
                "Error: apply update: resolve binary path: {error}"
            );
            return ExitCode::from(1);
        }
    };

    if result.update_available {
        let Some(release) = result.release.as_ref() else {
            let _ = writeln!(
                std::io::stderr(),
                "Error: apply update: cached release metadata is missing"
            );
            return ExitCode::from(1);
        };
        if let Err(error) = update_apply::apply(release, &binary_path) {
            let _ = writeln!(std::io::stderr(), "Error: apply update: {error}");
            return ExitCode::from(1);
        }
    }

    let new_version = if result.update_available {
        result.latest_version.as_str()
    } else {
        result.current_version.as_str()
    };
    if want_json {
        let output = ApplyResultJson {
            method: info.method,
            old_version: &result.current_version,
            new_version,
            backup_path: None,
            binary_path: binary_path.to_string_lossy().into_owned(),
            dry_run: false,
        };
        let stdout = match serde_json::to_string_pretty(&output) {
            Ok(value) => format!("{}\n", escape_go_json(&value)),
            Err(_) => {
                let _ = writeln!(
                    std::io::stderr(),
                    "Error: encode JSON output: serialize failed"
                );
                return ExitCode::from(1);
            }
        };
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(stdout.as_bytes());
        return ExitCode::SUCCESS;
    }
    let mut stdout = std::io::stdout().lock();
    if result.current_version == new_version {
        let _ = writeln!(
            stdout,
            "Symaira Vault is already up to date ({new_version})."
        );
    } else {
        let _ = writeln!(
            stdout,
            "Updated Symaira Vault: {} -> {new_version}",
            result.current_version
        );
        let _ = writeln!(stdout, "Installation method: {}", info.method);
        let _ = writeln!(stdout, "Binary: {}", binary_path.display());
    }
    ExitCode::SUCCESS
}

fn render_apply_dry_run(result: &CheckResult, want_json: bool) -> CheckOutput {
    if want_json {
        let output = ApplyDryRunJson {
            method: "",
            old_version: &result.current_version,
            new_version: if result.update_available {
                &result.latest_version
            } else {
                &result.current_version
            },
            binary_path: "",
            dry_run: true,
        };
        let Ok(mut text) = serde_json::to_string_pretty(&output) else {
            return CheckOutput {
                exit_code: ExitCode::from(1),
                stdout: String::new(),
                stderr: "Error: encode JSON output: serialize failed\n".into(),
            };
        };
        text = escape_go_json(&text);
        text.push('\n');
        return CheckOutput {
            exit_code: ExitCode::SUCCESS,
            stdout: text,
            stderr: String::new(),
        };
    }

    let message = if !result.checkable {
        format!(
            "Update checks are only available for stable release builds. Current version: {}\n",
            result.current_version
        )
    } else if result.update_available {
        format!(
            "Update available: {} -> {} (use --dry-run to preview)\n",
            result.current_version, result.latest_version
        )
    } else {
        format!(
            "Symaira Vault is up to date ({}).\n",
            result.current_version
        )
    };
    CheckOutput {
        exit_code: ExitCode::SUCCESS,
        stdout: String::new(),
        stderr: message,
    }
}

fn render_check(result: &CheckResult, want_json: bool, quiet: bool) -> CheckOutput {
    if want_json {
        let output = CheckJson {
            current_version: &result.current_version,
            latest_version: (!result.latest_version.is_empty()).then_some(&result.latest_version),
            release_url: (!result.release_url.is_empty()).then_some(&result.release_url),
            checkable: result.checkable,
            update_available: result.update_available,
        };
        let Ok(mut text) = serde_json::to_string_pretty(&output) else {
            return CheckOutput {
                exit_code: ExitCode::from(1),
                stdout: String::new(),
                stderr: "Error: encode JSON output: serialize failed\n".into(),
            };
        };
        text = escape_go_json(&text);
        text.push('\n');
        return CheckOutput {
            exit_code: update_available_exit(result.update_available),
            stdout: text,
            stderr: if result.update_available {
                "Error: update available\n".into()
            } else {
                String::new()
            },
        };
    }

    if quiet {
        return CheckOutput {
            exit_code: update_available_exit(result.update_available),
            stdout: String::new(),
            stderr: if result.update_available {
                "Error: update available\n".into()
            } else {
                String::new()
            },
        };
    }
    if !result.checkable {
        return CheckOutput {
            exit_code: ExitCode::SUCCESS,
            stdout: String::new(),
            stderr: format!(
                "Update checks are only available for stable release builds. Current version: {}",
                result.current_version
            ) + "\n",
        };
    }
    if result.update_available {
        let mut stderr = format!(
            "Update available: {} -> {}",
            result.current_version, result.latest_version
        );
        if !result.release_url.is_empty() {
            stderr.push_str(&format!("\nDownload: {}", result.release_url));
        }
        stderr.push_str("\nError: update available\n");
        return CheckOutput {
            exit_code: update_available_exit(true),
            stdout: String::new(),
            stderr,
        };
    }
    let stderr = if result.current_version == result.latest_version {
        format!(
            "Symaira Vault is up to date ({}).\n",
            result.current_version
        )
    } else {
        format!(
            "No newer stable release found. Current version: {}. Latest published stable release: {}.\n",
            result.current_version, result.latest_version
        )
    };
    CheckOutput {
        exit_code: ExitCode::SUCCESS,
        stdout: String::new(),
        stderr,
    }
}

fn update_available_exit(available: bool) -> ExitCode {
    if available {
        ExitCode::from(10)
    } else {
        ExitCode::SUCCESS
    }
}

fn write_check_output(output: CheckOutput) -> ExitCode {
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(output.stdout.as_bytes());
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(output.stderr.as_bytes());
    output.exit_code
}

fn escape_go_json(text: &str) -> String {
    text.replace('&', "\\u0026")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

#[cfg(test)]
mod check_tests {
    use super::*;

    #[derive(Deserialize)]
    struct Oracle {
        source_files: Vec<String>,
        source_digest: String,
    }

    #[derive(Deserialize)]
    struct Case {
        id: String,
        version: String,
        cache: String,
        json: bool,
        quiet: bool,
        exit: u8,
        stdout: String,
        stderr: String,
    }

    #[derive(Deserialize)]
    struct Fixture {
        oracle: Oracle,
        cases: Vec<Case>,
    }

    fn fixture() -> Fixture {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/update-check-cache/cases.json");
        let raw = fs::read_to_string(path).expect("read update-check cache fixture");
        serde_json::from_str(&raw.replace("\r\n", "\n")).expect("parse cache fixture")
    }

    #[test]
    fn stable_cache_cases_match_go_oracle() {
        let fixture = fixture();
        let now = OffsetDateTime::parse("2026-09-27T12:00:00Z", &Rfc3339).unwrap();
        let ttl = time::Duration::hours(24);
        for case in fixture.cases {
            let current = parse_stable_version(&case.version)
                .unwrap_or_else(|| panic!("{}: invalid fixture version", case.id));
            let result = cached_check_bytes(case.cache.as_bytes(), current, now, ttl)
                .unwrap_or_else(|| panic!("{}: cache should be fresh and usable", case.id));
            let got = render_check(&result, case.json, case.quiet);
            assert_eq!(
                got.exit_code,
                ExitCode::from(case.exit),
                "{}: exit",
                case.id
            );
            assert_eq!(got.stdout, case.stdout, "{}: stdout", case.id);
            assert_eq!(got.stderr, case.stderr, "{}: stderr", case.id);
        }
    }

    #[test]
    fn cache_fixture_is_bound_to_go_source() {
        let fixture = fixture();
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut hasher = Sha256::new();
        for name in &fixture.oracle.source_files {
            let data = fs::read(repo_root.join(name))
                .unwrap_or_else(|error| panic!("read pinned Go source {name}: {error}"));
            hasher.update(name.as_bytes());
            hasher.update([0]);
            hasher.update(&data);
            hasher.update([0]);
        }
        assert_eq!(
            format!("{:x}", hasher.finalize()),
            fixture.oracle.source_digest,
            "pinned Go source changed; recapture the stable update-check fixture"
        );
    }

    #[test]
    fn stale_cache_and_force_require_the_network_path() {
        let case = fixture().cases.into_iter().next().unwrap();
        let current = parse_stable_version(&case.version).unwrap();
        let expired_at = OffsetDateTime::parse("2100-01-01T00:00:00Z", &Rfc3339).unwrap();
        assert!(
            cached_check_bytes(
                case.cache.as_bytes(),
                current,
                expired_at,
                time::Duration::hours(24)
            )
            .is_none()
        );
        assert!(cached_check(current, true, OffsetDateTime::now_utc()).is_none());
    }

    #[test]
    fn update_cache_ttl_uses_legacy_vault_config_override() {
        let home = tempfile::tempdir().unwrap();
        let config_dir = home.path().join(".symvault");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(config_dir.join("config.yaml"), "update:\n  cache_ttl: 1h\n").unwrap();
        assert_eq!(
            update_cache_ttl_at(Some(home.path())),
            time::Duration::hours(1)
        );
        assert_eq!(update_cache_ttl_at(None), time::Duration::hours(24));
    }
}

#[cfg(test)]
mod apply_tests {
    use super::*;

    #[derive(Deserialize)]
    struct Oracle {
        source_files: Vec<String>,
        source_digest: String,
    }

    #[derive(Deserialize)]
    struct Case {
        id: String,
        version: String,
        cache: String,
        json: bool,
        exit: u8,
        stdout: String,
        stderr: String,
    }

    #[derive(Deserialize)]
    struct Fixture {
        oracle: Oracle,
        cases: Vec<Case>,
    }

    fn fixture() -> Fixture {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/update-apply-stable/cases.json");
        let raw = fs::read_to_string(path).expect("read stable update-apply fixture");
        serde_json::from_str(&raw.replace("\r\n", "\n")).expect("parse stable update-apply fixture")
    }

    #[test]
    fn stable_apply_preview_matches_go_oracle_bytes() {
        let fixture = fixture();
        let now = OffsetDateTime::parse("2026-09-27T12:00:00Z", &Rfc3339).unwrap();
        for case in &fixture.cases {
            let current = parse_stable_version(&case.version)
                .unwrap_or_else(|| panic!("{}: invalid fixture version", case.id));
            let result = cached_check_bytes(
                case.cache.as_bytes(),
                current,
                now,
                time::Duration::hours(24),
            )
            .unwrap_or_else(|| panic!("{}: cache should be fresh and usable", case.id));
            let got = render_apply_dry_run(&result, case.json);
            assert_eq!(
                got.exit_code,
                ExitCode::from(case.exit),
                "{}: exit",
                case.id
            );
            assert_eq!(got.stdout, case.stdout, "{}: stdout", case.id);
            assert_eq!(got.stderr, case.stderr, "{}: stderr", case.id);
        }
    }

    #[test]
    fn fixture_source_digest_matches_pinned_go_sources() {
        let fixture = fixture();
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut hasher = Sha256::new();
        for name in &fixture.oracle.source_files {
            let data = fs::read(repo_root.join(name))
                .unwrap_or_else(|error| panic!("read pinned Go source {name}: {error}"));
            hasher.update(name.as_bytes());
            hasher.update([0]);
            hasher.update(&data);
            hasher.update([0]);
        }
        assert_eq!(
            format!("{:x}", hasher.finalize()),
            fixture.oracle.source_digest,
            "pinned Go source changed; recapture the stable update-apply fixture"
        );
    }
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[derive(Deserialize)]
    struct Oracle {
        source_files: Vec<String>,
        source_digest: String,
        corekit_pin: String,
    }

    #[derive(Deserialize)]
    struct Case {
        id: String,
        current: String,
        response: String,
        latest: String,
        release_url: String,
        update_available: bool,
    }

    #[derive(Deserialize)]
    struct Fixture {
        oracle: Oracle,
        cases: Vec<Case>,
    }

    fn fixture() -> Fixture {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/update-check-http/cases.json");
        serde_json::from_slice(&fs::read(path).expect("read update HTTP fixture"))
            .expect("parse update HTTP fixture")
    }

    fn serve_once(
        status: &str,
        headers: &str,
        body: &[u8],
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind local HTTP oracle");
        let address = listener.local_addr().expect("local HTTP address");
        let status = status.to_owned();
        let headers = headers.to_owned();
        let body = body.to_vec();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept update request");
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).expect("read request header");
                request.push(byte[0]);
            }
            let request = String::from_utf8_lossy(&request).into_owned();
            write!(
                stream,
                "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("write response headers");
            // A bounded client closes an oversized response after the limit;
            // the resulting server-side broken pipe is expected in that case.
            let _ = stream.write_all(&body);
            request
        });
        (format!("http://{address}/releases/latest"), server)
    }

    #[test]
    fn release_http_fixture_matches_pinned_go_checker() {
        let fixture = fixture();
        assert_eq!(
            fixture.oracle.corekit_pin,
            "github.com/danieljustus/symaira-corekit v0.17.1-0.20260904101640-f3d3eb79b9b1"
        );
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut hasher = Sha256::new();
        for name in &fixture.oracle.source_files {
            let data = fs::read(repo_root.join(name))
                .unwrap_or_else(|error| panic!("read pinned Go source {name}: {error}"));
            hasher.update(name.as_bytes());
            hasher.update([0]);
            hasher.update(data);
            hasher.update([0]);
        }
        assert_eq!(
            format!("{:x}", hasher.finalize()),
            fixture.oracle.source_digest,
            "pinned Go source changed; recapture update HTTP fixture"
        );

        for case in fixture.cases {
            let (url, server) = serve_once(
                "200 OK",
                "Content-Type: application/json\r\n",
                case.response.as_bytes(),
            );
            let release = fetch_latest_release_at(&url, "v1.0.0")
                .unwrap_or_else(|error| panic!("{}: fetch release: {error}", case.id));
            let request = server.join().expect("update HTTP fixture server");
            assert!(request.starts_with("GET /releases/latest HTTP/1.1\r\n"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("accept: application/vnd.github+json")
            );
            assert!(request.contains("symaira-updatecheck/v1.0.0"));
            let current = parse_stable_version(&case.current)
                .unwrap_or_else(|| panic!("{}: invalid current version", case.id));
            let (result, cached) = result_from_latest_release(current, release)
                .unwrap_or_else(|error| panic!("{}: interpret release: {error}", case.id));
            assert_eq!(result.latest_version, case.latest, "{}: latest", case.id);
            assert_eq!(result.release_url, case.release_url, "{}: url", case.id);
            assert_eq!(
                result.update_available, case.update_available,
                "{}: available",
                case.id
            );
            if case.id == "newer-release" {
                assert_eq!(cached.body, "Release notes");
            }
        }
    }

    #[test]
    fn release_http_rejects_non_github_redirects() {
        let (url, server) = serve_once(
            "302 Found",
            "Location: https://updates.attacker.invalid/latest\r\n",
            b"",
        );
        let error = fetch_latest_release_at(&url, "1.0.0").expect_err("redirect must fail");
        let request = server.join().expect("redirect server");
        assert!(request.starts_with("GET /releases/latest HTTP/1.1\r\n"));
        assert!(error.contains("refusing unsafe update-check redirect"));

        let (url, server) = serve_once(
            "302 Found",
            "Location: http://api.github.com/releases/latest\r\n",
            b"",
        );
        let error =
            fetch_latest_release_at(&url, "1.0.0").expect_err("TLS downgrade redirect must fail");
        server.join().expect("downgrade redirect server");
        assert!(error.contains("refusing unsafe update-check redirect"));
    }

    #[test]
    fn release_http_honors_status_and_reads_only_a_bounded_body_prefix() {
        let (url, server) = serve_once("403 Forbidden", "X-RateLimit-Remaining: 0\r\n", b"{}");
        assert_eq!(
            fetch_latest_release_at(&url, "1.0.0").unwrap_err(),
            "GitHub API rate limit exceeded"
        );
        server.join().expect("rate-limit server");

        let mut huge = br#"{"tag_name":"v1.2.0","html_url":"https://example.com/v1.2.0"}"#.to_vec();
        huge.resize(MAX_RELEASE_RESPONSE_BYTES as usize + 1, b' ');
        let (url, server) = serve_once("200 OK", "", &huge);
        let release = fetch_latest_release_at(&url, "1.0.0").expect("decode bounded prefix");
        server.join().expect("oversize server");
        assert_eq!(release.tag_name, "v1.2.0");
    }

    #[test]
    fn release_cache_persistence_matches_go_schema_and_private_mode() {
        let directory = tempfile::tempdir().expect("temp cache root");
        let cache_path = directory.path().join("symaira/updatecheck/release.json");
        let cache = DiskCache {
            timestamp: "2026-09-27T12:00:00Z".into(),
            release: Some(CachedRelease {
                tag_name: "v1.2.0".into(),
                html_url: "https://example.com/v1.2.0".into(),
                body: "notes<&>".into(),
                assets: vec![CachedAsset {
                    name: "symvault".into(),
                    browser_download_url: "https://example.com/symvault".into(),
                    size: 123,
                }],
            }),
        };
        persist_release_cache_at(&cache_path, &cache);
        let bytes = symvault_sync::safeio::read(&cache_path)
            .expect("safe cache read")
            .expect("cache file exists");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("cache JSON");
        assert_eq!(value["timestamp"], "2026-09-27T12:00:00Z");
        assert_eq!(value["release"]["TagName"], "v1.2.0");
        assert_eq!(value["release"]["HTMLURL"], "https://example.com/v1.2.0");
        assert_eq!(
            value["release"]["Assets"][0]["BrowserDownloadURL"],
            "https://example.com/symvault"
        );
        assert!(String::from_utf8_lossy(&bytes).contains("notes\\u003c\\u0026\\u003e"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&cache_path)
                    .expect("cache metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(cache_path.parent().unwrap())
                    .expect("cache directory metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn update_cache_directory_creation_rejects_user_symlink_ancestors() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().expect("temp directory");
        let outside = directory.path().join("outside");
        fs::create_dir(&outside).expect("outside directory");
        let link = directory.path().join("link");
        symlink(&outside, &link).expect("untrusted symlink");
        let error = create_cache_directories(&link.join("cache"))
            .expect_err("refuse user-owned symlink ancestor");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!outside.join("cache").exists());
    }

    #[test]
    fn release_http_rejects_draft_prerelease_and_invalid_tags() {
        for (response, expected) in [
            (r#"{"draft":true,"tag_name":"v1.2.0"}"#, "draft release"),
            (r#"{"prerelease":true,"tag_name":"v1.2.0"}"#, "prerelease"),
            (r#"{"tag_name":"latest"}"#, "not a stable semantic version"),
        ] {
            let (url, server) = serve_once("200 OK", "", response.as_bytes());
            let release = fetch_latest_release_at(&url, "1.0.0").expect("decode release");
            server.join().expect("release validation server");
            let current = parse_stable_version("1.0.0").unwrap();
            let error = result_from_latest_release(current, release).unwrap_err();
            assert!(
                error.contains(expected),
                "{error:?} did not contain {expected:?}"
            );
        }
    }

    #[test]
    fn redirect_host_filter_matches_corekit_github_allowlist() {
        for host in [
            "github.com",
            "api.github.com",
            "objects.githubusercontent.com",
            "sub.github.com",
        ] {
            assert!(github_host(host), "expected {host} to be allowed");
        }
        for host in [
            "github.com.attacker.invalid",
            "example.com",
            "githubusercontent.com",
        ] {
            assert!(!github_host(host), "expected {host} to be denied");
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
