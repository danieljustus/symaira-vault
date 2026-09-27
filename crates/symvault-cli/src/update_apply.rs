//! Signed release download and transactional installation for `update apply`.
//!
//! The byte and transaction order follows corekit's pinned `updateapply`
//! implementation: fetch the exact checksum file, verify its Cosign signature,
//! match the selected archive checksum, stage beside the destination, extract
//! only the expected executable, then replace and validate with rollback.

use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::{CachedAsset, CachedRelease};

const DOWNLOAD_BASE: &str = "https://github.com/danieljustus/symaira-vault/releases/download";
const IDENTITY_REGEXP: &str =
    r"https://github\.com/danieljustus/symaira-vault/\.github/workflows/release\.yml@refs/tags/v.*";
const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
const MAX_ASSET_BYTES: u64 = 1 << 30;
const MAX_EXTRACT_BYTES: u64 = 100 * 1024 * 1024;
const MAX_COSIGN_BYTES: u64 = 1 << 20;

pub(super) fn apply(release: &CachedRelease, binary_path: &Path) -> Result<(), String> {
    apply_with_validator(release, binary_path, validate_installed)
}

fn apply_with_validator(
    release: &CachedRelease,
    binary_path: &Path,
    validate: impl Fn(&Path) -> Result<(), String>,
) -> Result<(), String> {
    if release.tag_name.trim().is_empty() {
        return Err("updateapply: release tag is empty".into());
    }
    let binary_name = if cfg!(windows) {
        "symvault.exe"
    } else {
        "symvault"
    };
    let asset = select_asset(
        &release.assets,
        std::env::consts::OS,
        std::env::consts::ARCH,
    )?;
    let checksums_asset = release
        .assets
        .iter()
        .find(|item| item.name.to_ascii_lowercase().contains("checksums"))
        .ok_or_else(|| "updateapply: release has no checksums.txt asset".to_owned())?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15 * 60))
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
                attempt.error("refusing unsafe update download redirect")
            }
        }))
        .build()
        .map_err(|error| format!("updateapply: create secure HTTP client: {error}"))?;

    let checksum_url = checked_github_url(&checksums_asset.browser_download_url)?;
    let checksum_bytes = download(&client, checksums_asset, &checksum_url, MAX_ASSET_BYTES)
        .map_err(|error| format!("updateapply: fetch checksums: {error}"))?;
    let sums = parse_checksums(&checksum_bytes)
        .map_err(|error| format!("updateapply: fetch checksums: {error}"))?;

    let signature_url = cosign_url(&release.tag_name, "sig")?;
    let certificate_url = cosign_url(&release.tag_name, "pem")?;
    let signature = download_named(
        &client,
        "Cosign signature",
        &signature_url,
        MAX_COSIGN_BYTES,
    )
    .map_err(|error| format!("updateapply: fetch cosign signature: {error}"))?;
    let certificate = download_named(
        &client,
        "Cosign certificate",
        &certificate_url,
        MAX_COSIGN_BYTES,
    )
    .map_err(|error| format!("updateapply: fetch cosign certificate: {error}"))?;
    verify_cosign(&checksum_bytes, &signature, &certificate)
        .map_err(|error| format!("updateapply: cosign verification failed: {error}"))?;

    let expected = sums
        .get(&asset.name)
        .ok_or_else(|| format!("updateapply: no checksum entry for asset {:?}", asset.name))?;
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "updateapply: invalid SHA-256 for asset {:?}",
            asset.name
        ));
    }

    let target = fs::canonicalize(binary_path)
        .map_err(|error| format!("updateapply: resolve target path: {error}"))?;
    let target_meta = fs::metadata(&target)
        .map_err(|error| format!("updateapply: inspect target binary: {error}"))?;
    if !target_meta.is_file() {
        return Err(format!(
            "updateapply: target binary {:?} is not a regular file",
            target
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if target_meta.permissions().mode() & 0o200 == 0 {
            return Err(format!(
                "updateapply: target binary {:?} is not writable",
                target
            ));
        }
    }
    #[cfg(windows)]
    if target_meta.permissions().readonly() {
        return Err(format!(
            "updateapply: target binary {:?} is not writable",
            target
        ));
    }
    let parent = target
        .parent()
        .ok_or_else(|| "updateapply: target binary has no parent directory".to_owned())?;
    let probe = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        format!(
            "updateapply: install location {:?} is not writable: {error}",
            parent
        )
    })?;
    drop(probe);

    let archive_url = checked_github_url(&asset.browser_download_url)?;
    let (archive, digest) = download_hashed(&client, asset, &archive_url)
        .map_err(|error| format!("updateapply: download asset: {error}"))?;
    if !digest.eq_ignore_ascii_case(expected) {
        return Err(format!(
            "updateapply: checksum mismatch for {:?}: got {digest}, want {expected}",
            asset.name
        ));
    }

    let (extraction_dir, extracted) = extract_binary(&archive, &asset.name, binary_name, parent)
        .map_err(|error| {
            format!("updateapply: extract binary {binary_name:?} from archive: {error}")
        })?;
    set_executable(&extracted)
        .map_err(|error| format!("updateapply: make downloaded asset executable: {error}"))?;
    atomic_swap_with_validator(&extracted, &target, &validate)?;
    drop(extraction_dir);
    Ok(())
}

fn select_asset<'a>(
    assets: &'a [CachedAsset],
    os: &str,
    arch: &str,
) -> Result<&'a CachedAsset, String> {
    let goos = match os {
        "macos" => "darwin",
        "windows" => "windows",
        "linux" => "linux",
        other => other,
    };
    let goarch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    assets
        .iter()
        .find(|item| {
            let name = item.name.to_ascii_lowercase();
            !name.contains("checksums") && name.contains(goos) && name.contains(goarch)
        })
        .ok_or_else(|| format!("updateapply: no release asset matches {goos}/{goarch}"))
}

fn github_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "github.com"
        || host == "api.github.com"
        || host.ends_with(".github.com")
        || host.ends_with(".githubusercontent.com")
}

fn checked_github_url(raw: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(raw)
        .map_err(|error| format!("updateapply: invalid release asset URL: {error}"))?;
    if url.scheme() != "https" || !github_host(url.host_str().unwrap_or_default()) {
        return Err("updateapply: release asset URL must use HTTPS on a GitHub host".into());
    }
    Ok(url)
}

fn cosign_url(tag: &str, extension: &str) -> Result<reqwest::Url, String> {
    let version = tag.strip_prefix('v').unwrap_or(tag);
    if version.is_empty() || version.contains('/') || version.contains('\\') {
        return Err("updateapply: invalid release tag for Cosign artifact".into());
    }
    checked_github_url(&format!(
        "{DOWNLOAD_BASE}/v{version}/symaira-vault_{version}_checksums.txt.{extension}"
    ))
}

fn download(
    client: &reqwest::blocking::Client,
    asset: &CachedAsset,
    url: &reqwest::Url,
    limit: u64,
) -> Result<Vec<u8>, String> {
    download_named(client, &asset.name, url, limit)
}

fn download_named(
    client: &reqwest::blocking::Client,
    name: &str,
    url: &reqwest::Url,
    limit: u64,
) -> Result<Vec<u8>, String> {
    let mut response = client
        .get(url.clone())
        .send()
        .map_err(|error| format!("updateapply: request {name:?}: {error}"))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!(
            "updateapply: download {name:?}: HTTP {}",
            response.status().as_u16()
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(format!(
            "updateapply: {name:?} exceeds maximum size of {limit} bytes"
        ));
    }
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("updateapply: read {name:?}: {error}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!(
            "updateapply: {name:?} exceeds maximum size of {limit} bytes"
        ));
    }
    Ok(bytes)
}

fn download_hashed(
    client: &reqwest::blocking::Client,
    asset: &CachedAsset,
    url: &reqwest::Url,
) -> Result<(Vec<u8>, String), String> {
    let mut response = client
        .get(url.clone())
        .send()
        .map_err(|error| format!("updateapply: request asset: {error}"))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!(
            "updateapply: download {:?}: HTTP {}",
            asset.name,
            response.status().as_u16()
        ));
    }
    let total = response.content_length();
    if total.is_some_and(|size| size > MAX_ASSET_BYTES) {
        return Err(format!(
            "updateapply: asset {:?} exceeds maximum size",
            asset.name
        ));
    }
    let mut bytes = Vec::new();
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    let mut chunk = [0u8; 32 * 1024];
    loop {
        let count = response
            .read(&mut chunk)
            .map_err(|error| format!("updateapply: read asset body: {error}"))?;
        if count == 0 {
            break;
        }
        written += count as u64;
        if written > MAX_ASSET_BYTES {
            return Err(format!(
                "updateapply: asset {:?} exceeds maximum size",
                asset.name
            ));
        }
        hasher.update(&chunk[..count]);
        bytes.extend_from_slice(&chunk[..count]);
    }
    if let Some(total) = total
        && written != total
    {
        return Err(format!(
            "updateapply: incomplete download: got {written} bytes, want {total}"
        ));
    }
    Ok((bytes, format!("{:x}", hasher.finalize())))
}

fn parse_checksums(bytes: &[u8]) -> Result<std::collections::HashMap<String, String>, String> {
    let mut result = std::collections::HashMap::new();
    for line in String::from_utf8_lossy(bytes).lines() {
        let mut fields = line.split_whitespace();
        let (Some(sum), Some(name), None) = (fields.next(), fields.next(), fields.next()) else {
            continue;
        };
        result.insert(name.to_owned(), sum.to_owned());
    }
    if result.is_empty() {
        return Err("updateapply: checksums.txt contained no parseable entries".into());
    }
    Ok(result)
}

fn verify_cosign(content: &[u8], signature: &[u8], certificate: &[u8]) -> Result<(), String> {
    if signature.is_empty() || certificate.is_empty() {
        return Err("updateapply: Cosign signature or certificate is empty".into());
    }
    if signature.len() as u64 > MAX_COSIGN_BYTES || certificate.len() as u64 > MAX_COSIGN_BYTES {
        return Err("updateapply: Cosign artifact exceeds maximum size".into());
    }
    let cosign = which_cosign()
        .map_err(|error| format!("updateapply: cosign verification failed: {error}"))?;
    verify_cosign_with(&cosign, content, signature, certificate)
}

fn verify_cosign_with(
    cosign: &Path,
    content: &[u8],
    signature: &[u8],
    certificate: &[u8],
) -> Result<(), String> {
    let temp = TempDir::new()
        .map_err(|error| format!("updateapply: create Cosign temp directory: {error}"))?;
    let content_path = temp.path().join("content");
    let signature_path = temp.path().join("signature.sig");
    let certificate_path = temp.path().join("certificate.pem");
    for (path, data) in [
        (&content_path, content),
        (&signature_path, signature),
        (&certificate_path, certificate),
    ] {
        write_private(path, data)?;
    }
    let output = Command::new(cosign)
        .arg("verify-blob")
        .arg("--certificate")
        .arg(&certificate_path)
        .arg("--signature")
        .arg(&signature_path)
        .arg("--certificate-identity-regexp")
        .arg(IDENTITY_REGEXP)
        .arg("--certificate-oidc-issuer")
        .arg(OIDC_ISSUER)
        .arg(&content_path)
        .output()
        .map_err(|error| format!("run cosign verify-blob: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cosign verify-blob failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn which_cosign() -> Result<PathBuf, String> {
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| {
            directory.join(if cfg!(windows) {
                "cosign.exe"
            } else {
                "cosign"
            })
        })
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            "cosign CLI not found — install cosign from https://docs.sigstore.dev to verify release signatures: executable not found in PATH".into()
        })
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("updateapply: create private verification file: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("updateapply: write private verification file: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("updateapply: sync private verification file: {error}"))
}

fn extract_binary(
    archive: &[u8],
    asset_name: &str,
    expected: &str,
    staging: &Path,
) -> Result<(TempDir, PathBuf), String> {
    let private_dir = tempfile::Builder::new()
        .prefix("updateapply-extract-")
        .tempdir_in(staging)
        .map_err(|error| format!("updateapply: create extract temp dir: {error}"))?;
    let output_path = private_dir.path().join("symvault-new-binary");
    let extracted = if asset_name.to_ascii_lowercase().ends_with(".zip") {
        extract_zip(archive, expected, &output_path)?
    } else if [".tar.gz", ".tgz"]
        .iter()
        .any(|suffix| asset_name.to_ascii_lowercase().ends_with(suffix))
    {
        extract_tar_gz(archive, expected, &output_path)?
    } else {
        return Err(format!(
            "updateapply: unsupported release archive format: {asset_name}"
        ));
    };
    if !extracted {
        return Err(format!(
            "updateapply: binary not found in archive: {expected}"
        ));
    }
    Ok((private_dir, output_path))
}

fn safe_archive_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!(
            "updateapply: archive entry attempts path traversal: {:?}",
            path
        ));
    }
    Ok(())
}

fn extract_tar_gz(archive: &[u8], expected: &str, destination: &Path) -> Result<bool, String> {
    let decoder = GzDecoder::new(Cursor::new(archive));
    let mut tar = tar::Archive::new(decoder);
    let mut total = 0u64;
    for item in tar
        .entries()
        .map_err(|error| format!("updateapply: open tar archive: {error}"))?
    {
        let entry = item.map_err(|error| format!("updateapply: read tar header: {error}"))?;
        let path = entry
            .path()
            .map_err(|error| format!("updateapply: read tar entry path: {error}"))?
            .into_owned();
        safe_archive_path(&path)?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        total = total.saturating_add(entry.size());
        if total >= MAX_EXTRACT_BYTES {
            return Err(format!(
                "updateapply: archive exceeds maximum extraction size of {MAX_EXTRACT_BYTES} bytes"
            ));
        }
        if path.file_name().is_some_and(|name| name == expected) {
            let mut file = File::create(destination)
                .map_err(|error| format!("updateapply: create extracted binary: {error}"))?;
            let remaining = MAX_EXTRACT_BYTES - total;
            let copied = std::io::copy(&mut entry.take(remaining), &mut file)
                .map_err(|error| format!("updateapply: extract binary: {error}"))?;
            if copied >= remaining {
                return Err(format!(
                    "updateapply: archive exceeds maximum extraction size of {MAX_EXTRACT_BYTES} bytes"
                ));
            }
            file.sync_all()
                .map_err(|error| format!("updateapply: sync extracted binary: {error}"))?;
        }
    }
    Ok(destination.is_file())
}

fn extract_zip(archive: &[u8], expected: &str, destination: &Path) -> Result<bool, String> {
    let mut zip = zip::ZipArchive::new(Cursor::new(archive))
        .map_err(|error| format!("updateapply: open zip archive: {error}"))?;
    let mut total = 0u64;
    let mut found = false;
    for index in 0..zip.len() {
        let entry = zip
            .by_index(index)
            .map_err(|error| format!("updateapply: read zip entry: {error}"))?;
        let path = Path::new(entry.name());
        safe_archive_path(path)?;
        if entry.is_dir()
            || entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            continue;
        }
        total = total.saturating_add(entry.size());
        if total >= MAX_EXTRACT_BYTES {
            return Err(format!(
                "updateapply: archive exceeds maximum extraction size of {MAX_EXTRACT_BYTES} bytes"
            ));
        }
        if path.file_name().is_some_and(|name| name == expected) {
            let mut file = File::create(destination)
                .map_err(|error| format!("updateapply: create extracted binary: {error}"))?;
            let remaining = MAX_EXTRACT_BYTES - total;
            let copied = std::io::copy(&mut entry.take(remaining), &mut file)
                .map_err(|error| format!("updateapply: extract binary: {error}"))?;
            if copied >= remaining {
                return Err(format!(
                    "updateapply: archive exceeds maximum extraction size of {MAX_EXTRACT_BYTES} bytes"
                ));
            }
            file.sync_all()
                .map_err(|error| format!("updateapply: sync extracted binary: {error}"))?;
            found = true;
        }
    }
    Ok(found)
}

fn set_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("updateapply: make downloaded asset executable: {error}"))?;
    }
    Ok(())
}

#[cfg(test)]
fn atomic_swap(new_path: &Path, target: &Path) -> Result<(), String> {
    atomic_swap_with_validator(new_path, target, &validate_installed)
}

fn atomic_swap_with_validator(
    new_path: &Path,
    target: &Path,
    validate: &impl Fn(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let mut backup_name = target.as_os_str().to_os_string();
    backup_name.push(".bak");
    let backup = PathBuf::from(backup_name);
    let had_existing = target.exists();
    if had_existing {
        match fs::remove_file(&backup) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(format!("updateapply: remove prior backup: {error}")),
        }
        fs::rename(target, &backup)
            .map_err(|error| format!("updateapply: backup current binary: {error}"))?;
    }
    if let Err(error) = fs::rename(new_path, target) {
        if had_existing && let Err(rollback) = fs::rename(&backup, target) {
            return Err(format!(
                "updateapply: install new binary failed ({error}) and rollback failed ({rollback})"
            ));
        }
        return Err(format!("updateapply: install new binary: {error}"));
    }
    if let Err(error) = validate(target) {
        if had_existing {
            if let Err(rollback) = restore_backup(&backup, target) {
                return Err(format!(
                    "updateapply: validate installed binary failed ({error}) and rollback failed: {rollback}"
                ));
            }
        } else if let Err(remove) = fs::remove_file(target) {
            return Err(format!(
                "updateapply: validate installed binary failed ({error}) and remove failed: {remove}"
            ));
        }
        return Err(format!("updateapply: validate installed binary: {error}"));
    }
    if had_existing {
        let _ = fs::remove_file(backup);
    }
    Ok(())
}

fn restore_backup(backup: &Path, target: &Path) -> Result<(), String> {
    match fs::remove_file(target) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(format!("remove failed installed binary: {error}")),
    }
    fs::rename(backup, target).map_err(|error| format!("restore previous binary: {error}"))
}

fn validate_installed(path: &Path) -> Result<(), String> {
    let output = Command::new(path)
        .arg("version")
        .output()
        .map_err(|error| format!("run installed binary version: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let mut combined = output.stdout;
        combined.extend_from_slice(&output.stderr);
        Err(format!(
            "installed binary version failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&combined)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn checksum_parser_matches_goreleaser_lines_and_ignores_noise() {
        let sums = parse_checksums(b"# release\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  symvault_linux_amd64.tar.gz\ninvalid line with extras\n").unwrap();
        assert_eq!(
            sums.get("symvault_linux_amd64.tar.gz").unwrap(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn selects_platform_archive_and_skips_checksums() {
        let assets = vec![
            CachedAsset {
                name: "checksums_linux_amd64.txt".into(),
                browser_download_url: "https://github.com/danieljustus/symaira-vault/asset".into(),
                size: 10,
            },
            CachedAsset {
                name: "symaira-vault_linux_amd64.tar.gz".into(),
                browser_download_url: "https://github.com/danieljustus/symaira-vault/asset".into(),
                size: 100,
            },
        ];
        assert_eq!(
            select_asset(&assets, "linux", "x86_64").unwrap().name,
            "symaira-vault_linux_amd64.tar.gz"
        );
    }

    #[test]
    fn failed_validation_restores_previous_binary() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("symvault");
        let replacement = dir.path().join("replacement");
        fs::write(&target, b"old").unwrap();
        let mut file = File::create(&replacement).unwrap();
        file.write_all(b"not executable").unwrap();
        drop(file);
        set_executable(&replacement).unwrap();
        let error = atomic_swap(&replacement, &target).unwrap_err();
        assert!(error.contains("validate installed binary"));
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert!(!PathBuf::from(format!("{}.bak", target.display())).exists());
    }

    #[test]
    #[ignore = "requires public GitHub release access, cosign, and SYMAIRA_VAULT_SMOKE_BINARY"]
    fn public_release_apply_smoke() {
        use std::process::Command;

        let source = std::env::var_os("SYMAIRA_VAULT_SMOKE_BINARY")
            .map(PathBuf::from)
            .expect("set SYMAIRA_VAULT_SMOKE_BINARY to the local Rust symvault binary");
        let source = fs::canonicalize(source).expect("resolve local Rust binary");
        assert!(source.is_file(), "smoke source must be a regular file");

        let release = super::super::fetch_latest_release_at(
            super::super::LATEST_RELEASE_URL,
            env!("CARGO_PKG_VERSION"),
        )
        .expect("fetch public latest release metadata");
        let (_, release) = super::super::result_from_latest_release(
            super::super::StableVersion {
                major: 0,
                minor: 0,
                patch: 0,
            },
            release,
        )
        .expect("latest release must be stable and valid");
        let asset_name = select_asset(
            &release.assets,
            std::env::consts::OS,
            std::env::consts::ARCH,
        )
        .expect("public release must include a matching platform archive")
        .name
        .clone();

        let dir = tempfile::tempdir().expect("create isolated install root");
        let canonical_dir = fs::canonicalize(dir.path()).expect("resolve isolated install root");
        let install_dir = dir.path().join("install");
        fs::create_dir(&install_dir).expect("create isolated install directory");
        let target = install_dir.join(if cfg!(windows) {
            "symvault.exe"
        } else {
            "symvault"
        });
        fs::copy(&source, &target).expect("seed isolated install target");
        set_executable(&target).expect("make isolated target executable");
        assert!(
            fs::canonicalize(&target)
                .expect("resolve isolated target")
                .starts_with(&canonical_dir),
            "update target must stay inside the temporary directory"
        );
        let original = fs::read(&target).expect("read seeded binary");

        apply(&release, &target).expect("verify and install the signed public release");
        let installed = fs::read(&target).expect("read installed public release binary");
        assert_ne!(
            installed, original,
            "release must replace the seeded binary"
        );
        let version = Command::new(&target)
            .arg("version")
            .output()
            .expect("run isolated installed binary version");
        assert!(
            version.status.success(),
            "installed version command failed: {}",
            String::from_utf8_lossy(&version.stderr)
        );
        println!(
            "verified public release {} asset {}; installed version output: {}{}",
            release.tag_name,
            asset_name,
            String::from_utf8_lossy(&version.stdout),
            String::from_utf8_lossy(&version.stderr)
        );

        let rollback_target = install_dir.join("symvault-rollback");
        fs::copy(&source, &rollback_target).expect("seed rollback target");
        let verified_release = install_dir.join("verified-release-copy");
        fs::write(&verified_release, &installed).expect("copy verified release bytes");
        set_executable(&verified_release).expect("make verified copy executable");
        let error = atomic_swap_with_validator(&verified_release, &rollback_target, &|_| {
            Err("injected validation failure".into())
        })
        .expect_err("injected validation failure must roll back");
        assert!(error.contains("injected validation failure"), "{error}");
        assert_eq!(
            fs::read(&rollback_target).expect("read rolled back binary"),
            original,
            "rollback must restore the original binary bytes"
        );
        assert!(
            !PathBuf::from(format!("{}.bak", rollback_target.display())).exists(),
            "successful rollback must remove its backup"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    #[ignore = "requires public GitHub release access, cosign, and Go/Rust smoke binaries"]
    fn public_release_apply_matches_go_in_isolated_targets() {
        use std::process::Output;

        fn run_cli(binary: &Path, args: &[&str], home: &Path, scratch: &Path) -> Output {
            let mut command = Command::new(binary);
            command
                .args(args)
                .env_clear()
                .env("PATH", "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin")
                .env("HOME", home)
                .env("TMPDIR", scratch)
                .env("GOPATH", home.join("gopath"))
                .env("GOMODCACHE", home.join("gomodcache"));
            command.output().expect("run isolated CLI")
        }

        let go_source = std::env::var_os("SYMAIRA_VAULT_GO_SMOKE_BINARY")
            .map(PathBuf::from)
            .expect("set SYMAIRA_VAULT_GO_SMOKE_BINARY to the controlled Go binary");
        let rust_source = std::env::var_os("SYMAIRA_VAULT_RUST_SMOKE_BINARY")
            .map(PathBuf::from)
            .expect("set SYMAIRA_VAULT_RUST_SMOKE_BINARY to the controlled Rust binary");
        let go_source = fs::canonicalize(go_source).expect("resolve Go smoke binary");
        let rust_source = fs::canonicalize(rust_source).expect("resolve Rust smoke binary");
        assert!(
            go_source.is_file(),
            "Go smoke source must be a regular file"
        );
        assert!(
            rust_source.is_file(),
            "Rust smoke source must be a regular file"
        );

        let dir = tempfile::tempdir().expect("create isolated differential root");
        let root = fs::canonicalize(dir.path()).expect("resolve differential root");
        let scratch = root.join("tmp");
        fs::create_dir(&scratch).expect("create isolated temporary directory");
        let mut binaries = Vec::new();
        let mut homes = Vec::new();
        for (name, source) in [("go", go_source), ("rust", rust_source)] {
            let home = root.join(format!("{name}-home"));
            let install = root.join(format!("{name}-install"));
            fs::create_dir(&home).expect("create isolated home");
            fs::create_dir(home.join("gopath")).expect("create isolated GOPATH");
            fs::create_dir(home.join("gomodcache")).expect("create isolated Go module cache");
            fs::create_dir(&install).expect("create isolated install target directory");
            let binary = install.join(if cfg!(windows) {
                "symvault.exe"
            } else {
                "symvault"
            });
            fs::copy(source, &binary).expect("seed isolated install target");
            set_executable(&binary).expect("make isolated target executable");
            assert!(
                fs::canonicalize(&binary)
                    .expect("resolve isolated target")
                    .starts_with(&root),
                "CLI install target must remain inside the temporary root"
            );
            binaries.push(binary);
            homes.push(home);
        }
        let [go_binary, rust_binary] = binaries.as_slice() else {
            unreachable!("exactly two smoke binaries are constructed")
        };
        let [go_home, rust_home] = homes.as_slice() else {
            unreachable!("exactly two isolated homes are constructed")
        };

        for (binary, home) in [(go_binary, go_home), (rust_binary, rust_home)] {
            let info = run_cli(binary, &["update", "info", "--json"], home, &scratch);
            assert!(
                info.status.success(),
                "update info failed: {}",
                String::from_utf8_lossy(&info.stderr)
            );
            let info: serde_json::Value =
                serde_json::from_slice(&info.stdout).expect("parse install info JSON");
            assert_eq!(info["method"], "direct-download");
            assert_eq!(info["self_update_supported"], true);
            assert_eq!(
                info["binary_path"].as_str().map(Path::new),
                Some(binary.as_path()),
                "update info must identify the isolated executable"
            );
        }

        let go = run_cli(
            go_binary,
            &["update", "apply", "--force", "--json"],
            go_home,
            &scratch,
        );
        let rust = run_cli(
            rust_binary,
            &["update", "apply", "--force", "--json"],
            rust_home,
            &scratch,
        );
        for (name, output) in [("Go", &go), ("Rust", &rust)] {
            assert!(
                output.status.success(),
                "{name} update apply failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let mut go_result: serde_json::Value =
            serde_json::from_slice(&go.stdout).expect("parse Go apply result JSON");
        let mut rust_result: serde_json::Value =
            serde_json::from_slice(&rust.stdout).expect("parse Rust apply result JSON");
        for result in [&go_result, &rust_result] {
            assert_eq!(result["method"], "direct-download");
            assert_eq!(result["old_version"], "0.0.1");
            assert_eq!(result["dry_run"], false);
        }
        assert_eq!(
            go_result["binary_path"].as_str().map(Path::new),
            Some(go_binary.as_path())
        );
        assert_eq!(
            rust_result["binary_path"].as_str().map(Path::new),
            Some(rust_binary.as_path())
        );
        let latest = go_result["new_version"]
            .as_str()
            .expect("Go result includes installed release version")
            .to_owned();
        assert!(
            !latest.is_empty(),
            "latest release version must not be empty"
        );
        assert_eq!(rust_result["new_version"], latest);
        go_result["binary_path"] = serde_json::Value::String("<isolated>/symvault".into());
        rust_result["binary_path"] = serde_json::Value::String("<isolated>/symvault".into());
        assert_eq!(
            go_result, rust_result,
            "sanitized apply outcomes must match"
        );

        let go_version = run_cli(go_binary, &["version"], go_home, &scratch);
        let rust_version = run_cli(rust_binary, &["version"], rust_home, &scratch);
        assert!(go_version.status.success());
        assert!(rust_version.status.success());
        assert_eq!(go_version.stdout, rust_version.stdout);
        assert_eq!(
            String::from_utf8_lossy(&go_version.stdout).trim(),
            format!("symvault {latest}")
        );
        let go_hash = Sha256::digest(fs::read(go_binary).expect("read Go installed binary"));
        let rust_hash = Sha256::digest(fs::read(rust_binary).expect("read Rust installed binary"));
        assert_eq!(go_hash, rust_hash, "both CLIs must install identical bytes");
        for binary in [go_binary, rust_binary] {
            let mut entries = fs::read_dir(binary.parent().expect("install directory exists"))
                .expect("list isolated install directory")
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            entries.sort();
            assert_eq!(entries, vec![binary.file_name().unwrap().to_os_string()]);
        }
        println!(
            "sanitized live Go/Rust update apply matched: release={latest}, method=direct-download, targets=<isolated>, post_install_files=[symvault], installed_binary_sha256={:x}",
            go_hash
        );
    }

    #[test]
    fn failed_rename_restores_previous_binary_and_removes_backup() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("symvault");
        fs::write(&target, b"old").unwrap();
        let missing = dir.path().join("missing-update");
        assert!(
            atomic_swap(&missing, &target)
                .unwrap_err()
                .contains("install new binary")
        );
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert!(!PathBuf::from(format!("{}.bak", target.display())).exists());
    }

    #[test]
    fn archive_paths_reject_parent_components_and_absolute_paths() {
        assert!(safe_archive_path(Path::new("../escape")).is_err());
        assert!(safe_archive_path(Path::new("/absolute")).is_err());
        assert!(safe_archive_path(Path::new("release/symvault")).is_ok());
    }

    #[test]
    fn extracts_only_expected_executable_from_tarball() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("symvault");
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        archive
            .append_data(&mut header, "release/symvault", Cursor::new(b"new!"))
            .unwrap();
        let archive_bytes = archive.into_inner().unwrap().finish().unwrap();
        assert!(extract_tar_gz(&archive_bytes, "symvault", &destination).unwrap());
        assert_eq!(fs::read(destination).unwrap(), b"new!");
    }

    #[cfg(unix)]
    #[test]
    fn cosign_receives_exact_signed_bytes_and_pinned_identity() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("cosign-test");
        let script = format!(
            "#!/bin/sh\nset -eu\n[ \"$1\" = verify-blob ]\n[ \"$2\" = --certificate ]\n[ \"$(cat \"$3\")\" = certificate-bytes ]\n[ \"$4\" = --signature ]\n[ \"$(cat \"$5\")\" = signature-bytes ]\n[ \"$6\" = --certificate-identity-regexp ]\n[ \"$7\" = '{IDENTITY_REGEXP}' ]\n[ \"$8\" = --certificate-oidc-issuer ]\n[ \"$9\" = '{OIDC_ISSUER}' ]\nprintf 'signed checksum bytes\\n' | cmp - \"${{10}}\"\n"
        );
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        verify_cosign_with(
            &executable,
            b"signed checksum bytes\n",
            b"signature-bytes",
            b"certificate-bytes",
        )
        .unwrap();
    }

    #[test]
    fn go_oracle_fixture_pins_apply_transaction_contract() {
        #[derive(serde::Deserialize)]
        struct Fixture {
            oracle: Oracle,
            cases: Vec<Case>,
        }
        #[derive(serde::Deserialize)]
        struct Oracle {
            source_files: Vec<String>,
            source_digest: String,
            corekit_pin: String,
            corekit_revision: String,
            corekit_source_digest: String,
            corekit_source_files: Vec<String>,
        }
        #[derive(serde::Deserialize)]
        struct Case {
            id: String,
            go_test: String,
            expected: String,
        }
        let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/update-apply-transaction/cases.json");
        let fixture: Fixture = serde_json::from_slice(&fs::read(fixture_path).unwrap()).unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut hasher = Sha256::new();
        for name in &fixture.oracle.source_files {
            hasher.update(name.as_bytes());
            hasher.update([0]);
            hasher.update(fs::read(root.join(name)).unwrap());
            hasher.update([0]);
        }
        assert_eq!(
            format!("{:x}", hasher.finalize()),
            fixture.oracle.source_digest
        );
        let go_mod = fs::read_to_string(root.join("go.mod")).unwrap();
        assert!(go_mod.contains(&fixture.oracle.corekit_pin));
        assert_eq!(fixture.oracle.corekit_revision.len(), 12);
        assert_eq!(fixture.oracle.corekit_revision, "f3d3eb79b9b1");
        assert_eq!(
            fixture.oracle.corekit_source_digest,
            "f17ed1f441ab19902dac8f63f7850f734bcac0c28ca51a5fc022698e2a23acbd"
        );
        assert_eq!(
            fixture.oracle.corekit_source_files,
            [
                "updatecheck/updateapply/updateapply.go",
                "updatecheck/extract/extract.go",
                "updatecheck/cosign/cosign.go"
            ]
        );
        assert_eq!(fixture.cases.len(), 3);
        assert!(fixture.cases.iter().all(|case| !case.id.is_empty()));
        assert!(fixture.cases.iter().any(|case| case.go_test
            == "TestAtomicSwapRollsBackOnFailedRename"
            && case.expected == "old binary restored; backup removed"));
        assert!(fixture.cases.iter().any(|case| case.go_test
            == "TestApplyRollsBackWhenBinaryValidationFails"
            && case.expected == "old binary restored after validation failure"));
        assert!(
            fixture
                .cases
                .iter()
                .any(|case| case.go_test == "TestExtractTarGz_PathTraversal"
                    && case.expected == "reject archive traversal")
        );
    }
}
