//! Read-only agent integration diagnostics.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use symvault_core::config::Config;

pub(crate) const SENTINEL: &str = "symaira";

#[derive(Debug, Deserialize)]
pub(crate) struct Manifest {
    #[serde(default)]
    pub(crate) managed_by: String,
    #[serde(default)]
    managed_version: String,
    #[serde(default)]
    managed_hash: String,
    #[serde(default)]
    managed_profile_tier: String,
}

pub(crate) fn doctor(
    vault: &Path,
    agent: &str,
    version: &str,
    output: &mut impl Write,
) -> Result<(), String> {
    let config =
        Config::load(vault.join("config.yaml")).map_err(|error| format!("load config: {error}"))?;
    let Some(profile) = config.agents.get(agent) else {
        writeln!(output, "❌ No profile found for agent {agent:?}").map_err(io_error)?;
        writeln!(output, "   Run: symvault agent install {agent}").map_err(io_error)?;
        return Err(format!("agent {agent:?} not configured"));
    };
    let tier = profile.tier.as_deref().unwrap_or("standard");
    writeln!(output, "✓ Profile found: {agent} (tier={tier})").map_err(io_error)?;

    if profile.skill_path.is_empty() {
        writeln!(output, "⚠ No skill path configured for agent {agent:?}").map_err(io_error)?;
        writeln!(
            output,
            "   Run: symvault agent install {agent} --skill-only"
        )
        .map_err(io_error)?;
        return Err("no skill path configured".into());
    }
    let path =
        expand_tilde(&profile.skill_path).unwrap_or_else(|| PathBuf::from(&profile.skill_path));
    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            writeln!(output, "❌ Skill file not found: {}", path.display()).map_err(io_error)?;
            writeln!(
                output,
                "   Run: symvault agent install {agent} --skill-only"
            )
            .map_err(io_error)?;
            return Err("skill file not installed".into());
        }
        Err(error) => return Err(format!("read skill file: {error}")),
    };

    let (manifest, body) = parse_manifest(&data).map_err(|_| {
        let _ = writeln!(output, "⚠ Skill file exists but has no valid frontmatter");
        let _ = writeln!(output, "   Path: {}", path.display());
        "invalid skill file frontmatter".to_owned()
    })?;
    if manifest.managed_by != SENTINEL {
        writeln!(output, "⚠ Skill file is not managed by Symaira Vault").map_err(io_error)?;
        writeln!(output, "   Path: {}", path.display()).map_err(io_error)?;
        writeln!(
            output,
            "   To overwrite: symvault agent install {agent} --skill-only --force"
        )
        .map_err(io_error)?;
        return Err("unmanaged skill file".into());
    }
    writeln!(output, "✓ Skill file is managed by Symaira Vault").map_err(io_error)?;
    writeln!(output, "   Path:    {}", path.display()).map_err(io_error)?;
    writeln!(output, "   Version: {}", manifest.managed_version).map_err(io_error)?;
    writeln!(output, "   Tier:    {}", manifest.managed_profile_tier).map_err(io_error)?;

    let actual = format!("sha256:{}", symvault_store::sha256_hex(body));
    if actual != manifest.managed_hash {
        writeln!(output, "\n⚠ Skill version drift detected").map_err(io_error)?;
        writeln!(output, "   Installed:  {}", manifest.managed_version).map_err(io_error)?;
        writeln!(output, "   Expected:   {version}").map_err(io_error)?;
        writeln!(output, "   Run: symvault agent skill refresh {agent}").map_err(io_error)?;
        return Err("skill drift detected".into());
    }
    writeln!(output, "✓ Skill hash is current (no drift)").map_err(io_error)?;
    writeln!(output, "\nAll checks passed for {agent}").map_err(io_error)
}

pub(crate) fn parse_manifest(data: &[u8]) -> Result<(Manifest, &[u8]), ()> {
    let opening = if data.starts_with(b"---\r\n") {
        5
    } else if data.starts_with(b"---\n") {
        4
    } else {
        return Err(());
    };
    let rest = &data[opening..];
    let (marker, marker_len) = rest
        .windows(5)
        .position(|window| window == b"\n---\n")
        .map(|index| (index, 5))
        .or_else(|| {
            rest.windows(6)
                .position(|window| window == b"\n---\r\n")
                .map(|index| (index, 6))
        })
        .ok_or(())?;
    let yaml = &rest[..marker];
    let manifest = serde_yaml_ng::from_slice::<Manifest>(yaml).map_err(|_| ())?;
    let mut body_start = marker + marker_len;
    while body_start < rest.len() && matches!(rest[body_start], b'\r' | b'\n') {
        body_start += 1;
    }
    Ok((manifest, &rest[body_start..]))
}

pub(crate) fn expand_tilde(value: &str) -> Option<PathBuf> {
    let suffix = value.strip_prefix("~/")?;
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })?;
    Some(PathBuf::from(home).join(suffix))
}

fn io_error(error: std::io::Error) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::{doctor, parse_manifest};
    use std::fs;

    #[test]
    fn parses_manifest_body_and_crlf() {
        let unix = b"---\nmanaged_by: symaira\nmanaged_hash: sha256:x\n---\nbody\n";
        let (manifest, body) = parse_manifest(unix).expect("unix frontmatter");
        assert_eq!(manifest.managed_by, "symaira");
        assert_eq!(body, b"body\n");

        let crlf = b"---\r\nmanaged_by: symaira\r\nmanaged_hash: sha256:x\r\n---\r\nbody";
        let (_, body) = parse_manifest(crlf).expect("CRLF frontmatter");
        assert_eq!(body, b"body");
    }

    #[test]
    fn rejects_missing_or_malformed_frontmatter() {
        assert!(parse_manifest(b"body").is_err());
        assert!(parse_manifest(b"---\nmanaged_by: [\n---\nbody").is_err());
    }

    #[test]
    fn doctor_accepts_current_managed_skill() {
        let root = tempfile::tempdir().expect("fixture root");
        let skill = root.path().join("skill.md");
        let body = b"Use the vault.\n";
        let hash = symvault_store::sha256_hex(body);
        fs::write(&skill, format!("---\nmanaged_by: symaira\nmanaged_version: dev\nmanaged_hash: sha256:{hash}\nmanaged_profile_tier: standard\n---\n{}", String::from_utf8_lossy(body))).unwrap();
        fs::write(
            root.path().join("config.yaml"),
            format!("agents:\n  demo:\n    skillPath: {}\n", skill.display()),
        )
        .unwrap();
        let mut output = Vec::new();
        doctor(root.path(), "demo", "dev", &mut output).expect("doctor success");
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("All checks passed for demo"));
    }
}
