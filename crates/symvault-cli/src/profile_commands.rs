use std::{
    env,
    fmt::Write as FmtWrite,
    io::Write,
    path::{Path, PathBuf},
};

use symvault_core::config::Config;

const CONFIG_FILE: &str = ".symvault/config.yaml";
const APP_NAME: &str = "symaira-vault";

/// List the profiles from the legacy config location used by Go's profile
/// command. A missing or invalid config has the same effect as Go's fallback
/// to `config.Default()`: it is an empty profile set.
pub(crate) fn list(home: &Path, quiet: bool, output: &mut impl Write) -> Result<(), String> {
    let config = Config::load(home.join(CONFIG_FILE)).unwrap_or_default();
    let profiles = config.profiles.unwrap_or_default();

    if profiles.is_empty() {
        if !quiet {
            writeln!(output, "No profiles configured.")
                .map_err(|error| format!("write profile output: {error}"))?;
            writeln!(
                output,
                "Use 'symvault profile add <name> --vault <path>' to create a profile."
            )
            .map_err(|error| format!("write profile output: {error}"))?;
        }
        return Ok(());
    }

    let rows: Vec<(String, String, String)> = profiles
        .into_iter()
        .map(|(name, profile)| {
            let vault_path = if profile.vault_path.is_empty() {
                "(not set)".to_owned()
            } else {
                profile.vault_path
            };
            let default_marker = if name == config.default_profile {
                "*".to_owned()
            } else {
                String::new()
            };
            (name, vault_path, default_marker)
        })
        .collect();

    let name_width = rows
        .iter()
        .map(|(name, _, _)| name.chars().count())
        .max()
        .unwrap_or(0)
        .max("NAME".len());
    let path_width = rows
        .iter()
        .map(|(_, path, _)| path.chars().count())
        .max()
        .unwrap_or(0)
        .max("VAULT PATH".len());

    writeln!(
        output,
        "{:<name_width$}  {:<path_width$}  DEFAULT",
        "NAME", "VAULT PATH"
    )
    .map_err(|error| format!("write profile output: {error}"))?;
    for (name, path, marker) in rows {
        let mut line = String::new();
        write!(line, "{name:<name_width$}  {path:<path_width$}  {marker}")
            .map_err(|error| format!("format profile output: {error}"))?;
        writeln!(output, "{line}").map_err(|error| format!("write profile output: {error}"))?;
    }
    Ok(())
}

pub(crate) fn add(
    home: &Path,
    name: &str,
    vault_path: &str,
    quiet: bool,
    output: &mut impl Write,
) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("profile name cannot be empty".to_owned());
    }
    if vault_path.is_empty() {
        return Err("--vault is required".to_owned());
    }

    let source = home.join(CONFIG_FILE);
    if let Ok(config) = Config::load(&source)
        && config
            .profiles
            .as_ref()
            .is_some_and(|profiles| profiles.contains_key(name))
    {
        return Err(format!("profile {name:?} already exists"));
    }
    let destination = default_config_path(home);
    let bytes = config_bytes(&source, &destination)?;
    patch_config(&destination, &bytes, |document| {
        let profiles = document
            .entry(serde_yaml_ng::Value::String("profiles".into()))
            .or_insert_with(|| serde_yaml_ng::Value::Mapping(Default::default()));
        if profiles.is_null() {
            *profiles = serde_yaml_ng::Value::Mapping(Default::default());
        }
        let profiles = profiles
            .as_mapping_mut()
            .ok_or_else(|| "cannot save config: profiles is not a mapping".to_owned())?;
        let profile = serde_yaml_ng::Mapping::from_iter([(
            serde_yaml_ng::Value::String("vault".into()),
            serde_yaml_ng::Value::String(vault_path.into()),
        )]);
        profiles.insert(
            serde_yaml_ng::Value::String(name.into()),
            serde_yaml_ng::Value::Mapping(profile),
        );
        Ok(())
    })?;
    if !quiet {
        writeln!(output, "Profile {name:?} added with vault {vault_path}")
            .map_err(|error| format!("write profile output: {error}"))?;
    }
    Ok(())
}

pub(crate) fn use_profile(
    home: &Path,
    name: &str,
    quiet: bool,
    output: &mut impl Write,
) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("profile name cannot be empty".to_owned());
    }
    let source = home.join(CONFIG_FILE);
    let config = Config::load(&source).map_err(|error| format!("cannot load config: {error}"))?;
    if !config
        .profiles
        .as_ref()
        .is_some_and(|profiles| profiles.contains_key(name))
    {
        return Err(format!("profile {name:?} not found"));
    }

    let destination = default_config_path(home);
    let bytes = config_bytes(&source, &destination)?;
    patch_config(&destination, &bytes, |document| {
        document.insert(
            serde_yaml_ng::Value::String("defaultProfile".into()),
            serde_yaml_ng::Value::String(name.into()),
        );
        Ok(())
    })?;
    if !quiet {
        writeln!(output, "Default profile set to {name:?}")
            .map_err(|error| format!("write profile output: {error}"))?;
    }
    Ok(())
}

// Preserve unknown semantic fields. YAML formatting/comments are normalized,
// as in Go's writer; validate the entire result before publishing it once.
fn patch_config(
    path: &Path,
    bytes: &[u8],
    patch: impl FnOnce(&mut serde_yaml_ng::Mapping) -> Result<(), String>,
) -> Result<(), String> {
    Config::load_from_bytes(bytes).map_err(|error| format!("cannot load config: {error}"))?;
    let mut document: serde_yaml_ng::Value =
        serde_yaml_ng::from_slice(bytes).map_err(|error| format!("cannot load config: {error}"))?;
    let mapping = document
        .as_mapping_mut()
        .ok_or_else(|| "cannot save config: root is not a mapping".to_owned())?;
    patch(mapping)?;
    let rendered = serde_yaml_ng::to_string(&document)
        .map_err(|error| format!("cannot save config: {error}"))?;
    Config::load_from_bytes(rendered.as_bytes())
        .map_err(|error| format!("config is invalid after update: {error}"))?;
    if let Some(parent) = path.parent() {
        symvault_sync::safeio::create_dir_all(parent)
            .map_err(|error| format!("cannot save config: {error}"))?;
    }
    symvault_sync::safeio::write_atomic(path, rendered.as_bytes())
        .map_err(|error| format!("cannot save config: {error}"))
}

/// Match Go's resolver: an existing legacy directory selects its config;
/// otherwise the XDG config directory is selected for `Config.Save`.
fn default_config_path(home: &Path) -> PathBuf {
    if home.join(".symvault").is_dir() {
        return home.join(CONFIG_FILE);
    }
    let config_home = env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    config_home.join(APP_NAME).join("config.yaml")
}

fn config_bytes(source: &Path, destination: &Path) -> Result<Vec<u8>, String> {
    let source_bytes = symvault_sync::safeio::read(source)
        .map_err(|error| format!("cannot load config: {error}"))?;
    if let Some(bytes) = &source_bytes {
        Config::load_from_bytes(bytes).map_err(|error| format!("cannot load config: {error}"))?;
    }
    if source == destination {
        return Ok(source_bytes.unwrap_or_else(|| b"profiles: {}\n".to_vec()));
    }
    let destination_bytes = symvault_sync::safeio::read(destination)
        .map_err(|error| format!("cannot load config: {error}"))?;
    Ok(destination_bytes
        .or(source_bytes)
        .unwrap_or_else(|| b"profiles: {}\n".to_vec()))
}
