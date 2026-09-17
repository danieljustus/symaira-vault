use std::{
    env,
    fmt::Write as FmtWrite,
    fs,
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
        let profiles = mapping_or_create(document, "profiles")?;
        let profile = yaml_edit::MappingBuilder::new()
            .pair("vault", yaml_edit::ScalarValue::double_quoted(vault_path))
            .build_document();
        let profile = profile
            .as_mapping()
            .ok_or_else(|| "cannot save config: invalid profile mapping".to_owned())?;
        profiles.set(name, profile);
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
        document.set(
            "defaultProfile",
            yaml_edit::ScalarValue::double_quoted(name),
        );
        Ok(())
    })?;
    if !quiet {
        writeln!(output, "Default profile set to {name:?}")
            .map_err(|error| format!("write profile output: {error}"))?;
    }
    Ok(())
}

fn mapping_or_create(
    document: &yaml_edit::Document,
    key: &str,
) -> Result<yaml_edit::Mapping, String> {
    if let Some(node) = document.get(key) {
        return node
            .as_mapping()
            .cloned()
            .ok_or_else(|| format!("cannot save config: {key} is not a mapping"));
    }
    document.set(key, yaml_edit::Mapping::new());
    document
        .get_mapping(key)
        .ok_or_else(|| format!("cannot save config: {key} is not a mapping"))
}

fn patch_config(
    path: &Path,
    bytes: &[u8],
    patch: impl FnOnce(&yaml_edit::Document) -> Result<(), String>,
) -> Result<(), String> {
    let source = std::str::from_utf8(bytes)
        .map_err(|error| format!("cannot load config: invalid UTF-8: {error}"))?;
    let file = source
        .parse::<yaml_edit::YamlFile>()
        .map_err(|error| format!("cannot load config: {error}"))?;
    let mut documents = file.documents();
    let document = documents
        .next()
        .ok_or_else(|| "cannot load config: missing YAML document".to_owned())?;
    if documents.next().is_some() {
        return Err("cannot load config: multiple YAML documents are not supported".to_owned());
    }
    if document.as_mapping().is_none() {
        return Err("cannot save config: root is not a mapping".to_owned());
    }
    patch(&document)?;
    let mut rendered = document.to_string();
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Config::load_from_bytes(rendered.as_bytes())
        .map_err(|error| format!("config is invalid after update: {error}"))?;
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
    if let Some(parent) = destination.parent() {
        symvault_sync::safeio::create_dir_all(parent)
            .map_err(|error| format!("cannot save config: {error}"))?;
    }
    let source_config = Config::load(source);
    if source.exists() {
        source_config
            .as_ref()
            .map_err(|error| format!("cannot load config: {error}"))?;
    }
    if destination.exists() {
        return fs::read(destination).map_err(|error| format!("cannot load config: {error}"));
    }
    if source_config.is_ok() {
        fs::read(source).map_err(|error| format!("cannot load config: {error}"))
    } else {
        Ok(b"profiles: {}\n".to_vec())
    }
}
