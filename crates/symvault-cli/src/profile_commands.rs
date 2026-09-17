use std::{fmt::Write as FmtWrite, io::Write, path::Path};

use symvault_core::config::Config;

const CONFIG_FILE: &str = ".symvault/config.yaml";

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
        .map(|(name, _, _)| name.len())
        .max()
        .unwrap_or(0)
        .max("NAME".len());
    let path_width = rows
        .iter()
        .map(|(_, path, _)| path.len())
        .max()
        .unwrap_or(0)
        .max("VAULT PATH".len());

    writeln!(
        output,
        "{:<name_width$}  {:<path_width$}  {}",
        "NAME", "VAULT PATH", "DEFAULT"
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
