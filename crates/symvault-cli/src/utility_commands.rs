//! Pure helpers for the top-level `generate` command.
//!
//! The Go command has no standalone `totp` subcommand. TOTP codes are
//! generated while rendering `get`, so this module keeps that boundary out of
//! the utility command instead of inventing a second command contract.

use serde::Serialize;
use std::io::{Read, Write};
use symvault_core::password::{self, GeneratedPassword};

#[derive(Serialize)]
struct PasswordResult<'a> {
    password: &'a str,
}

#[derive(Serialize)]
struct StoredResult<'a> {
    stored: bool,
    path: &'a str,
    file: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputOptions<'a> {
    pub format: &'a str,
    pub json: bool,
    pub quiet: bool,
}

/// Generates a password with the same command-level validation as Go.
pub fn generate_password(length: i64, use_symbols: bool) -> Result<GeneratedPassword, String> {
    if length <= 0 {
        return Err("length must be greater than zero".to_owned());
    }
    password::generate_password(
        isize::try_from(length).map_err(|_| "length is out of range".to_owned())?,
        use_symbols,
    )
    .map_err(|error| error.to_string())
}

/// Deterministic seam for Go/Rust fixture comparisons.
pub fn generate_password_with_reader<R: Read>(
    length: i64,
    use_symbols: bool,
    reader: &mut R,
) -> Result<GeneratedPassword, String> {
    if length <= 0 {
        return Err("length must be greater than zero".to_owned());
    }
    password::generate_password_with_reader(
        isize::try_from(length).map_err(|_| "length is out of range".to_owned())?,
        use_symbols,
        reader,
    )
    .map_err(|error| error.to_string())
}

/// Renders an unstored generated password using the global output contract.
pub fn render_password<W: Write>(
    output: &mut W,
    password: &str,
    options: OutputOptions<'_>,
) -> Result<(), String> {
    if options.quiet {
        return Ok(());
    }
    if options.format == "text" && !options.json {
        return writeln!(output, "{password}").map_err(|error| error.to_string());
    }
    render_structured(
        output,
        &PasswordResult { password },
        options.format,
        options.json,
    )
}

/// Renders the result of `generate --store`. The caller writes the generated
/// password through the normal entry mutation boundary before calling this.
pub fn render_stored<W: Write>(
    output: &mut W,
    path: &str,
    file: &str,
    password: &str,
    options: OutputOptions<'_>,
    reveal: bool,
) -> Result<(), String> {
    if options.format == "text" && !options.json {
        if options.quiet {
            return Ok(());
        }
        return writeln!(output, "Password stored at: {file}").map_err(|error| error.to_string());
    }
    render_structured(
        output,
        &StoredResult {
            stored: true,
            path,
            file,
            password: reveal.then_some(password),
        },
        options.format,
        options.json,
    )
}

fn render_structured<W: Write, T: Serialize>(
    output: &mut W,
    value: &T,
    output_format: &str,
    json: bool,
) -> Result<(), String> {
    if json || output_format == "json" {
        serde_json::to_writer(&mut *output, value).map_err(|error| error.to_string())?;
        output.write_all(b"\n").map_err(|error| error.to_string())?;
        return Ok(());
    }
    if output_format == "yaml" {
        let yaml = serde_yaml_ng::to_string(value).map_err(|error| error.to_string())?;
        output
            .write_all(yaml.as_bytes())
            .map_err(|error| error.to_string())?;
        return Ok(());
    }
    Err(format!(
        "unsupported output format: {output_format} (supported: text, json, yaml)"
    ))
}
