use std::{
    io,
    path::{Component, Path, PathBuf},
};

/// English month abbreviations matching Go's `Jan 2006` layout, which cobra
/// uses to render `GenManHeader.Date` into the `.TH` line.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Generate the complete Go-compatible public manual tree.
///
/// This mirrors the offline `cobra/doc.GenManTree` path: the output directory
/// is made absolute, created with the Go command's requested mode on Unix, the
/// page date is resolved (cobra does so inside `GenManTree`, i.e. after the
/// directory exists), then one section-1 page is written for every visible
/// command with the oracle's header.
pub fn generate(_command: clap::Command, requested_dir: &Path) -> Result<PathBuf, String> {
    let output_dir = absolute_path(requested_dir)
        .map_err(|error| format!("resolve manpage directory: {error}"))?;
    create_directory(&output_dir).map_err(|error| format!("create manpage directory: {error}"))?;
    let date = man_date().map_err(|error| format!("generate manpages: {error}"))?;
    write_pages(&output_dir, &date).map_err(|error| format!("generate manpages: {error}"))?;
    Ok(output_dir)
}

/// Write actual generated Go pages, substituting the live date and config path.
fn write_pages(output_dir: &Path, date: &str) -> io::Result<()> {
    // Go's md2man paragraph renderer doubles backslashes in a live Windows
    // config path. Help uses the unescaped path; roff must preserve its syntax.
    let config_path = symvault_core::config::PathResolver::new()
        .config_path()
        .to_string_lossy()
        .replace('\\', "\\\\");
    for (name, page) in &crate::cli_artifacts::DATA.manpages {
        let rendered = page.replace("__CONFIG_PATH__", &config_path).replacen(
            "\"Jan 1970\"",
            &format!("\"{date}\""),
            1,
        );
        std::fs::write(output_dir.join(name), rendered)?;
    }
    Ok(())
}

/// Render the page date the way cobra's `fillHeader` does: local time, using
/// the current instant or the instant pinned by `SOURCE_DATE_EPOCH`.
fn man_date() -> Result<String, String> {
    let utc_moment = match std::env::var_os("SOURCE_DATE_EPOCH") {
        Some(raw) if !raw.is_empty() => {
            let raw = raw
                .to_str()
                .ok_or("invalid SOURCE_DATE_EPOCH: invalid digit found in string")?;
            let stamp = raw
                .parse::<i64>()
                .map_err(|error| format!("invalid SOURCE_DATE_EPOCH: {error}"))?;
            time::OffsetDateTime::from_unix_timestamp(stamp)
                .map_err(|error| format!("invalid SOURCE_DATE_EPOCH: {error}"))?
        }
        None => time::OffsetDateTime::now_utc(),
        Some(_) => time::OffsetDateTime::now_utc(),
    };
    let local_offset = time::UtcOffset::local_offset_at(utc_moment)
        .map_err(|error| format!("cannot determine local timezone: {error}"))?;
    let moment = utc_moment.to_offset(local_offset);
    Ok(format!(
        "{} {}",
        MONTHS[(u8::from(moment.month()) - 1) as usize],
        moment.year()
    ))
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

fn create_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o750).create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}
