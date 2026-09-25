use std::{
    io,
    path::{Component, Path, PathBuf},
};

use clap_mangen::Man;

/// `.TH` header values taken verbatim from the Go oracle (`cmd/manpages.go`).
///
/// The reference builds one `doc.GenManHeader` for the whole tree —
/// `Title: strings.ToUpper(root.Name())`, `Section: "1"`,
/// `Manual: "Symaira Vault Manual"`, `Source: "Symaira Vault"` — and hands a
/// copy of it to every page, so the title stays the constant root name instead
/// of falling back to cobra's per-command path (`fillHeader` only derives a
/// title when the header one is empty).
const TITLE: &str = "SYMVAULT";
const SECTION: &str = "1";
const MANUAL: &str = "Symaira Vault Manual";
const SOURCE: &str = "Symaira Vault";

/// English month abbreviations matching Go's `Jan 2006` layout, which cobra
/// uses to render `GenManHeader.Date` into the `.TH` line.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Generate manual pages for the complete clap command tree.
///
/// This mirrors the offline `cobra/doc.GenManTree` path: the output directory
/// is made absolute, created with the Go command's requested mode on Unix, the
/// page date is resolved (cobra does so inside `GenManTree`, i.e. after the
/// directory exists), then one section-1 page is written for every visible
/// command with the oracle's header.
pub fn generate(command: clap::Command, requested_dir: &Path) -> Result<PathBuf, String> {
    let output_dir = absolute_path(requested_dir)
        .map_err(|error| format!("resolve manpage directory: {error}"))?;
    create_directory(&output_dir).map_err(|error| format!("create manpage directory: {error}"))?;
    let date = man_date().map_err(|error| format!("generate manpages: {error}"))?;
    // Build before walking so every subcommand carries the `display_name` that
    // `clap_mangen` uses for its file name (`symvault-generate-manpages.1`).
    let mut command = command.disable_help_subcommand(true);
    command.build();
    write_pages(command, &output_dir, &date)
        .map_err(|error| format!("generate manpages: {error}"))?;
    Ok(output_dir)
}

/// Depth-first page writer matching `clap_mangen::generate_to`: children first,
/// hidden commands skipped, one page per command.
fn write_pages(command: clap::Command, output_dir: &Path, date: &str) -> io::Result<()> {
    for subcommand in command
        .get_subcommands()
        .filter(|subcommand| !subcommand.is_hide_set())
        .cloned()
    {
        write_pages(subcommand, output_dir, date)?;
    }
    Man::new(command)
        .title(TITLE)
        .section(SECTION)
        .date(date)
        .source(SOURCE)
        .manual(MANUAL)
        .generate_to(output_dir)?;
    Ok(())
}

/// Render the page date the way cobra's `fillHeader` does: the current month
/// and year, or the instant pinned by `SOURCE_DATE_EPOCH` for reproducible
/// builds. The default case reads the clock in UTC, where the oracle reads it
/// in the local zone, so the two can disagree only inside the first hours of a
/// month in a zone ahead of UTC.
fn man_date() -> Result<String, String> {
    let moment = match std::env::var_os("SOURCE_DATE_EPOCH") {
        Some(raw) => {
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
    };
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
