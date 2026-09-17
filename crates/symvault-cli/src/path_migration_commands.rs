use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

const LEGACY_SUBDIR: &str = ".symvault";
const APP_SUBDIR: &str = "symaira-vault";
const MAX_ITEMS: usize = 100_000;
const MAX_BYTES: u64 = 1 << 30;

#[derive(Debug, Eq, PartialEq)]
struct MigrationItem {
    source: PathBuf,
    destination: PathBuf,
    bytes: u64,
}

/// Render the non-mutating legacy-to-XDG migration preview.
///
/// The caller supplies the discovered home and XDG roots so the command can
/// keep environment discovery in the dispatcher and remain deterministic in
/// tests. Empty XDG roots use the same home-relative defaults as Go.
pub(crate) fn preview(
    home: &Path,
    xdg_config_home: Option<&Path>,
    xdg_data_home: Option<&Path>,
    xdg_cache_home: Option<&Path>,
    quiet: bool,
    output: &mut impl Write,
) -> Result<(), String> {
    let legacy = home.join(LEGACY_SUBDIR);
    let metadata = match fs::symlink_metadata(&legacy) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return write_no_migration(quiet, output);
        }
        Err(error) => return Err(error.to_string()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "legacy path is not a directory: {}",
            display(&legacy)
        ));
    }
    if fs::symlink_metadata(legacy.join(".migrated")).is_ok() {
        return write_no_migration(quiet, output);
    }

    let config_dir = xdg_root(xdg_config_home, home, ".config").join(APP_SUBDIR);
    let data_dir = xdg_root(xdg_data_home, home, ".local/share").join(APP_SUBDIR);
    let cache_dir = xdg_root(xdg_cache_home, home, ".cache").join(APP_SUBDIR);
    let groups = [
        ("config.yaml", config_dir.join("config.yaml")),
        ("vault", data_dir.join("vault")),
        ("audit", data_dir.join("audit")),
        ("devices.json", data_dir.join("devices.json")),
        ("pairing", data_dir.join("pairing")),
        ("update-cache.json", cache_dir.join("update-cache.json")),
    ];
    let mut plan = Vec::new();
    let mut total_bytes = 0_u64;
    for (relative, destination) in groups {
        append_entry(
            &legacy.join(relative),
            &destination,
            Path::new(relative),
            &mut plan,
            &mut total_bytes,
        )?;
    }
    plan.sort_unstable_by(|left, right| left.destination.cmp(&right.destination));

    if quiet {
        return Ok(());
    }
    writeln!(
        output,
        "Legacy path migration would copy {} item(s):",
        plan.len()
    )
    .map_err(|error| format!("write migration preview: {error}"))?;
    for item in plan {
        writeln!(
            output,
            "  {} -> {} ({} bytes)",
            display(&item.source),
            display(&item.destination),
            item.bytes
        )
        .map_err(|error| format!("write migration preview: {error}"))?;
    }
    writeln!(output, "Preview only: no changes written.")
        .map_err(|error| format!("write migration preview: {error}"))?;
    Ok(())
}

fn write_no_migration(quiet: bool, output: &mut impl Write) -> Result<(), String> {
    if !quiet {
        writeln!(output, "No legacy path migration is needed.")
            .map_err(|error| format!("write migration preview: {error}"))?;
    }
    Ok(())
}

fn xdg_root(value: Option<&Path>, home: &Path, fallback: &str) -> PathBuf {
    value
        .filter(|path| !path.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home.join(fallback))
}

fn append_entry(
    source: &Path,
    destination: &Path,
    relative: &Path,
    items: &mut Vec<MigrationItem>,
    total_bytes: &mut u64,
) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(source) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    if metadata.file_type().is_symlink() {
        return Err(format!("refusing symlink: {}", display(relative)));
    }
    if metadata.is_dir() {
        add_item(items, total_bytes, source, destination, 0)?;
        let mut children = fs::read_dir(source)
            .map_err(|error| error.to_string())?
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        children.sort_unstable();
        for child in children {
            let name = child
                .file_name()
                .ok_or_else(|| format!("cannot determine relative path: {}", display(&child)))?;
            append_entry(
                &child,
                &destination.join(name),
                &relative.join(name),
                items,
                total_bytes,
            )?;
        }
        return Ok(());
    }
    add_item(items, total_bytes, source, destination, metadata.len())
}

fn add_item(
    items: &mut Vec<MigrationItem>,
    total_bytes: &mut u64,
    source: &Path,
    destination: &Path,
    bytes: u64,
) -> Result<(), String> {
    if items.len() >= MAX_ITEMS {
        return Err(format!("migration exceeds item limit ({MAX_ITEMS})"));
    }
    if bytes > MAX_BYTES {
        return Err(format!(
            "migration file exceeds size limit: {}",
            display(source)
        ));
    }
    if bytes > MAX_BYTES.saturating_sub(*total_bytes) {
        return Err(format!("migration exceeds size limit ({MAX_BYTES} bytes)"));
    }
    *total_bytes += bytes;
    items.push(MigrationItem {
        source: source.to_owned(),
        destination: destination.to_owned(),
        bytes,
    });
    Ok(())
}

fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
