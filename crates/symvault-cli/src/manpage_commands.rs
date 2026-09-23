use std::{
    io,
    path::{Component, Path, PathBuf},
};

/// Generate manual pages for the complete clap command tree.
///
/// This mirrors the offline `cobra/doc.GenManTree` path: the output directory
/// is made absolute, created with the Go command's requested mode on Unix,
/// then one section-1 page is written for every visible command.
pub fn generate(command: clap::Command, requested_dir: &Path) -> Result<PathBuf, String> {
    let output_dir = absolute_path(requested_dir)
        .map_err(|error| format!("resolve manpage directory: {error}"))?;
    create_directory(&output_dir).map_err(|error| format!("create manpage directory: {error}"))?;
    clap_mangen::generate_to(command, &output_dir)
        .map_err(|error| format!("generate manpages: {error}"))?;
    Ok(output_dir)
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
