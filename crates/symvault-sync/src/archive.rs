use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::{Component, Path, PathBuf},
};
use tar::{Archive, Builder, EntryType, Header};
use thiserror::Error;

const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_ARCHIVE_FILE: u64 = 64 * 1024 * 1024;
const MAX_ARCHIVE_TOTAL: u64 = 512 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("archive I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("unsafe archive path: {0}")]
    UnsafePath(String),
    #[error("archive entry is not a regular file or directory: {0}")]
    UnsupportedEntry(String),
    #[error("archive exceeds safety limits")]
    Limit,
    #[error("archive destination already exists: {0}")]
    Exists(PathBuf),
    #[error("archive path is not a directory: {0}")]
    NotDirectory(PathBuf),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub path: String,
    pub directory: bool,
    pub mode: u32,
    pub size: u64,
    pub sha256: String,
}

fn safe_relative(path: &Path) -> Result<PathBuf, ArchiveError> {
    if path.is_absolute() {
        return Err(ArchiveError::UnsafePath(path.display().to_string()));
    }
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(v) => out.push(v),
            Component::CurDir => {}
            _ => return Err(ArchiveError::UnsafePath(path.display().to_string())),
        }
    }
    if out.as_os_str().is_empty() {
        return Err(ArchiveError::UnsafePath(path.display().to_string()));
    }
    Ok(out)
}
fn mode(meta: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Creates a gzip-compressed tar backup. Symlinks and special files are rejected.
pub fn backup(
    root: impl AsRef<Path>,
    output: impl AsRef<Path>,
    exclude_git: bool,
) -> Result<Vec<ArchiveEntry>, ArchiveError> {
    let root = root.as_ref();
    if !root.is_dir() {
        return Err(ArchiveError::NotDirectory(root.to_path_buf()));
    }
    let file = fs::File::create(output)?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = Builder::new(encoder);
    let mut manifest = Vec::new();
    let mut paths: Vec<_> = walkdir(root)?.into_iter().collect();
    paths.sort();
    for path in paths {
        let rel = path
            .strip_prefix(root)
            .map_err(|_| ArchiveError::UnsafePath(path.display().to_string()))?;
        let rel = safe_relative(rel)?;
        if exclude_git && (rel == Path::new(".git") || rel.starts_with(".git")) {
            continue;
        }
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() || (!meta.is_dir() && !meta.is_file()) {
            return Err(ArchiveError::UnsupportedEntry(rel.display().to_string()));
        }
        let slash = rel
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        if meta.is_dir() {
            builder.append_dir(&rel, &path)?;
            manifest.push(ArchiveEntry {
                path: slash,
                directory: true,
                mode: mode(&meta),
                size: 0,
                sha256: digest(&[]),
            });
        } else {
            if meta.len() > MAX_ARCHIVE_FILE {
                return Err(ArchiveError::Limit);
            }
            let bytes = fs::read(&path)?;
            let mut h = Header::new_gnu();
            h.set_metadata(&meta);
            h.set_mode(mode(&meta));
            h.set_size(bytes.len() as u64);
            h.set_cksum();
            builder.append_data(&mut h, &rel, bytes.as_slice())?;
            manifest.push(ArchiveEntry {
                path: slash,
                directory: false,
                mode: mode(&meta),
                size: bytes.len() as u64,
                sha256: digest(&bytes),
            });
        }
        if manifest.len() > MAX_ARCHIVE_ENTRIES {
            return Err(ArchiveError::Limit);
        }
    }
    builder.into_inner()?.finish()?;
    Ok(manifest)
}
fn walkdir(root: &Path) -> Result<Vec<PathBuf>, ArchiveError> {
    fn visit(path: &Path, out: &mut Vec<PathBuf>) -> Result<(), ArchiveError> {
        let mut children: Vec<_> = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
        children.sort_by_key(|e| e.file_name());
        for e in children {
            let p = e.path();
            out.push(p.clone());
            if fs::symlink_metadata(&p)?.is_dir() {
                visit(&p, out)?;
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    visit(root, &mut out)?;
    Ok(out)
}

/// Restores a gzip tar backup into an existing or newly created directory.
pub fn restore(
    input: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    overwrite: bool,
) -> Result<Vec<ArchiveEntry>, ArchiveError> {
    let dest = destination.as_ref();
    if fs::symlink_metadata(dest)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(ArchiveError::UnsafePath(dest.display().to_string()));
    }
    fs::create_dir_all(dest)?;
    if !dest.is_dir() {
        return Err(ArchiveError::NotDirectory(dest.to_path_buf()));
    }
    let file = fs::File::open(input)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    let mut result = Vec::new();
    let mut total = 0u64;
    for (index, item) in archive.entries()?.enumerate() {
        if index >= MAX_ARCHIVE_ENTRIES {
            return Err(ArchiveError::Limit);
        }
        let mut entry = item?;
        let raw = entry.path()?.into_owned();
        let rel = safe_relative(&raw)?;
        let target = dest.join(&rel);
        if !target.starts_with(dest) {
            return Err(ArchiveError::UnsafePath(raw.display().to_string()));
        }
        ensure_no_symlink_components(dest, &rel)?;
        let kind = entry.header().entry_type();
        if kind == EntryType::Directory {
            fs::create_dir_all(&target)?;
            apply_mode(&target, entry.header().mode()?)?;
            result.push(ArchiveEntry {
                path: rel
                    .to_string_lossy()
                    .replace(std::path::MAIN_SEPARATOR, "/"),
                directory: true,
                mode: entry.header().mode()?,
                size: 0,
                sha256: digest(&[]),
            });
            continue;
        }
        if kind != EntryType::Regular {
            return Err(ArchiveError::UnsupportedEntry(rel.display().to_string()));
        }
        let size = entry.size();
        total = total.checked_add(size).ok_or(ArchiveError::Limit)?;
        if size > MAX_ARCHIVE_FILE || total > MAX_ARCHIVE_TOTAL {
            return Err(ArchiveError::Limit);
        }
        if target.exists() && !overwrite {
            return Err(ArchiveError::Exists(target));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut bytes = Vec::with_capacity(size.min(MAX_ARCHIVE_FILE) as usize);
        entry.read_to_end(&mut bytes)?;
        if bytes.len() as u64 != size {
            return Err(ArchiveError::Limit);
        }
        let hash = digest(&bytes);
        let m = entry.header().mode()?;
        let tmp = target.with_extension(format!("tmp-{}", std::process::id()));
        fs::write(&tmp, &bytes)?;
        apply_mode(&tmp, m)?;
        fs::rename(&tmp, &target)?;
        result.push(ArchiveEntry {
            path: rel
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/"),
            directory: false,
            mode: m,
            size,
            sha256: hash,
        });
    }
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}
fn ensure_no_symlink_components(dest: &Path, rel: &Path) -> Result<(), ArchiveError> {
    let mut current = dest.to_path_buf();
    for component in rel.components() {
        if let Component::Normal(name) = component {
            current.push(name);
            if fs::symlink_metadata(&current)
                .map(|meta| meta.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(ArchiveError::UnsafePath(rel.display().to_string()));
            }
        }
    }
    Ok(())
}
fn apply_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}
