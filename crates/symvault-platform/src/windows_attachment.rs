//! Retain Windows file identity without blocking ordinary FileShare.Read.
//! See ADR 0012 for handle ownership, memory lifetime and cleanup invariants.
#![allow(unsafe_code)] // Three audited FFI/ownership operations behind safe owned File inputs.
use std::{
    fs::File,
    io::{self, Seek, SeekFrom, Write},
    os::windows::io::{AsRawHandle, FromRawHandle},
};
use windows_sys::Win32::{
    Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        DELETE, FILE_DISPOSITION_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FileDispositionInfo, ReOpenFile, SetFileInformationByHandle,
    },
};

fn reopen(original: &File, access: u32) -> io::Result<File> {
    // SAFETY: original owns a live ordinary file handle for the entire call.
    // ReOpenFile opens that object, without traversing a mutable pathname.
    let handle = unsafe {
        ReOpenFile(
            original.as_raw_handle(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the API returned a new owned handle; File closes it exactly once.
    Ok(unsafe { File::from_raw_handle(handle) })
}

pub fn shareable_guard(writer: File) -> io::Result<File> {
    let guard = reopen(&writer, FILE_READ_ATTRIBUTES)?;
    // A retained WRITE_DATA handle conflicts with readers sharing only READ.
    // Acquire the identity guard before releasing that writer, with no gap.
    drop(writer);
    Ok(guard)
}

pub fn shred_and_delete(guard: File, length: u64) -> io::Result<()> {
    let mut writer = reopen(&guard, GENERIC_WRITE | DELETE)?;
    writer.seek(SeekFrom::Start(0))?;
    let zeros = [0u8; 8192];
    let mut remaining = length;
    while remaining > 0 {
        let count = remaining.min(zeros.len() as u64) as usize;
        writer.write_all(&zeros[..count])?;
        remaining -= count as u64;
    }
    writer.sync_all()?;
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: writer is live and owns DELETE access; disposition matches the
    // requested Windows information class and remains live throughout the call.
    let success = unsafe {
        SetFileInformationByHandle(
            writer.as_raw_handle(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(writer);
    drop(guard);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Read, os::windows::fs::OpenOptionsExt};

    fn fixture(path: &std::path::Path) -> File {
        let mut writer = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        writer.write_all(b"synthetic attachment").unwrap();
        writer.sync_all().unwrap();
        shareable_guard(writer).unwrap()
    }

    #[test]
    fn ordinary_read_only_sharing_reads_exact_payload() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("attachment");
        let guard = fixture(&path);
        let mut reader = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .unwrap();
        let mut bytes = vec![];
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"synthetic attachment");
        drop(reader);
        shred_and_delete(guard, bytes.len() as u64).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn cleanup_deletes_original_after_path_and_parent_replacement() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("private");
        fs::create_dir(&directory).unwrap();
        let path = directory.join("attachment");
        let guard = fixture(&path);
        // Windows refuses moving a directory that still contains an open
        // file. Move the retained file object out first, then actually replace
        // both its old pathname and parent. No failed swap is treated as proof.
        let original_file = root.path().join("retained-original");
        fs::rename(&path, &original_file).unwrap();
        let original_directory = root.path().join("renamed");
        fs::rename(&directory, &original_directory).unwrap();
        fs::create_dir(&directory).unwrap();
        fs::write(&path, b"replacement must survive").unwrap();
        shred_and_delete(guard, b"synthetic attachment".len() as u64).unwrap();
        assert!(!original_file.exists());
        assert_eq!(fs::read(&path).unwrap(), b"replacement must survive");
    }

    #[test]
    fn retained_reader_reports_cleanup_failure_without_path_fallback() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("attachment");
        let guard = fixture(&path);
        let reader = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .unwrap();
        assert!(shred_and_delete(guard, b"synthetic attachment".len() as u64).is_err());
        assert!(path.exists());
        drop(reader);
    }
}
