//! Streaming integrity reads using the same no-follow descriptor as metadata.

use crate::{StoreError, read_admission};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::Path,
};

pub(crate) fn opened(
    file: fs::File,
    path: &Path,
    limit: u64,
    batch: Option<&read_admission::Batch>,
) -> Result<(String, u64, fs::Metadata), StoreError> {
    let _lease = read_admission::acquire()?;
    let metadata = file.metadata().map_err(|source| StoreError::Read {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(StoreError::NotRegularFile(path.to_owned()));
    }
    if metadata.len() > limit {
        return Err(StoreError::ResourceLimit);
    }
    if let Some(batch) = batch {
        batch.consume(metadata.len() as usize)?;
    }
    let read_limit = if batch.is_some() {
        metadata.len()
    } else {
        limit
    };
    let mut reader = file.take(read_limit + 1);
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 32 * 1024];
    let mut size = 0;
    loop {
        let count = match reader.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result.map_err(|source| StoreError::Read {
                path: path.to_owned(),
                source,
            })?,
        };
        if count == 0 {
            break;
        }
        size += count as u64;
        if size > read_limit {
            if let Some(batch) = batch {
                batch.fail();
            }
            return Err(StoreError::ResourceLimit);
        }
        hash.update(&buffer[..count]);
    }

    Ok((format!("{:x}", hash.finalize()), size, metadata))
}
