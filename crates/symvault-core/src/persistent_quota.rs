//! Persistent quota counters. State is exactly `{ "counters": { ... } }`.
use fs4::fs_std::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};
use thiserror::Error;

pub const QUOTA_FILE_NAME: &str = ".quotas.json";

#[derive(Debug, Error)]
pub enum QuotaError {
    #[error("quota counter is closed")]
    Closed,
    #[error("quota I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("malformed quota data: {0}")]
    Malformed(String),
    #[error("quota lock unavailable: {0}")]
    Lock(String),
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
struct Persisted {
    counters: BTreeMap<String, i64>,
}

/// The side-effect boundary for persistent quota storage. Tests can inject
/// every operation; the default uses an exclusive OS file lock (flock on Unix
/// and LockFileEx-compatible locking through fs4 on Windows).
pub trait QuotaPlatform: Send + Sync {
    fn lock(&self, file: &File) -> Result<(), QuotaError>;
    fn unlock(&self, file: &File) -> Result<(), QuotaError>;
    fn read(&self, file: &mut File, path: &Path) -> Result<Vec<u8>, QuotaError>;
    fn write_sync(&self, file: &mut File, path: &Path, bytes: &[u8]) -> Result<(), QuotaError>;
}
#[derive(Default)]
pub struct NativeQuotaPlatform;

#[cfg(unix)]
fn native_lock(file: &File) -> Result<(), QuotaError> {
    file.lock_exclusive()
        .map_err(|e| QuotaError::Lock(e.to_string()))
}
#[cfg(windows)]
fn native_lock(file: &File) -> Result<(), QuotaError> {
    // fs4's Windows backend calls LockFileEx with an exclusive whole-file
    // range; keep this branch explicit so cross-target compilation covers the
    // production Windows locking path rather than a Unix fallback.
    file.lock_exclusive()
        .map_err(|e| QuotaError::Lock(e.to_string()))
}
#[cfg(not(any(unix, windows)))]
fn native_lock(_: &File) -> Result<(), QuotaError> {
    Err(QuotaError::Lock("native file locking unavailable".into()))
}

#[cfg(unix)]
fn native_unlock(file: &File) -> Result<(), QuotaError> {
    file.unlock().map_err(|e| QuotaError::Lock(e.to_string()))
}
#[cfg(windows)]
fn native_unlock(file: &File) -> Result<(), QuotaError> {
    file.unlock().map_err(|e| QuotaError::Lock(e.to_string()))
}
#[cfg(not(any(unix, windows)))]
fn native_unlock(_: &File) -> Result<(), QuotaError> {
    Err(QuotaError::Lock("native file locking unavailable".into()))
}

impl QuotaPlatform for NativeQuotaPlatform {
    fn lock(&self, file: &File) -> Result<(), QuotaError> {
        native_lock(file)
    }
    fn unlock(&self, file: &File) -> Result<(), QuotaError> {
        native_unlock(file)
    }
    fn read(&self, file: &mut File, path: &Path) -> Result<Vec<u8>, QuotaError> {
        file.seek(SeekFrom::Start(0))
            .map_err(|source| QuotaError::Io {
                path: path.into(),
                source,
            })?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|source| QuotaError::Io {
                path: path.into(),
                source,
            })?;
        Ok(bytes)
    }
    fn write_sync(&self, file: &mut File, path: &Path, bytes: &[u8]) -> Result<(), QuotaError> {
        file.set_len(0).map_err(|source| QuotaError::Io {
            path: path.into(),
            source,
        })?;
        file.seek(SeekFrom::Start(0))
            .map_err(|source| QuotaError::Io {
                path: path.into(),
                source,
            })?;
        file.write_all(bytes).map_err(|source| QuotaError::Io {
            path: path.into(),
            source,
        })?;
        file.sync_all().map_err(|source| QuotaError::Io {
            path: path.into(),
            source,
        })
    }
}

pub struct QuotaCounter<P: QuotaPlatform = NativeQuotaPlatform> {
    path: PathBuf,
    file: Option<File>,
    platform: P,
    operation: Mutex<()>,
}
impl QuotaCounter<NativeQuotaPlatform> {
    pub fn new(vault_dir: impl AsRef<Path>) -> Result<Self, QuotaError> {
        Self::with_platform(vault_dir, NativeQuotaPlatform)
    }
}
impl<P: QuotaPlatform> QuotaCounter<P> {
    pub fn with_platform(vault_dir: impl AsRef<Path>, platform: P) -> Result<Self, QuotaError> {
        let dir = vault_dir.as_ref();
        fs::create_dir_all(dir).map_err(|source| QuotaError::Io {
            path: dir.into(),
            source,
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|source| {
                QuotaError::Io {
                    path: dir.into(),
                    source,
                }
            })?;
        }
        let path = dir.join(QUOTA_FILE_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| QuotaError::Io {
                path: path.clone(),
                source,
            })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|source| QuotaError::Io {
                    path: path.clone(),
                    source,
                })?;
        }
        Ok(Self {
            path,
            file: Some(file),
            platform,
            operation: Mutex::new(()),
        })
    }
    pub fn close(&mut self) -> Result<(), QuotaError> {
        self.file.take();
        Ok(())
    }
    fn with_locked<T>(
        &self,
        operation: impl FnOnce(&mut File, &Path, &P) -> Result<T, QuotaError>,
    ) -> Result<T, QuotaError> {
        let _serial = self.operation.lock().unwrap();
        let file = self.file.as_ref().ok_or(QuotaError::Closed)?;
        self.platform.lock(file)?;
        let result = operation(
            &mut file.try_clone().map_err(|source| QuotaError::Io {
                path: self.path.clone(),
                source,
            })?,
            &self.path,
            &self.platform,
        );
        let unlock = self.platform.unlock(file);
        match (result, unlock) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }
    fn read_state(file: &mut File, path: &Path, p: &P) -> Result<Persisted, QuotaError> {
        let bytes = p.read(file, path)?;
        if bytes.is_empty() {
            return Ok(Persisted::default());
        }
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| QuotaError::Malformed(e.to_string()))?;
        let Some(counters) = value.get("counters") else {
            return Ok(Persisted::default());
        };
        if counters.is_null() {
            return Ok(Persisted::default());
        };
        let object = counters
            .as_object()
            .ok_or_else(|| QuotaError::Malformed("counters must be an object".into()))?;
        let mut state = Persisted::default();
        for (key, value) in object {
            let count = value.as_i64().ok_or_else(|| {
                QuotaError::Malformed(format!("counter {key:?} must be an integer"))
            })?;
            state.counters.insert(key.clone(), count);
        }
        Ok(state)
    }
    fn write_state(
        file: &mut File,
        path: &Path,
        p: &P,
        state: &Persisted,
    ) -> Result<(), QuotaError> {
        let bytes = serde_json::to_vec(state).map_err(|e| QuotaError::Malformed(e.to_string()))?;
        p.write_sync(file, path, &bytes)
    }
    pub fn increment(&self, name: &str) -> Result<i64, QuotaError> {
        self.with_locked(|file, path, p| {
            let mut state = Self::read_state(file, path, p)?;
            let count = state.counters.entry(name.into()).or_default();
            *count = count.saturating_add(1);
            let value = *count;
            Self::write_state(file, path, p, &state)?;
            Ok(value)
        })
    }
    pub fn check(&self, name: &str, limit: i64) -> Result<(bool, i64), QuotaError> {
        if limit <= 0 {
            return Ok((false, 0));
        }
        self.with_locked(|file, path, p| {
            let state = Self::read_state(file, path, p)?;
            let count = *state.counters.get(name).unwrap_or(&0);
            Ok((count < limit, count))
        })
    }
    pub fn reset(&self) -> Result<(), QuotaError> {
        self.with_locked(|file, path, p| Self::write_state(file, path, p, &Persisted::default()))
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg_attr(miri, ignore = "uses native filesystem locking unsupported by Miri")]
    fn persisted_layout_and_modes() {
        let dir = std::env::temp_dir().join(format!("symvault-quota-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut q = QuotaCounter::new(&dir).unwrap();
        assert_eq!(q.increment("read_entry").unwrap(), 1);
        assert_eq!(q.check("read_entry", 2).unwrap(), (true, 1));
        let raw = fs::read(dir.join(QUOTA_FILE_NAME)).unwrap();
        assert_eq!(raw, br#"{"counters":{"read_entry":1}}"#);
        q.close().unwrap();
        assert!(matches!(q.check("read_entry", 2), Err(QuotaError::Closed)));
        let _ = fs::remove_dir_all(dir);
    }
    #[test]
    #[cfg_attr(miri, ignore = "uses native filesystem locking unsupported by Miri")]
    fn concurrent_updates_are_not_lost() {
        let dir =
            std::env::temp_dir().join(format!("symvault-quota-concurrent-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut joins = Vec::new();
        for _ in 0..8 {
            let d = dir.clone();
            joins.push(std::thread::spawn(move || {
                let q = QuotaCounter::new(d).unwrap();
                for _ in 0..25 {
                    q.increment("read_entry").unwrap();
                }
            }));
        }
        for j in joins {
            j.join().unwrap();
        }
        let q = QuotaCounter::new(&dir).unwrap();
        assert_eq!(q.check("read_entry", 201).unwrap(), (true, 200));
        let _ = fs::remove_dir_all(dir);
    }
}
