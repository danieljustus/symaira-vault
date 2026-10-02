use std::{
    ffi::OsStr,
    fs,
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Owns a collision-safe temporary parent for one test root.
///
/// `missing` keeps the test root absent, while `existing` creates it before
/// returning. The parent guard remains alive for the full lifetime of this
/// value and removes the root recursively when the final clone is dropped.
#[derive(Clone)]
pub struct TempRoot {
    _guard: Arc<tempfile::TempDir>,
    path: PathBuf,
}

#[allow(dead_code)]
impl TempRoot {
    pub fn missing(prefix: &str) -> Self {
        let guard = Arc::new(
            tempfile::Builder::new()
                .prefix(prefix)
                .tempdir()
                .expect("allocate unique temporary parent"),
        );
        let path = guard.path().join("root");
        Self {
            _guard: guard,
            path,
        }
    }

    pub fn existing(prefix: &str) -> Self {
        let root = Self::missing(prefix);
        fs::create_dir_all(&root.path).expect("create temporary root");
        root
    }
}

impl AsRef<OsStr> for TempRoot {
    fn as_ref(&self) -> &OsStr {
        self.path.as_os_str()
    }
}

impl AsRef<Path> for TempRoot {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Deref for TempRoot {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}
