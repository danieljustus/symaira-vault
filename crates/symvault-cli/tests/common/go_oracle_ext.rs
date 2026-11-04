//! Observation recorder for Go-oracle differentials whose Go side is not a plain
//! `Command::output()` of the Go binary (pty drivers, JSON-RPC sessions, signed
//! handshakes, library drivers, ...). Sibling of `go_oracle.rs`, same rules:
//!
//! * the Go observation of a key is answered from
//!   `testdata/port/cli-observations/<file>.json`; a missing recording, a key
//!   that the test no longer asks for and an empty recording are test FAILURES,
//!   never skips. There is no capture mode: the recordings were made once from
//!   the pinned Go oracle and are re-recorded, if ever needed, from the archived
//!   Go tree (tag `legacy/go-oracle`, `docs/rust-port/go-oracle-archive.md`).
//!
//! The closure a test passes to [`Observations::observe`] documents how the
//! observation was made against the Go oracle; replay never calls it.
//! Recordings carry no operator paths (`recordings_have_no_operator_paths.rs`
//! scans them); frozen vault trees mask their roots with [`mask_paths`] /
//! [`unmask_paths`].
#![allow(dead_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

const SENTINEL: &str = "/nonexistent/symvault-go-oracle-replay";

/// Output normalization a test declared for its observations (unused by replay).
pub type Normalizer = fn(&Value) -> Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleInfo {
    pub commit: String,
    pub go_version: String,
    pub goos: String,
    pub goarch: String,
    pub vcs_modified: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Recording {
    schema: u32,
    oracle: OracleInfo,
    /// test name -> key -> observation
    tests: BTreeMap<String, BTreeMap<String, Value>>,
}

struct Inner {
    file: String,
    test: String,
    go_path: PathBuf,
    oracle: OracleInfo,
    prior: BTreeMap<String, Value>,
    used: BTreeSet<String>,
}

#[derive(Clone)]
pub struct Observations {
    inner: Arc<Mutex<Inner>>,
}

fn path_of(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/port/cli-observations")
        .join(format!("{file}.json"))
}

fn load(file: &str) -> Option<Recording> {
    let path = path_of(file);
    let bytes = fs::read(&path).ok()?;
    Some(serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
}

impl Observations {
    /// Start one test. `file` names the recording, `test` the test function.
    pub fn begin(file: &str, test: &str, expected_commit: Option<&str>) -> Self {
        let recording = load(file).unwrap_or_else(|| {
            panic!(
                "go_oracle_ext: recording {} is missing; recapture it from the archived Go \
                 oracle (docs/rust-port/go-oracle-archive.md, \"Recapture\")",
                path_of(file).display()
            )
        });
        let prior = recording.tests.get(test).cloned().unwrap_or_else(|| {
            panic!(
                "go_oracle_ext: recording {} has no entry for test `{test}`; recapture",
                path_of(file).display()
            )
        });
        if let Some(expected) = expected_commit {
            assert_eq!(
                recording.oracle.commit, expected,
                "go_oracle_ext: recording oracle commit differs from the pinned one"
            );
        }
        Self {
            inner: Arc::new(Mutex::new(Inner {
                file: file.to_owned(),
                test: test.to_owned(),
                go_path: PathBuf::from(SENTINEL),
                oracle: recording.oracle,
                prior,
                used: BTreeSet::new(),
            })),
        }
    }

    /// Kept for call-site compatibility; the normalization only mattered when
    /// recapturing.
    pub fn stable_under(&self, _normalize: Normalizer) {}

    /// Path of the Go oracle binary (always a sentinel: nothing runs Go).
    pub fn binary(&self) -> PathBuf {
        self.inner.lock().unwrap().go_path.clone()
    }

    pub fn oracle(&self) -> OracleInfo {
        self.inner.lock().unwrap().oracle.clone()
    }

    /// Return the recorded observation of `key`; `live` documents how it was
    /// made against the Go oracle and is never called.
    pub fn observe(&self, key: &str, _live: impl FnOnce(&Path) -> Value) -> Value {
        let mut st = self.inner.lock().unwrap();
        let value = st.prior.get(key).cloned().unwrap_or_else(|| {
            panic!(
                "go_oracle_ext: {}::{} has no recorded observation `{key}`; recapture",
                st.file, st.test
            )
        });
        assert!(
            st.used.insert(key.to_owned()),
            "go_oracle_ext: observation `{key}` asked for twice"
        );
        value
    }

    /// Like [`observe`], for set-up steps whose result was random (fresh keys).
    pub fn observe_frozen(&self, key: &str, live: impl FnOnce(&Path) -> Value) -> Value {
        self.observe(key, live)
    }

    /// Number of observations replayed so far.
    pub fn count(&self) -> usize {
        self.inner.lock().unwrap().used.len()
    }
}

/// Every spelling of `path` (as given and canonicalized -- `/var` vs
/// `/private/var`), longest first, paired with its placeholder.
fn spellings(subs: &[(&Path, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut pairs = Vec::new();
    for (path, placeholder) in subs {
        let mut forms = vec![path.to_string_lossy().into_owned()];
        if let Ok(real) = fs::canonicalize(path) {
            forms.push(real.to_string_lossy().into_owned());
        } else if let Some(parent) = path.parent().and_then(|p| fs::canonicalize(p).ok())
            && let Some(name) = path.file_name()
        {
            forms.push(parent.join(name).to_string_lossy().into_owned());
        }
        forms.dedup();
        for form in forms {
            pairs.push((form.into_bytes(), placeholder.as_bytes().to_vec()));
        }
    }
    pairs.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
    pairs
}

fn replace_all(haystack: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(from) {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

/// Replaces the per-run directories in `bytes` by stable placeholders, e.g.
/// `[(vault_root, "<ROOT>"), (home, "<HOME>")]`. Longest path first.
pub fn mask_paths(bytes: &[u8], subs: &[(&Path, &str)]) -> Vec<u8> {
    spellings(subs)
        .iter()
        .fold(bytes.to_vec(), |text, (from, to)| {
            replace_all(&text, from, to)
        })
}

/// Inverse of [`mask_paths`] for the directories of the current run.
pub fn unmask_paths(bytes: &[u8], subs: &[(&Path, &str)]) -> Vec<u8> {
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = subs
        .iter()
        .map(|(path, placeholder)| {
            (
                placeholder.as_bytes().to_vec(),
                path.to_string_lossy().into_owned().into_bytes(),
            )
        })
        .collect();
    pairs.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
    pairs.iter().fold(bytes.to_vec(), |text, (from, to)| {
        replace_all(&text, from, to)
    })
}

impl Drop for Observations {
    fn drop(&mut self) {
        // Only the last handle finalizes.
        if Arc::strong_count(&self.inner) > 1 || std::thread::panicking() {
            return;
        }
        let st = self.inner.lock().unwrap();
        {
            let unused: Vec<&String> = st.prior.keys().filter(|k| !st.used.contains(*k)).collect();
            assert!(
                unused.is_empty(),
                "go_oracle_ext: {}::{} did not replay recorded observations {unused:?} (stale \
                 recording; recapture)",
                st.file,
                st.test
            );
            assert!(
                !st.used.is_empty(),
                "go_oracle_ext: {}::{} replayed zero observations",
                st.file,
                st.test
            );
            let _ = writeln!(
                std::io::stderr(),
                "go_oracle: replayed {} observations for {}::{} (oracle {} {} {}/{})",
                st.used.len(),
                st.file,
                st.test,
                &st.oracle.commit[..12.min(st.oracle.commit.len())],
                st.oracle.go_version,
                st.oracle.goos,
                st.oracle.goarch
            );
        }
    }
}
