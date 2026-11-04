//! Observation recorder for Go-oracle differentials whose Go side is not a plain
//! `Command::output()` of the Go binary (pty drivers, JSON-RPC sessions, signed
//! handshakes, library drivers, ...). Sibling of `go_oracle.rs`, same rules:
//!
//! * default mode is **replay**: the Go observation of a key is answered from
//!   `testdata/port/cli-observations/<file>.json`; a missing recording, a key
//!   that the test no longer asks for and an empty recording are test FAILURES,
//!   never skips;
//! * `SYMVAULT_ORACLE=capture` plus `SYMVAULT_GO_BINARY[_<8 hex>]=<oracle>` runs
//!   the live closure against the real Go oracle and rewrites the keys that ran.
//!   A capture keeps the committed value when the new one is equal under the
//!   test's own normalization, so recapturing is byte-stable.
//!
//! The closure returns a JSON value that must already be free of per-run temp
//! paths and clocks. A capture refuses to write a recording that still carries
//! the capturing machine's paths (`/Volumes`, `/Users`, `/var/folders`,
//! `/private/var`, also inside base64 file contents); frozen vault trees mask
//! their roots with [`mask_paths`] / [`unmask_paths`].
#![allow(dead_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[path = "operator_paths.rs"]
mod operator_paths;

const SENTINEL: &str = "/nonexistent/symvault-go-oracle-replay";
static FILE_LOCK: Mutex<()> = Mutex::new(());

/// Normalization under which a recapture is considered unchanged.
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
    capture: bool,
    go_path: PathBuf,
    oracle: OracleInfo,
    prior: BTreeMap<String, Value>,
    captured: BTreeMap<String, Value>,
    used: BTreeSet<String>,
    stable: Option<Normalizer>,
}

#[derive(Clone)]
pub struct Observations {
    inner: Arc<Mutex<Inner>>,
}

fn path_of(file: &str) -> PathBuf {
    let dir = env::var_os("SYMVAULT_ORACLE_DIR")
        .filter(|d| !d.is_empty())
        .map_or_else(
            || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/port/cli-observations"),
            |d| PathBuf::from(d).join("observations"),
        );
    dir.join(format!("{file}.json"))
}

fn load(file: &str) -> Option<Recording> {
    let path = path_of(file);
    let bytes = fs::read(&path).ok()?;
    Some(serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
}

fn inspect(binary: &Path, expected: Option<&str>) -> OracleInfo {
    let go = env::var("GO").unwrap_or_else(|_| "go".to_owned());
    let output = Command::new(&go)
        .args(["version", "-m"])
        .arg(binary)
        .env_remove("GOFLAGS")
        .output()
        .expect("run `go version -m` on the oracle binary");
    assert!(
        output.status.success(),
        "go version -m failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let setting = |key: &str| {
        text.lines()
            .filter_map(|l| l.trim().strip_prefix("build"))
            .filter_map(|l| l.trim().strip_prefix(&format!("{key}=")))
            .next()
            .unwrap_or_default()
            .to_owned()
    };
    let info = OracleInfo {
        commit: setting("vcs.revision"),
        go_version: text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or_default()
            .to_owned(),
        goos: setting("GOOS"),
        goarch: setting("GOARCH"),
        vcs_modified: setting("vcs.modified"),
    };
    assert!(
        !info.commit.is_empty(),
        "oracle binary carries no vcs.revision"
    );
    assert_eq!(
        info.vcs_modified, "false",
        "oracle binary is built from a dirty tree"
    );
    if let Some(expected) = expected {
        assert_eq!(
            info.commit, expected,
            "oracle binary is not the pinned commit"
        );
    }
    info
}

impl Observations {
    /// Start one test. `file` names the recording, `test` the test function.
    pub fn begin(file: &str, test: &str, expected_commit: Option<&str>) -> Self {
        let capture = match env::var("SYMVAULT_ORACLE").as_deref() {
            Ok("capture") => true,
            Ok("") | Err(_) => false,
            Ok(other) => panic!("SYMVAULT_ORACLE={other:?} is not recognised (use `capture`)"),
        };
        let (go_path, oracle, prior) = if capture {
            let binary = expected_commit
                .and_then(|c| env::var_os(format!("SYMVAULT_GO_BINARY_{}", &c[..8])))
                .or_else(|| env::var_os("SYMVAULT_GO_BINARY"))
                .expect("SYMVAULT_ORACLE=capture requires SYMVAULT_GO_BINARY");
            let binary = PathBuf::from(binary);
            let oracle = inspect(&binary, expected_commit);
            let prior = load(file)
                .and_then(|r| r.tests.get(test).cloned())
                .unwrap_or_default();
            (binary, oracle, prior)
        } else {
            let recording = load(file).unwrap_or_else(|| {
                panic!(
                    "go_oracle_ext: recording {} is missing; run the capture against the \
                     pinned Go oracle (docs/rust-port/go-oracle-archive.md, \"Recapture\")",
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
            (PathBuf::from(SENTINEL), recording.oracle, prior)
        };
        Self {
            inner: Arc::new(Mutex::new(Inner {
                file: file.to_owned(),
                test: test.to_owned(),
                capture,
                go_path,
                oracle,
                prior,
                captured: BTreeMap::new(),
                used: BTreeSet::new(),
                stable: None,
            })),
        }
    }

    /// Declare the normalization under which a recapture keeps the old value.
    pub fn stable_under(&self, normalize: Normalizer) {
        self.inner.lock().unwrap().stable = Some(normalize);
    }

    pub fn capturing(&self) -> bool {
        self.inner.lock().unwrap().capture
    }

    /// Path of the Go oracle binary (a sentinel in replay mode).
    pub fn binary(&self) -> PathBuf {
        self.inner.lock().unwrap().go_path.clone()
    }

    pub fn oracle(&self) -> OracleInfo {
        self.inner.lock().unwrap().oracle.clone()
    }

    /// Capture: run `live` against the Go oracle and record its observation.
    /// Replay: return the recorded observation and never call `live`.
    pub fn observe(&self, key: &str, live: impl FnOnce(&Path) -> Value) -> Value {
        let (capture, go_path) = {
            let st = self.inner.lock().unwrap();
            (st.capture, st.go_path.clone())
        };
        if !capture {
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
            return value;
        }
        let value = live(&go_path);
        let mut st = self.inner.lock().unwrap();
        let kept = match (st.prior.get(key), st.stable) {
            (Some(old), Some(normalize)) if normalize(old) == normalize(&value) => old.clone(),
            (Some(old), None) if *old == value => old.clone(),
            _ => value,
        };
        st.used.insert(key.to_owned());
        st.captured.insert(key.to_owned(), kept.clone());
        kept
    }

    /// Like [`observe`], for set-up steps whose result is random (fresh keys):
    /// a capture keeps the committed value and only runs `live` when none exists.
    pub fn observe_frozen(&self, key: &str, live: impl FnOnce(&Path) -> Value) -> Value {
        let prior = {
            let st = self.inner.lock().unwrap();
            if st.capture {
                st.prior.get(key).cloned()
            } else {
                None
            }
        };
        match prior {
            Some(value) => {
                let mut st = self.inner.lock().unwrap();
                st.used.insert(key.to_owned());
                st.captured.insert(key.to_owned(), value.clone());
                value
            }
            None => self.observe(key, live),
        }
    }

    /// Number of observations replayed (replay) or recorded (capture) so far.
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
        if st.capture {
            assert!(
                !st.captured.is_empty(),
                "go_oracle_ext: {}::{} captured zero observations",
                st.file,
                st.test
            );
            let _guard = FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let path = path_of(&st.file);
            let mut recording = load(&st.file).unwrap_or_else(|| Recording {
                schema: 1,
                oracle: st.oracle.clone(),
                tests: BTreeMap::new(),
            });
            assert_eq!(
                recording.oracle,
                st.oracle,
                "capture oracle differs from the one already recorded in {}; delete the \
                 recording to recapture it from scratch",
                path.display()
            );
            recording.tests.insert(st.test.clone(), st.captured.clone());
            operator_paths::assert_clean(
                &format!("go_oracle_ext: recording {}::{}", st.file, st.test),
                &serde_json::to_value(&recording).expect("recording value"),
            );
            fs::create_dir_all(path.parent().expect("parent")).expect("recording dir");
            let mut text = serde_json::to_string_pretty(&recording).expect("serialize");
            text.push('\n');
            fs::write(&path, text).expect("write recording");
        } else {
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
