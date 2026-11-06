//! `symvault setup` non-TTY guard (`cmd/admin/setup.go`).
//!
//! Go refuses to start the wizard unless stdin is a terminal and prints
//! "setup needs a TTY; use `symvault init` for non-interactive vault
//! initialization" through cobra and again through `ExecuteRoot` (both with an
//! `Error: ` prefix), exit status 1, empty stdout. The command declares nil
//! `Args`, so stray positionals never change that verdict. The expected bytes
//! were captured from a CGO-disabled build of the pinned oracle with stdin on
//! `/dev/null` and on a pipe, with and without an initialized vault.
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

const GUARD: &str =
    "Error: setup needs a TTY; use `symvault init` for non-interactive vault initialization\n";

fn expected_stderr() -> String {
    GUARD.repeat(2)
}

fn binary() -> PathBuf {
    PathBuf::from(std::env::var_os("CARGO_BIN_EXE_symvault").expect("Rust binary"))
}

fn command(home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(binary());
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_DATA_HOME", home.join("data"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("TMPDIR", home.join("tmp"))
        .env("CI", "1")
        .env("NO_COLOR", "1");
    cmd
}

fn sandbox() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("symvault-setup-guard-")
        .tempdir()
        .expect("temp dir");
    std::fs::create_dir_all(dir.path().join("tmp")).expect("tmp");
    dir
}

fn assert_guard(out: &Output, label: &str) {
    assert_eq!(out.status.code(), Some(1), "{label}: exit code");
    assert!(out.stdout.is_empty(), "{label}: stdout must be empty");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        expected_stderr(),
        "{label}: stderr"
    );
}

#[test]
fn guard_fires_for_devnull_stdin_with_any_positionals() {
    let home = sandbox();
    for args in [
        vec!["setup"],
        vec!["setup", "x"],
        vec!["setup", "x", "y"],
        vec!["setup", "--", "x"],
        vec!["setup", "--keep-on-error"],
        vec!["setup", "--no-resume"],
        vec!["setup", "--keep-on-error=true", "--no-resume=false"],
    ] {
        let out = command(home.path(), &args)
            .stdin(Stdio::null())
            .output()
            .expect("run");
        assert_guard(&out, &args.join(" "));
    }
}

#[test]
fn guard_fires_for_piped_stdin() {
    let home = sandbox();
    let mut child = command(home.path(), &["setup"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"\n")
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    assert_guard(&out, "pipe");
}

#[test]
fn guard_does_not_touch_an_existing_vault_or_create_state() {
    let home = sandbox();
    let vault = home.path().join("v");
    let init = command(home.path(), &["init", "--vault", vault.to_str().unwrap()])
        .env("SYMVAULT_PASSPHRASE", "correct horse battery staple")
        .env("SYMVAULT_ALLOW_ENV_PASSPHRASE", "1")
        .stdin(Stdio::null())
        .output()
        .expect("init");
    assert_eq!(
        init.status.code(),
        Some(0),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let before = tree(home.path());
    let out = command(home.path(), &["setup"])
        .env("SYMVAULT_VAULT", &vault)
        .stdin(Stdio::null())
        .output()
        .expect("run");
    assert_guard(&out, "initialized vault");
    assert_eq!(tree(home.path()), before, "guard must not write anything");
}

#[test]
fn help_flag_bypasses_the_guard_and_lists_both_flags() {
    let home = sandbox();
    let out = command(home.path(), &["setup", "--help"])
        .stdin(Stdio::null())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("--keep-on-error"), "{text}");
    assert!(text.contains("--no-resume"), "{text}");
}

fn tree(root: &Path) -> Vec<(String, u64)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, u64)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir).expect("dir").flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).expect("meta");
            let rel = path.strip_prefix(root).unwrap().display().to_string();
            out.push((rel, if meta.is_file() { meta.len() } else { 0 }));
            if meta.is_dir() {
                walk(&path, root, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}
