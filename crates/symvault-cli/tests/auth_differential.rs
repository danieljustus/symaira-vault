#![deny(unsafe_code)]

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            env::temp_dir().join(format!("symvault-auth-diff-{label}-{pid}-{suffix}-{count}"));
        fs::create_dir_all(&path).expect("temporary directory");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(binary: &Path, vault: &Path, home: &Path, args: &[&str], input: Option<&[u8]>) -> Output {
    let mut cmd = Command::new(binary);
    cmd.args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("SYMVAULT_VAULT", vault)
        .env("CI", "1")
        .env("SYMVAULT_TEST_KEYRING", "memory")
        .env("NO_COLOR", "1");
    if let Some(data) = input {
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn command");
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data).expect("write to stdin");
        }
        child.wait_with_output().expect("wait for output")
    } else {
        cmd.output().expect("run command")
    }
}

fn assert_same(go: &Output, rust: &Output, case: &str) {
    assert_eq!(
        rust.status.code(),
        go.status.code(),
        "{case}: exit code differs\ngo stderr: {:?}\nrust stderr: {:?}",
        String::from_utf8_lossy(&go.stderr),
        String::from_utf8_lossy(&rust.stderr)
    );
    assert_eq!(
        rust.stdout,
        go.stdout,
        "{case}: stdout differs\ngo: {:?}\nrust: {:?}",
        String::from_utf8_lossy(&go.stdout),
        String::from_utf8_lossy(&rust.stdout)
    );
    assert_eq!(
        rust.stderr,
        go.stderr,
        "{case}: stderr differs\ngo: {:?}\nrust: {:?}",
        String::from_utf8_lossy(&go.stderr),
        String::from_utf8_lossy(&rust.stderr)
    );
}

#[test]
fn auth_set_matches_go_contract() {
    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go = PathBuf::from(go);
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let home = TempDir::new("home");
    let uninit_vault = home.0.join("uninit");

    // Case 1: Invalid auth method
    let res_go = run(
        &go,
        &uninit_vault,
        &home.0,
        &["auth", "set", "invalid-method"],
        None,
    );
    let res_rust = run(
        &rust,
        &uninit_vault,
        &home.0,
        &["auth", "set", "invalid-method"],
        None,
    );
    assert_same(&res_go, &res_rust, "auth set invalid method");

    // Case 2: Uninitialized vault with valid method
    let res_go = run(
        &go,
        &uninit_vault,
        &home.0,
        &["auth", "set", "passphrase"],
        None,
    );
    let res_rust = run(
        &rust,
        &uninit_vault,
        &home.0,
        &["auth", "set", "passphrase"],
        None,
    );
    assert_same(&res_go, &res_rust, "auth set uninitialized");

    // Case 3: Initialized vault happy path
    let init_go = run(
        &go,
        &uninit_vault,
        &home.0,
        &["init"],
        Some(b"passphrase-for-test\npassphrase-for-test\n"),
    );
    assert!(init_go.status.success(), "init failed");

    let res_go = run(
        &go,
        &uninit_vault,
        &home.0,
        &["auth", "set", "passphrase"],
        None,
    );
    let res_rust = run(
        &rust,
        &uninit_vault,
        &home.0,
        &["auth", "set", "passphrase"],
        None,
    );
    assert_same(&res_go, &res_rust, "auth set passphrase happy path");

    // Case 4: Quiet mode
    let res_go = run(
        &go,
        &uninit_vault,
        &home.0,
        &["--quiet", "auth", "set", "passphrase"],
        None,
    );
    let res_rust = run(
        &rust,
        &uninit_vault,
        &home.0,
        &["--quiet", "auth", "set", "passphrase"],
        None,
    );
    assert_same(&res_go, &res_rust, "auth set quiet");
}

#[test]
fn auth_rotate_passphrase_matches_go_contract() {
    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go = PathBuf::from(go);
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let home = TempDir::new("home");
    let uninit_vault = home.0.join("uninit");

    // Case 1: Uninitialized vault
    let res_go = run(
        &go,
        &uninit_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        None,
    );
    let res_rust = run(
        &rust,
        &uninit_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        None,
    );
    assert_same(&res_go, &res_rust, "auth rotate-passphrase uninitialized");

    // Initialize vault with Go
    let init_go = run(
        &go,
        &uninit_vault,
        &home.0,
        &["init"],
        Some(b"original-passphrase-123\noriginal-passphrase-123\n"),
    );
    assert!(init_go.status.success(), "init failed");

    // Case 2: Wrong current passphrase
    let input = b"wrong-passphrase\n";
    let res_go = run(
        &go,
        &uninit_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    let res_rust = run(
        &rust,
        &uninit_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    assert_same(&res_go, &res_rust, "auth rotate-passphrase wrong current");

    // Case 3: Short new passphrase
    let input = b"original-passphrase-123\nshort\n";
    let res_go = run(
        &go,
        &uninit_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    let res_rust = run(
        &rust,
        &uninit_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    assert_same(&res_go, &res_rust, "auth rotate-passphrase short new");

    // Case 4: Mismatched new passphrase
    let input = b"original-passphrase-123\nnew-passphrase-long-1\nnew-passphrase-long-2\n";
    let res_go = run(
        &go,
        &uninit_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    let res_rust = run(
        &rust,
        &uninit_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    assert_same(&res_go, &res_rust, "auth rotate-passphrase mismatch");

    // Case 5: Same new passphrase as current
    let input = b"original-passphrase-123\noriginal-passphrase-123\noriginal-passphrase-123\n";
    let res_go = run(
        &go,
        &uninit_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    let res_rust = run(
        &rust,
        &uninit_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    assert_same(&res_go, &res_rust, "auth rotate-passphrase same passphrase");

    // Case 6: Confirmation canceled
    let input = b"original-passphrase-123\nnew-rotated-passphrase-1\nnew-rotated-passphrase-1\nn\n";
    let res_go = run(
        &go,
        &uninit_vault,
        &home.0,
        &["auth", "rotate-passphrase"],
        Some(input),
    );
    let res_rust = run(
        &rust,
        &uninit_vault,
        &home.0,
        &["auth", "rotate-passphrase"],
        Some(input),
    );
    assert_same(&res_go, &res_rust, "auth rotate-passphrase canceled");

    // Case 7: Successful rotation
    let input = b"original-passphrase-123\nnew-rotated-passphrase-1\nnew-rotated-passphrase-1\n";
    let res_go = run(
        &go,
        &uninit_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    let res_rust = run(
        &rust,
        &uninit_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    assert_same(&res_go, &res_rust, "auth rotate-passphrase success");
}
