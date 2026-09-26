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
    if matches!(args.first(), Some(&"init" | &"add"))
        && let Some(data) = input
    {
        let pass = String::from_utf8_lossy(data)
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned();
        cmd.env("SYMVAULT_PASSPHRASE", pass);
    }
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
    let rust_vault = home.0.join("rust-vault");
    copy_dir_all(&uninit_vault, &rust_vault);
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
        &rust_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    assert_same(&res_go, &res_rust, "auth rotate-passphrase success");
}

#[test]
fn auth_rotate_legacy_migration_matches_go_on_normal_root() {
    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go = PathBuf::from(go);
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let home = TempDir::new("legacy-normal");
    let (go_vault, rust_vault) = legacy_vault_pair(&go, &home.0);
    let input = b"original-passphrase-123\nnew-passphrase-1234\nnew-passphrase-1234\n";

    let result_go = run(
        &go,
        &go_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    let result_rust = run(
        &rust,
        &rust_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    assert_eq!(
        result_go.status.code(),
        Some(0),
        "Go rotation: {:?}",
        result_go.stderr
    );
    assert_eq!(result_rust.status.code(), result_go.status.code());
    assert_eq!(result_rust.stdout, result_go.stdout);
    assert_eq!(result_rust.stderr, result_go.stderr);
    for vault in [&go_vault, &rust_vault] {
        assert!(!vault.join("legacy.age").exists());
        assert!(vault.join(".symvault-migrated").is_file());
        assert!(fs::read_dir(vault.join("entries")).unwrap().any(|entry| {
            entry
                .unwrap()
                .path()
                .extension()
                .is_some_and(|extension| extension == "age")
        }));
    }
}

#[cfg(unix)]
#[test]
fn auth_rotate_rejects_user_owned_ancestor_symlink_before_new_passphrase_validation() {
    use std::os::unix::fs::symlink;

    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go = PathBuf::from(go);
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let home = TempDir::new("legacy-user-symlink");
    let (go_vault, rust_vault) = legacy_vault_pair(&go, &home.0);
    let alias = home.0.join("user-owned-alias");
    symlink(&home.0, &alias).expect("create user-owned ancestor symlink");
    let alias_go_vault = alias.join("go-vault");
    let alias_rust_vault = alias.join("rust-vault");
    let before_go = tree_snapshot(&go_vault);
    let input = b"original-passphrase-123\nshort\n";

    let result_go = run(
        &go,
        &alias_go_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    assert_eq!(
        tree_snapshot(&go_vault),
        before_go,
        "Go changed rejected vault"
    );
    let before_rust = tree_snapshot(&rust_vault);
    let result_rust = run(
        &rust,
        &alias_rust_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    assert_eq!(
        tree_snapshot(&rust_vault),
        before_rust,
        "Rust changed rejected vault"
    );

    for result in [&result_go, &result_rust] {
        assert_eq!(result.status.code(), Some(1));
        assert!(result.stdout.is_empty());
        let error = String::from_utf8_lossy(&result.stderr).to_lowercase();
        assert!(error.contains("current passphrase is incorrect"), "{error}");
        assert!(
            error.contains("symlink")
                || error.contains("symbolic link")
                || error.contains("too many levels"),
            "{error}"
        );
        assert!(
            !error.contains("passphrase must be at least 12 characters"),
            "{error}"
        );
    }
    assert_eq!(result_go.stdout, result_rust.stdout);
}

#[cfg(target_os = "macos")]
#[test]
fn auth_rotate_accepts_root_owned_macos_alias_and_migrates_legacy_entry() {
    use std::os::unix::fs::MetadataExt;

    let Some(go) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go = PathBuf::from(go);
    let rust = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let home = TempDir::new("legacy-trusted-alias");
    let (go_real, rust_real) = legacy_vault_pair(&go, &home.0);
    let go_vault = macos_var_alias(&go_real).expect("/var alias for Go fixture");
    let rust_vault = macos_var_alias(&rust_real).expect("/var alias for Rust fixture");
    assert!(
        go_vault
            .ancestors()
            .filter_map(|path| fs::symlink_metadata(path).ok())
            .any(|metadata| metadata.file_type().is_symlink() && metadata.uid() == 0),
        "fixture must traverse a root-owned system alias"
    );
    let input = b"original-passphrase-123\nnew-passphrase-1234\nnew-passphrase-1234\n";
    let result_go = run(
        &go,
        &go_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    let result_rust = run(
        &rust,
        &rust_vault,
        &home.0,
        &["auth", "rotate-passphrase", "-y"],
        Some(input),
    );
    assert_eq!(
        result_go.status.code(),
        Some(0),
        "Go rotation: {:?}",
        result_go.stderr
    );
    assert_eq!(result_rust.status.code(), result_go.status.code());
    assert_eq!(result_rust.stdout, result_go.stdout);
    assert_eq!(result_rust.stderr, result_go.stderr);
    for vault in [&go_real, &rust_real] {
        assert!(vault.join(".symvault-migrated").is_file());
        assert!(fs::read_dir(vault.join("entries")).unwrap().any(|entry| {
            entry
                .unwrap()
                .path()
                .extension()
                .is_some_and(|extension| extension == "age")
        }));
    }
}

fn legacy_vault_pair(go: &Path, home: &Path) -> (PathBuf, PathBuf) {
    let seed = home.join("seed-vault");
    let init = run(
        go,
        &seed,
        home,
        &["init"],
        Some(b"original-passphrase-123\noriginal-passphrase-123\n"),
    );
    assert_eq!(
        init.status.code(),
        Some(0),
        "Go vault initialization: {:?}",
        init.stderr
    );
    let add = run(
        go,
        &seed,
        home,
        &["add", "legacy", "--value", "legacy-secret"],
        Some(b"original-passphrase-123\n"),
    );
    assert_eq!(
        add.status.code(),
        Some(0),
        "Go entry creation: {:?}",
        add.stderr
    );
    fs::rename(seed.join("entries/legacy.age"), seed.join("legacy.age")).unwrap();
    fs::remove_file(seed.join(".symvault-migrated")).unwrap();
    let go_vault = home.join("go-vault");
    let rust_vault = home.join("rust-vault");
    copy_dir_all(&seed, &go_vault);
    copy_dir_all(&seed, &rust_vault);
    (go_vault, rust_vault)
}

#[cfg(target_os = "macos")]
fn macos_var_alias(path: &Path) -> Option<PathBuf> {
    let canonical = fs::canonicalize(path).ok()?;
    Some(Path::new("/var").join(canonical.strip_prefix("/private/var").ok()?))
}

#[cfg(unix)]
fn tree_snapshot(root: &Path) -> Vec<(PathBuf, bool, Vec<u8>)> {
    let mut pending = vec![root.to_path_buf()];
    let mut result = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let metadata = entry.file_type().unwrap();
            if metadata.is_dir() {
                result.push((relative, false, Vec::new()));
                pending.push(path);
            } else if metadata.is_file() {
                result.push((relative, true, fs::read(path).unwrap()));
            } else {
                panic!("unexpected fixture item: {}", path.display());
            }
        }
    }
    result.sort_by(|left, right| left.0.cmp(&right.0));
    result
}

fn copy_dir_all(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create dst dir");
    for entry in fs::read_dir(src).expect("read src dir") {
        let entry = entry.expect("dir entry");
        let ty = entry.file_type().expect("file type");
        let dest_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dest_path);
        } else {
            fs::copy(entry.path(), &dest_path).expect("copy file");
        }
    }
}
