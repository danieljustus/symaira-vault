use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::TempDir;

fn run(binary: &Path, args: &[&str], home: &Path, xdg: (&Path, &Path, &Path)) -> Output {
    Command::new(binary)
        .args(args)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", xdg.0)
        .env("XDG_DATA_HOME", xdg.1)
        .env("XDG_CACHE_HOME", xdg.2)
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run Go migration preview")
}

fn fixture(name: &str) -> (TempDir, PathBuf, (PathBuf, PathBuf, PathBuf)) {
    let root = tempfile::tempdir().expect("fixture root");
    let home = root.path().join(name);
    let config = root.path().join("xdg-config");
    let data = root.path().join("xdg-data");
    let cache = root.path().join("xdg-cache");
    fs::create_dir_all(&home).expect("home");
    (root, home, (config, data, cache))
}

fn assert_same(go: &Output, rust: &Output, case: &str) {
    assert_eq!(rust.status, go.status, "{case}: status differs");
    assert_eq!(rust.stdout, go.stdout, "{case}: stdout differs");
    assert_eq!(rust.stderr, go.stderr, "{case}: stderr differs");
}

#[test]
fn migration_preview_matches_go_for_empty_marker_and_complete_tree() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));

    let (_empty_root, empty_home, empty_xdg) = fixture("empty");
    let args = ["migrate", "paths"];
    let go_empty = run(
        &go_binary,
        &args,
        &empty_home,
        (&empty_xdg.0, &empty_xdg.1, &empty_xdg.2),
    );
    let rust_empty = run(
        &rust_binary,
        &args,
        &empty_home,
        (&empty_xdg.0, &empty_xdg.1, &empty_xdg.2),
    );
    assert!(
        go_empty.status.success(),
        "Go empty preview failed: {:?}\nstdout={:?}\nstderr={:?}",
        go_empty.status,
        go_empty.stdout,
        go_empty.stderr
    );
    assert_same(&go_empty, &rust_empty, "empty preview");

    let quiet_args = ["--quiet", "migrate", "xdg"];
    let go_quiet = run(
        &go_binary,
        &quiet_args,
        &empty_home,
        (&empty_xdg.0, &empty_xdg.1, &empty_xdg.2),
    );
    let rust_quiet = run(
        &rust_binary,
        &quiet_args,
        &empty_home,
        (&empty_xdg.0, &empty_xdg.1, &empty_xdg.2),
    );
    assert_same(&go_quiet, &rust_quiet, "quiet xdg alias");

    let (_tree_root, tree_home, tree_xdg) = fixture("tree");
    let legacy = tree_home.join(".symvault");
    fs::create_dir_all(legacy.join("vault/nested")).expect("legacy vault");
    fs::create_dir_all(legacy.join("audit")).expect("legacy audit");
    fs::create_dir_all(legacy.join("pairing")).expect("legacy pairing");
    fs::write(legacy.join("config.yaml"), b"vaultDir: fixture\n").expect("config");
    fs::write(legacy.join("vault/identity.age"), b"identity").expect("identity");
    fs::write(legacy.join("vault/nested/entry.age"), b"entry-data").expect("entry");
    fs::write(legacy.join("audit/log.jsonl"), b"audit\n").expect("audit");
    fs::write(legacy.join("devices.json"), b"[]\n").expect("devices");
    fs::write(legacy.join("pairing/invite.json"), b"invite").expect("pairing");
    fs::write(legacy.join("update-cache.json"), b"{}\n").expect("cache");

    let go_tree = run(
        &go_binary,
        &args,
        &tree_home,
        (&tree_xdg.0, &tree_xdg.1, &tree_xdg.2),
    );
    let rust_tree = run(
        &rust_binary,
        &args,
        &tree_home,
        (&tree_xdg.0, &tree_xdg.1, &tree_xdg.2),
    );
    assert!(
        go_tree.status.success(),
        "Go tree preview failed: {:?}\nstdout={:?}\nstderr={:?}",
        go_tree.status,
        go_tree.stdout,
        go_tree.stderr
    );
    assert_same(&go_tree, &rust_tree, "complete tree preview");
    assert!(
        tree_home.join(".symvault/config.yaml").is_file(),
        "preview must not remove legacy files"
    );

    fs::write(legacy.join(".migrated"), b"migration complete\n").expect("marker");
    let go_marker = run(
        &go_binary,
        &args,
        &tree_home,
        (&tree_xdg.0, &tree_xdg.1, &tree_xdg.2),
    );
    let rust_marker = run(
        &rust_binary,
        &args,
        &tree_home,
        (&tree_xdg.0, &tree_xdg.1, &tree_xdg.2),
    );
    assert!(go_marker.status.success(), "Go marker preview failed");
    assert_same(&go_marker, &rust_marker, "marker preview");
}

#[cfg(unix)]
#[test]
fn migration_preview_matches_go_for_legacy_symlink_errors() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = PathBuf::from(env!("CARGO_BIN_EXE_symvault"));
    let (_root, home, xdg) = fixture("symlink");
    let target = home.join("real-legacy");
    fs::create_dir_all(&target).expect("target legacy directory");
    std::os::unix::fs::symlink(&target, home.join(".symvault")).expect("legacy symlink");

    for args in [
        &["migrate", "paths"][..],
        &["migrate", "xdg"][..],
        &["--quiet", "migrate", "paths"][..],
    ] {
        let go = run(&go_binary, &args, &home, (&xdg.0, &xdg.1, &xdg.2));
        let rust = run(&rust_binary, &args, &home, (&xdg.0, &xdg.1, &xdg.2));
        assert_same(&go, &rust, &format!("legacy symlink {args:?}"));
        assert!(!go.status.success(), "Go must reject legacy symlink");
    }

    let (_nested_root, nested_home, nested_xdg) = fixture("nested-symlink");
    let nested_vault = nested_home.join(".symvault/vault");
    fs::create_dir_all(&nested_vault).expect("nested vault directory");
    let nested_target = nested_home.join("nested-target");
    fs::create_dir_all(&nested_target).expect("nested symlink target");
    std::os::unix::fs::symlink(&nested_target, nested_vault.join("nested-link"))
        .expect("nested symlink");
    for args in [
        &["migrate", "paths"][..],
        &["--quiet", "migrate", "xdg"][..],
    ] {
        let go = run(
            &go_binary,
            &args,
            &nested_home,
            (&nested_xdg.0, &nested_xdg.1, &nested_xdg.2),
        );
        let rust = run(
            &rust_binary,
            &args,
            &nested_home,
            (&nested_xdg.0, &nested_xdg.1, &nested_xdg.2),
        );
        assert_same(&go, &rust, &format!("nested legacy symlink {args:?}"));
        assert!(!go.status.success(), "Go must reject nested legacy symlink");
        assert!(
            String::from_utf8_lossy(&go.stderr).contains(nested_vault.to_string_lossy().as_ref()),
            "Go nested symlink diagnostic should contain the absolute walked path: {:?}",
            go.stderr
        );
    }
}
