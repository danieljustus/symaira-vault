#[path = "../src/path_migration_commands.rs"]
mod path_migration_commands;

use std::{
    env, fs,
    io::Cursor,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::TempDir;

fn run_go(binary: &Path, home: &Path, xdg: (&Path, &Path, &Path)) -> Output {
    Command::new(binary)
        .args(["migrate", "paths"])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", xdg.0)
        .env("XDG_DATA_HOME", xdg.1)
        .env("XDG_CACHE_HOME", xdg.2)
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .output()
        .expect("run Go migration preview")
}

fn rust_preview(home: &Path, xdg: (&Path, &Path, &Path)) -> Result<Vec<u8>, String> {
    let mut output = Cursor::new(Vec::new());
    path_migration_commands::preview(
        home,
        Some(xdg.0),
        Some(xdg.1),
        Some(xdg.2),
        false,
        &mut output,
    )?;
    Ok(output.into_inner())
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

#[test]
fn migration_preview_matches_go_for_empty_marker_and_complete_tree() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);

    let (_empty_root, empty_home, empty_xdg) = fixture("empty");
    let go_empty = run_go(
        &go_binary,
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
    assert_eq!(
        rust_preview(&empty_home, (&empty_xdg.0, &empty_xdg.1, &empty_xdg.2)).unwrap(),
        go_empty.stdout,
        "empty preview stdout"
    );

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

    let go_tree = run_go(
        &go_binary,
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
    assert_eq!(
        rust_preview(&tree_home, (&tree_xdg.0, &tree_xdg.1, &tree_xdg.2)).unwrap(),
        go_tree.stdout,
        "complete tree preview stdout"
    );
    assert!(
        tree_home.join(".symvault/config.yaml").is_file(),
        "preview must not remove legacy files"
    );

    fs::write(legacy.join(".migrated"), b"migration complete\n").expect("marker");
    let go_marker = run_go(
        &go_binary,
        &tree_home,
        (&tree_xdg.0, &tree_xdg.1, &tree_xdg.2),
    );
    assert!(go_marker.status.success(), "Go marker preview failed");
    assert_eq!(
        rust_preview(&tree_home, (&tree_xdg.0, &tree_xdg.1, &tree_xdg.2)).unwrap(),
        go_marker.stdout,
        "marker preview stdout"
    );
}
