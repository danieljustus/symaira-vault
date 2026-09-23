use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, Output},
};

#[cfg(target_os = "macos")]
use std::fs;

use tempfile::TempDir;

fn run(binary: &Path, home: &Path) -> Output {
    Command::new(binary)
        .args(["intake", "watch", "disable"])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .env_remove("SYMVAULT_VAULT")
        .env_remove("SYMVAULT_PASSPHRASE")
        .output()
        .expect("run intake watch disable")
}

#[test]
fn watch_disable_matches_go_in_throwaway_home() {
    let Some(go_binary) = env::var_os("SYMVAULT_GO_BINARY") else {
        eprintln!("skipping Go differential: SYMVAULT_GO_BINARY is not set");
        return;
    };
    let go_binary = PathBuf::from(go_binary);
    let rust_binary = Path::new(env!("CARGO_BIN_EXE_symvault"));
    let home = TempDir::new().expect("temporary home");
    let plist = home
        .path()
        .join("Library/LaunchAgents/com.symaira.vault-intake.plist");

    let go = run(&go_binary, home.path());
    let rust = run(rust_binary, home.path());
    assert_eq!(rust.status.code(), go.status.code());
    assert_eq!(rust.stdout, go.stdout);
    assert_eq!(rust.stderr, go.stderr);
    assert!(!plist.exists(), "disable must not create a LaunchAgent");

    #[cfg(target_os = "macos")]
    {
        fs::create_dir_all(plist.parent().unwrap()).expect("create LaunchAgents");
        fs::write(&plist, b"fixture plist").expect("seed LaunchAgent");
        let go = run(&go_binary, home.path());
        assert!(!plist.exists(), "Go oracle did not remove its LaunchAgent");

        fs::write(&plist, b"fixture plist").expect("reseed LaunchAgent");
        let rust = run(rust_binary, home.path());
        assert_eq!(rust.status.code(), go.status.code());
        assert_eq!(rust.stdout, go.stdout);
        assert_eq!(rust.stderr, go.stderr);
        assert!(
            !plist.exists(),
            "Rust command did not remove its LaunchAgent"
        );
    }
}
