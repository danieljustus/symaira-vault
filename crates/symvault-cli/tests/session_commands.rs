#![deny(unsafe_code)]

#[path = "../src/session_commands.rs"]
mod session_commands;

use std::{sync::Arc, time::Duration};

use symvault_core::{
    config::AuthMethod,
    session::{MemoryKeyring, SessionManager},
};

fn manager() -> SessionManager {
    SessionManager::with_system_clock(Arc::new(MemoryKeyring::new()))
}

#[test]
fn status_matches_go_text_and_json_shapes() {
    let status = session_commands::auth_status(
        std::path::Path::new("/fixture/vault"),
        AuthMethod::Passphrase,
        session_commands::CacheStatus {
            backend: "os-keyring".into(),
            persistent: true,
            message: "fixture cache".into(),
        },
        false,
    )
    .unwrap();
    assert_eq!(
        session_commands::render_status(&status, "text", false, false).unwrap(),
        "Vault: /fixture/vault\nAuth method: passphrase\nTouch ID available: false\nSession cache: os-keyring (persistent: true)\nKeyring health: available\n"
    );
    let json = session_commands::render_status(&status, "text", true, false).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["touchIDAvailable"], false);
    assert_eq!(value["cache"]["message"], "fixture cache");
}

#[test]
fn status_quiet_suppresses_both_formats() {
    let status = session_commands::auth_status(
        std::path::Path::new("/fixture/vault"),
        AuthMethod::Touchid,
        session_commands::CacheStatus {
            backend: "memory".into(),
            persistent: false,
            message: "memory-only".into(),
        },
        true,
    )
    .unwrap();
    assert_eq!(
        session_commands::render_status(&status, "json", false, true).unwrap(),
        ""
    );
}

#[test]
fn lock_revokes_all_entries_and_check_tracks_identity() {
    let manager = manager();
    let vault = std::path::Path::new("/fixture/vault");
    manager
        .save_passphrase(
            vault.to_str().unwrap(),
            b"fixture",
            Duration::from_secs(60),
            Duration::from_secs(600),
        )
        .unwrap();
    assert!(session_commands::session_active(&manager, vault));
    assert!(session_commands::check(&manager, vault).is_ok());

    assert_eq!(
        session_commands::lock(&manager, vault, false).unwrap(),
        "Vault locked\n"
    );
    assert!(!session_commands::session_active(&manager, vault));
    assert_eq!(
        session_commands::check(&manager, vault).unwrap_err(),
        "no active session"
    );

    manager
        .save_identity(
            vault.to_str().unwrap(),
            b"identity",
            Duration::from_secs(60),
            Duration::from_secs(600),
        )
        .unwrap();
    assert!(session_commands::session_active(&manager, vault));
    session_commands::lock(&manager, vault, true).unwrap();
    assert!(!session_commands::session_active(&manager, vault));
}

#[test]
fn malformed_vault_path_is_rejected_before_keyring_access() {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(vec![0xff]));
        let manager = manager();
        let error = session_commands::lock(&manager, &path, false).unwrap_err();
        assert_eq!(error, "vault path is not valid UTF-8");
    }
}
