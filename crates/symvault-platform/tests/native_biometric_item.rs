#![cfg(target_os = "macos")]
#![deny(unsafe_code)]

//! SESSION-003 (non-interactive half): the Security-framework adapter against
//! disposable file keychains. Nothing here touches the operator's keychains:
//! every call is aimed at keychains created in a private temp directory, the
//! user's keychain search list is asserted unchanged afterwards, and keychain
//! UI is disabled so a would-be prompt fails the test instead of hanging it.
//!
//! The independent writer/inspector is Apple's own `security` tool, used only
//! to stand in for Go's cgo `SecItemAdd` and to read item *attributes* (reading
//! item data would need an access-control prompt). It is a test oracle, not a
//! product dependency.

use std::{
    ffi::OsString,
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
    process::Command,
};

use security_framework::os::macos::keychain::{CreateOptions, SecKeychain};
use symvault_core::keychain_status::{
    BIOMETRIC_ACCOUNT, BiometricItemStore, ERR_SEC_ITEM_NOT_FOUND, KeychainErrorKind,
    biometric_service_name, keychain_status_error,
};
use symvault_platform::SecurityBiometricItems;

const VAULT: &str = "/fixture/vault";

fn security(args: &[OsString]) -> std::process::Output {
    Command::new("/usr/bin/security")
        .args(args)
        .output()
        .expect("run /usr/bin/security")
}

fn user_search_list() -> String {
    let output = security(&["list-keychains".into(), "-d".into(), "user".into()]);
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn disposable_keychain(dir: &Path, name: &str) -> (SecKeychain, PathBuf) {
    // A throwaway passphrase for a keychain that lives for one test run; it
    // protects nothing and is derived from the process id and name.
    let password = format!("disposable-{}-{name}", std::process::id());
    let path = dir.join(format!("{name}.keychain-db"));
    let keychain = CreateOptions::new()
        .password(&password)
        .create(&path)
        .expect("create disposable keychain");
    (keychain, path)
}

/// Writes a Go-layout item the way Go's cgo does: class generic password,
/// service `symvault-biometric:<vault>`, account `passphrase`, raw bytes.
/// `-A` lets this process read it without an access prompt.
fn write_like_go(path: &Path, vault: &str, passphrase: &[u8]) {
    let output = security(&[
        "add-generic-password".into(),
        "-A".into(),
        "-s".into(),
        biometric_service_name(vault).into(),
        "-a".into(),
        BIOMETRIC_ACCOUNT.into(),
        "-w".into(),
        OsString::from_vec(passphrase.to_vec()),
        path.into(),
    ]);
    assert!(
        output.status.success(),
        "stand-in Go writer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Attribute listing of the item(s) in one keychain (no data access).
fn dump(path: &Path) -> String {
    let output = security(&["dump-keychain".into(), path.into()]);
    assert!(output.status.success(), "dump-keychain failed");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn item_count(path: &Path, vault: &str) -> usize {
    let needle = format!("\"svce\"<blob>=\"{}\"", biometric_service_name(vault));
    dump(path).matches(&needle).count()
}

const PASSPHRASES: [&[u8]; 6] = [
    b"plain",
    b" leading and trailing \n",
    b"go-keyring-base64:cGFzcw==",
    b"go-keyring-encoded:7061",
    "pässwörd-üñí".as_bytes(),
    b"\xff\xfe\x80",
];

#[test]
fn security_framework_items_match_go_layout_on_disposable_keychains() {
    let before = user_search_list();
    let dir = tempfile::tempdir().expect("private temp dir");
    let _no_ui = SecKeychain::disable_user_interaction().expect("disable keychain UI");
    let (kc, kc_path) = disposable_keychain(dir.path(), "primary");
    let (other, other_path) = disposable_keychain(dir.path(), "other");
    let items = SecurityBiometricItems::scoped(kc.clone(), vec![kc.clone()]);

    // A: missing item is "not found" without any error, and delete is idempotent.
    assert!(!items.exists(VAULT).unwrap());
    let missing = items.load(VAULT).unwrap_err();
    assert_eq!(missing.kind(), KeychainErrorKind::ItemNotFound);
    assert_eq!(missing.status(), ERR_SEC_ITEM_NOT_FOUND);
    assert_eq!(
        missing.to_string(),
        keychain_status_error(ERR_SEC_ITEM_NOT_FOUND)
            .unwrap()
            .to_string()
    );
    items.delete(VAULT).unwrap();

    // B: Rust-written items hold the raw bytes at Go's address; saving again
    // replaces rather than appending.
    for passphrase in PASSPHRASES {
        items.save(VAULT, passphrase).unwrap();
        assert!(items.exists(VAULT).unwrap());
        assert_eq!(&**items.load(VAULT).unwrap(), passphrase, "{passphrase:?}");
        assert_eq!(item_count(&kc_path, VAULT), 1, "save must replace");
    }
    let listing = dump(&kc_path);
    assert!(listing.contains("class: \"genp\""), "{listing}");
    assert!(
        listing.contains(&format!(
            "\"svce\"<blob>=\"{}\"",
            biometric_service_name(VAULT)
        )),
        "{listing}"
    );
    assert!(
        listing.contains(&format!("\"acct\"<blob>=\"{BIOMETRIC_ACCOUNT}\"")),
        "{listing}"
    );

    // C: removing works, and removing again is still success (Go: not found
    // is success on delete).
    items.delete(VAULT).unwrap();
    assert!(!items.exists(VAULT).unwrap());
    assert_eq!(item_count(&kc_path, VAULT), 0);
    items.delete(VAULT).unwrap();

    // D: an item written by the Go layout (stand-in writer) is read back
    // byte for byte -- including the values the old go-keyring-wrapped path
    // would have trimmed or decoded.
    for passphrase in PASSPHRASES {
        write_like_go(&kc_path, VAULT, passphrase);
        assert!(items.exists(VAULT).unwrap());
        assert_eq!(&**items.load(VAULT).unwrap(), passphrase, "{passphrase:?}");
        items.delete(VAULT).unwrap();
    }

    // E: a C-string passphrase is cut at its first NUL on both save and load.
    items.save(VAULT, b"ab\0cd").unwrap();
    assert_eq!(&**items.load(VAULT).unwrap(), b"ab");
    // The stored bytes, read by the framework's own reader (which does not
    // truncate), not by `load`: removing the NUL cut-off on the save path would
    // leave "ab\0cd" in the keychain, which Go's `C.GoString` reader would then
    // return as "ab" but any other reader would not.
    let (stored, _) = kc
        .find_generic_password(&biometric_service_name(VAULT), BIOMETRIC_ACCOUNT)
        .expect("read stored item with the Security.framework reader");
    assert_eq!(&*stored, b"ab", "save must cut the value at the first NUL");
    items.delete(VAULT).unwrap();

    // F: duplicate fallback. The lookup scope cannot see the item (search list
    // is a different, empty keychain), so the delete misses, the add reports a
    // duplicate, and the update must succeed in the add's keychain.
    write_like_go(&kc_path, VAULT, b"first");
    let blind = SecurityBiometricItems::scoped(kc.clone(), vec![other.clone()]);
    assert!(
        !blind.exists(VAULT).unwrap(),
        "scope must really exclude the item"
    );
    blind.save(VAULT, b"second").unwrap();
    assert_eq!(
        item_count(&kc_path, VAULT),
        1,
        "update in place, no second item"
    );
    assert_eq!(item_count(&other_path, VAULT), 0);
    assert_eq!(&**items.load(VAULT).unwrap(), b"second");
    items.delete(VAULT).unwrap();

    // G: items are per vault directory.
    items.save("/vault/a", b"a").unwrap();
    items.save("/vault/b", b"b").unwrap();
    assert_eq!(&**items.load("/vault/a").unwrap(), b"a");
    assert_eq!(&**items.load("/vault/b").unwrap(), b"b");
    items.delete("/vault/a").unwrap();
    assert!(!items.exists("/vault/a").unwrap());
    assert!(items.exists("/vault/b").unwrap());

    drop(items);
    drop(blind);
    drop(kc);
    drop(other);
    dir.close().expect("remove disposable keychains");
    assert_eq!(
        user_search_list(),
        before,
        "the operator's keychain search list changed"
    );
}
