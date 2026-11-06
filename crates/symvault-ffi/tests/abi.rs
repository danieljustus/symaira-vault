//! Boundary behavior of the C ABI that the Go fixture cannot express:
//! argument misuse, panic containment, buffer ownership and header coverage.

#![allow(unsafe_code)]

use std::ptr;

use symvault_ffi::abi::{self, SvBuf};

fn empty() -> SvBuf {
    SvBuf {
        ptr: ptr::null_mut(),
        len: 0,
    }
}

fn text(buf: &SvBuf) -> String {
    if buf.ptr.is_null() {
        return String::new();
    }
    // SAFETY: the library returned `len` initialized bytes at `ptr`.
    let bytes = unsafe { std::slice::from_raw_parts(buf.ptr, buf.len) };
    String::from_utf8(bytes.to_vec()).expect("UTF-8")
}

#[test]
fn abi_version_is_stable() {
    assert_eq!(abi::symvault_ffi_abi_version(), 1);
}

#[test]
fn the_host_chooses_the_backup_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let chosen = dir.path().join("host-backups");
    let text_of = chosen.to_str().expect("utf-8").as_bytes();
    let mut err = empty();
    // SAFETY: the path bytes and `err` are valid for the call.
    let status = unsafe { abi::symvault_set_backup_dir(text_of.as_ptr(), text_of.len(), &mut err) };
    assert_eq!(status, 0);
    assert!(err.ptr.is_null());
    assert_eq!(
        symvault_sync::data_safety::backup_dir().expect("dir"),
        chosen
    );
    // An empty path restores the environment-derived default.
    // SAFETY: a null pointer with length 0 is the documented empty input.
    let status = unsafe { abi::symvault_set_backup_dir(ptr::null(), 0, &mut err) };
    assert_eq!(status, 0);
    assert_ne!(
        symvault_sync::data_safety::backup_dir().ok(),
        Some(chosen),
        "the empty path must clear the host's choice"
    );
}

#[test]
fn a_panic_is_contained_and_reported() {
    let mut err = empty();
    // SAFETY: `err` is writable.
    let status = unsafe { abi::symvault_ffi_selftest_panic(&mut err) };
    assert_eq!(status, 2);
    assert_eq!(
        text(&err),
        "internal error: panic contained at the FFI boundary"
    );
    // SAFETY: `err` came from the library.
    unsafe { abi::symvault_buf_free(err) };
}

#[test]
fn null_pointer_with_a_length_is_rejected_not_dereferenced() {
    let (mut out, mut err) = (empty(), empty());
    // SAFETY: out-parameters are writable; the null input is the point.
    let status = unsafe { abi::symvault_identity_public_key(ptr::null(), 5, &mut out, &mut err) };
    assert_eq!(status, 3);
    assert!(out.ptr.is_null());
    assert_eq!(text(&err), "argument identity is null");
    // SAFETY: `err` came from the library.
    unsafe { abi::symvault_buf_free(err) };
}

#[test]
fn invalid_utf8_text_is_rejected() {
    let bad = [0xffu8, 0xfe];
    let (mut out, mut err) = (empty(), empty());
    // SAFETY: valid pointer/length pair and writable out-parameters.
    let status =
        unsafe { abi::symvault_identity_public_key(bad.as_ptr(), bad.len(), &mut out, &mut err) };
    assert_eq!(status, 3);
    assert_eq!(text(&err), "argument identity is not valid UTF-8");
    // SAFETY: `err` came from the library.
    unsafe { abi::symvault_buf_free(err) };
}

#[test]
fn null_with_zero_length_is_an_empty_argument_and_outputs_are_reset() {
    // A stale pointer in the out-parameter must be overwritten, not freed.
    let mut out = SvBuf {
        ptr: ptr::dangling_mut::<u8>(),
        len: 7,
    };
    let mut err = SvBuf {
        ptr: ptr::dangling_mut::<u8>(),
        len: 7,
    };
    // SAFETY: zero-length null input is accepted; out-parameters writable.
    let status = unsafe { abi::symvault_identity_public_key(ptr::null(), 0, &mut out, &mut err) };
    assert_eq!(status, 1);
    assert!(out.ptr.is_null() && out.len == 0);
    assert!(
        text(&err).starts_with("validate identity: "),
        "{}",
        text(&err)
    );
    // SAFETY: `err` came from the library.
    unsafe { abi::symvault_buf_free(err) };
}

#[test]
fn null_out_parameters_are_tolerated() {
    // SAFETY: both out-parameters are null, which the contract allows.
    let status = unsafe { abi::symvault_generate_identity(ptr::null_mut(), ptr::null_mut()) };
    assert_eq!(status, 0);
    // SAFETY: as above.
    let status = unsafe {
        abi::symvault_identity_public_key(ptr::null(), 0, ptr::null_mut(), ptr::null_mut())
    };
    assert_eq!(status, 1);
}

#[test]
fn freeing_an_empty_buffer_is_a_no_op() {
    // SAFETY: an empty buffer owns nothing.
    unsafe { abi::symvault_buf_free(empty()) };
}

#[test]
fn header_declares_every_exported_symbol() {
    let header = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/swift/Sources/CSymvaultFFI/include/symvault_ffi.h"
    ))
    .expect("header");
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/abi.rs"))
        .expect("abi source");
    let mut exported = Vec::new();
    for line in source.lines() {
        if let Some(rest) = line.split("extern \"C\" fn ").nth(1) {
            exported.push(rest.split('(').next().expect("name").to_owned());
        }
    }
    assert!(exported.len() >= 16, "found {exported:?}");
    for name in exported {
        if name == "symvault_ffi_selftest_panic" {
            continue; // test hook, intentionally not public
        }
        assert!(
            header.contains(&format!("{name}(")),
            "{name} missing from header"
        );
    }
}

fn set_thread(dir: &str) -> i32 {
    let mut err = empty();
    // SAFETY: the path bytes and `err` are valid for the call.
    let status = unsafe { abi::symvault_set_thread_backup_dir(dir.as_ptr(), dir.len(), &mut err) };
    unsafe { abi::symvault_buf_free(err) };
    status
}

fn push_thread(dir: &str) -> (i32, u64) {
    let mut err = empty();
    let mut token = 77_u64;
    // SAFETY: the path bytes, `token` and `err` are valid for the call.
    let status = unsafe {
        abi::symvault_push_thread_backup_dir(dir.as_ptr(), dir.len(), &mut token, &mut err)
    };
    unsafe { abi::symvault_buf_free(err) };
    (status, token)
}

fn pop_thread(token: u64) -> (i32, String) {
    let mut err = empty();
    // SAFETY: `err` is writable.
    let status = unsafe { abi::symvault_pop_thread_backup_dir(token, &mut err) };
    let message = text(&err);
    // SAFETY: `err` came from the library and is freed once.
    unsafe { abi::symvault_buf_free(err) };
    (status, message)
}

fn unwind_thread(token: u64) -> (i32, String) {
    let mut err = empty();
    // SAFETY: `err` is writable.
    let status = unsafe { abi::symvault_unwind_thread_backup_dir(token, &mut err) };
    let message = text(&err);
    // SAFETY: `err` came from the library and is freed once.
    unsafe { abi::symvault_buf_free(err) };
    (status, message)
}

/// FFI-001: a host scope (what `SymvaultFFI.withBackupDirectory` does) must hand
/// back the override that the C API had set before it, on every exit.
#[test]
fn a_pushed_scope_restores_an_override_set_through_the_c_api() {
    let dir = tempfile::tempdir().expect("tempdir");
    let c_dir = dir.path().join("c-set");
    let outer = dir.path().join("outer-scope");
    let inner = dir.path().join("inner-scope");
    let c_text = c_dir.to_str().expect("utf-8");
    let outer_text = outer.to_str().expect("utf-8");
    let inner_text = inner.to_str().expect("utf-8");

    assert_eq!(set_thread(c_text), 0);
    let (status, first) = push_thread(outer_text);
    assert_eq!(status, 0);
    assert_ne!(first, 0);
    assert_eq!(
        symvault_sync::data_safety::thread_backup_dir(),
        Some(outer.clone())
    );
    let (status, second) = push_thread(inner_text);
    assert_eq!(status, 0);
    assert_ne!(second, first, "tokens are unique, not depths");
    assert_ne!(second, 0);
    assert_eq!(symvault_sync::data_safety::thread_backup_dir(), Some(inner));

    // The outer token cannot close the inner scope; nothing changes.
    let (status, message) = pop_thread(first);
    assert_eq!(status, 1, "{message}");
    assert!(
        message.contains("not the innermost open scope of this thread"),
        "{message}"
    );
    assert_eq!(pop_thread(second).0, 0);
    assert_eq!(
        symvault_sync::data_safety::thread_backup_dir(),
        Some(outer.clone())
    );
    assert_eq!(pop_thread(first).0, 0);
    assert_eq!(
        symvault_sync::data_safety::thread_backup_dir(),
        Some(c_dir),
        "the C-set override survives the scopes"
    );
    assert_eq!(pop_thread(first).0, 1, "a closed scope's token is refused");

    // Empty clears; a scope over a cleared thread restores "no override".
    assert_eq!(set_thread(""), 0);
    let (status, token) = push_thread(outer_text);
    assert_eq!(status, 0);
    assert_eq!(pop_thread(token).0, 0);
    assert_eq!(symvault_sync::data_safety::thread_backup_dir(), None);
}

/// FFI-001 review: a token is a process-unique serial. After push/pop/push the
/// second scope sits at the first one's depth, yet the first token stays dead.
#[test]
fn a_closed_scopes_token_is_refused_when_a_later_scope_has_the_same_depth() {
    assert_eq!(set_thread(""), 0);
    let (status, a) = push_thread("/tmp/ffi-stale-a");
    assert_eq!(status, 0);
    assert_eq!(pop_thread(a).0, 0);
    let (status, b) = push_thread("/tmp/ffi-stale-b");
    assert_eq!(status, 0);
    assert_ne!(a, b);
    let (status, message) = pop_thread(a);
    assert_eq!(status, 1, "{message}");
    assert_eq!(unwind_thread(a).0, 1);
    assert_eq!(
        symvault_sync::data_safety::thread_backup_dir(),
        Some(std::path::PathBuf::from("/tmp/ffi-stale-b")),
        "the stale token changed nothing"
    );
    assert_eq!(pop_thread(b).0, 0);
    assert_eq!(symvault_sync::data_safety::thread_backup_dir(), None);
}

/// Both threads hold exactly one open scope; neither can close the other's.
#[test]
fn a_token_from_another_thread_is_refused_at_equal_depth() {
    assert_eq!(set_thread(""), 0);
    let (status, mine) = push_thread("/tmp/ffi-thread-main");
    assert_eq!(status, 0);
    let other = std::thread::spawn(move || {
        let (status, theirs) = push_thread("/tmp/ffi-thread-other");
        assert_eq!(status, 0);
        let refused = (pop_thread(mine).0, unwind_thread(mine).0);
        let still = symvault_sync::data_safety::thread_backup_dir();
        assert_eq!(pop_thread(theirs).0, 0);
        (theirs, refused, still)
    })
    .join()
    .expect("thread");
    assert_ne!(other.0, mine);
    assert_eq!(other.1, (1, 1), "the foreign token is refused");
    assert_eq!(
        other.2,
        Some(std::path::PathBuf::from("/tmp/ffi-thread-other"))
    );
    assert_eq!(
        symvault_sync::data_safety::thread_backup_dir(),
        Some(std::path::PathBuf::from("/tmp/ffi-thread-main"))
    );
    assert_eq!(pop_thread(mine).0, 0);
}

/// The Swift defer's recovery after a refused pop: unwind restores the value
/// saved by that exact scope and drops the leaked inner scope.
#[test]
fn unwind_restores_the_named_scope_and_drops_leaked_inner_scopes() {
    assert_eq!(set_thread("/tmp/ffi-unwind-base"), 0);
    let (_, outer) = push_thread("/tmp/ffi-unwind-outer");
    let (_, leaked) = push_thread("/tmp/ffi-unwind-leaked");
    assert_eq!(
        pop_thread(outer).0,
        1,
        "the leaked inner scope blocks the pop"
    );
    assert_eq!(unwind_thread(outer).0, 0);
    assert_eq!(
        symvault_sync::data_safety::thread_backup_dir(),
        Some(std::path::PathBuf::from("/tmp/ffi-unwind-base"))
    );
    assert_eq!(pop_thread(leaked).0, 1, "dropped with the unwound scope");
    let (status, message) = unwind_thread(outer);
    assert_eq!(status, 1, "{message}");
    assert!(
        message.contains("not an open scope of this thread"),
        "{message}"
    );
    assert_eq!(set_thread(""), 0);
}

#[test]
fn a_refused_push_leaves_the_thread_untouched() {
    assert_eq!(set_thread(""), 0);
    let (status, token) = push_thread("relative/dir");
    assert_eq!(status, 1);
    assert_eq!(token, 0, "no scope was opened");
    assert_eq!(symvault_sync::data_safety::thread_backup_dir(), None);
    let mut err = empty();
    // SAFETY: a null token pointer is the misuse under test; `err` is writable.
    let status = unsafe {
        abi::symvault_push_thread_backup_dir(b"/x".as_ptr(), 2, ptr::null_mut(), &mut err)
    };
    assert_eq!(status, 3);
    // SAFETY: `err` came from the library.
    unsafe { abi::symvault_buf_free(err) };
    assert_eq!(symvault_sync::data_safety::thread_backup_dir(), None);
}
