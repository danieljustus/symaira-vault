//! Compiles `tests/c/abi_check.c` with the system C compiler against the public
//! header and links it with the static library Cargo built, then runs it. This
//! checks the header and the Rust `extern "C"` definitions against each other:
//! the C compiler lays out `SvBuf` and passes every argument the way an app
//! would, so a wrong width, order or struct layout gives a wrong result here.
//!
//! Needs a C compiler (`$CC`, else `cc`); on macOS that is the Xcode one.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn static_library() -> PathBuf {
    // target/<profile>/deps/<test> -> target/<profile>/libsymvault_ffi.a
    let exe = std::env::current_exe().expect("test executable path");
    let profile_dir = exe
        .parent()
        .and_then(Path::parent)
        .expect("target profile directory");
    // `cargo test` links the crate as an rlib and never writes the staticlib,
    // so an existing archive may predate the code under test. Build it now with
    // the profile of this test binary (cargo has released its lock by the time
    // tests run).
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let mut build = Command::new(&cargo);
    build.args(["build", "-p", "symvault-ffi", "--lib", "--locked"]);
    // ponytail: assumes target/<profile> (no --target triple directory); a
    // cross-target run would need the triple passed through as well.
    if let Some(profile) = profile_dir.file_name().and_then(|name| name.to_str())
        && profile != "debug"
    {
        build.args(["--profile", profile]);
    }
    if let Some(target_dir) = profile_dir.parent() {
        build.env("CARGO_TARGET_DIR", target_dir);
    }
    let built = build
        .output()
        .unwrap_or_else(|error| panic!("cannot run {cargo:?} build: {error}"));
    assert!(
        built.status.success(),
        "cargo build of the staticlib failed:\n{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let library = profile_dir.join("libsymvault_ffi.a");
    assert!(
        library.exists(),
        "{} was not built (crate-type staticlib)",
        library.display()
    );
    library
}

#[test]
fn c_program_built_from_the_header_runs_against_the_library() {
    // The nested build and `cc` link assume a plain host build: under
    // `cargo llvm-cov` the staticlib would be instrumented without the profiler
    // runtime on the C link line, and `--target` moves the archive.
    if std::env::var_os("LLVM_PROFILE_FILE").is_some()
        || std::env::var_os("CARGO_LLVM_COV").is_some()
        || std::env::var_os("CARGO_BUILD_TARGET").is_some()
    {
        eprintln!("SKIP c_abi: coverage instrumentation or an explicit --target is active");
        return;
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let include = manifest.join("swift/Sources/CSymvaultFFI/include");
    let source = manifest.join("tests/c/abi_check.c");
    let scratch = tempfile::tempdir().expect("scratch directory");
    let executable = scratch.path().join("abi_check");

    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let mut compile = Command::new(&compiler);
    compile
        .arg("-std=c11")
        .args(["-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(&include)
        .arg(&source)
        .arg(static_library())
        .arg("-o")
        .arg(&executable);
    if cfg!(target_os = "linux") {
        compile.args(["-lm", "-lpthread", "-ldl"]);
    }
    let compiled = compile
        .output()
        .unwrap_or_else(|error| panic!("cannot run the C compiler {compiler:?}: {error}"));
    assert!(
        compiled.status.success(),
        "C compile/link failed:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let vault = scratch.path().join("vault");
    let ran = Command::new(&executable)
        .arg(&vault)
        .output()
        .expect("run abi_check");
    assert!(
        ran.status.success(),
        "abi_check failed ({}):\n{}",
        ran.status,
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(String::from_utf8_lossy(&ran.stdout).contains("abi_check: ok"));
}
