#![deny(unsafe_code)]

//! Go↔Rust differential for `symvault startup-profile`.
//!
//! `startup_profile.rs` pins the Rust-side behaviour and does not invoke Go;
//! this file is the oracle-bound half. The oracle comes from
//! `SYMVAULT_GO_BINARY` (exported by the port-contract gate) and the whole
//! suite skips when it is unset, mirroring `doctor_differential.rs`.
//!
//! Documented divergences that are intentional and therefore asserted per
//! side instead of compared for equality:
//!
//! - `--trace <file>`: Go writes a `runtime/trace` file and exits 0. The Rust
//!   binary cannot produce a stream `go tool trace` understands, so it refuses
//!   (exit 1, no file — see `trace_fails_clearly_...` in `startup_profile.rs`)
//!   rather than fabricating one. Only the shared failure row (unusable path:
//!   both exit 1) is compared here.
//! - Report environment/hints: `Go:`/`GOMAXPROCS:` and five Go-specific hints
//!   become `Runtime:`/`Threads:` and four Rust-specific hints — honest
//!   runtime-specific text, mapped to shared tokens by `normalize_report`.
//! - Parse-error wording (unknown flag): clap dialect vs cobra dialect is a
//!   CLI-wide normalization present in every ported command (verified equal in
//!   shape against `doctor --badflag`); only the exit code is compared.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const BINARY: &str = env!("CARGO_BIN_EXE_symvault");

/// Returns `(go_binary, rust_binary)` or skips the suite when the gate did
/// not export the oracle.
fn oracle_binaries() -> Option<(PathBuf, PathBuf)> {
    let raw = env::var_os("SYMVAULT_GO_BINARY")?;
    let candidate = PathBuf::from(&raw);
    if candidate.is_file() {
        return Some((candidate, PathBuf::from(BINARY)));
    }
    println!(
        "skipping startup-profile differential: SYMVAULT_GO_BINARY is not a file: {:?}",
        candidate
    );
    None
}

/// Fresh HOME/XDG tree per case; removed on drop.
struct TempFixture {
    root: PathBuf,
    home: PathBuf,
}

impl TempFixture {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "symvault-startup-profile-diff-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create fixture root");
        let home = root.join("home");
        fs::create_dir_all(&home).expect("create fixture home");
        Self { root, home }
    }
}

impl Drop for TempFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn run(binary: &Path, args: &[&str], home: &Path, child_marker: bool) -> Output {
    let mut command = Command::new(binary);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join("xdg/cache"))
        .env("XDG_CONFIG_HOME", home.join("xdg/config"))
        .env("XDG_DATA_HOME", home.join("xdg/data"))
        .env("XDG_STATE_HOME", home.join("xdg/state"))
        .env("SYMVAULT_VAULT", home.join("missing-vault"))
        .env("SYMVAULT_PASSPHRASE", "differential-test-only")
        .env("NO_COLOR", "1")
        .env("TZ", "UTC")
        .env("LC_ALL", "C.UTF-8")
        .env("CI", "1");
    if child_marker {
        command.env("SYMVAULT_STARTUP_PROFILE_CHILD", "1");
    }
    command.output().expect("run binary")
}

/// Maps the two honest runtime-specific adaptations onto shared tokens so the
/// rest of the report must be line-for-line identical.
fn normalize_report(stderr: &str) -> String {
    let mut normalized = String::new();
    for line in stderr.lines() {
        if line.starts_with("  Min:")
            || line.starts_with("  Max:")
            || line.starts_with("  Avg:")
            || line.starts_with("  P95:")
            || line.starts_with("  P99:")
        {
            let label = line.split(':').next().unwrap_or(line);
            normalized.push_str(label);
            normalized.push_str(": <duration>\n");
        } else if line.starts_with("  Go:") || line.starts_with("  Runtime:") {
            normalized.push_str("  RUNTIME: <runtime>\n");
        } else if line.starts_with("  GOMAXPROCS:") || line.starts_with("  Threads:") {
            normalized.push_str("  PARALLELISM: <count>\n");
        } else if line.starts_with("  CPU:") {
            normalized.push_str("  CPU:        <count> core(s)\n");
        } else if line.starts_with("  • ") {
            // Optimization hints are runtime-specific by design.
            continue;
        } else {
            normalized.push_str(line);
            normalized.push('\n');
        }
    }
    normalized
}

/// Relative paths below `root`, sorted — side-effect manifest.
fn tree(root: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(rel) = path.strip_prefix(base) else {
                continue;
            };
            out.push(rel.to_string_lossy().into_owned());
            if path.is_dir() {
                walk(base, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

#[test]
fn differential_report_matches_after_normalizing_runtime_specific_lines() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let fixture = TempFixture::new("report");
    let args = ["startup-profile", "--count", "1"];

    let go_out = run(&go, &args, &fixture.home, false);
    let rust_out = run(&rust, &args, &fixture.home, false);

    assert_eq!(go_out.status.code(), Some(0), "Go normal run exits 0");
    assert_eq!(rust_out.status.code(), Some(0), "Rust normal run exits 0");
    // cmd.Printf → stderr on the Go side; the port must match the stream.
    assert!(
        go_out.stdout.is_empty(),
        "Go writes the report to stderr, stdout was: {:?}",
        String::from_utf8_lossy(&go_out.stdout)
    );
    assert!(
        rust_out.stdout.is_empty(),
        "Rust must not use stdout, stdout was: {:?}",
        String::from_utf8_lossy(&rust_out.stdout)
    );

    let go_err = stderr_text(&go_out);
    let rust_err = stderr_text(&rust_out);
    // The adaptations themselves stay visible before they are normalized away.
    assert!(go_err.contains("  Go:"), "Go keeps its runtime label");
    assert!(go_err.contains("  GOMAXPROCS:"), "Go keeps GOMAXPROCS");
    assert!(
        rust_err.contains("  Runtime:"),
        "Rust reports its own runtime"
    );
    assert!(rust_err.contains("  Threads:"), "Rust parallelism label");
    assert_eq!(
        normalize_report(&go_err),
        normalize_report(&rust_err),
        "report must match line-for-line after runtime-specific normalization"
    );

    // Benchmark side effect: neither implementation writes into the fresh HOME.
    assert!(
        tree(&fixture.home).is_empty(),
        "no side effects expected, found: {:?}",
        tree(&fixture.home)
    );
}

#[test]
fn differential_unsupported_json_error_is_byte_identical() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let fixture = TempFixture::new("json");
    let cases: &[&[&str]] = &[
        &["startup-profile", "--json"],
        &["startup-profile", "--output", "yaml"],
        // flags still parse after a positional on both sides
        &["startup-profile", "extra-positional", "--json"],
        // Go doubles this error (cobra, then ExecuteRoot); both lines must match
        &["startup-profile", "--json", "--quiet"],
    ];
    for args in cases {
        let go_out = run(&go, args, &fixture.home, false);
        let rust_out = run(&rust, args, &fixture.home, false);
        assert_eq!(
            go_out.status.code(),
            Some(9),
            "Go exit for {args:?}: {:?}",
            String::from_utf8_lossy(&go_out.stderr)
        );
        assert_eq!(
            rust_out.status.code(),
            Some(9),
            "Rust exit for {args:?}: {:?}",
            String::from_utf8_lossy(&rust_out.stderr)
        );
        assert!(go_out.stdout.is_empty(), "Go stdout empty for {args:?}");
        assert!(rust_out.stdout.is_empty(), "Rust stdout empty for {args:?}");
        assert_eq!(
            go_out.stderr, rust_out.stderr,
            "usage error must be byte-identical (including doubling) for {args:?}"
        );
    }
}

#[test]
fn differential_count_clamping_matches() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let fixture = TempFixture::new("count");
    let cases: &[&[&str]] = &[
        &["startup-profile", "--count", "0"],
        &["startup-profile", "--count", "-5"],
        &["startup-profile", "-n", "0"],
    ];
    for args in cases {
        let go_out = run(&go, args, &fixture.home, false);
        let rust_out = run(&rust, args, &fixture.home, false);
        assert_eq!(go_out.status.code(), Some(0), "Go exit for {args:?}");
        assert_eq!(rust_out.status.code(), Some(0), "Rust exit for {args:?}");
        let go_err = stderr_text(&go_out);
        let rust_err = stderr_text(&rust_out);
        assert!(
            go_err.contains("Profiling startup time (1 iterations)..."),
            "Go clamps for {args:?}: {go_err:?}"
        );
        assert!(
            rust_err.contains("Profiling startup time (1 iterations)..."),
            "Rust clamps for {args:?}: {rust_err:?}"
        );
        assert!(go_err.contains("  Success:    1 / 1 iterations"));
        assert!(rust_err.contains("  Success:    1 / 1 iterations"));
    }
}

#[test]
fn differential_positional_and_empty_trace_are_accepted_on_both() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let fixture = TempFixture::new("accepted");
    let cases: &[&[&str]] = &[
        &["startup-profile", "extra-positional", "-n", "1"],
        &["startup-profile", "--trace", "", "-n", "1"],
        &["startup-profile", "-n", "1", "--top", "-3"],
    ];
    for args in cases {
        let go_out = run(&go, args, &fixture.home, false);
        let rust_out = run(&rust, args, &fixture.home, false);
        assert_eq!(go_out.status.code(), Some(0), "Go exit for {args:?}");
        assert_eq!(rust_out.status.code(), Some(0), "Rust exit for {args:?}");
        assert!(
            stderr_text(&go_out).contains("  Success:    1 / 1 iterations"),
            "Go benchmark ran for {args:?}"
        );
        assert!(
            stderr_text(&rust_out).contains("  Success:    1 / 1 iterations"),
            "Rust benchmark ran for {args:?}"
        );
    }
}

#[test]
fn differential_missing_and_broken_config_still_benchmark() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    // Missing config: fresh HOME with no ~/.symvault at all.
    let missing = TempFixture::new("missing-config");
    let args = ["startup-profile", "--count", "1"];
    let go_out = run(&go, &args, &missing.home, false);
    let rust_out = run(&rust, &args, &missing.home, false);
    assert_eq!(go_out.status.code(), Some(0), "Go without config");
    assert_eq!(rust_out.status.code(), Some(0), "Rust without config");
    assert!(stderr_text(&go_out).contains("Startup Time Statistics"));
    assert!(stderr_text(&rust_out).contains("Startup Time Statistics"));

    // Broken config at the real path (~/.symvault/config.yaml): the command
    // requires neither vault nor config, so both sides must still benchmark.
    let broken = TempFixture::new("broken-config");
    let config_dir = broken.home.join(".symvault");
    fs::create_dir_all(&config_dir).expect("create config dir");
    fs::write(config_dir.join("config.yaml"), "{ not: valid: yaml: [\n")
        .expect("write corrupt config");
    let go_out = run(&go, &args, &broken.home, false);
    let rust_out = run(&rust, &args, &broken.home, false);
    assert_eq!(go_out.status.code(), Some(0), "Go with corrupt config");
    assert_eq!(rust_out.status.code(), Some(0), "Rust with corrupt config");
    assert!(stderr_text(&go_out).contains("Startup Time Statistics"));
    assert!(stderr_text(&rust_out).contains("Startup Time Statistics"));
}

#[test]
fn differential_trace_with_unusable_path_exits_one_on_both() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let fixture = TempFixture::new("trace");
    // A directory: Go cannot create the trace file, Rust refuses outright.
    // Message text differs by design (capability gap); exit code and doubled
    // error shape must match.
    let args = ["startup-profile", "--trace", fixture.root.to_str().unwrap()];
    let go_out = run(&go, &args, &fixture.home, false);
    let rust_out = run(&rust, &args, &fixture.home, false);
    assert_eq!(go_out.status.code(), Some(1), "Go trace failure exits 1");
    assert_eq!(
        rust_out.status.code(),
        Some(1),
        "Rust rejects trace exits 1"
    );
    let go_err = stderr_text(&go_out);
    let rust_err = stderr_text(&rust_out);
    for (side, err) in [("Go", &go_err), ("Rust", &rust_err)] {
        let lines: Vec<&str> = err.lines().collect();
        assert_eq!(lines.len(), 2, "{side} doubles its error, got: {err:?}");
        assert_eq!(lines[0], lines[1], "{side} prints the same line twice");
        assert!(lines[0].starts_with("Error: "), "{side} uses Error: prefix");
    }
    assert!(
        go_err.contains("cannot create trace file"),
        "Go names its creation failure: {go_err:?}"
    );
    assert!(
        rust_err.contains("runtime trace output is not available in the Rust CLI"),
        "Rust states the capability gap: {rust_err:?}"
    );
    assert!(!fixture.root.join("startup.trace").exists());
}

#[test]
fn differential_unknown_flag_exits_one_on_both() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let fixture = TempFixture::new("badflag");
    let args = ["startup-profile", "--definitely-not-a-flag"];
    let go_out = run(&go, &args, &fixture.home, false);
    let rust_out = run(&rust, &args, &fixture.home, false);
    // Exit parity holds; the wording is the CLI-wide clap-vs-cobra dialect
    // normalization shared with every ported command (e.g. `doctor --badflag`).
    assert_eq!(go_out.status.code(), Some(1), "Go unknown flag exits 1");
    assert_eq!(rust_out.status.code(), Some(1), "Rust unknown flag exits 1");
    assert!(go_out.stdout.is_empty());
    assert!(rust_out.stdout.is_empty());
    assert!(!go_out.stderr.is_empty());
    assert!(!rust_out.stderr.is_empty());
}

#[test]
fn differential_child_marker_reports_integer_on_both() {
    let Some((go, rust)) = oracle_binaries() else {
        return;
    };
    let fixture = TempFixture::new("marker");
    let args = ["startup-profile"];
    let go_out = run(&go, &args, &fixture.home, true);
    let rust_out = run(&rust, &args, &fixture.home, true);
    assert_eq!(go_out.status.code(), Some(0), "Go marker mode exits 0");
    assert_eq!(rust_out.status.code(), Some(0), "Rust marker mode exits 0");
    assert!(go_out.stdout.is_empty());
    assert!(rust_out.stdout.is_empty());
    for (side, out) in [("Go", &go_out), ("Rust", &rust_out)] {
        let text = String::from_utf8(out.stderr.clone()).expect("stderr UTF-8");
        let nanos: u128 = text
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("{side} prints one bare nanosecond count, got: {text:?}"));
        assert!(nanos > 0, "{side} elapsed nanos must be positive");
    }
}
