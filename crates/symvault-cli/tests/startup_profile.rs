use std::process::{Command, Output};

const BINARY: &str = env!("CARGO_BIN_EXE_symvault");

fn run(args: &[&str]) -> Output {
    Command::new(BINARY)
        .args(args)
        .env_remove("SYMVAULT_STARTUP_PROFILE_CHILD")
        .output()
        .expect("run symvault startup-profile")
}

#[test]
fn count_runs_a_fresh_cli_process_and_reports_startup_statistics() {
    let output = run(&["startup-profile", "--count", "2", "--top", "-3"]);
    assert_eq!(output.status.code(), Some(0));
    // Go writes the whole report through cmd.Printf, which lands on stderr.
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("startup-profile output is UTF-8");
    assert!(stderr.contains("Profiling startup time (2 iterations)..."));
    assert!(stderr.contains("Startup Time Statistics"));
    assert!(stderr.contains("  Min:"));
    assert!(stderr.contains("  P95:"));
    assert!(stderr.contains("  P99:"));
    assert!(stderr.contains("  Success:    2 / 2 iterations"));
    assert!(stderr.contains("Environment"));
}

#[test]
fn unsupported_json_output_matches_go_usage_error_and_exit() {
    let output = run(&["startup-profile", "--json"]);
    assert_eq!(output.status.code(), Some(9));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("error output is UTF-8");
    // Go prints this error twice (cobra, then ExecuteRoot); both lines must match.
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines.len(), 2, "expected doubled error, got: {stderr:?}");
    assert_eq!(lines[0], lines[1]);
    assert!(
        lines[0].contains("output format \"json\" is not supported by 'symvault startup-profile'")
    );
}

#[test]
fn non_positive_count_is_clamped_to_one_like_go() {
    let output = run(&["startup-profile", "--count", "0"]);
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).expect("startup-profile output is UTF-8");
    assert!(stderr.contains("Profiling startup time (1 iterations)..."));
    assert!(stderr.contains("  Success:    1 / 1 iterations"));
}

#[test]
fn negative_count_after_space_is_clamped_like_go() {
    // pflag accepts `--count -5` as a value; the benchmark clamps it to one run.
    let output = run(&["startup-profile", "--count", "-5"]);
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).expect("startup-profile output is UTF-8");
    assert!(stderr.contains("Profiling startup time (1 iterations)..."));
    assert!(stderr.contains("  Success:    1 / 1 iterations"));
}

#[test]
fn empty_trace_value_runs_the_benchmark_like_go() {
    let output = run(&["startup-profile", "--trace", "", "--count", "1"]);
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).expect("startup-profile output is UTF-8");
    assert!(stderr.contains("Profiling startup time (1 iterations)..."));
}

#[test]
fn extra_positional_arguments_are_accepted_like_go() {
    let output = run(&["startup-profile", "extra-arg", "-n", "1"]);
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).expect("startup-profile output is UTF-8");
    assert!(stderr.contains("Profiling startup time (1 iterations)..."));
}

#[test]
fn child_env_marker_reports_startup_nanoseconds_like_go() {
    let output = Command::new(BINARY)
        .args(["startup-profile"])
        .env("SYMVAULT_STARTUP_PROFILE_CHILD", "1")
        .output()
        .expect("run symvault startup-profile with child marker");
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("marker output is UTF-8");
    let nanos: u128 = stderr
        .trim()
        .parse()
        .expect("child mode prints one bare nanosecond count");
    assert!(nanos > 0);
}

#[test]
fn trace_fails_clearly_instead_of_emitting_an_incompatible_runtime_trace() {
    let trace_path = std::env::temp_dir().join(format!(
        "symvault-startup-profile-trace-{}.trace",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&trace_path);
    let output = run(&["startup-profile", "--trace", trace_path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("error output is UTF-8");
    assert!(stderr.contains("runtime trace output is not available in the Rust CLI"));
    // Honest rejection: no file that could be mistaken for a Go trace.
    assert!(!trace_path.exists());
}
