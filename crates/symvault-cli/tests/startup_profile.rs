use std::process::{Command, Output};

const BINARY: &str = env!("CARGO_BIN_EXE_symvault");

fn run(args: &[&str]) -> Output {
    Command::new(BINARY)
        .args(args)
        .output()
        .expect("run symvault startup-profile")
}

#[test]
fn count_runs_a_fresh_cli_process_and_reports_startup_statistics() {
    let output = run(&["startup-profile", "--count", "2", "--top", "-3"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("startup-profile output is UTF-8");
    assert!(stdout.contains("Profiling startup time (2 iterations)..."));
    assert!(stdout.contains("Startup Time Statistics"));
    assert!(stdout.contains("  Min:"));
    assert!(stdout.contains("  P95:"));
    assert!(stdout.contains("  P99:"));
    assert!(stdout.contains("  Success:    2 / 2 iterations"));
    assert!(stdout.contains("Environment"));
}

#[test]
fn unsupported_json_output_matches_go_usage_error_and_exit() {
    let output = run(&["startup-profile", "--json"]);
    assert_eq!(output.status.code(), Some(9));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("error output is UTF-8");
    assert!(
        stderr.contains("output format \"json\" is not supported by 'symvault startup-profile'")
    );
}

#[test]
fn non_positive_count_is_clamped_to_one_like_go() {
    let output = run(&["startup-profile", "--count", "0"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("startup-profile output is UTF-8");
    assert!(stdout.contains("Profiling startup time (1 iterations)..."));
    assert!(stdout.contains("  Success:    1 / 1 iterations"));
}

#[test]
fn trace_fails_clearly_instead_of_emitting_an_incompatible_runtime_trace() {
    let output = run(&["startup-profile", "--trace", "/tmp/startup-profile.trace"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("error output is UTF-8");
    assert!(stderr.contains("runtime trace output is not available in the Rust CLI"));
}
