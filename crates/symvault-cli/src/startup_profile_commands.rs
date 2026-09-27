//! Startup-time benchmark for the native CLI.

use std::{
    env,
    ffi::OsStr,
    path::Path,
    process::{Command, Stdio},
    sync::OnceLock,
    time::{Duration, Instant},
};

/// Program start, recorded by [`mark_process_start`] before the CLI thread spawns.
static PROCESS_START: OnceLock<Instant> = OnceLock::new();

/// Records program start so child-marker mode can report time since startup.
///
/// Mirrors Go's `cli.SetStartTime` call, which the Go `startup-profile` child
/// mode measures against.
pub fn mark_process_start() {
    let _ = PROCESS_START.set(Instant::now());
}

/// Re-executes the current binary to measure process startup and argument parsing.
///
/// The report is written to stderr, matching the Go command's `cmd.Printf`
/// stream (cobra prints to `OutOrStderr`).
///
/// Go's `--trace` output is produced by `runtime/trace` and understood by
/// `go tool trace`; the Rust binary has no compatible trace runtime, so reject
/// that option rather than creating a file that only looks like a Go trace.
pub fn run(count: i64, _top: i64, trace: Option<&Path>) -> Result<(), String> {
    if env::var_os("SYMVAULT_STARTUP_PROFILE_CHILD").as_deref() == Some(OsStr::new("1")) {
        let start = *PROCESS_START.get_or_init(Instant::now);
        eprintln!("{}", start.elapsed().as_nanos());
        return Ok(());
    }

    if let Some(path) = trace.filter(|path| !path.as_os_str().is_empty()) {
        return Err(format!(
            "runtime trace output is not available in the Rust CLI: {}",
            path.display()
        ));
    }

    let count = usize::try_from(count.max(1)).unwrap_or(usize::MAX);
    let binary = env::current_exe().map_err(|error| format!("cannot find executable: {error}"))?;
    eprintln!("Profiling startup time ({count} iterations)...\n");

    let mut times = Vec::with_capacity(count);
    let mut failures = 0usize;
    for iteration in 0..count {
        let start = Instant::now();
        let mut child = Command::new(&binary);
        child.env_clear();
        child.stdout(Stdio::null()).stderr(Stdio::null());
        for (key, value) in env::vars_os() {
            if !key.to_string_lossy().starts_with("SYMVAULT_") {
                child.env(key, value);
            }
        }
        // Go's harness marks its benchmark children the same way.
        child.env("SYMVAULT_STARTUP_PROFILE_CHILD", "1");
        match child.status() {
            Ok(status) if status.success() => times.push(start.elapsed()),
            Ok(status) => {
                failures += 1;
                eprintln!("  iteration {}: exec failed: {status}", iteration + 1);
            }
            Err(error) => {
                failures += 1;
                eprintln!("  iteration {}: exec failed: {error}", iteration + 1);
            }
        }
    }

    if times.is_empty() {
        return Err(format!("all {count} iterations failed"));
    }

    times.sort_unstable();
    let total = times.iter().copied().sum::<Duration>();
    let average = Duration::from_nanos((total.as_nanos() / times.len() as u128) as u64);
    let min = times[0];
    let max = times[times.len() - 1];
    let p95 = percentile(&times, 95);
    let p99 = percentile(&times, 99);

    eprintln!("Startup Time Statistics");
    eprintln!("{}", "─".repeat(50));
    eprintln!("  Min:        {}", go_duration(min));
    eprintln!("  Max:        {}", go_duration(max));
    eprintln!("  Avg:        {}", go_duration(average));
    eprintln!("  P95:        {}", go_duration(p95));
    eprintln!("  P99:        {}", go_duration(p99));
    eprintln!("  Success:    {} / {count} iterations", times.len());
    if failures > 0 {
        eprintln!("  Failures:   {failures}");
    }
    eprintln!();
    eprintln!("Environment");
    eprintln!("{}", "─".repeat(50));
    eprintln!("  Runtime:    Rust CLI");
    eprintln!("  OS/Arch:    {}/{}", go_os(), go_arch());
    let cores = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    eprintln!("  CPU:        {cores} core(s)");
    // Label fits the 14-character field the other lines use for their values.
    eprintln!("  Threads:    {cores}");
    eprintln!();
    eprintln!("Optimization Hints");
    eprintln!("{}", "─".repeat(50));
    eprintln!("  • Keep command startup paths free of vault and keychain work.");
    eprintln!("  • Defer expensive service setup until a command needs it.");
    eprintln!("  • Keep the default CLI dependency graph lean.");
    eprintln!("  • Use an external profiler to inspect phase-level startup costs.");
    Ok(())
}

fn percentile(sorted: &[Duration], percent: usize) -> Duration {
    let rank = percent.saturating_mul(sorted.len()).div_ceil(100);
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn go_duration(duration: Duration) -> String {
    const NS_PER_US: u128 = 1_000;
    const NS_PER_MS: u128 = 1_000_000;
    const NS_PER_S: u128 = 1_000_000_000;
    const NS_PER_MIN: u128 = 60 * NS_PER_S;
    const NS_PER_HOUR: u128 = 60 * NS_PER_MIN;

    let nanos = duration.as_nanos();
    if nanos >= NS_PER_HOUR {
        let hours = nanos / NS_PER_HOUR;
        let remainder = nanos % NS_PER_HOUR;
        let minutes = remainder / NS_PER_MIN;
        let seconds = remainder % NS_PER_MIN;
        format!(
            "{hours}h{minutes}m{}",
            fractional_unit(seconds, NS_PER_S, "s")
        )
    } else if nanos >= NS_PER_MIN {
        let minutes = nanos / NS_PER_MIN;
        let seconds = nanos % NS_PER_MIN;
        format!("{minutes}m{}", fractional_unit(seconds, NS_PER_S, "s"))
    } else if nanos >= NS_PER_S {
        fractional_unit(nanos, NS_PER_S, "s")
    } else if nanos >= NS_PER_MS {
        fractional_unit(nanos, NS_PER_MS, "ms")
    } else if nanos >= NS_PER_US {
        fractional_unit(nanos, NS_PER_US, "µs")
    } else {
        format!("{nanos}ns")
    }
}

fn fractional_unit(nanos: u128, unit_nanos: u128, suffix: &str) -> String {
    let whole = nanos / unit_nanos;
    let remainder = nanos % unit_nanos;
    if remainder == 0 {
        return format!("{whole}{suffix}");
    }
    let digits = unit_nanos.ilog10() as usize;
    let fraction = format!("{remainder:0digits$}");
    format!("{whole}.{}{suffix}", fraction.trim_end_matches('0'))
}

fn go_os() -> &'static str {
    match env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

fn go_arch() -> &'static str {
    match env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        other => other,
    }
}
