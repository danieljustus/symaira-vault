//! `symvault config validate --fix` — the interactive repair flow.
//!
//! Port of Go's `cli.InteractiveFixConfig` (`internal/cli/configfix.go`) and
//! the `--fix` branches of `configValidateCmd` (`cmd/admin/config.go`). The
//! flow runs only when stdin is a terminal:
//!
//! 1. A load failure (no usable config) offers `$EDITOR`, then reloads.
//! 2. A validation failure first offers deterministic auto-fixes (one `y/N`
//!    prompt per recognised error), saves the result, re-validates, and falls
//!    back to `$EDITOR` when that is not enough.
//!
//! Prompts, hints and the error report go to **stderr**; the closing
//! `Configuration repaired successfully.` line goes to stdout (quiet-aware).
//! Go keeps no backup of the file, and neither does this port.
//!
//! The typed [`Config`] carries every section Go's `SaveTo` rewrites (`audit`,
//! `logging`, `scan_patterns`, ...), so the saved bytes come straight from
//! [`Config::to_yaml_bytes`].

use std::{
    env, fs,
    io::{self, BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use symvault_core::config::{AuditConfig, ClipboardConfig, Config, McpConfig};

/// `DefaultVaultSubdir` in Go's config package.
const DEFAULT_VAULT_SUBDIR: &str = ".symvault";
const AUDIT_DEFAULT_MAX_BYTES: i64 = 100 * 1024 * 1024;

/// A loaded config.
#[derive(Clone, Debug)]
pub(crate) struct Loaded {
    pub(crate) config: Config,
}

/// Go's `config.Load`: the error text is exactly what Go prints after
/// `cannot load config from <path>: ` and in the fix report's `Load error:`.
pub(crate) fn load(path: &Path) -> Result<Loaded, String> {
    // The header prints the RAW argument, while config.Load rejects traversal
    // before os.ReadFile(filepath.Clean(path)) — so the open attempt (and its
    // error text) sees the cleaned path.
    let read_path = crate::agent_list_commands::clean_path(path);
    let bytes = if path
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err("config file path escapes expected directory".to_owned());
    } else {
        fs::read(&read_path)
            .map_err(|error| super::format_go_path_error("open", &read_path, &error))?
    };
    let config = Config::load_from_bytes(&bytes).map_err(|error| error.to_string())?;
    Ok(Loaded { config })
}

/// Go's `Config.Validate`. `audit.maxFileSize` and `paymentPolicies` are
/// checked by the core validator, which sees them as typed config fields.
pub(crate) fn validate(loaded: &Loaded) -> Vec<String> {
    loaded.config.validate()
}

/// The `--fix` flow after the first `Load` of `configValidateCmd`.
///
/// Returns the final valid config, or the CLI error message (Go's
/// `CLIError.Error()`, i.e. `message: cause`).
pub(crate) fn fix(
    path: &Path,
    first: Result<Loaded, String>,
    quiet: bool,
) -> Result<Loaded, String> {
    let mut loaded = match first {
        Err(load_error) => {
            report_errors(path, Some(&load_error), None);
            run_editor_fix(path).map_err(|error| format!("config fix failed: {error}"))?;
            // The user edited the file in $EDITOR; reload and re-validate.
            load(path)
                .map_err(|error| format!("config still invalid after manual edit: {error}"))?
        }
        Ok(loaded) => loaded,
    };

    let errors = validate(&loaded);
    if errors.is_empty() {
        return Ok(loaded);
    }
    let validation_error = errors.join("\n");
    match interactive_fix(path, &mut loaded, &validation_error)
        .map_err(|error| format!("config fix failed: {error}"))?
    {
        Fixed::Repaired(repaired) => {
            let repaired = *repaired;
            println_quiet(quiet, "Configuration repaired successfully.");
            let errors = validate(&repaired);
            if !errors.is_empty() {
                return Err(format!(
                    "config still invalid after auto-fix: {}",
                    errors.join("\n")
                ));
            }
            Ok(repaired)
        }
        Fixed::Edited => {
            let reloaded = load(path)
                .map_err(|error| format!("config still invalid after manual edit: {error}"))?;
            let errors = validate(&reloaded);
            if !errors.is_empty() {
                return Err(format!(
                    "config still invalid after manual edit: {}",
                    errors.join("\n")
                ));
            }
            println_quiet(quiet, "Configuration repaired successfully.");
            Ok(reloaded)
        }
    }
}

enum Fixed {
    /// Auto-fixes were saved and the file now validates.
    Repaired(Box<Loaded>),
    /// The editor ran (Go returns `nil, nil`); the caller reloads the file.
    Edited,
}

fn println_quiet(quiet: bool, line: &str) {
    if !quiet {
        let mut out = io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }
}

/// Go's `InteractiveFixConfig` for a loadable-but-invalid config.
fn interactive_fix(
    path: &Path,
    loaded: &mut Loaded,
    validation_error: &str,
) -> Result<Fixed, String> {
    report_errors(path, None, Some(validation_error));
    if apply_auto_fixes(loaded, None, validation_error) {
        return save_and_revalidate(path, loaded);
    }
    run_editor_fix(path).map(|()| Fixed::Edited)
}

fn report_errors(path: &Path, load_error: Option<&str>, validation_error: Option<&str>) {
    let mut report = format!("Configuration error detected in {}\n", path.display());
    if let Some(load_error) = load_error {
        report.push_str(&format!("  ✗ Load error: {load_error}\n"));
    }
    if let Some(validation_error) = validation_error {
        for line in validation_error.split('\n') {
            if !line.is_empty() {
                report.push_str(&format!("  ✗ Validation error: {line}\n"));
            }
        }
    }
    let mut err = io::stderr().lock();
    let _ = err.write_all(report.as_bytes());
    let _ = err.flush();
}

/// Go's `ConfirmInteractive(prompt, false)`: a `y/N` prompt on stderr, one line
/// from stdin; only `y` (any case, trimmed) confirms, EOF and errors decline.
fn confirm(prompt: &str) -> bool {
    {
        let mut err = io::stderr().lock();
        let _ = write!(err, "{prompt} (y/N): ");
        let _ = err.flush();
    }
    let mut answer = Vec::new();
    let read = io::stdin().lock().read_until(b'\n', &mut answer);
    if read.is_err() && answer.is_empty() {
        return false;
    }
    String::from_utf8_lossy(&answer).trim().to_lowercase() == "y"
}

/// Walks the well-known validation errors and offers the deterministic fix
/// for each. Returns whether any change was made.
fn apply_auto_fixes(loaded: &mut Loaded, load_error: Option<&str>, validation_error: &str) -> bool {
    let mut error_text = String::new();
    if let Some(load_error) = load_error {
        error_text.push_str(load_error);
        error_text.push('\n');
    }
    error_text.push_str(validation_error);
    let mentions = |needle: &str| error_text.contains(needle);
    let mut modified = false;

    if mentions("sessionTimeout")
        && confirm(
            "Field 'sessionTimeout' must be greater than 0. Suggestion: 15m. Apply this fix?",
        )
    {
        loaded.config.session_timeout = Duration::from_secs(15 * 60);
        modified = true;
    }
    if mentions("audit.maxFileSize")
        && confirm(
            "Field 'audit.maxFileSize' must be greater than 0. Suggestion: 100MB. Apply this fix?",
        )
    {
        loaded
            .config
            .audit
            .get_or_insert(AuditConfig {
                max_file_size: 0,
                max_backups: 0,
                max_age_days: 0,
            })
            .max_file_size = AUDIT_DEFAULT_MAX_BYTES;
        modified = true;
    }
    if mentions("clipboard.autoClearDuration")
        && confirm(
            "Field 'clipboard.autoClearDuration' must be non-negative. Suggestion: 30s. Apply this fix?",
        )
    {
        loaded
            .config
            .clipboard
            .get_or_insert(ClipboardConfig {
                auto_clear_duration: 0,
                copy_by_default: false,
                print_by_default: None,
            })
            .auto_clear_duration = 30;
        modified = true;
    }
    if (mentions("mcp.bind") || load_error.is_some_and(|text| text.contains("mcp.bind")))
        && confirm("Field 'mcp.bind' must not be empty. Suggestion: 127.0.0.1. Apply this fix?")
    {
        loaded
            .config
            .mcp
            .get_or_insert_with(McpConfig::default)
            .bind = "127.0.0.1".to_owned();
        modified = true;
    }

    if mentions("vaultDir: must not be empty") {
        let home = home_dir();
        let suggestion = if home.is_empty() {
            format!("~/{DEFAULT_VAULT_SUBDIR}")
        } else {
            crate::agent_list_commands::clean_path(&PathBuf::from(home).join(DEFAULT_VAULT_SUBDIR))
                .to_string_lossy()
                .into_owned()
        };
        if confirm(&format!(
            "Field 'vaultDir' must not be empty. Suggestion: {suggestion}. Apply this fix?"
        )) {
            loaded.config.vault_dir = suggestion;
            modified = true;
        }
    }

    if mentions("defaultAgent:")
        && mentions("not found in agents")
        && let Some(first_agent) = loaded.config.agents.keys().next().cloned()
        && confirm(&format!(
            "Field 'defaultAgent' references an agent profile that does not exist. Suggestion: {} (the only defined agent). Apply this fix?",
            symvault_core::go_quote(&first_agent)
        ))
    {
        loaded.config.default_agent = first_agent;
        modified = true;
    }

    if mentions("invalid approvalMode")
        && confirm(
            "An agent profile has an invalid approvalMode. Suggestion: 'prompt'. Apply this fix for all affected agents?",
        )
    {
        let mut changed = false;
        for profile in loaded.config.agents.values_mut() {
            let Some(current) = profile.approval_mode.as_deref() else {
                continue;
            };
            if matches!(current, "none" | "deny" | "prompt" | "auto" | "") {
                continue;
            }
            profile.approval_mode = Some("prompt".to_owned());
            changed = true;
        }
        modified = changed || modified;
    }

    if mentions("invalid promptInjectionMode")
        && confirm(
            "An agent profile has an invalid promptInjectionMode. Suggestion: 'off'. Apply this fix for all affected agents?",
        )
    {
        let mut changed = false;
        for profile in loaded.config.agents.values_mut() {
            let current = profile.prompt_injection_mode.as_str();
            if matches!(current, "off" | "log-only" | "wrap" | "deny" | "") {
                continue;
            }
            profile.prompt_injection_mode = "off".to_owned();
            changed = true;
        }
        modified = changed || modified;
    }

    if (mentions("invalid auth method") || mentions("invalid authMethod"))
        && confirm("Auth method is invalid. Suggestion: 'passphrase'. Apply this fix?")
        && loaded.config.set_auth_method("passphrase").is_ok()
    {
        modified = true;
    }

    modified
}

/// Go's `saveAndRevalidate`.
fn save_and_revalidate(path: &Path, loaded: &Loaded) -> Result<Fixed, String> {
    match render(loaded).and_then(|bytes| save(path, &bytes)) {
        Err(error) => errorf(&format!("Failed to save auto-fixes: {error}")),
        Ok(()) => {
            hintf("Auto-fixes applied successfully.");
            if let Ok(reloaded) = load(path)
                && validate(&reloaded).is_empty()
            {
                return Ok(Fixed::Repaired(Box::new(reloaded)));
            }
            // Otherwise, continue to the manual editor fix.
        }
    }
    run_editor_fix(path).map(|()| Fixed::Edited)
}

/// Go's `runEditorFix`: confirm, resolve `$EDITOR` (default `vi`), run it on
/// the config path with the terminal inherited.
fn run_editor_fix(path: &Path) -> Result<(), String> {
    if !confirm("Open config.yaml in $EDITOR to fix manually?") {
        return Err("configuration fix aborted by user".to_owned());
    }
    let mut editor = env::var("EDITOR").unwrap_or_default();
    if editor.is_empty() {
        editor = "vi".to_owned();
    }
    let Some(resolved) = look_path(&editor) else {
        return Err(format!(
            "editor {} not found in PATH",
            symvault_core::go_quote(&editor)
        ));
    };
    let status = Command::new(resolved)
        .arg(path)
        .status()
        .map_err(|error| format!("editor failed: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("editor failed: {}", exit_status_text(status)))
    }
}

/// Go's `exec.LookPath`: a name with a slash is checked as given; otherwise
/// each `PATH` entry is tried, and a hit through a relative entry is rejected
/// (`exec.ErrDot`).
fn look_path(file: &str) -> Option<PathBuf> {
    if file.contains('/') {
        return is_executable(Path::new(file)).then(|| PathBuf::from(file));
    }
    let search = env::var_os("PATH")?;
    for dir in env::split_paths(&search) {
        let dir = if dir.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            dir
        };
        let candidate = dir.join(file);
        if is_executable(&candidate) {
            return candidate.is_absolute().then_some(candidate);
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if metadata.is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Go's `(*os.ProcessState).String()`: `exit status N` or `signal: <name>`.
fn exit_status_text(status: std::process::ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            let mut text = format!("signal: {}", signal_name(signal));
            if status.core_dumped() {
                text.push_str(" (core dumped)");
            }
            return text;
        }
    }
    format!("exit status {}", status.code().unwrap_or(-1))
}

/// Go's `syscall.Signal.String` table for the signals an editor realistically
/// dies from; other numbers print as `signal N`, like Go.
#[cfg(unix)]
fn signal_name(signal: i32) -> String {
    let name = match signal {
        1 => "hangup",
        2 => "interrupt",
        3 => "quit",
        4 => "illegal instruction",
        #[cfg(target_os = "macos")]
        5 => "trace/BPT trap",
        #[cfg(not(target_os = "macos"))]
        5 => "trace/breakpoint trap",
        #[cfg(target_os = "macos")]
        6 => "abort trap",
        #[cfg(not(target_os = "macos"))]
        6 => "aborted",
        8 => "floating point exception",
        9 => "killed",
        #[cfg(target_os = "macos")]
        10 => "bus error",
        #[cfg(not(target_os = "macos"))]
        10 => "user defined signal 1",
        11 => "segmentation fault",
        13 => "broken pipe",
        14 => "alarm clock",
        15 => "terminated",
        other => return format!("signal {other}"),
    };
    name.to_owned()
}

fn home_dir() -> String {
    #[cfg(windows)]
    let key = "USERPROFILE";
    #[cfg(not(windows))]
    let key = "HOME";
    env::var(key).unwrap_or_default()
}

// --- colour: Go's cliout.Hintf / cliout.Errorf on stderr ------------------

const SUCCESS_256: u8 = 82;
const ERROR_256: u8 = 203;
const WARN_256: u8 = 220;

/// Go styles through lipgloss' default renderer, which profiles *stdout*, and
/// only when stderr is a terminal and `NO_COLOR` is empty. Background
/// detection, `SYMVAULT_THEME` presets and `--color` are not modelled: the
/// dark-background default palette is assumed.
fn style(text: &str, color: u8) -> String {
    if env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty())
        || !io::stderr().is_terminal()
        || !io::stdout().is_terminal()
    {
        return text.to_owned();
    }
    let term = env::var("TERM").unwrap_or_default();
    let colorterm = env::var("COLORTERM").unwrap_or_default().to_lowercase();
    let truecolor =
        matches!(colorterm.as_str(), "truecolor" | "24bit") && !term.starts_with("screen");
    let code =
        if truecolor || term.contains("256color") || matches!(colorterm.as_str(), "yes" | "true") {
            format!("38;5;{color}")
        } else if term.is_empty() || term == "dumb" {
            return text.to_owned();
        } else {
            // 16-colour profile: the bright variant termenv picks for the palette.
            match color {
                SUCCESS_256 => "92".to_owned(),
                WARN_256 => "93".to_owned(),
                _ => "91".to_owned(),
            }
        };
    format!("\x1b[{code}m{text}\x1b[0m")
}

fn hintf(message: &str) {
    let mut err = io::stderr().lock();
    let _ = writeln!(err, "{}", style(message, SUCCESS_256));
}

/// Go's `cliout.Warnf` on stderr: the sink the loader hands its deprecation
/// warnings to (Go installs the same function with `config.SetWarnFunc`).
///
/// `--quiet` does not silence it. Go copies `ctx.QuietMode` into `cliout`
/// before cobra has parsed any flag, so the persistent flag never reaches
/// `cliout.isQuiet`, and neither does `--color`: the output is the plain
/// auto-colour one.
pub(crate) fn warnf(message: &str) {
    let mut err = io::stderr().lock();
    let _ = writeln!(err, "{}", style(message, WARN_256));
}

fn errorf(message: &str) {
    let mut err = io::stderr().lock();
    let _ = writeln!(err, "{}", style(message, ERROR_256));
}

// --- saving: Go's Config.SaveTo --------------------------------------------

/// The bytes Go's `SaveTo` marshals, from the typed config's writer.
fn render(loaded: &Loaded) -> Result<Vec<u8>, String> {
    let yaml = loaded
        .config
        .to_yaml_bytes()
        .map_err(|error| error.to_string())?;
    let mut yaml = String::from_utf8(yaml).map_err(|error| error.to_string())?;
    // The core writer double-quotes a whitespace-only string; yaml.v3 (Go)
    // single-quotes it. Only `vaultDir` can reach this state: a blank value
    // is exactly what the `vaultDir` auto-fix is offered for.
    let vault_dir = &loaded.config.vault_dir;
    if !vault_dir.is_empty() && vault_dir.chars().all(|c| c == ' ') {
        yaml = yaml.replacen(
            &format!("\nvaultDir: \"{vault_dir}\"\n"),
            &format!("\nvaultDir: '{vault_dir}'\n"),
            1,
        );
    }
    Ok(yaml.into_bytes())
}

/// Go's `Config.SaveTo` file handling: reject traversal, `MkdirAll(dir, 0700)`,
/// then a unique `<name>.tmp-<random>` sibling written 0600, synced and renamed
/// over the target. Error texts are Go's `*PathError` wording.
fn save(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err("config file path escapes expected directory".to_owned());
    }
    let clean = crate::agent_list_commands::clean_path(path);
    let dir = clean
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let dir = if dir.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        dir
    };
    make_private_dirs(&dir)?;
    let name = clean
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut attempts = 0;
    let (mut file, temporary) = loop {
        let mut random = [0u8; 4];
        getrandom::fill(&mut random).map_err(|error| error.to_string())?;
        let temporary = dir.join(format!("{name}.tmp-{}", u32::from_le_bytes(random)));
        match options.open(&temporary) {
            Ok(file) => break (file, temporary),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && attempts < 10_000 => {
                attempts += 1;
            }
            Err(error) => return Err(super::format_go_path_error("open", &temporary, &error)),
        }
    };
    let result = file
        .write_all(bytes)
        .map_err(|error| super::format_go_path_error("write", &temporary, &error))
        .and_then(|()| {
            file.sync_all()
                .map_err(|error| super::format_go_path_error("sync", &temporary, &error))
        })
        .and_then(|()| {
            drop(file);
            fs::rename(&temporary, path).map_err(|error| {
                format!(
                    "rename {} {}: {}",
                    temporary.display(),
                    path.display(),
                    super::go_errno_text(&error).unwrap_or("input/output error")
                )
            })
        });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn make_private_dirs(dir: &Path) -> Result<(), String> {
    if dir.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(dir)
            .map_err(|error| super::format_go_path_error("mkdir", dir, &error))
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir).map_err(|error| super::format_go_path_error("mkdir", dir, &error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(yaml: &str) -> Loaded {
        Loaded {
            config: Config::load_from_bytes(yaml.as_bytes()).expect("load"),
        }
    }

    #[test]
    fn sections_follow_go_merge_defaults() {
        let loaded = parsed(
            "audit:\n  maxSizeMb: 0\nlogging:\n  level: debug\nscan_patterns:\n  - name: foo\n",
        );
        let audit = loaded.config.audit.expect("audit section");
        assert_eq!(
            (audit.max_file_size, audit.max_backups, audit.max_age_days),
            (0, 5, 30)
        );
        let logging = loaded.config.logging.expect("logging section");
        assert_eq!(
            (logging.level.as_str(), logging.format.as_str()),
            ("debug", "text")
        );
        assert_eq!(loaded.config.scan_patterns.len(), 1);
        assert!(parsed("audit:\n").config.audit.is_none());
    }

    #[test]
    fn audit_error_sits_between_agent_and_clipboard_errors() {
        let mut loaded = parsed("audit:\n  maxSizeMb: -1\n");
        loaded.config.clipboard = Some(ClipboardConfig {
            auto_clear_duration: -1,
            copy_by_default: true,
            print_by_default: None,
        });
        let errors = validate(&loaded);
        assert!(errors[0].starts_with("audit.maxFileSize"), "{errors:?}");
        assert!(
            errors[1].starts_with("clipboard.autoClearDuration"),
            "{errors:?}"
        );
    }

    #[test]
    fn render_places_sections_in_go_struct_order() {
        let mut loaded = parsed(
            "audit:\n  maxSizeMb: 7\nlogging:\n  format: json\nscan_patterns:\n  - name: nm\n    pattern: p\n",
        );
        loaded.config.clipboard = Some(ClipboardConfig {
            auto_clear_duration: 30,
            copy_by_default: true,
            print_by_default: None,
        });
        let text = String::from_utf8(render(&loaded).expect("render")).expect("utf8");
        let clipboard = text.find("\nclipboard:\n").expect("clipboard");
        let audit = text
            .find("\naudit:\n    maxSizeMb: 7\n    maxBackups: 5\n    maxAgeDays: 30\n")
            .expect("audit");
        let logging = text
            .find("\nlogging:\n    level: warn\n    format: json\n")
            .expect("logging");
        let vault_dir = text.find("\nvaultDir:").expect("vaultDir");
        assert!(
            clipboard < audit && audit < logging && logging < vault_dir,
            "{text}"
        );
        assert!(text.ends_with("scan_patterns:\n    - name: nm\n      pattern: p\n      description: \"\"\n      severity: \"\"\n"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn signal_names_match_go() {
        assert_eq!(signal_name(9), "killed");
        assert_eq!(signal_name(15), "terminated");
        assert_eq!(signal_name(2), "interrupt");
        assert_eq!(signal_name(44), "signal 44");
    }

    #[test]
    fn look_path_rejects_directories_and_missing_names() {
        assert!(look_path("/definitely/not/a/real/editor").is_none());
        assert!(look_path("/tmp").is_none());
    }
}
