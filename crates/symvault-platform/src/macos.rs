//! Native macOS adapters.
//!
//! These adapters use the maintained Keychain Services wrapper and public
//! macOS command-line bridges (`osascript`, `pbcopy`, and `launchctl`) without
//! putting secret values in argv. The core traits remain injectable, so tests
//! never need the user's keychain, pasteboard, GUI, or LaunchAgents directory.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use symvault_core::platform::{
    Autotype, Clipboard, Daemon, Notifier, PlatformError, PlatformErrorKind, SecureUi, TouchId,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const LAUNCH_AGENT_LABEL: &str = "com.symvault.mcp";
const LAUNCH_AGENT_FILE: &str = "com.symvault.mcp.plist";

fn failed(message: &'static str) -> PlatformError {
    PlatformError {
        kind: PlatformErrorKind::Failed,
        message: message.to_owned(),
    }
}

fn unavailable(message: &'static str) -> PlatformError {
    PlatformError::unavailable(message)
}

fn contains_disallowed_runtime_character(value: &str) -> bool {
    value.chars().any(|ch| {
        matches!(
            ch,
            '\n' | '\r' | '<' | '>' | '"' | '\'' | '$' | '`' | ';' | '&' | '|'
        )
    })
}

fn bounded_timeout(timeout: Duration) -> Duration {
    if timeout.is_zero() {
        DEFAULT_TIMEOUT
    } else {
        timeout
    }
}

/// Run a small native helper with a deadline. Input is always sent through
/// stdin, keeping secrets out of the process argument list.
fn run_stdin_command(
    program: &str,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, PlatformError> {
    let output = run_native_process(program, args, input, timeout)?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(failed("native macOS helper returned an error"))
    }
}

pub(crate) fn run_native_process(
    program: &str,
    args: &[&str],
    input: &[u8],
    timeout: Duration,
) -> Result<std::process::Output, PlatformError> {
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
    use std::os::unix::process::CommandExt;

    let deadline = Instant::now()
        .checked_add(bounded_timeout(timeout))
        .ok_or_else(|| failed("native macOS helper timeout out of range"))?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Preserve private-home keychain routing in the disposable native runner.
    // No credential-bearing environment variables reach native helpers.
    if let Some(home) = std::env::var_os("HOME") {
        command.env("HOME", home);
    }
    let mut child = command
        .spawn()
        .map_err(|_| unavailable("native macOS helper unavailable"))?;
    let result = (|| {
        let mut stdin = child.stdin.take();
        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");
        // All three pipes must make progress together. Secrets stay in memory,
        // and a helper that never reads stdin cannot bypass the deadline.
        for fd in [
            std::os::fd::AsFd::as_fd(stdin.as_ref().expect("piped stdin")),
            std::os::fd::AsFd::as_fd(&stdout),
            std::os::fd::AsFd::as_fd(&stderr),
        ] {
            let flags = fcntl_getfl(fd).map_err(|_| failed("native helper pipe setup failed"))?;
            fcntl_setfl(fd, flags | OFlags::NONBLOCK)
                .map_err(|_| failed("native helper pipe setup failed"))?;
        }
        let mut written = 0;
        let mut output = Vec::new();
        let mut diagnostic = Vec::new();
        let (mut stdout_done, mut stderr_done) = (false, false);
        let mut status = None;
        loop {
            if let Some(pipe) = stdin.as_mut() {
                match pipe.write(&input[written..]) {
                    Ok(count) => written += count,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return Err(failed("native macOS helper input failed")),
                }
                if written == input.len() {
                    stdin.take();
                }
            }
            for (pipe, done, captured) in [
                (&mut stdout as &mut dyn Read, &mut stdout_done, &mut output),
                (
                    &mut stderr as &mut dyn Read,
                    &mut stderr_done,
                    &mut diagnostic,
                ),
            ] {
                if *done {
                    continue;
                }
                let mut buffer = [0_u8; 8192];
                match pipe.read(&mut buffer) {
                    Ok(0) => *done = true,
                    Ok(count) => captured.extend_from_slice(&buffer[..count]),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return Err(failed("native macOS helper output failed")),
                }
            }
            if status.is_none() {
                status = child
                    .try_wait()
                    .map_err(|_| failed("native macOS helper status failed"))?;
            }
            if let Some(status) = status
                && stdout_done
                && stderr_done
                && stdin.is_none()
            {
                return Ok(std::process::Output {
                    status,
                    stdout: output,
                    stderr: diagnostic,
                });
            }
            if Instant::now() >= deadline {
                return Err(PlatformError {
                    kind: PlatformErrorKind::TimedOut,
                    message: "native macOS helper timed out".to_owned(),
                });
            }
            thread::sleep(Duration::from_millis(1));
        }
    })();
    if result.is_err() {
        let group = format!("-{}", child.id());
        let _ = Command::new("/bin/kill")
            .args(["-KILL", "--", &group])
            .output();
        let _ = child.kill();
    }
    let _ = child.wait();
    result
}

fn run_jxa(script: &str, timeout: Duration) -> Result<Vec<u8>, PlatformError> {
    run_stdin_command(
        "/usr/bin/osascript",
        &["-l", "JavaScript"],
        script.as_bytes(),
        timeout,
    )
}

fn js_string(value: &str) -> String {
    serde_json::to_string(value)
        .expect("strings always serialize")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029")
}

/// Backward-compatible macOS name for the shared native OS keyring adapter.
pub use crate::os_keyring::OsKeyring as MacOsKeyring;

/// Touch ID availability and authentication using LocalAuthentication via
/// JavaScript for Automation. The authenticator returns only a decision.
#[derive(Default)]
pub struct MacOsTouchId;

impl MacOsTouchId {
    fn availability_script() -> &'static str {
        r#"ObjC.import('LocalAuthentication');
var context = $.LAContext.alloc.init;
var error = $();
var available = context.canEvaluatePolicyError(2, error);
console.log(available ? 'available' : 'unavailable');"#
    }

    fn authentication_script(reason: &str) -> String {
        format!(
            "ObjC.import('Foundation');\nObjC.import('LocalAuthentication');\nvar context = $.LAContext.alloc.init;\nvar result = null;\nvar error = $();\nif (!context.canEvaluatePolicyError(2, error)) {{ console.log('unavailable'); }} else {{ context.evaluatePolicyLocalizedReasonReply(2, {}, function(success, replyError) {{ result = success; }}); while (result === null) {{ $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.05)); }} console.log(result ? 'authenticated' : 'rejected'); }}\n",
            js_string(reason)
        )
    }
}

impl TouchId for MacOsTouchId {
    fn is_available(&self) -> bool {
        run_jxa(Self::availability_script(), Duration::from_secs(5))
            .map(|output| output == b"available\n" || output == b"available")
            .unwrap_or(false)
    }

    fn authenticate(&self, reason: &str, timeout: Duration) -> Result<(), PlatformError> {
        if !self.is_available() {
            return Err(unavailable("touch id unavailable"));
        }
        let output = run_jxa(&Self::authentication_script(reason), timeout)?;
        match output.as_slice() {
            b"authenticated\n" | b"authenticated" => Ok(()),
            b"unavailable\n" | b"unavailable" => Err(unavailable("touch id unavailable")),
            _ => Err(PlatformError {
                kind: PlatformErrorKind::Canceled,
                message: "touch id authentication was not accepted".to_owned(),
            }),
        }
    }
}

/// macOS automated typing through System Events. Accessibility permission
/// failures are surfaced; text is never put in argv.
#[derive(Default)]
pub struct MacOsPlatform;

impl MacOsPlatform {
    /// These are capability probes only. Permission failures still return an
    /// error from the operation rather than being reported as success.
    pub fn clipboard_available(&self) -> bool {
        Path::new("/usr/bin/pbcopy").is_file()
    }

    pub fn autotype_available(&self) -> bool {
        Path::new("/usr/bin/osascript").is_file()
    }

    pub fn notification_available(&self) -> bool {
        self.autotype_available()
    }
}

impl Autotype for MacOsPlatform {
    fn type_text(&self, text: &str) -> Result<(), PlatformError> {
        let script = format!(
            "Application('System Events').keystroke({});",
            js_string(text)
        );
        run_jxa(&script, DEFAULT_TIMEOUT).map(|_| ())
    }
}

impl Clipboard for MacOsPlatform {
    fn set(&self, text: &[u8]) -> Result<(), PlatformError> {
        run_stdin_command("/usr/bin/pbcopy", &[], text, DEFAULT_TIMEOUT).map(|_| ())
    }

    fn clear(&self) -> Result<(), PlatformError> {
        self.set(b"")
    }
}

impl Notifier for MacOsPlatform {
    fn notify(&self, title: &str, message: &str) -> Result<(), PlatformError> {
        let script = format!(
            "var app = Application.currentApplication(); app.includeStandardAdditions = true; app.displayNotification({}, {{ withTitle: {} }});",
            js_string(message),
            js_string(title)
        );
        run_jxa(&script, DEFAULT_TIMEOUT).map(|_| ())
    }
}

impl SecureUi for MacOsPlatform {
    fn prompt(
        &self,
        title: &str,
        hidden: bool,
        timeout: Duration,
    ) -> Result<Vec<u8>, PlatformError> {
        let hidden_answer = if hidden { "true" } else { "false" };
        let script = format!(
            "var app = Application.currentApplication(); app.includeStandardAdditions = true; var answer = app.displayDialog('', {{ withTitle: {}, defaultAnswer: '', hiddenAnswer: {} }}); console.log(answer.textReturned);",
            js_string(title),
            hidden_answer
        );
        let output = run_jxa(&script, timeout)?;
        Ok(output.strip_suffix(b"\n").unwrap_or(&output).to_vec())
    }

    fn approve(&self, operation: &str, timeout: Duration) -> Result<bool, PlatformError> {
        let script = format!(
            "var app = Application.currentApplication(); app.includeStandardAdditions = true; var answer = app.displayDialog({}, {{ withTitle: 'Symaira Vault', buttons: ['Cancel', 'Allow'], defaultButton: 'Allow', cancelButton: 'Cancel' }}); console.log(answer.buttonReturned);",
            js_string(operation)
        );
        let output = run_jxa(&script, timeout)?;
        Ok(output.trim_ascii() == b"Allow")
    }
}

/// launchd user-agent adapter. `with_home` exists for tests and never invokes
/// launchctl; production construction uses the real user home explicitly.
pub struct MacOsDaemon {
    home: PathBuf,
    binary_path: PathBuf,
    vault_dir: PathBuf,
    bind: String,
    port: u16,
}

impl MacOsDaemon {
    pub fn new(
        binary_path: impl Into<PathBuf>,
        vault_dir: impl Into<PathBuf>,
        bind: impl Into<String>,
        port: u16,
    ) -> Result<Self, PlatformError> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| unavailable("macOS home directory unavailable"))?;
        Ok(Self {
            home,
            binary_path: binary_path.into(),
            vault_dir: vault_dir.into(),
            bind: bind.into(),
            port,
        })
    }

    pub fn with_home(
        home: impl Into<PathBuf>,
        binary_path: impl Into<PathBuf>,
        vault_dir: impl Into<PathBuf>,
        bind: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            home: home.into(),
            binary_path: binary_path.into(),
            vault_dir: vault_dir.into(),
            bind: bind.into(),
            port,
        }
    }

    pub fn plist_path(&self) -> PathBuf {
        self.home
            .join("Library")
            .join("LaunchAgents")
            .join(LAUNCH_AGENT_FILE)
    }

    pub fn render_plist(&self) -> String {
        fn xml(value: &Path) -> String {
            xml_text(&value.to_string_lossy())
        }
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>{}</string><key>ProgramArguments</key><array><string>{}</string><string>serve</string><string>--port</string><string>{}</string><string>--bind</string><string>{}</string></array><key>EnvironmentVariables</key><dict><key>SYMVAULT_VAULT</key><string>{}</string></dict><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>\n",
            LAUNCH_AGENT_LABEL,
            xml(&self.binary_path),
            self.port,
            xml_text(&self.bind),
            xml(&self.vault_dir)
        )
    }

    fn write_plist(&self) -> Result<(), PlatformError> {
        if !self.binary_path.is_absolute() || !self.vault_dir.is_absolute() {
            return Err(failed("daemon paths must be absolute"));
        }
        if contains_disallowed_runtime_character(&self.binary_path.to_string_lossy())
            || contains_disallowed_runtime_character(&self.vault_dir.to_string_lossy())
        {
            return Err(failed("daemon paths contain disallowed characters"));
        }
        if self.bind.trim().is_empty() || self.port == 0 {
            return Err(failed("daemon bind and port are invalid"));
        }
        if contains_disallowed_runtime_character(&self.bind) {
            return Err(failed("daemon bind contains disallowed characters"));
        }
        let path = self.plist_path();
        fs::create_dir_all(path.parent().expect("launch agent has a parent"))
            .map_err(|_| failed("launch agent directory could not be created"))?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .map_err(|_| failed("launch agent could not be written"))?;
        file.write_all(self.render_plist().as_bytes())
            .map_err(|_| failed("launch agent could not be written"))?;
        file.sync_all()
            .map_err(|_| failed("launch agent could not be synced"))
    }

    fn launchctl(&self, args: &[&str]) -> Result<Vec<u8>, PlatformError> {
        run_stdin_command("/bin/launchctl", args, b"", DEFAULT_TIMEOUT)
    }
}

impl Daemon for MacOsDaemon {
    fn install(&self) -> Result<(), PlatformError> {
        self.write_plist()?;
        let path = self.plist_path();
        let path = path.to_string_lossy();
        let _ = self.launchctl(&["unload", &path]);
        self.launchctl(&["load", &path]).map(|_| ())
    }

    fn uninstall(&self) -> Result<(), PlatformError> {
        let path = self.plist_path();
        let path_string = path.to_string_lossy().into_owned();
        let _ = self.launchctl(&["unload", &path_string]);
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(failed("launch agent could not be removed")),
        }
    }

    fn status(&self) -> Result<bool, PlatformError> {
        if !self.plist_path().is_file() {
            return Ok(false);
        }
        Ok(self.launchctl(&["list", LAUNCH_AGENT_LABEL]).is_ok())
    }
}

fn xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use symvault_core::session::{Keyring, SessionError};

    #[test]
    fn native_helper_drains_pipes_and_bounds_blocked_input_and_descendants() {
        let input = vec![b'x'; 256 * 1024];
        let output = run_stdin_command(
            "/bin/sh",
            &["-c", "head -c 131072 /dev/zero >&2; cat"],
            &input,
            Duration::from_secs(5),
        )
        .expect("large bidirectional pipe traffic completes");
        assert_eq!(output, input);
        for (script, bytes) in [
            ("sleep 30", input.as_slice()),
            ("sleep 30 & exit 0", &[][..]),
        ] {
            let start = Instant::now();
            let error = run_stdin_command(
                "/bin/sh",
                &["-c", script],
                bytes,
                Duration::from_millis(100),
            )
            .expect_err("blocked helper fails");
            assert_eq!(error.kind, PlatformErrorKind::TimedOut);
            assert!(start.elapsed() < Duration::from_secs(3));
        }
    }

    #[test]
    fn jxa_strings_are_escaped_without_changing_content() {
        let source = "line\u{2028}paragraph\u{2029}literal\\u2028";
        let encoded = js_string(source);
        assert!(!encoded.contains(['\u{2028}', '\u{2029}']));
        assert_eq!(serde_json::from_str::<String>(&encoded).unwrap(), source);
        assert_eq!(js_string("a\\\"\n\t"), "\"a\\\\\\\"\\n\\t\"");
    }

    #[test]
    fn daemon_plist_escapes_paths_and_keeps_secret_values_out_of_argv() {
        let daemon = MacOsDaemon::with_home(
            "/tmp/symvault-platform-test",
            "/Applications/Sym&Vault/symvault",
            "/tmp/vault/<fixture>",
            "127.0.0.1",
            8787,
        );
        let plist = daemon.render_plist();
        assert!(plist.contains("Sym&amp;Vault"));
        assert!(plist.contains("&lt;fixture&gt;"));
        assert!(plist.contains("<string>8787</string>"));
    }

    #[test]
    fn native_capability_probes_are_noninteractive() {
        let platform = MacOsPlatform;
        assert_eq!(
            platform.autotype_available(),
            Path::new("/usr/bin/osascript").is_file()
        );
        assert_eq!(
            platform.clipboard_available(),
            Path::new("/usr/bin/pbcopy").is_file()
        );
        assert_eq!(
            platform.notification_available(),
            platform.autotype_available()
        );
        // LAContext canEvaluatePolicy does not display an authentication prompt.
        let _ = MacOsTouchId.is_available();
    }

    #[test]
    fn malformed_keyring_key_fails_before_native_access() {
        assert!(matches!(
            MacOsKeyring.get("not-a-composite-key"),
            Err(SessionError::Keyring(_))
        ));
    }

    #[test]
    fn touch_id_authentication_script_returns_only_a_decision() {
        let script = MacOsTouchId::authentication_script("fixture reason");
        assert!(script.contains("authenticated"));
        assert!(script.contains("rejected"));
        assert!(!script.contains("passphrase"));
    }

    #[test]
    fn daemon_rejects_invalid_runtime_options_before_writing() {
        for (bind, port) in [("", 8787), ("127.0.0.1\nlaunch", 8787), ("127.0.0.1", 0)] {
            let daemon = MacOsDaemon::with_home(
                "/tmp/symvault-platform-invalid",
                "/usr/bin/true",
                "/tmp/symvault-platform-vault",
                bind,
                port,
            );
            let error = daemon.install().unwrap_err();
            assert_eq!(error.kind, PlatformErrorKind::Failed);
            assert!(!daemon.plist_path().exists());
        }
    }
}
