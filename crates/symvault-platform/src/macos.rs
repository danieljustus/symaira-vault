//! Native macOS adapters.
//!
//! These adapters use the maintained Keychain Services wrapper and public
//! macOS command-line bridges (`osascript`, `pbcopy`, and `launchctl`) without
//! putting secret values in argv. The core traits remain injectable, so tests
//! never need the user's keychain, pasteboard, GUI, or LaunchAgents directory.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use symvault_core::{
    platform::{
        Autotype, Clipboard, Daemon, Notifier, PlatformError, PlatformErrorKind, SecureUi, TouchId,
    },
    session::{Keyring, SessionError},
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
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| unavailable("native macOS helper unavailable"))?;
    if let Some(mut stdin) = child.stdin.take()
        && stdin.write_all(input).is_err()
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(failed("native macOS helper input failed"));
    }
    let deadline = Instant::now() + bounded_timeout(timeout);
    loop {
        match child
            .try_wait()
            .map_err(|_| failed("native macOS helper status failed"))?
        {
            Some(status) => {
                let output = child
                    .wait_with_output()
                    .map_err(|_| failed("native macOS helper output failed"))?;
                if status.success() {
                    return Ok(output.stdout);
                }
                return Err(failed("native macOS helper returned an error"));
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(PlatformError {
                    kind: PlatformErrorKind::TimedOut,
                    message: "native macOS helper timed out".to_owned(),
                });
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }
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
    let mut result = String::with_capacity(value.len() + 2);
    result.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            ch if ch.is_control() => {
                result.push_str(&format!("\\u{:04x}", ch as u32));
            }
            ch => result.push(ch),
        }
    }
    result.push('"');
    result
}

/// macOS Keychain Services through the maintained `keyring` adapter. This is
/// intentionally a separate type from the in-memory test keyring.
#[derive(Default)]
pub struct MacOsKeyring;

impl MacOsKeyring {
    fn entry(key: &str) -> Result<keyring::Entry, SessionError> {
        let split = key.rfind('|');
        let Some(index) = split else {
            return Err(SessionError::Keyring("invalid keyring key".to_owned()));
        };
        let (service, account) = key.split_at(index);
        let account = &account[1..];
        keyring::Entry::new(service, account)
            .map_err(|_| SessionError::Keyring("native macOS keychain unavailable".to_owned()))
    }

    fn unavailable(_error: keyring::Error) -> SessionError {
        // Do not copy provider diagnostics into session errors: some keychain
        // implementations include account or path details in their display.
        SessionError::Keyring("native macOS keychain operation failed".to_owned())
    }
}

impl Keyring for MacOsKeyring {
    fn get(&self, key: &str) -> Result<Vec<u8>, SessionError> {
        Self::entry(key)?.get_secret().map_err(|error| {
            if matches!(error, keyring::Error::NoEntry) {
                SessionError::NotFound
            } else {
                Self::unavailable(error)
            }
        })
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), SessionError> {
        Self::entry(key)?
            .set_secret(value)
            .map_err(Self::unavailable)
    }

    fn delete(&self, key: &str) -> Result<(), SessionError> {
        match Self::entry(key)?.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(Self::unavailable(error)),
        }
    }
}

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

    #[test]
    fn jxa_strings_are_escaped_without_changing_content() {
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
}
