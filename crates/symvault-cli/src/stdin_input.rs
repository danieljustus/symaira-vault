//! Go's stdin readers (`internal/cli/terminal.go`): the hidden terminal read
//! (`term.ReadPassword`), the unbuffered `ReadLineFromStdin` and the shared
//! `bufio.Reader` that `set` hands to its prompts.
//!
//! Everything works on bytes (Go reads and stores raw bytes) and keeps every
//! buffer in `Zeroizing`.

use std::{
    fs::File,
    io::{self, Read},
    os::fd::AsFd,
    sync::Mutex,
};

use zeroize::Zeroizing;

/// `bufio.defaultBufSize`: Go's reader takes at most this much per `read(2)`.
const BUFIO_SIZE: usize = 4096;

/// A secret line buffer: sized up front, and when a line outgrows it the old
/// allocation is wiped before it is freed, so no stray copy of a growing
/// passphrase is left on the heap.
fn secret_line() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Vec::with_capacity(LINE_CAPACITY))
}

fn push_secret(line: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    if line.capacity() - line.len() < bytes.len() {
        let mut grown = Zeroizing::new(Vec::with_capacity(
            (line.len() + bytes.len()).max(line.capacity() * 2),
        ));
        grown.extend_from_slice(line);
        std::mem::swap(line, &mut grown);
        // `grown` now holds the old allocation and wipes it on drop.
    }
    line.extend_from_slice(bytes);
}

/// Room for any ordinary passphrase line without a reallocation.
const LINE_CAPACITY: usize = 4096;

fn stdin_file() -> io::Result<File> {
    Ok(File::from(io::stdin().as_fd().try_clone_to_owned()?))
}

/// `cli.ReadLineFromStdin`: unbuffered, one byte per `read(2)`, so nothing
/// beyond the line is consumed. `None` is Go's `(nil, io.EOF)`: end of input
/// before any byte.
pub(crate) fn read_unbuffered_line() -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut file = stdin_file()?;
    let mut line = secret_line();
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        match file.read(&mut byte[..]) {
            Ok(0) => return Ok((!line.is_empty()).then_some(line)),
            Ok(_) if byte[0] == b'\n' => return Ok(Some(line)),
            Ok(_) => push_secret(&mut line, &byte[..]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                if line.is_empty() {
                    return Err(error);
                }
                return Ok(Some(line));
            }
        }
    }
}

struct Bufio {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

static BUFIO: Mutex<Bufio> = Mutex::new(Bufio {
    buf: Vec::new(),
    start: 0,
    end: 0,
});

/// `bufio.Reader.ReadString('\n')` on the process-wide reader `set` creates
/// over `os.Stdin`: the delimiter is kept; the flag is true when the input
/// ended before one (Go returns the partial line with `io.EOF`). The reader
/// takes up to 4096 bytes per fill, so what it has buffered is gone for later
/// unbuffered reads, exactly as in Go.
pub(crate) fn read_buffered_line() -> io::Result<(Zeroizing<Vec<u8>>, bool)> {
    let mut state = BUFIO
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if state.buf.is_empty() {
        state.buf = vec![0u8; BUFIO_SIZE];
    }
    let mut file = stdin_file()?;
    let mut line = secret_line();
    loop {
        let (start, end) = (state.start, state.end);
        if let Some(offset) = state.buf[start..end].iter().position(|&byte| byte == b'\n') {
            push_secret(&mut line, &state.buf[start..=start + offset]);
            // The consumed bytes live on in `line`; do not leave a second
            // copy in the process-wide buffer.
            state.buf[start..=start + offset].fill(0);
            state.start = start + offset + 1;
            return Ok((line, false));
        }
        push_secret(&mut line, &state.buf[start..end]);
        state.buf[start..end].fill(0);
        state.start = 0;
        state.end = 0;
        let read = loop {
            match file.read(&mut state.buf[..]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                other => break other,
            }
        };
        match read {
            Ok(0) => return Ok((line, true)),
            Ok(count) => state.end = count,
            Err(error) => {
                if line.is_empty() {
                    return Err(error);
                }
                return Ok((line, true));
            }
        }
    }
}

/// Puts the terminal's attributes back when dropped, so every way out of the
/// hidden read (including an unwinding panic) restores echo. A signal that
/// ends the process does not run it: Go's `defer` does not run then either, and
/// with `ISIG` on a Ctrl-C kills both binaries with echo still off.
#[cfg(unix)]
struct TermiosRestore {
    stdin: io::Stdin,
    original: rustix::termios::Termios,
}

#[cfg(unix)]
impl Drop for TermiosRestore {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            &self.stdin,
            rustix::termios::OptionalActions::Now,
            &self.original,
        );
    }
}

/// `term.ReadPassword(os.Stdin.Fd())`: echo off, canonical mode on, bytes up
/// to the newline (CRs dropped, backspace erases). End of input before any
/// byte is Go's `io.EOF`, reported as the text `EOF`; Ctrl-D on an open
/// terminal is ignored, as in Go.
#[cfg(unix)]
pub(crate) fn read_hidden_tty() -> Result<Zeroizing<Vec<u8>>, String> {
    use rustix::termios::{InputModes, LocalModes, OptionalActions, tcgetattr, tcsetattr};

    let stdin = io::stdin();
    let describe = |error: rustix::io::Errno| go_errno_text(&io::Error::from(error));
    let original = tcgetattr(&stdin).map_err(describe)?;
    let mut hidden = original.clone();
    hidden.local_modes.remove(LocalModes::ECHO);
    hidden
        .local_modes
        .insert(LocalModes::ICANON | LocalModes::ISIG);
    hidden.input_modes.insert(InputModes::ICRNL);
    tcsetattr(&stdin, OptionalActions::Now, &hidden).map_err(describe)?;
    let _restore = TermiosRestore { stdin, original };

    stdin_file()
        .map_err(|error| go_errno_text(&error))
        .and_then(|mut file| read_password_line(&mut file, &mut HangupWatch::new()))
}

/// Without termios, fall back to the platform's secure read.
#[cfg(not(unix))]
pub(crate) fn read_hidden_tty() -> Result<Zeroizing<Vec<u8>>, String> {
    rpassword::read_password()
        .map(|text| Zeroizing::new(text.into_bytes()))
        .map_err(|error| go_errno_text(&error))
}

/// Decides what a zero-byte read of the terminal means.
///
/// Go reads the terminal with a raw `read(2)` and `readPasswordLine` loops on
/// `(0, nil)`, so Ctrl-D (the terminal's EOF character, one zero-byte read) is
/// ignored and the prompt keeps waiting. On a terminal that has hung up the
/// read returns zero immediately and forever, which spins Go's process at full
/// CPU. A zero-byte read that comes back at once, many times in a row, is that
/// hang-up here: it ends the read as end of input instead of spinning. A human
/// pressing Ctrl-D never gets near the limit, each press being a separate wait.
struct HangupWatch {
    last: Option<std::time::Instant>,
    streak: u32,
}

impl HangupWatch {
    /// Consecutive immediate zero-byte reads that mean "hung up".
    const LIMIT: u32 = 64;
    /// A zero-byte read this soon after the previous one did not wait for a key.
    const IMMEDIATE: std::time::Duration = std::time::Duration::from_millis(5);

    const fn new() -> Self {
        Self {
            last: None,
            streak: 0,
        }
    }

    /// Records a zero-byte read; true while the terminal is still open.
    fn still_open(&mut self) -> bool {
        let now = std::time::Instant::now();
        let immediate = self
            .last
            .is_some_and(|last| now.duration_since(last) < Self::IMMEDIATE);
        self.last = Some(now);
        self.streak = if immediate { self.streak + 1 } else { 0 };
        self.streak < Self::LIMIT
    }
}

/// x/term's `readPasswordLine` (the non-Windows branch).
#[cfg(unix)]
fn read_password_line(
    reader: &mut impl Read,
    watch: &mut HangupWatch,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut line = secret_line();
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        match reader.read(&mut byte[..]) {
            Ok(0) => {
                // Go: `(0, nil)` from the raw read is not an error; keep reading.
                if watch.still_open() {
                    continue;
                }
                if line.is_empty() {
                    return Err("EOF".to_owned());
                }
                return Ok(line);
            }
            Ok(_) => match byte[0] {
                b'\x08' => {
                    line.pop();
                }
                b'\n' => return Ok(line),
                b'\r' => {}
                other => push_secret(&mut line, &[other]),
            },
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(go_errno_text(&error)),
        }
    }
}

/// Go prints an errno in lower case without Rust's ` (os error N)` suffix.
fn go_errno_text(error: &io::Error) -> String {
    let text = error.to_string();
    let text = text.split(" (os error").next().unwrap_or(&text).to_owned();
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => text,
    }
}

/// `string(bytes)` as Go's JSON encoder stores it: every invalid UTF-8 byte
/// becomes one U+FFFD (Rust's lossy conversion folds a truncated sequence
/// into one).
pub(crate) fn go_string(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len().saturating_mul(3)));
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                out.push_str(text);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if let Ok(text) = std::str::from_utf8(&rest[..valid]) {
                    out.push_str(text);
                }
                out.push('\u{fffd}');
                rest = &rest[valid + 1..];
            }
        }
    }
    out
}

/// `bytes.TrimSpace` over the Go string form of `bytes`.
pub(crate) fn trim_space(bytes: &[u8]) -> Zeroizing<String> {
    let text = go_string(bytes);
    let trimmed = text.trim();
    if trimmed.len() == text.len() {
        return text;
    }
    Zeroizing::new(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_string_replaces_each_invalid_byte() {
        assert_eq!(go_string(b"caf\xe9").as_str(), "caf\u{fffd}");
        // A truncated three byte sequence is two bad bytes to Go.
        assert_eq!(go_string(b"a\xe2\x82b").as_str(), "a\u{fffd}\u{fffd}b");
        assert_eq!(go_string("é".as_bytes()).as_str(), "é");
    }

    #[test]
    fn trim_space_trims_unicode_space_only() {
        assert_eq!(trim_space(b"  hi there \t\r\n").as_str(), "hi there");
        assert_eq!(trim_space("\u{a0}x\u{2003}".as_bytes()).as_str(), "x");
        assert_eq!(trim_space(b"\xffx\xff").as_str(), "\u{fffd}x\u{fffd}");
    }

    #[cfg(unix)]
    #[test]
    fn password_line_follows_x_term() {
        let mut input: &[u8] = b"ab\x08c\r\nrest";
        let mut watch = HangupWatch::new();
        assert_eq!(
            read_password_line(&mut input, &mut watch)
                .unwrap()
                .as_slice(),
            b"ac"
        );
        // A reader that never blocks and is at its end: a hung-up terminal.
        let mut empty: &[u8] = b"";
        assert_eq!(
            read_password_line(&mut empty, &mut HangupWatch::new()).unwrap_err(),
            "EOF"
        );
        let mut partial: &[u8] = b"xy";
        assert_eq!(
            read_password_line(&mut partial, &mut HangupWatch::new())
                .unwrap()
                .as_slice(),
            b"xy"
        );
    }

    /// Reads that yield scripted chunks; an empty chunk is a zero-byte read.
    #[cfg(unix)]
    struct Scripted(std::collections::VecDeque<Vec<u8>>);

    #[cfg(unix)]
    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.pop_front() {
                None => Ok(0),
                Some(chunk) => {
                    buf[..chunk.len()].copy_from_slice(&chunk);
                    Ok(chunk.len())
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn ctrl_d_on_an_open_terminal_is_ignored_like_x_term() {
        // 'a', Ctrl-D (a zero-byte read), 'b', Ctrl-D, newline.
        let script = [&b"a"[..], b"", b"b", b"", b"\n"];
        let mut reader = Scripted(script.iter().map(|chunk| chunk.to_vec()).collect());
        let line = read_password_line(&mut reader, &mut HangupWatch::new()).unwrap();
        assert_eq!(line.as_slice(), b"ab");
    }

    #[cfg(unix)]
    #[test]
    fn a_hung_up_terminal_ends_as_eof_instead_of_spinning() {
        let mut reader = Scripted(std::collections::VecDeque::new());
        assert_eq!(
            read_password_line(&mut reader, &mut HangupWatch::new()).unwrap_err(),
            "EOF"
        );
    }

    #[test]
    fn secret_lines_grow_without_leaving_the_old_allocation_live() {
        let mut line = secret_line();
        assert_eq!(line.capacity(), LINE_CAPACITY);
        push_secret(&mut line, &vec![b'x'; LINE_CAPACITY + 10]);
        assert_eq!(line.len(), LINE_CAPACITY + 10);
        assert!(line.iter().all(|&byte| byte == b'x'));
    }
}
