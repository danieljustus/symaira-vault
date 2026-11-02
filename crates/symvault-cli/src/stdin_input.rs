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

fn stdin_file() -> io::Result<File> {
    Ok(File::from(io::stdin().as_fd().try_clone_to_owned()?))
}

/// `cli.ReadLineFromStdin`: unbuffered, one byte per `read(2)`, so nothing
/// beyond the line is consumed. `None` is Go's `(nil, io.EOF)`: end of input
/// before any byte.
pub(crate) fn read_unbuffered_line() -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut file = stdin_file()?;
    let mut line = Zeroizing::new(Vec::new());
    let mut byte = [0u8; 1];
    loop {
        match file.read(&mut byte) {
            Ok(0) => return Ok((!line.is_empty()).then_some(line)),
            Ok(_) if byte[0] == b'\n' => return Ok(Some(line)),
            Ok(_) => line.push(byte[0]),
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
    let mut line = Zeroizing::new(Vec::new());
    loop {
        let (start, end) = (state.start, state.end);
        if let Some(offset) = state.buf[start..end].iter().position(|&byte| byte == b'\n') {
            line.extend_from_slice(&state.buf[start..=start + offset]);
            state.start = start + offset + 1;
            return Ok((line, false));
        }
        line.extend_from_slice(&state.buf[start..end]);
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

/// `term.ReadPassword(os.Stdin.Fd())`: echo off, canonical mode on, bytes up
/// to the newline (CRs dropped, backspace erases). End of input before any
/// byte is Go's `io.EOF`, reported as the text `EOF`.
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

    let result = stdin_file()
        .map_err(|error| go_errno_text(&error))
        .and_then(|mut file| read_password_line(&mut file));
    let _ = tcsetattr(&stdin, OptionalActions::Now, &original);
    result
}

/// Without termios, fall back to the platform's secure read.
#[cfg(not(unix))]
pub(crate) fn read_hidden_tty() -> Result<Zeroizing<Vec<u8>>, String> {
    rpassword::read_password()
        .map(|text| Zeroizing::new(text.into_bytes()))
        .map_err(|error| go_errno_text(&error))
}

/// x/term's `readPasswordLine` (the non-Windows branch).
#[cfg(unix)]
fn read_password_line(reader: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut line = Zeroizing::new(Vec::new());
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
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
                other => line.push(other),
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
        assert_eq!(read_password_line(&mut input).unwrap().as_slice(), b"ac");
        let mut empty: &[u8] = b"";
        assert_eq!(read_password_line(&mut empty).unwrap_err(), "EOF");
        let mut partial: &[u8] = b"xy";
        assert_eq!(read_password_line(&mut partial).unwrap().as_slice(), b"xy");
    }
}
