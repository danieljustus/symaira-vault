//! Go `filippo.io/age` decryption diagnostics.
//!
//! `symvault-crypto` decides *whether* a ciphertext decrypts. When it does not,
//! the Go bridge's error text depends on where age gave up: header parsing,
//! stanza unwrapping, the header MAC, the nonce, or a payload chunk. This module
//! repeats that walk (a port of `internal/format.Parse`, the relevant parts of
//! `age.decryptHdr` and `internal/stream`) on the failing bytes and returns the
//! exact Go text. It never produces plaintext and is only reached after the
//! shared crypto crate has already refused the input.

use std::io::Read;
use std::iter;

use age::secrecy::SecretString;

use super::{age_base64_decode, quote, quote_bytes};

const INTRO: &[u8] = b"age-encryption.org/v1\n";
const MAX_HEADER_BYTES: usize = 2 << 20;
const MAX_RECIPIENT_STANZAS: usize = 1024;
const MAX_STANZA_ARGS: usize = 128;
const BYTES_PER_LINE: usize = 48;
const CHUNK: usize = 64 * 1024;
const ENC_CHUNK: usize = CHUNK + 16;
const MAX_SCRYPT_WORK_FACTOR: i64 = 22;

/// How Go's `ParseError` and plain `fmt.Errorf` values differ in `Error()`.
enum Fail {
    Parse(String),
    Plain(String),
}

impl Fail {
    fn text(&self) -> String {
        match self {
            Self::Parse(message) => format!("parsing age header: {message}"),
            Self::Plain(message) => message.clone(),
        }
    }
}

struct Stanza {
    kind: String,
    args: Vec<String>,
    body: Vec<u8>,
}

struct Parsed {
    stanzas: Vec<Stanza>,
    end: usize,
}

struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl Reader<'_> {
    /// `headerReader.ReadBytes('\n')`: the line including its delimiter, and
    /// whether input ended before a delimiter was found.
    fn read_line(&mut self) -> Result<(Vec<u8>, bool), Fail> {
        let rest = &self.data[self.position..];
        let (line, eof) = match rest.iter().position(|byte| *byte == b'\n') {
            Some(index) => (rest[..=index].to_vec(), false),
            None => (rest.to_vec(), true),
        };
        if self.position + line.len() > MAX_HEADER_BYTES {
            return Err(Fail::Parse("header exceeds 2 MiB".to_owned()));
        }
        self.position += line.len();
        Ok((line, eof))
    }

    fn peek3(&self) -> Result<Option<[u8; 3]>, Fail> {
        if self.position + 3 > MAX_HEADER_BYTES {
            return Err(Fail::Parse("header exceeds 2 MiB".to_owned()));
        }
        let rest = &self.data[self.position..];
        if rest.len() < 3 {
            return Ok(None);
        }
        Ok(Some([rest[0], rest[1], rest[2]]))
    }
}

fn describe_intro(line: &[u8]) -> Option<String> {
    if line.starts_with(b"AGE-SECRET-KEY-") || line.starts_with(b"AGE-PLUGIN-") {
        return None;
    }
    Some(quote_bytes(&line[..line.len().min(INTRO.len())]))
}

fn valid_arg(arg: &[u8]) -> bool {
    !arg.is_empty() && arg.iter().all(|byte| (33..=126).contains(byte))
}

/// `splitArgs`: `(prefix, Some(args))`, or the whole line with `None`.
fn split_args(line: &[u8]) -> (Vec<u8>, Option<Vec<Vec<u8>>>) {
    let text = line.strip_suffix(b"\n").unwrap_or(line);
    let Some(cut) = text.iter().position(|byte| *byte == b' ') else {
        return (text.to_vec(), None);
    };
    let mut args: Vec<Vec<u8>> = Vec::new();
    for arg in text[cut + 1..].split(|byte| *byte == b' ') {
        if !valid_arg(arg) || args.len() > MAX_STANZA_ARGS {
            return (text.to_vec(), None);
        }
        args.push(arg.to_vec());
    }
    (text[..cut].to_vec(), Some(args))
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn read_stanza(reader: &mut Reader<'_>) -> Result<Stanza, Fail> {
    let line_error = |error: Fail| Fail::Plain(format!("failed to read line: {}", error.text()));
    let (line, eof) = reader.read_line().map_err(line_error)?;
    if eof {
        return Err(Fail::Plain("failed to read line: EOF".to_owned()));
    }
    if !line.starts_with(b"->") {
        return Err(Fail::Plain(format!(
            "malformed stanza opening line: {}",
            quote_bytes(&line)
        )));
    }
    let (prefix, args) = split_args(&line);
    let Some(args) = args.filter(|args| prefix == b"->" && !args.is_empty()) else {
        return Err(Fail::Plain(format!(
            "malformed stanza: {}",
            quote_bytes(&line)
        )));
    };
    let mut stanza = Stanza {
        kind: lossy(&args[0]),
        args: args[1..].iter().map(|arg| lossy(arg)).collect(),
        body: Vec::new(),
    };
    loop {
        let (line, eof) = reader.read_line().map_err(line_error)?;
        if eof {
            return Err(Fail::Plain("failed to read line: EOF".to_owned()));
        }
        let trimmed = line.strip_suffix(b"\n").unwrap_or(&line);
        let decoded = match std::str::from_utf8(trimmed) {
            Ok(text) => age_base64_decode(text),
            // Go decodes bytes; a non-UTF-8 byte is never in the alphabet.
            Err(error) => Err(format!(
                "illegal base64 data at input byte {}",
                error.valid_up_to()
            )),
        };
        let bytes = match decoded {
            Ok(bytes) => bytes,
            Err(reason) => {
                if line.starts_with(b"---") || line.starts_with(b"->") {
                    return Err(Fail::Plain(format!(
                        "malformed body line {}: stanza ended without a short line\nnote: this might be a file encrypted with an old beta version of age or rage; use age v1.0.0-beta6 or rage to decrypt it",
                        quote_bytes(&line)
                    )));
                }
                return Err(Fail::Parse(format!(
                    "malformed body line {}: {reason}",
                    quote_bytes(&line)
                )));
            }
        };
        if bytes.len() > BYTES_PER_LINE {
            return Err(Fail::Parse(format!(
                "malformed body line {}: too long",
                quote_bytes(&line)
            )));
        }
        stanza.body.extend_from_slice(&bytes);
        if bytes.len() < BYTES_PER_LINE {
            return Ok(stanza);
        }
    }
}

fn parse(data: &[u8]) -> Result<Parsed, Fail> {
    let mut reader = Reader { data, position: 0 };
    let (line, eof) = reader.read_line()?;
    if eof {
        if line.is_empty() {
            return Err(Fail::Parse("file is empty".to_owned()));
        }
        return Err(Fail::Parse(match describe_intro(&line) {
            Some(description) => format!("unexpected EOF reading intro: {description}"),
            None => format!(
                "unexpected EOF reading intro, expected {}",
                quote_bytes(INTRO)
            ),
        }));
    }
    if line != INTRO {
        return Err(Fail::Parse(match describe_intro(&line) {
            Some(description) => format!("unexpected intro: {description}"),
            None => format!("unexpected intro, expected {}", quote_bytes(INTRO)),
        }));
    }
    let mut stanzas = Vec::new();
    loop {
        let Some(peek) = reader.peek3()? else {
            return Err(Fail::Parse("failed to read header: EOF".to_owned()));
        };
        if &peek == b"---" {
            let (line, eof) = reader.read_line()?;
            if eof {
                return Err(Fail::Plain("failed to read header: EOF".to_owned()));
            }
            let (prefix, args) = split_args(&line);
            let Some(args) = args.filter(|args| prefix == b"---" && args.len() == 1) else {
                return Err(Fail::Parse(format!(
                    "malformed closing line: {}",
                    quote_bytes(&line)
                )));
            };
            let mac = std::str::from_utf8(&args[0])
                .map_err(|_| "illegal base64 data at input byte 0".to_owned())
                .and_then(age_base64_decode);
            match mac {
                Ok(mac) if mac.len() == 32 => {}
                Ok(_) => {
                    return Err(Fail::Parse(format!(
                        "malformed closing line {}: <nil>",
                        quote_bytes(&line)
                    )));
                }
                Err(reason) => {
                    return Err(Fail::Parse(format!(
                        "malformed closing line {}: {reason}",
                        quote_bytes(&line)
                    )));
                }
            }
            break;
        }
        if stanzas.len() == MAX_RECIPIENT_STANZAS {
            return Err(Fail::Parse(format!(
                "header contains more than {MAX_RECIPIENT_STANZAS} recipient stanzas"
            )));
        }
        match read_stanza(&mut reader) {
            Ok(stanza) => stanzas.push(stanza),
            Err(error) => {
                return Err(Fail::Plain(format!(
                    "failed to parse header: {}",
                    error.text()
                )));
            }
        }
    }
    if stanzas.is_empty() {
        return Err(Fail::Parse("no recipient stanzas".to_owned()));
    }
    Ok(Parsed {
        stanzas,
        end: reader.position,
    })
}

/// Which identity the failing decryption used.
pub(crate) enum Identity<'a> {
    X25519(&'a age::x25519::Identity),
    Passphrase(&'a [u8]),
}

const NO_MATCH: &str =
    "identity did not match any of the recipients: incorrect identity for recipient block";

/// Go's error text for a ciphertext that `symvault-crypto` refused.
///
/// `payload_prefix` is what Go prepends to payload-stage errors: `read
/// decrypted data` for the plain helpers, `read decrypted entry` for the bounded
/// entry/manifest reader.
pub(crate) fn explain(ciphertext: &[u8], identity: &Identity<'_>, payload_prefix: &str) -> String {
    let parsed = match parse(ciphertext) {
        Ok(parsed) => parsed,
        Err(error) => return format!("decryption failed: failed to read header: {}", error.text()),
    };
    if let Some(error) = unwrap_error(&parsed.stanzas, identity) {
        return format!("decryption failed: {error}");
    }
    match probe(ciphertext, &parsed, identity, payload_prefix) {
        Probe::Message(message) => message,
        Probe::Unexplained => format!(
            "decryption failed: failed to read header: parsing age header: malformed header ({} bytes)",
            ciphertext.len()
        ),
    }
}

/// Stanza-structure errors that Go raises before any key derivation, in stanza
/// order. `None` means the structure is acceptable and only key material can
/// still fail.
fn unwrap_error(stanzas: &[Stanza], identity: &Identity<'_>) -> Option<String> {
    match identity {
        Identity::X25519(_) => {
            for stanza in stanzas.iter().filter(|stanza| stanza.kind == "X25519") {
                if stanza.args.len() != 1 {
                    return Some("invalid X25519 recipient block".to_owned());
                }
                match age_base64_decode(&stanza.args[0]) {
                    Err(reason) => {
                        return Some(format!("failed to parse X25519 recipient: {reason}"));
                    }
                    Ok(key) if key.len() != 32 => {
                        return Some("invalid X25519 recipient block".to_owned());
                    }
                    Ok(_) => {}
                }
                if stanza.body.len() != 32 {
                    return Some(
                        "invalid X25519 recipient block: incorrect file key size".to_owned(),
                    );
                }
            }
            if !stanzas.iter().any(|stanza| stanza.kind == "X25519") {
                return Some(NO_MATCH.to_owned());
            }
            None
        }
        Identity::Passphrase(_) => {
            if stanzas.iter().any(|stanza| stanza.kind == "scrypt") && stanzas.len() != 1 {
                return Some("an scrypt recipient must be the only one".to_owned());
            }
            let Some(stanza) = stanzas.iter().find(|stanza| stanza.kind == "scrypt") else {
                return Some(format!("{NO_MATCH}: file is not passphrase-encrypted"));
            };
            if stanza.args.len() != 2 {
                return Some("invalid scrypt recipient block".to_owned());
            }
            match age_base64_decode(&stanza.args[0]) {
                Err(reason) => return Some(format!("failed to parse scrypt salt: {reason}")),
                Ok(salt) if salt.len() != 16 => {
                    return Some("invalid scrypt recipient block".to_owned());
                }
                Ok(_) => {}
            }
            let factor = &stanza.args[1];
            let digits = factor.bytes().all(|byte| byte.is_ascii_digit())
                && !factor.starts_with('0')
                && !factor.is_empty();
            if !digits {
                return Some(format!(
                    "scrypt work factor encoding invalid: {}",
                    quote(factor)
                ));
            }
            let Ok(log_n) = factor.parse::<i64>() else {
                return Some(format!(
                    "failed to parse scrypt work factor: strconv.Atoi: parsing {}: value out of range",
                    quote(factor)
                ));
            };
            if log_n > MAX_SCRYPT_WORK_FACTOR {
                return Some(format!("scrypt work factor too large: {log_n}"));
            }
            if stanza.body.len() != 32 {
                return Some("invalid scrypt recipient block: incorrect file key size".to_owned());
            }
            None
        }
    }
}

enum Probe {
    Message(String),
    Unexplained,
}

fn probe(
    ciphertext: &[u8],
    parsed: &Parsed,
    identity: &Identity<'_>,
    payload_prefix: &str,
) -> Probe {
    let remaining = ciphertext.len() - parsed.end;
    // age-rs reads the nonce while opening the decryptor; Go checks the header
    // MAC first. A stub nonce lets the header checks run on a truncated file.
    let stubbed: Vec<u8> = if remaining < 16 {
        let mut padded = ciphertext[..parsed.end].to_vec();
        padded.extend_from_slice(&[0u8; 16]);
        padded
    } else {
        Vec::new()
    };
    let subject = if remaining < 16 {
        &stubbed[..]
    } else {
        ciphertext
    };
    // The bytes are untrusted: a line the age crate would chew on for minutes
    // is never handed to it (Go's parser would accept it; the text it would
    // then give depends on key material, which is not worth the walk).
    let Ok(decryptor) = symvault_crypto::entry_decryptor(subject) else {
        return Probe::Unexplained;
    };
    let reader = match identity {
        Identity::X25519(key) => decryptor.decrypt(iter::once(*key as &dyn age::Identity)),
        Identity::Passphrase(passphrase) => {
            let secret = SecretString::from(String::from_utf8_lossy(passphrase).into_owned());
            let mut scrypt = age::scrypt::Identity::new(secret);
            scrypt.set_max_work_factor(MAX_SCRYPT_WORK_FACTOR as u8);
            decryptor.decrypt(iter::once(&scrypt as &dyn age::Identity))
        }
    };
    let mut reader = match reader {
        Ok(reader) => reader,
        Err(age::DecryptError::InvalidMac) => {
            return Probe::Message("decryption failed: bad header MAC".to_owned());
        }
        Err(
            age::DecryptError::NoMatchingKeys
            | age::DecryptError::KeyDecryptionFailed
            | age::DecryptError::DecryptionFailed,
        ) => {
            let suffix = match identity {
                Identity::X25519(_) => "",
                Identity::Passphrase(_) => ": incorrect passphrase",
            };
            return Probe::Message(format!("decryption failed: {NO_MATCH}{suffix}"));
        }
        Err(_) => return Probe::Unexplained,
    };
    if remaining < 16 {
        let reason = if remaining == 0 {
            "EOF"
        } else {
            "unexpected EOF"
        };
        return Probe::Message(format!("decryption failed: failed to read nonce: {reason}"));
    }
    let payload = remaining - 16;
    let verified = read_verified(&mut reader);
    Probe::Message(format!(
        "{payload_prefix}: {}",
        payload_error(ciphertext, parsed, identity, payload, verified)
    ))
}

/// Plaintext bytes that authenticated before the first failure.
fn read_verified(reader: &mut impl Read) -> usize {
    let mut total = 0usize;
    let mut buffer = vec![0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => return total,
            Ok(read) => total += read,
        }
    }
}

fn payload_error(
    ciphertext: &[u8],
    parsed: &Parsed,
    identity: &Identity<'_>,
    payload: usize,
    verified: usize,
) -> String {
    const TAMPERED: &str =
        "failed to decrypt and authenticate payload chunk, file may be corrupted or tampered with";
    let mut chunk = verified / CHUNK;
    let mut remaining = payload as i64 - (chunk * ENC_CHUNK) as i64;
    if remaining == ENC_CHUNK as i64 && payload == (chunk + 1) * ENC_CHUNK {
        // The last chunk is full-length. Go accepts it as a non-final chunk
        // and then hits EOF; age-rs refused it only because nothing follows.
        // Appending a stub chunk tells the two apart.
        let mut extended = ciphertext.to_vec();
        extended.extend_from_slice(&[0u8; 16]);
        if authenticates_first_chunks(&extended, parsed, identity, chunk + 1) {
            chunk += 1;
            remaining = 0;
        }
    }
    if remaining <= 0 {
        return "unexpected EOF".to_owned();
    }
    if remaining < ENC_CHUNK as i64 && chunk > 0 && remaining == 16 {
        return "last chunk is empty, try age v1.0.0, and please consider reporting this"
            .to_owned();
    }
    TAMPERED.to_owned()
}

fn authenticates_first_chunks(
    ciphertext: &[u8],
    _parsed: &Parsed,
    identity: &Identity<'_>,
    chunks: usize,
) -> bool {
    let Ok(decryptor) = symvault_crypto::entry_decryptor(ciphertext) else {
        return false;
    };
    let reader = match identity {
        Identity::X25519(key) => decryptor.decrypt(iter::once(*key as &dyn age::Identity)),
        Identity::Passphrase(passphrase) => {
            let secret = SecretString::from(String::from_utf8_lossy(passphrase).into_owned());
            let mut scrypt = age::scrypt::Identity::new(secret);
            scrypt.set_max_work_factor(MAX_SCRYPT_WORK_FACTOR as u8);
            decryptor.decrypt(iter::once(&scrypt as &dyn age::Identity))
        }
    };
    match reader {
        Ok(mut reader) => read_verified(&mut reader) >= chunks * CHUNK,
        Err(_) => false,
    }
}
