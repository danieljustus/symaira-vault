#![deny(unsafe_code)]

//! Password generation and strength assessment with explicit deterministic seams.

use std::{collections::HashSet, fmt, io::Read, ops::Deref};

use unicode_categories::UnicodeCategories;
use zeroize::Zeroizing;

/// Maximum password length accepted by the Go and Rust implementations.
pub const MAX_PASSWORD_LENGTH: usize = 1024;

const LETTERS: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?/~";

/// An owned generated password that zeroizes its contents on drop.
///
/// Its debug representation is deliberately redacted; callers must opt into
/// `as_str()` when they intentionally need the secret bytes.
pub struct GeneratedPassword(Zeroizing<String>);

impl GeneratedPassword {
    /// Borrows the generated password for an intentional use site.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for GeneratedPassword {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for GeneratedPassword {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Debug for GeneratedPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GeneratedPassword(REDACTED)")
    }
}

/// Error returned by password generation.
#[derive(Debug, Eq, PartialEq)]
pub enum PasswordError {
    /// The requested length exceeds [`MAX_PASSWORD_LENGTH`].
    TooLong { length: usize, maximum: usize },
    /// The random source could not provide bytes.
    RandomSource(String),
}

impl fmt::Display for PasswordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { maximum, .. } => {
                write!(formatter, "password length must be at most {maximum}")
            }
            Self::RandomSource(message) => write!(formatter, "generate password: {message}"),
        }
    }
}

impl std::error::Error for PasswordError {}

/// Generates a cryptographically random password and zeroizes it on drop.
///
/// A non-positive length uses the Go-compatible default of 16 characters.
pub fn generate_password(
    length: isize,
    use_symbols: bool,
) -> Result<GeneratedPassword, PasswordError> {
    let mut source = OsRandomSource;
    generate_password_with_reader(length, use_symbols, &mut source)
}

/// Generates a password from an explicit byte reader.
///
/// This is both a test seam and the input used by the Go-generated parity
/// fixture. Sampling uses the same masked-byte rejection strategy as Go's
/// `crypto/rand.Int`, so a byte stream is a language-neutral random vector.
pub fn generate_password_with_reader<R: Read>(
    length: isize,
    use_symbols: bool,
    reader: &mut R,
) -> Result<GeneratedPassword, PasswordError> {
    let length = if length <= 0 { 16 } else { length as usize };
    if length > MAX_PASSWORD_LENGTH {
        return Err(PasswordError::TooLong {
            length,
            maximum: MAX_PASSWORD_LENGTH,
        });
    }

    let mut charset = Vec::with_capacity(LETTERS.len() + SYMBOLS.len());
    charset.extend_from_slice(LETTERS);
    if use_symbols {
        charset.extend_from_slice(SYMBOLS);
    }

    let mut result = Vec::with_capacity(length);
    for _ in 0..length {
        let index = uniform_index(reader, charset.len())?;
        result.push(charset[index]);
    }
    let password = String::from_utf8(result).expect("password charset is ASCII");
    Ok(GeneratedPassword(Zeroizing::new(password)))
}

fn uniform_index<R: Read>(reader: &mut R, upper: usize) -> Result<usize, PasswordError> {
    debug_assert!(upper > 0 && upper <= 256);
    let bits = usize::BITS - (upper - 1).leading_zeros();
    let mask = ((1u16 << bits) - 1) as u8;
    loop {
        let mut byte = [0u8; 1];
        reader
            .read_exact(&mut byte)
            .map_err(|error| PasswordError::RandomSource(error.to_string()))?;
        let value = byte[0] & mask;
        if usize::from(value) < upper {
            return Ok(usize::from(value));
        }
    }
}

struct OsRandomSource;

impl Read for OsRandomSource {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        getrandom::fill(buffer).map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(buffer.len())
    }
}

/// Result of assessing a password against the minimum policy.
#[derive(Clone, Debug, PartialEq)]
pub struct PasswordStrength {
    pub weak: bool,
    pub message: String,
    pub entropy: f64,
    pub missing: Vec<String>,
}

/// Assesses password length, character diversity, and estimated entropy.
#[must_use]
pub fn assess_password_strength(password: &str) -> PasswordStrength {
    let rune_count = password.chars().count();
    if rune_count < 10 {
        return PasswordStrength {
            weak: true,
            message: "password too short: must be at least 10 characters".to_owned(),
            entropy: 0.0,
            missing: Vec::new(),
        };
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut other_runes = HashSet::new();

    for character in password.chars() {
        if character.is_lowercase() {
            has_lower = true;
        } else if character.is_uppercase() {
            has_upper = true;
        } else if character.is_number_decimal_digit() {
            has_digit = true;
        } else if character.is_ascii_punctuation()
            || character.is_punctuation()
            || character.is_symbol()
        {
            has_symbol = true;
        } else {
            other_runes.insert(character);
        }
    }

    let mut missing = Vec::new();
    if !has_lower {
        missing.push("lowercase".to_owned());
    }
    if !has_upper {
        missing.push("uppercase".to_owned());
    }
    if !has_digit {
        missing.push("digits".to_owned());
    }
    if !has_symbol {
        missing.push("symbols".to_owned());
    }

    let mut charset_size = other_runes.len();
    if has_lower {
        charset_size += 26;
    }
    if has_upper {
        charset_size += 26;
    }
    if has_digit {
        charset_size += 10;
    }
    if has_symbol {
        charset_size += 32;
    }
    let charset_size = charset_size.max(1);
    let entropy = rune_count as f64 * (charset_size as f64).log2();
    let (weak, message) = if entropy < 60.0 {
        (
            true,
            format!(
                "password too weak: estimated entropy {:.1} bits, need at least 60 bits",
                entropy
            ),
        )
    } else {
        (false, String::new())
    };

    PasswordStrength {
        weak,
        message,
        entropy,
        missing,
    }
}

/// Validates password strength and returns the Go-compatible message on failure.
pub fn validate_password_strength(password: &str) -> Result<(), String> {
    let assessment = assess_password_strength(password);
    if assessment.weak {
        Err(assessment.message)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_reader_matches_charset_policy() {
        let mut reader = std::io::Cursor::new((0..64).map(|value| value as u8).collect::<Vec<_>>());
        let password = generate_password_with_reader(32, true, &mut reader).expect("password");
        assert_eq!(password.as_str(), "abcdefghjkmnpqrstuvwxyzABCDEFGHJ");
    }

    #[test]
    fn generated_password_debug_is_redacted() {
        let mut reader = std::io::Cursor::new(vec![0; 16]);
        let password = generate_password_with_reader(16, false, &mut reader).expect("password");
        let debug = format!("{password:?}");
        assert_eq!(debug, "GeneratedPassword(REDACTED)");
        assert!(!debug.contains(password.as_str()));
    }

    #[test]
    fn generated_password_is_zeroizing_and_bounded() {
        let mut reader = std::io::Cursor::new(vec![0; 16]);
        let password = generate_password_with_reader(0, false, &mut reader).expect("password");
        assert_eq!(password.len(), 16);
        assert_eq!(MAX_PASSWORD_LENGTH, 1024);
        let mut reader = std::io::Cursor::new(Vec::new());
        let error = generate_password_with_reader(1025, false, &mut reader).unwrap_err();
        assert_eq!(
            error,
            PasswordError::TooLong {
                length: 1025,
                maximum: 1024
            }
        );
    }

    #[test]
    fn strength_matches_unicode_policy() {
        let assessment = assess_password_strength("HelloW0rld!日本語テスト");
        assert!(!assessment.weak);
        assert!(assessment.entropy > 60.0);
        assert_eq!(assessment.missing, Vec::<String>::new());
    }
}
