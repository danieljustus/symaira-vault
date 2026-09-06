#![deny(unsafe_code)]

//! Secret reference parsing and handle formatting contracts.

use core::fmt;
use core::str::FromStr;
use serde::{Deserialize, Serialize};

/// Error returned when parsing an invalid secret reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretRefError {
    /// The reference string is empty.
    Empty,
    /// An `op://` reference did not specify a field component.
    MissingFieldInOp(String),
    /// Syntax neither matches `op://path/field` nor `path.field`.
    InvalidSyntax(String),
}

impl fmt::Display for SecretRefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty reference"),
            Self::MissingFieldInOp(s) => write!(f, "missing field in op:// reference: {s}"),
            Self::InvalidSyntax(s) => {
                write!(f, "expected path.field or op://path/field syntax, got: {s}")
            }
        }
    }
}

impl std::error::Error for SecretRefError {}

/// Parsed secret reference with distinct vault entry path and field name.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretRef {
    pub path: String,
    pub field: String,
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretRef")
            .field("path", &self.path)
            .field("field", &self.field)
            .finish()
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "op://{}/{}", self.path, self.field)
    }
}

impl FromStr for SecretRef {
    type Err = SecretRefError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl SecretRef {
    /// Creates a new `SecretRef` from path and field components.
    #[must_use]
    pub fn new(path: impl Into<String>, field: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            field: field.into(),
        }
    }

    /// Parses a secret reference string in either `op://path/field` or `path.field` format.
    ///
    /// # Errors
    ///
    /// Returns `SecretRefError` if the reference is empty or does not conform to either syntax.
    pub fn parse(s: &str) -> Result<Self, SecretRefError> {
        if s.is_empty() {
            return Err(SecretRefError::Empty);
        }

        if let Some(rest) = s.strip_prefix("op://") {
            let idx = match rest.rfind('/') {
                Some(i) if i < rest.len() - 1 => i,
                _ => return Err(SecretRefError::MissingFieldInOp(s.to_string())),
            };
            return Ok(Self {
                path: rest[..idx].to_string(),
                field: rest[idx + 1..].to_string(),
            });
        }

        let idx = match s.rfind('.') {
            Some(i) if i > 0 && i < s.len() - 1 => i,
            _ => return Err(SecretRefError::InvalidSyntax(s.to_string())),
        };

        Ok(Self {
            path: s[..idx].to_string(),
            field: s[idx + 1..].to_string(),
        })
    }

    /// Renders the reference in dot notation: `path.field`.
    #[must_use]
    pub fn to_dot_notation(&self) -> String {
        format!("{}.{}", self.path, self.field)
    }

    /// Renders the reference in canonical `op://path/field` URI notation.
    #[must_use]
    pub fn to_op_uri(&self) -> String {
        format!("op://{}/{}", self.path, self.field)
    }

    /// Converts this reference into a `SecretHandle`.
    #[must_use]
    pub fn to_handle(&self) -> SecretHandle {
        SecretHandle {
            path: self.path.clone(),
            field: Some(self.field.clone()),
        }
    }
}

/// A secret handle safe for presentation or logs that does not contain secret values.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretHandle {
    pub path: String,
    pub field: Option<String>,
}

impl fmt::Debug for SecretHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretHandle")
            .field("path", &self.path)
            .field("field", &self.field)
            .finish()
    }
}

impl fmt::Display for SecretHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.field {
            Some(field) => write!(f, "op://{}/{}", self.path, field),
            None => write!(f, "op://{}/", self.path),
        }
    }
}

impl SecretHandle {
    /// Creates a new `SecretHandle`.
    #[must_use]
    pub fn new(path: impl Into<String>, field: Option<impl Into<String>>) -> Self {
        Self {
            path: path.into(),
            field: field.map(Into::into),
        }
    }

    /// Parses an `op://` handle string into components.
    ///
    /// Returns `None` if the input does not start with `op://`, has an empty body,
    /// or starts with an unexpected slash.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.strip_prefix("op://")?;
        if rest.is_empty() || rest.starts_with('/') {
            return None;
        }
        if let Some(idx) = rest
            .rfind('/')
            .filter(|&idx| idx > 0 && idx < rest.len() - 1)
        {
            return Some(Self {
                path: rest[..idx].to_string(),
                field: Some(rest[idx + 1..].to_string()),
            });
        }
        Some(Self {
            path: rest.to_string(),
            field: None,
        })
    }

    /// Attempts to convert this handle into a `SecretRef`. Fails if field is omitted.
    #[must_use]
    pub fn to_secret_ref(&self) -> Option<SecretRef> {
        self.field.as_ref().map(|f| SecretRef {
            path: self.path.clone(),
            field: f.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_op_ref() {
        let r = SecretRef::parse("op://work/aws/password").expect("valid ref");
        assert_eq!(r.path, "work/aws");
        assert_eq!(r.field, "password");
        assert_eq!(r.to_op_uri(), "op://work/aws/password");
        assert_eq!(r.to_dot_notation(), "work/aws.password");
    }

    #[test]
    fn parse_valid_dot_ref() {
        let r = SecretRef::parse("work/aws.password").expect("valid ref");
        assert_eq!(r.path, "work/aws");
        assert_eq!(r.field, "password");
    }

    #[test]
    fn parse_invalid_ref() {
        assert_eq!(SecretRef::parse(""), Err(SecretRefError::Empty));
        assert!(matches!(
            SecretRef::parse("op://work/aws/"),
            Err(SecretRefError::MissingFieldInOp(_))
        ));
        assert!(matches!(
            SecretRef::parse("notavalidref"),
            Err(SecretRefError::InvalidSyntax(_))
        ));
    }

    #[test]
    fn handle_roundtrip() {
        let h = SecretHandle::new("work/aws", Some("password"));
        assert_eq!(h.to_string(), "op://work/aws/password");
        let parsed = SecretHandle::parse(&h.to_string()).expect("parsed");
        assert_eq!(parsed, h);
    }

    #[test]
    fn handle_path_only_roundtrip_formatting() {
        let h = SecretHandle::new("personal/notes", None::<String>);
        assert_eq!(h.to_string(), "op://personal/notes/");
    }

    #[test]
    fn property_non_crashing_fuzz() {
        // Property: parse must never panic on arbitrary strings
        let candidates = [
            "",
            "op://",
            "op:///",
            "op://a",
            "op://a/",
            "op://a/b",
            "op://a/b/c",
            "...",
            ".",
            "a.",
            ".b",
            "a.b",
            "a.b.c",
            "op://work/team/aws/secret",
            "中文/路径.字段",
            "op://中文/路径/字段",
        ];
        for s in candidates {
            let _ = SecretRef::parse(s);
            let _ = SecretHandle::parse(s);
        }
    }
}
