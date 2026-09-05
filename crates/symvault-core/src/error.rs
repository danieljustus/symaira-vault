use std::{error::Error, fmt};

/// Stable Symaira Vault process exit categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExitCode {
    Success = 0,
    General = 1,
    NotFound = 2,
    NotInitialized = 3,
    Locked = 4,
    PermissionDenied = 5,
    Config = 6,
    DoctorWarn = 7,
    DoctorFail = 8,
    InvalidInput = 9,
    UpdateAvailable = 10,
}

impl ExitCode {
    /// Alias used for flag and usage validation errors.
    pub const USAGE: Self = Self::InvalidInput;

    /// Returns the stable numeric process code.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Resolves a stable numeric process code.
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Success),
            1 => Some(Self::General),
            2 => Some(Self::NotFound),
            3 => Some(Self::NotInitialized),
            4 => Some(Self::Locked),
            5 => Some(Self::PermissionDenied),
            6 => Some(Self::Config),
            7 => Some(Self::DoctorWarn),
            8 => Some(Self::DoctorFail),
            9 => Some(Self::InvalidInput),
            10 => Some(Self::UpdateAvailable),
            _ => None,
        }
    }
}

/// Stable service-level error classification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum ErrorKind {
    #[default]
    None = 0,
    NotFound = 1,
    FieldNotFound = 2,
    ReadFailed = 3,
    WriteFailed = 4,
}

impl ErrorKind {
    /// Returns the stable numeric classification.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }
}

/// Sentinel category retained across adapter-specific error chains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CauseKind {
    EntryNotFound,
    VaultNotInitialized,
    VaultLocked,
    PermissionDenied,
    Other,
}

impl CauseKind {
    /// Returns the language-neutral fixture name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EntryNotFound => "entry_not_found",
            Self::VaultNotInitialized => "vault_not_initialized",
            Self::VaultLocked => "vault_locked",
            Self::PermissionDenied => "permission_denied",
            Self::Other => "other",
        }
    }
}

/// An adapter-provided cause summary owned by the domain error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorCause {
    kind: CauseKind,
    message: String,
}

impl ErrorCause {
    #[must_use]
    pub fn new(kind: CauseKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> CauseKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ErrorCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ErrorCause {}

/// Structured CLI error preserving the Go oracle's code, kind, cause, and hint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliError {
    code: ExitCode,
    kind: ErrorKind,
    message: String,
    cause: Option<ErrorCause>,
    hint: Option<String>,
}

impl CliError {
    #[must_use]
    pub fn new(code: ExitCode, message: impl Into<String>, cause: Option<ErrorCause>) -> Self {
        Self {
            code,
            kind: ErrorKind::None,
            message: message.into(),
            cause,
            hint: None,
        }
    }

    #[must_use]
    pub fn wrap(
        code: ExitCode,
        kind: ErrorKind,
        message: impl Into<String>,
        cause: Option<ErrorCause>,
    ) -> Self {
        Self {
            code,
            kind,
            message: message.into(),
            cause,
            hint: None,
        }
    }

    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::wrap(
            ExitCode::NotFound,
            ErrorKind::NotFound,
            message,
            Some(ErrorCause::new(CauseKind::EntryNotFound, "entry not found")),
        )
        .with_hint(
            "Try: symvault list to browse entries, or symvault find <term> to search by keyword.",
        )
    }

    #[must_use]
    pub fn read_failed(message: impl Into<String>, cause: Option<String>) -> Self {
        Self::wrap(
            ExitCode::General,
            ErrorKind::ReadFailed,
            message,
            cause.map(|message| ErrorCause::new(CauseKind::Other, message)),
        )
    }

    #[must_use]
    pub fn write_failed(message: impl Into<String>, cause: Option<String>) -> Self {
        Self::wrap(
            ExitCode::General,
            ErrorKind::WriteFailed,
            message,
            cause.map(|message| ErrorCause::new(CauseKind::Other, message)),
        )
    }

    #[must_use]
    pub fn not_initialized(message: impl Into<String>) -> Self {
        Self::new(
            ExitCode::NotInitialized,
            message,
            Some(ErrorCause::new(
                CauseKind::VaultNotInitialized,
                "vault not initialized",
            )),
        )
        .with_hint("Run: symvault init to initialize a new vault.")
    }

    #[must_use]
    pub fn vault_not_initialized() -> Self {
        Self::new(
            ExitCode::NotInitialized,
            "vault not initialized. Run 'symvault init' first",
            Some(ErrorCause::new(
                CauseKind::VaultNotInitialized,
                "vault not initialized",
            )),
        )
    }

    #[must_use]
    pub fn locked(message: impl Into<String>) -> Self {
        Self::new(
            ExitCode::Locked,
            message,
            Some(ErrorCause::new(CauseKind::VaultLocked, "vault locked")),
        )
        .with_hint(
            "Run: symvault unlock to unlock the vault, or set a passphrase via 'symvault auth set passphrase'.",
        )
    }

    #[must_use]
    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(
            ExitCode::PermissionDenied,
            message,
            Some(ErrorCause::new(
                CauseKind::PermissionDenied,
                "permission denied",
            )),
        )
    }

    #[must_use]
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(ExitCode::InvalidInput, message, None)
    }

    #[must_use]
    pub fn config(message: impl Into<String>) -> Self {
        Self::new(ExitCode::Config, message, None)
    }

    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ExitCode::General, message, None)
    }

    #[must_use]
    pub fn already_exists(message: impl Into<String>) -> Self {
        Self::new(ExitCode::General, message, None)
    }

    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    #[must_use]
    pub const fn code(&self) -> ExitCode {
        self.code
    }

    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn cause(&self) -> Option<&ErrorCause> {
        self.cause.as_ref()
    }

    #[must_use]
    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }

    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(self.kind, ErrorKind::NotFound | ErrorKind::FieldNotFound)
    }

    #[must_use]
    pub const fn is_write_error(&self) -> bool {
        matches!(self.kind, ErrorKind::WriteFailed)
    }

    #[must_use]
    pub fn effective_exit_code(&self) -> ExitCode {
        exit_code_from_error(Some(self))
    }

    #[must_use]
    pub fn formatted(&self) -> String {
        match self.hint() {
            Some(hint) => format!("{}\nHint: {hint}", self),
            None => self.to_string(),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.cause {
            Some(cause)
                if cause.kind() == CauseKind::VaultNotInitialized
                    && self
                        .message
                        .to_lowercase()
                        .contains("vault not initialized") =>
            {
                formatter.write_str(&self.message)
            }
            Some(cause) => write!(formatter, "{}: {cause}", self.message),
            None => formatter.write_str(&self.message),
        }
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause.as_ref().map(|cause| cause as &dyn Error)
    }
}

/// Resolves sentinel causes before typed CLI codes, matching Go `errors.Is`/`errors.As` order.
#[must_use]
pub fn exit_code_from_error(error: Option<&(dyn Error + 'static)>) -> ExitCode {
    let Some(error) = error else {
        return ExitCode::Success;
    };

    let mut current = Some(error);
    while let Some(item) = current {
        if let Some(cause) = item.downcast_ref::<ErrorCause>() {
            match cause.kind() {
                CauseKind::EntryNotFound => return ExitCode::NotFound,
                CauseKind::VaultNotInitialized => return ExitCode::NotInitialized,
                CauseKind::VaultLocked => return ExitCode::Locked,
                CauseKind::PermissionDenied => return ExitCode::PermissionDenied,
                CauseKind::Other => {}
            }
        }
        current = item.source();
    }

    current = Some(error);
    while let Some(item) = current {
        if let Some(cli_error) = item.downcast_ref::<CliError>() {
            return cli_error.code();
        }
        current = item.source();
    }
    ExitCode::General
}

/// Formats a plain or nested CLI error with the typed error's remediation hint.
#[must_use]
pub fn format_cli_error(error: Option<&(dyn Error + 'static)>) -> String {
    let Some(error) = error else {
        return String::new();
    };
    let mut current = Some(error);
    while let Some(item) = current {
        if let Some(cli_error) = item.downcast_ref::<CliError>() {
            return cli_error.formatted();
        }
        current = item.source();
    }
    error.to_string()
}

/// Returns whether an arbitrary error chain contains a typed not-found error.
#[must_use]
pub fn is_not_found(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(item) = current {
        if let Some(cli_error) = item.downcast_ref::<CliError>() {
            return cli_error.is_not_found();
        }
        current = item.source();
    }
    false
}

/// Returns whether an arbitrary error chain contains a typed write failure.
#[must_use]
pub fn is_write_error(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(item) = current {
        if let Some(cli_error) = item.downcast_ref::<CliError>() {
            return cli_error.is_write_error();
        }
        current = item.source();
    }
    false
}

/// Maps a vault exit code onto the historical corekit numeric category.
#[must_use]
pub const fn to_corekit_exit_code(code: ExitCode) -> u8 {
    match code {
        ExitCode::Success => 0,
        ExitCode::NotFound => 5,
        ExitCode::PermissionDenied => 4,
        ExitCode::Config => 9,
        ExitCode::InvalidInput => 2,
        ExitCode::General
        | ExitCode::NotInitialized
        | ExitCode::Locked
        | ExitCode::DoctorWarn
        | ExitCode::DoctorFail
        | ExitCode::UpdateAvailable => 1,
    }
}

/// Maps a historical corekit numeric category onto the vault exit taxonomy.
#[must_use]
pub const fn from_corekit_exit_code(code: u8) -> ExitCode {
    match code {
        0 => ExitCode::Success,
        5 => ExitCode::NotFound,
        4 => ExitCode::PermissionDenied,
        9 => ExitCode::Config,
        2 => ExitCode::InvalidInput,
        _ => ExitCode::General,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CauseKind, CliError, ErrorCause, ExitCode, exit_code_from_error, format_cli_error,
    };

    #[test]
    fn optional_io_causes_preserve_display_shape() {
        let without = CliError::write_failed("write failed", None);
        let with = CliError::write_failed("write failed", Some("disk full".into()));
        assert_eq!(without.to_string(), "write failed");
        assert!(std::error::Error::source(&without).is_none());
        assert_eq!(with.to_string(), "write failed: disk full");
        assert!(std::error::Error::source(&with).is_some());
    }

    #[test]
    fn sentinel_cause_precedes_cli_code() {
        let error = CliError::new(
            ExitCode::General,
            "wrapper",
            Some(ErrorCause::new(CauseKind::VaultLocked, "vault locked")),
        );
        assert_eq!(exit_code_from_error(Some(&error)), ExitCode::Locked);
    }

    #[test]
    fn generic_formatter_handles_nil_and_typed_errors() {
        let error = CliError::internal("failed").with_hint("repair");
        assert_eq!(format_cli_error(None), "");
        assert_eq!(format_cli_error(Some(&error)), "failed\nHint: repair");
    }
}
