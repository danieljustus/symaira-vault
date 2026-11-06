//! Wizard state, key names and the passphrase meter
//! (`internal/ui/wizard/step.go`, `passphrase_meter.go`).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub(super) const SYNC_GIT: &str = "git";
pub(super) const SYNC_LOCAL: &str = "local";
pub(super) const DEFAULT_PROFILE: &str = "default";
pub(super) const MIN_PASSPHRASE_LEN: usize = 12;

/// `AgentSelection`: the YAML keys are Go's lower-cased field names because
/// the struct carries no yaml tags.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct AgentSelection {
    #[serde(rename = "agenttype")]
    pub agent_type: String,
    pub transport: String,
    pub scope: String,
    #[serde(rename = "readonly")]
    pub read_only: bool,
}

/// The vault passphrase while the wizard holds it. Go zeroes
/// `state.Passphrase` once the vault is initialized; here the bytes are wiped
/// whenever the value is dropped or replaced, and `Debug` never prints them.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Passphrase(Zeroizing<Vec<u8>>);

impl Passphrase {
    pub(crate) fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

/// Everything the user chose, `WizardState` in Go.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct WizardState {
    pub vault_dir: String,
    pub existing_vault: bool,
    /// Cleared after the vault is initialized. `None` is Go's nil slice.
    pub passphrase: Option<Passphrase>,
    pub auth_method: String,
    pub sync_mode: String,
    pub git_remote_url: String,
    pub auto_push: bool,
    pub multi_device: bool,
    pub vault_public_key: String,
    pub recipients: Vec<String>,
    pub selected_agents: Vec<AgentSelection>,
    pub backup_dir: String,
    pub profile_name: String,
    pub apply_errors: Vec<String>,
    pub keep_on_error: bool,
    pub no_resume: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PassphraseStrength {
    Weak,
    Fair,
    Good,
    Strong,
}

impl PassphraseStrength {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Weak => "weak",
            Self::Fair => "fair",
            Self::Good => "good",
            Self::Strong => "strong",
        }
    }

    pub(crate) fn bar(self) -> &'static str {
        match self {
            Self::Weak => "[▓░░░] weak",
            Self::Fair => "[▓▓░░] fair",
            Self::Good => "[▓▓▓░] good",
            Self::Strong => "[▓▓▓▓] strong",
        }
    }
}

/// `MeasureStrength`: length plus character diversity, byte length like Go's
/// `len(p)`.
pub(crate) fn measure_strength(passphrase: &str) -> PassphraseStrength {
    if passphrase.is_empty() {
        return PassphraseStrength::Weak;
    }
    let length = passphrase.len();
    let mut score = match length {
        20.. => 4,
        16..=19 => 3,
        12..=15 => 2,
        8..=11 => 1,
        _ => 0,
    };
    let (mut lower, mut upper, mut digit, mut special) = (false, false, false, false);
    for ch in passphrase.chars() {
        if ch.is_lowercase() {
            lower = true;
        } else if ch.is_uppercase() {
            upper = true;
        } else if go_is_digit(ch) {
            digit = true;
        } else {
            special = true;
        }
    }
    for present in [lower, upper, digit, special] {
        if present {
            score += 1;
        }
    }
    match score {
        7.. => PassphraseStrength::Strong,
        5..=6 => PassphraseStrength::Good,
        3..=4 => PassphraseStrength::Fair,
        _ => PassphraseStrength::Weak,
    }
}

/// Go's `unicode.IsDigit` is the decimal-digit category (Nd) only.
fn go_is_digit(ch: char) -> bool {
    const NDS: &[(u32, u32)] = &[
        (0x0660, 0x0669),
        (0x06F0, 0x06F9),
        (0x07C0, 0x07C9),
        (0x0966, 0x096F),
        (0x09E6, 0x09EF),
        (0x0A66, 0x0A6F),
        (0x0AE6, 0x0AEF),
        (0x0B66, 0x0B6F),
        (0x0BE6, 0x0BEF),
        (0x0C66, 0x0C6F),
        (0x0CE6, 0x0CEF),
        (0x0D66, 0x0D6F),
        (0x0E50, 0x0E59),
        (0x0ED0, 0x0ED9),
        (0x0F20, 0x0F29),
        (0x1040, 0x1049),
        (0x17E0, 0x17E9),
        (0x1810, 0x1819),
        (0xFF10, 0xFF19),
    ];
    let code = ch as u32;
    ch.is_ascii_digit() || NDS.iter().any(|&(lo, hi)| (lo..=hi).contains(&code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strength_matches_the_go_scoring_table() {
        let cases = [
            ("", PassphraseStrength::Weak),
            ("abc", PassphraseStrength::Weak),
            ("abcdefgh", PassphraseStrength::Weak),
            ("abcdefghi!", PassphraseStrength::Fair),
            ("correct horse battery staple", PassphraseStrength::Good),
            ("Correct Horse 1 battery staple", PassphraseStrength::Strong),
            ("aaaaaaaaaaaa", PassphraseStrength::Fair),
            ("AAAAAAAAAAAA1", PassphraseStrength::Fair),
        ];
        for (input, want) in cases {
            assert_eq!(measure_strength(input), want, "{input:?}");
        }
    }

    #[test]
    fn strength_bars_are_the_frozen_strings() {
        assert_eq!(PassphraseStrength::Weak.bar(), "[▓░░░] weak");
        assert_eq!(PassphraseStrength::Fair.bar(), "[▓▓░░] fair");
        assert_eq!(PassphraseStrength::Good.bar(), "[▓▓▓░] good");
        assert_eq!(PassphraseStrength::Strong.bar(), "[▓▓▓▓] strong");
    }

    #[test]
    fn debug_output_never_contains_the_passphrase() {
        let state = WizardState {
            passphrase: Some(Passphrase::new(Zeroizing::new(
                b"correct horse battery staple".to_vec(),
            ))),
            ..WizardState::default()
        };
        let shown = format!("{state:?}");
        assert!(!shown.contains("correct horse"), "{shown}");
        assert!(!shown.contains("99, 111"), "no byte dump either: {shown}");
        assert!(shown.contains("redacted"));
    }
}
