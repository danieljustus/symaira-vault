//! Pure agent-tier presets shared by policy consumers.

/// Named agent capability tiers from the Go configuration contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TierPreset {
    ReadOnly,
    Standard,
    Admin,
}

impl TierPreset {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::Standard => "standard",
            Self::Admin => "admin",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "read-only" => Some(Self::ReadOnly),
            "standard" => Some(Self::Standard),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

/// The tier fields that are observable through GetPreset and ApplyTierPreset.
/// `Option<Vec<String>>` preserves the Go distinction between nil and a
/// non-nil empty/specified slice for AllowedExecutables.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentProfile {
    pub name: String,
    pub tier: Option<String>,
    pub approval_mode: Option<String>,
    pub allowed_paths: Vec<String>,
    pub can_write: Option<bool>,
    pub can_run_commands: Option<bool>,
    pub can_manage_config: Option<bool>,
    pub can_use_clipboard: Option<bool>,
    pub can_use_autotype: Option<bool>,
    pub can_read_values: Option<bool>,
    pub expose_value_tools: Option<bool>,
    pub auto_unseal: Option<bool>,
    pub require_approval: Option<bool>,
    pub allowed_executables: Option<Vec<String>>,
}

/// Returns a fresh copy of the named preset, or `None` for an unknown tier.
#[must_use]
pub fn get_preset(tier: &str) -> Option<AgentProfile> {
    let preset = match TierPreset::parse(tier)? {
        TierPreset::ReadOnly => AgentProfile {
            can_write: Some(false),
            can_run_commands: Some(false),
            can_manage_config: Some(false),
            can_use_clipboard: Some(false),
            can_use_autotype: Some(false),
            can_read_values: Some(false),
            expose_value_tools: Some(false),
            auto_unseal: Some(false),
            approval_mode: Some("deny".to_owned()),
            require_approval: Some(false),
            allowed_paths: Vec::new(),
            ..AgentProfile::default()
        },
        TierPreset::Standard => AgentProfile {
            can_write: Some(false),
            can_run_commands: Some(false),
            can_manage_config: Some(false),
            can_use_clipboard: Some(true),
            can_use_autotype: Some(true),
            can_read_values: Some(true),
            expose_value_tools: Some(false),
            auto_unseal: Some(false),
            approval_mode: Some("prompt".to_owned()),
            require_approval: Some(true),
            allowed_paths: Vec::new(),
            allowed_executables: Some(standard_executables()),
            ..AgentProfile::default()
        },
        TierPreset::Admin => AgentProfile {
            can_write: Some(true),
            can_run_commands: Some(true),
            can_manage_config: Some(true),
            can_use_clipboard: Some(true),
            can_use_autotype: Some(true),
            can_read_values: Some(true),
            expose_value_tools: Some(true),
            auto_unseal: Some(true),
            approval_mode: Some("prompt".to_owned()),
            require_approval: Some(true),
            allowed_paths: Vec::new(),
            ..AgentProfile::default()
        },
    };
    Some(preset)
}

/// Applies the named preset to capability/approval fields only.
///
/// Name and AllowedPaths are preserved. As in Go, a preset with nil
/// AllowedExecutables leaves an existing target value untouched.
pub fn apply_tier_preset(target: &mut AgentProfile, tier: &str) -> bool {
    let Some(preset) = get_preset(tier) else {
        return false;
    };
    target.can_write = Some(preset.can_write == Some(true));
    target.can_run_commands = Some(preset.can_run_commands == Some(true));
    target.can_manage_config = Some(preset.can_manage_config == Some(true));
    target.can_use_clipboard = Some(preset.can_use_clipboard == Some(true));
    target.can_use_autotype = Some(preset.can_use_autotype == Some(true));
    target.can_read_values = Some(preset.can_read_values == Some(true));
    target.expose_value_tools = Some(preset.expose_value_tools == Some(true));
    target.auto_unseal = Some(preset.auto_unseal == Some(true));
    if preset.approval_mode.is_some() {
        target.approval_mode = preset.approval_mode;
    }
    target.require_approval = Some(preset.require_approval == Some(true));
    if preset.allowed_executables.is_some() {
        target.allowed_executables = preset.allowed_executables;
    }
    true
}

fn standard_executables() -> Vec<String> {
    [
        "curl",
        "git",
        "terraform",
        "npm",
        "node",
        "python",
        "python3",
        "docker",
        "kubectl",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::{AgentProfile, apply_tier_preset, get_preset};

    #[test]
    fn unknown_tier_is_non_mutating() {
        let mut profile = AgentProfile {
            can_write: Some(true),
            ..AgentProfile::default()
        };
        assert!(!apply_tier_preset(&mut profile, "unknown"));
        assert_eq!(profile.can_write, Some(true));
    }

    #[test]
    fn apply_preserves_identity_fields() {
        let mut profile = AgentProfile {
            name: "agent".into(),
            allowed_paths: vec!["work/*".into()],
            allowed_executables: Some(vec!["custom".into()]),
            ..AgentProfile::default()
        };
        assert!(apply_tier_preset(&mut profile, "admin"));
        assert_eq!(profile.name, "agent");
        assert_eq!(profile.allowed_paths, ["work/*"]);
        assert_eq!(profile.allowed_executables, Some(vec!["custom".into()]));
    }

    #[test]
    fn presets_are_independent_owned_copies() {
        let mut first = get_preset("standard").expect("standard preset");
        first.can_write = Some(true);
        first.allowed_executables.as_mut().unwrap()[0] = "changed".into();
        let second = get_preset("standard").expect("standard preset");
        assert_eq!(second.can_write, Some(false));
        assert_eq!(second.allowed_executables.unwrap()[0], "curl");
    }
}
