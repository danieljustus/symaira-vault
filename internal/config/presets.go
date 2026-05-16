package config

// TierPreset represents a named set of agent profile defaults.
type TierPreset string

const (
	TierReadOnly TierPreset = "read-only"
	TierStandard TierPreset = "standard"
	TierAdmin    TierPreset = "admin"
)

// TierPresets maps tier names to their default agent profile values.
// These are applied as a base when an AgentProfile specifies a Tier.
// Explicit YAML fields for the same agent override the preset values.
var TierPresets = map[TierPreset]AgentProfile{
	TierReadOnly: {
		CanWrite:         false,
		CanRunCommands:   false,
		CanManageConfig:  false,
		CanUseClipboard:  false,
		CanUseAutotype:   false,
		CanReadValues:    false,
		ExposeValueTools: false,
		ApprovalMode:     "none",
		RequireApproval:  false,
		AllowedPaths:     []string{},
	},
	TierStandard: {
		CanWrite:         false,
		CanRunCommands:   false,
		CanManageConfig:  false,
		CanUseClipboard:  true,
		CanUseAutotype:   true,
		CanReadValues:    true,
		ExposeValueTools: false,
		ApprovalMode:     "prompt",
		RequireApproval:  true,
		AllowedPaths:     []string{},
	},
	TierAdmin: {
		CanWrite:         true,
		CanRunCommands:   true,
		CanManageConfig:  true,
		CanUseClipboard:  true,
		CanUseAutotype:   true,
		CanReadValues:    true,
		ExposeValueTools: true,
		ApprovalMode:     "prompt",
		RequireApproval:  true,
		AllowedPaths:     []string{},
	},
}

// GetPreset returns a pointer to a copy of the AgentProfile for the given tier,
// or nil if the tier is not recognized. Callers can safely modify the returned copy.
func GetPreset(tier string) *AgentProfile {
	p, ok := TierPresets[TierPreset(tier)]
	if !ok {
		return nil
	}
	return &p
}


// ApplyTierPreset applies the preset values for the given tier to target.
// Only capability/approval fields are overwritten; Name and AllowedPaths are preserved.
// Returns true if the tier was found and applied, false otherwise.
func ApplyTierPreset(target *AgentProfile, tier string) bool {
	preset, ok := TierPresets[TierPreset(tier)]
	if !ok {
		return false
	}
	target.CanWrite = preset.CanWrite
	target.CanRunCommands = preset.CanRunCommands
	target.CanManageConfig = preset.CanManageConfig
	target.CanUseClipboard = preset.CanUseClipboard
	target.CanUseAutotype = preset.CanUseAutotype
	target.CanReadValues = preset.CanReadValues
	target.ExposeValueTools = preset.ExposeValueTools
	target.ApprovalMode = preset.ApprovalMode
	target.RequireApproval = preset.RequireApproval
	return true
}
