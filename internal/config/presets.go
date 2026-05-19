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
		CanWrite:         BoolPtr(false),
		CanRunCommands:   BoolPtr(false),
		CanManageConfig:  BoolPtr(false),
		CanUseClipboard:  BoolPtr(false),
		CanUseAutotype:   BoolPtr(false),
		CanReadValues:    BoolPtr(false),
		ExposeValueTools: BoolPtr(false),
		AutoUnseal:       BoolPtr(false),
		ApprovalMode:     StrPtr("deny"),
		RequireApproval:  BoolPtr(false),
		AllowedPaths:     []string{},
	},
	TierStandard: {
		CanWrite:           BoolPtr(false),
		CanRunCommands:     BoolPtr(false),
		CanManageConfig:    BoolPtr(false),
		CanUseClipboard:    BoolPtr(true),
		CanUseAutotype:     BoolPtr(true),
		CanReadValues:      BoolPtr(true),
		ExposeValueTools:   BoolPtr(false),
		AutoUnseal:         BoolPtr(false),
		ApprovalMode:       StrPtr("prompt"),
		RequireApproval:    BoolPtr(true),
		AllowedPaths:       []string{},
		AllowedExecutables: []string{"curl", "git", "terraform", "npm", "node", "python", "python3", "docker", "kubectl"},
	},
	TierAdmin: {
		CanWrite:         BoolPtr(true),
		CanRunCommands:   BoolPtr(true),
		CanManageConfig:  BoolPtr(true),
		CanUseClipboard:  BoolPtr(true),
		CanUseAutotype:   BoolPtr(true),
		CanReadValues:    BoolPtr(true),
		ExposeValueTools: BoolPtr(true),
		AutoUnseal:       BoolPtr(true),
		ApprovalMode:     StrPtr("prompt"),
		RequireApproval:  BoolPtr(true),
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
	target.CanWrite = BoolPtr(preset.CanWrite != nil && *preset.CanWrite)
	target.CanRunCommands = BoolPtr(preset.CanRunCommands != nil && *preset.CanRunCommands)
	target.CanManageConfig = BoolPtr(preset.CanManageConfig != nil && *preset.CanManageConfig)
	target.CanUseClipboard = BoolPtr(preset.CanUseClipboard != nil && *preset.CanUseClipboard)
	target.CanUseAutotype = BoolPtr(preset.CanUseAutotype != nil && *preset.CanUseAutotype)
	target.CanReadValues = BoolPtr(preset.CanReadValues != nil && *preset.CanReadValues)
	target.ExposeValueTools = BoolPtr(preset.ExposeValueTools != nil && *preset.ExposeValueTools)
	target.AutoUnseal = BoolPtr(preset.AutoUnseal != nil && *preset.AutoUnseal)
	if preset.ApprovalMode != nil {
		target.ApprovalMode = StrPtr(*preset.ApprovalMode)
	}
	target.RequireApproval = BoolPtr(preset.RequireApproval != nil && *preset.RequireApproval)
	if preset.AllowedExecutables != nil {
		target.AllowedExecutables = append([]string(nil), preset.AllowedExecutables...)
	}
	return true
}
