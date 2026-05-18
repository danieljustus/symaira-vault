package mcp

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

type whoamiProfile struct {
	Name            string   `json:"name"`
	Tier            string   `json:"tier"`
	AllowedPaths    []string `json:"allowed_paths"`
	ApprovalMode    string   `json:"approval_mode"`
	CanWrite        bool     `json:"can_write"`
	CanRunCommands  bool     `json:"can_run_commands"`
	CanUseClipboard bool     `json:"can_use_clipboard"`
	CanUseAutotype  bool     `json:"can_use_autotype"`
	RedactFields    []string `json:"redact_fields"`
}

type whoamiTools struct {
	Available   []string            `json:"available"`
	Unavailable []whoamiUnavailable `json:"unavailable"`
}

type whoamiUnavailable struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

type whoamiQuotas struct {
	ReadsPerHour      quotaInfo `json:"reads_per_hour"`
	ReadsPerDay       quotaInfo `json:"reads_per_day"`
	SecretsPerSession quotaInfo `json:"secrets_per_session"`
}

type quotaInfo struct {
	Used  int `json:"used"`
	Limit int `json:"limit"`
}

type whoamiVault struct {
	Unlocked     bool `json:"unlocked"`
	EntriesCount int  `json:"entries_count"`
}

type whoamiInfo struct {
	Agent           string        `json:"agent"`
	OpenPassVersion string        `json:"openpass_version"`
	Profile         whoamiProfile `json:"profile"`
	Tools           whoamiTools   `json:"tools"`
	Quotas          whoamiQuotas  `json:"quotas"`
	Vault           whoamiVault   `json:"vault"`
	CLIAlternative  string        `json:"cli_alternative_hint"`
	ErrorsDoc       string        `json:"errors_doc"`
	TierUpgradeHint string        `json:"tier_upgrade_hint"`
}

func (s *Server) handleWhoami(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
	_, _ = ctx, req

	info := whoamiInfo{
		Agent:           s.agent.Name,
		OpenPassVersion: defaultServerVersion,
		Profile: whoamiProfile{
			Name:            s.agent.Name,
			Tier:            s.agent.Tier,
			AllowedPaths:    s.agent.AllowedPaths,
			ApprovalMode:    s.agent.ApprovalMode,
			CanWrite:        s.agent.CanWrite,
			CanRunCommands:  s.agent.CanRunCommands,
			CanUseClipboard: s.agent.CanUseClipboard,
			CanUseAutotype:  s.agent.CanUseAutotype,
			RedactFields:    s.agent.RedactFields,
		},
		Quotas: whoamiQuotas{
			ReadsPerHour: quotaInfo{
				Used:  0,
				Limit: s.agent.MaxReadsPerHour,
			},
			ReadsPerDay: quotaInfo{
				Used:  0,
				Limit: s.agent.MaxReadsPerDay,
			},
			SecretsPerSession: quotaInfo{
				Used:  int(s.secretsAccessed.Load()),
				Limit: s.agent.MaxSecretsInSession,
			},
		},
		Vault: whoamiVault{
			Unlocked:     s.vault.Identity != nil,
			EntriesCount: 0,
		},
		CLIAlternative:  "Use 'openpass status' for a comprehensive overview.",
		ErrorsDoc:       "See https://github.com/danieljustus/OpenPass/blob/main/docs/errors.md for error code documentation.",
		TierUpgradeHint: "Upgrade your agent tier in ~/.openpass/config.yaml to unlock additional tools.",
	}

	var available []string
	var unavailable []whoamiUnavailable

	for _, def := range toolDefinitions() {
		if def.Deprecated {
			continue
		}
		if def.Available != nil && !def.Available(s) {
			unavailable = append(unavailable, whoamiUnavailable{
				Name:   def.Name,
				Code:   "not_available",
				Reason: "Tool is not available in the current environment",
			})
			continue
		}
		if agentErr := isToolBlockedByAgent(s.agent, def.Name); agentErr != nil {
			unavailable = append(unavailable, whoamiUnavailable{
				Name:   def.Name,
				Code:   "blocked_by_agent",
				Reason: agentErr.Error(),
			})
			continue
		}
		available = append(available, def.Name)
	}

	info.Tools = whoamiTools{
		Available:   available,
		Unavailable: unavailable,
	}

	svc := vaultsvc.New(slog.Default(), s.vault)
	paths, err := svc.List("")
	if err == nil {
		info.Vault.EntriesCount = len(paths)
	}

	resultJSON, err := json.Marshal(info)
	if err != nil {
		return nil, err
	}
	return NewToolResultText(string(resultJSON)), nil
}
