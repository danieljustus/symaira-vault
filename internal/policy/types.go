// Package policy provides a declarative policy engine for context-aware
// auto-approvals of MCP tool calls.
package policy

import (
	"errors"
	"fmt"
	"time"
)

// Action represents the result of a policy evaluation.
type Action string

const (
	ActionAllow           Action = "allow"
	ActionDeny            Action = "deny"
	ActionPrompt          Action = "prompt"
	ActionRequireBiometry Action = "require_biometry"
)

// Valid actions for policies.
var validActions = map[Action]bool{
	ActionAllow:           true,
	ActionDeny:            true,
	ActionPrompt:          true,
	ActionRequireBiometry: true,
}

// IsValid returns whether the action is a known policy action.
func (a Action) IsValid() bool {
	return validActions[a]
}

// String returns the string representation of the action.
func (a Action) String() string {
	return string(a)
}

// Policy represents a collection of rules loaded from one or more policy files.
type Policy struct {
	Version     string `yaml:"version"`
	Description string `yaml:"description,omitempty"`
	Rules       []Rule `yaml:"rules"`
}

// Rule represents a single policy rule with conditions and an action.
type Rule struct {
	Name       string     `yaml:"name"`
	Priority   int        `yaml:"priority,omitempty"`
	Conditions Conditions `yaml:"conditions"`
	Action     Action     `yaml:"action"`
}

type RateLimitCondition struct {
	MaxReadsPerHour int `yaml:"max_reads_per_hour,omitempty"`
	MaxReadsPerDay  int `yaml:"max_reads_per_day,omitempty"`
}

// Conditions defines the matching criteria for a policy rule.
type Conditions struct {
	AgentID      string              `yaml:"agent_id,omitempty"`
	Path         string              `yaml:"path,omitempty"`
	Tags         []string            `yaml:"tags,omitempty"`
	WorkingDir   string              `yaml:"working_dir,omitempty"`
	TimeOfDay    *TimeRange          `yaml:"time_of_day,omitempty"`
	EnvVars      map[string]string   `yaml:"env_vars,omitempty"`
	ActionType   string              `yaml:"action,omitempty"` // read, write, delete, run, etc.
	RateLimit    *RateLimitCondition `yaml:"rate_limit,omitempty"`
	AllowedTools []string            `yaml:"allowed_tools,omitempty"`
	MaxSecrets   int                 `yaml:"max_secrets,omitempty"`
}

// TimeRange represents a time-of-day range for policy conditions.
type TimeRange struct {
	Start string `yaml:"start"`
	End   string `yaml:"end"`
}

// Parse parses the start and end times in HH:MM format.
func (tr *TimeRange) Parse() (start, end time.Time, err error) {
	if tr == nil {
		return time.Time{}, time.Time{}, errors.New("nil time range")
	}
	start, err = time.Parse("15:04", tr.Start)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid start time %q: %w", tr.Start, err)
	}
	end, err = time.Parse("15:04", tr.End)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid end time %q: %w", tr.End, err)
	}
	return start, end, nil
}

// Contains checks if the given time falls within the range.
// Supports wrap-around ranges (e.g., 22:00 to 06:00).
func (tr *TimeRange) Contains(t time.Time) bool {
	start, end, err := tr.Parse()
	if err != nil {
		return false
	}

	now := time.Date(0, 1, 1, t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
	start = time.Date(0, 1, 1, start.Hour(), start.Minute(), 0, 0, time.UTC)
	end = time.Date(0, 1, 1, end.Hour(), end.Minute(), 0, 0, time.UTC)

	if end.Before(start) || end.Equal(start) {
		// Wrap-around range (e.g., 22:00 - 06:00)
		return now.Equal(start) || now.After(start) || now.Before(end)
	}
	return (now.Equal(start) || now.After(start)) && now.Before(end)
}

// AuditLogFunc is a callback for logging policy-related events.
type AuditLogFunc func(action Action, ruleName, reason string)

// EvalContext provides runtime context for policy evaluation.
type EvalContext struct {
	AgentID    string
	Path       string
	Tags       []string
	WorkingDir string
	EnvVars    map[string]string
	ActionType string // read, write, delete, run, etc.
	ToolName   string
	Now        time.Time

	// RateLimiter is used for rate limit condition evaluation.
	RateLimiter *AgentRateLimiter

	// SecretsAccessed tracks how many secrets the agent has accessed in this session.
	SecretsAccessed int

	// AuditLogFunc is called when policy denies access.
	AuditLogFunc AuditLogFunc
}

// Result represents the outcome of a policy evaluation.
type Result struct {
	Action   Action
	RuleName string
	Matched  bool
}

// Validate checks a policy for syntax and semantic errors.
func (p *Policy) Validate() error {
	if p == nil {
		return errors.New("policy is nil")
	}

	if p.Version == "" {
		return errors.New("policy version is required")
	}

	if len(p.Rules) == 0 {
		return errors.New("policy must contain at least one rule")
	}

	var errs []error
	seenNames := make(map[string]int)

	for i, rule := range p.Rules {
		if rule.Name == "" {
			errs = append(errs, fmt.Errorf("rule at index %d: name is required", i))
		} else {
			if prevIdx, seen := seenNames[rule.Name]; seen {
				errs = append(errs, fmt.Errorf("rule %q at index %d: duplicate name (first seen at index %d)", rule.Name, i, prevIdx))
			} else {
				seenNames[rule.Name] = i
			}
		}

		if !rule.Action.IsValid() {
			errs = append(errs, fmt.Errorf("rule %q: invalid action %q (valid: allow, deny, prompt, require_biometry)", rule.Name, rule.Action))
		}

		if err := rule.Conditions.validate(); err != nil {
			errs = append(errs, fmt.Errorf("rule %q: %w", rule.Name, err))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (c *Conditions) validate() error {
	if c == nil {
		return nil
	}

	// At least one condition must be set (except for catch-all rules)
	// We allow empty conditions for default-deny/default-allow catch-all rules

	if c.TimeOfDay != nil {
		if _, _, err := c.TimeOfDay.Parse(); err != nil {
			return fmt.Errorf("invalid time_of_day: %w", err)
		}
	}

	if c.ActionType != "" {
		switch c.ActionType {
		case "read", "write", "delete", "run", "list", "get", "set", "find": //nolint:goconst // string literals in switch
			// valid
		default:
			return fmt.Errorf("invalid action type %q", c.ActionType)
		}
	}

	return nil
}

// DefaultResult returns the default deny result.
func DefaultResult() Result {
	return Result{
		Action:  ActionDeny,
		Matched: false,
	}
}
