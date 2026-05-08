package policy

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

var pathMatch = path.Match

// Engine evaluates policies against evaluation contexts.
type Engine struct {
	rules []compiledRule
}

type compiledRule struct {
	Rule
	pathPattern    string
	workDirPattern string
}

// NewEngine creates a new policy engine from one or more policies.
// Rules are sorted by priority (highest first).
func NewEngine(policies []*Policy) *Engine {
	var rules []compiledRule
	for _, policy := range policies {
		for _, rule := range policy.Rules {
			cr := compiledRule{
				Rule:           rule,
				pathPattern:    normalizePattern(rule.Conditions.Path),
				workDirPattern: normalizePattern(rule.Conditions.WorkingDir),
			}
			rules = append(rules, cr)
		}
	}

	// Sort by priority descending (highest first)
	for i := 0; i < len(rules)-1; i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[j].Priority > rules[i].Priority {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}

	return &Engine{rules: rules}
}

// Evaluate evaluates the given context against all rules and returns the first match.
// If no rule matches, it returns the default deny result.
func (e *Engine) Evaluate(ctx EvalContext) Result {
	if e == nil || len(e.rules) == 0 {
		return DefaultResult()
	}

	if ctx.Now.IsZero() {
		ctx.Now = time.Now()
	}

	for _, rule := range e.rules {
		if e.matches(rule, ctx) {
			result := Result{
				Action:   rule.Action,
				RuleName: rule.Name,
				Matched:  true,
			}
			if result.Action == ActionDeny && ctx.AuditLogFunc != nil {
				ctx.AuditLogFunc(ActionDeny, rule.Name, "rule matched with deny action")
			}
			return result
		}
	}

	if ctx.AuditLogFunc != nil {
		ctx.AuditLogFunc(ActionDeny, "", "no matching rule found, default deny")
	}
	return DefaultResult()
}

//nolint:gocyclo // complexity inherent to policy rule matching with many condition types
func (e *Engine) matches(rule compiledRule, ctx EvalContext) bool {
	c := rule.Conditions

	if c.AgentID != "" && !matchString(c.AgentID, ctx.AgentID) {
		return false
	}

	if c.Path != "" && !matchPath(rule.pathPattern, ctx.Path) {
		return false
	}

	if len(c.Tags) > 0 && !matchAnyTag(c.Tags, ctx.Tags) {
		return false
	}

	if c.WorkingDir != "" && !matchPath(rule.workDirPattern, ctx.WorkingDir) {
		return false
	}

	if c.TimeOfDay != nil && !c.TimeOfDay.Contains(ctx.Now) {
		return false
	}

	if len(c.EnvVars) > 0 && !matchEnvVars(c.EnvVars, ctx.EnvVars) {
		return false
	}

	if c.ActionType != "" && !matchString(c.ActionType, ctx.ActionType) {
		return false
	}

	if len(c.AllowedTools) > 0 && !matchAllowedTool(c.AllowedTools, ctx.ToolName) {
		return false
	}

	if c.RateLimit != nil {
		if ctx.RateLimiter == nil {
			return false
		}
		if !ctx.RateLimiter.HasLimits(ctx.AgentID) {
			ctx.RateLimiter.SetLimits(ctx.AgentID, c.RateLimit.MaxReadsPerHour, c.RateLimit.MaxReadsPerDay)
		}
		if !ctx.RateLimiter.Allow(ctx.AgentID) {
			if ctx.AuditLogFunc != nil {
				ctx.AuditLogFunc(ActionDeny, rule.Name, "rate limit exceeded")
			}
			return false
		}
	}

	if c.MaxSecrets > 0 {
		if ctx.SecretsAccessed >= c.MaxSecrets {
			if ctx.AuditLogFunc != nil {
				ctx.AuditLogFunc(ActionDeny, rule.Name, fmt.Sprintf("max secrets exceeded: %d >= %d", ctx.SecretsAccessed, c.MaxSecrets))
			}
			return false
		}
	}

	return true
}

func matchString(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	return pattern == value
}

//nolint:gocyclo // complexity inherent to glob-style path matching logic
func matchPath(pattern, path string) bool {
	if pattern == "" {
		return true
	}
	if pattern == "*" {
		return true
	}

	cleanPath := filepath.ToSlash(filepath.Clean(path))
	if cleanPath == "." {
		cleanPath = ""
	}

	// Exact match
	if pattern == cleanPath {
		return true
	}

	matched, err := pathMatch(pattern, cleanPath)
	if err == nil && matched {
		return true
	}

	// Prefix match for directory patterns ending with "/" or "/**" (recursive)
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		prefix = strings.TrimSuffix(prefix, "/")
		if prefix != "" && (cleanPath == prefix || strings.HasPrefix(cleanPath, prefix+"/")) {
			return true
		}
	}

	// Prefix match for plain directory patterns ending with "/"
	if strings.HasSuffix(pattern, "/") {
		prefix := strings.TrimSuffix(pattern, "/")
		if prefix != "" && (cleanPath == prefix || strings.HasPrefix(cleanPath, prefix+"/")) {
			return true
		}
	}

	// For plain paths without wildcards, also match as directory prefix
	if !strings.Contains(pattern, "*") {
		if cleanPath == pattern || strings.HasPrefix(cleanPath, pattern+"/") {
			return true
		}
	}

	// Expand home directory if needed
	if strings.HasPrefix(pattern, "~/") {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			expandedPattern := filepath.ToSlash(filepath.Join(home, pattern[2:]))
			return matchPath(expandedPattern, cleanPath)
		}
	}

	return false
}

func matchAnyTag(required, actual []string) bool {
	if len(required) == 0 || len(actual) == 0 {
		return false
	}
	for _, r := range required {
		for _, a := range actual {
			if r == a {
				return true
			}
		}
	}
	return false
}

func matchEnvVars(required, actual map[string]string) bool {
	for key, pattern := range required {
		value, ok := actual[key]
		if !ok {
			return false
		}
		if !matchString(pattern, value) {
			return false
		}
	}
	return true
}

func matchAllowedTool(allowed []string, toolName string) bool {
	if len(allowed) == 0 || toolName == "" {
		return true
	}
	for _, t := range allowed {
		if t == toolName {
			return true
		}
	}
	return false
}

func normalizePattern(pattern string) string {
	if pattern == "" {
		return ""
	}
	cleaned := strings.TrimSpace(pattern)
	if cleaned == "." {
		return ""
	}
	return cleaned
}
