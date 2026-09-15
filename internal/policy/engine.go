package policy

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"time"
)

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

	if c.Path != "" && !matchPath(rule.pathPattern, ctx.Path, ctx.HomeDir) {
		return false
	}

	if len(c.Tags) > 0 && !matchAnyTag(c.Tags, ctx.Tags) {
		return false
	}

	if c.WorkingDir != "" && !matchPath(rule.workDirPattern, ctx.WorkingDir, ctx.HomeDir) {
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

// matchPath is defined over slash-separated logical paths and is deliberately
// OS-independent: it uses the slash-based path package rather than filepath, so
// a policy evaluates identically on every host. Converting a native path into
// this logical form happens once, at the runtime boundary in BuildContext.
//
// home is the caller-supplied home directory used to expand a leading "~/".
// The matcher performs no runtime discovery of its own, which keeps evaluation
// pure and reproducible for the POLICY-001 contract.
//
//nolint:gocyclo // complexity inherent to glob-style path matching logic
func matchPath(pattern, value, home string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}

	if strings.HasPrefix(pattern, "~/") && home != "" {
		pattern = path.Join(home, pattern[2:])
	}

	cleanPath := path.Clean(value)
	if cleanPath == "." {
		cleanPath = ""
	}

	if pattern == cleanPath {
		return true
	}
	if matched, err := path.Match(pattern, cleanPath); err == nil && matched {
		return true
	}

	// The recursive directory suffix is a policy extension over path.Match:
	// it means this directory and every descendant.
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		prefix = strings.TrimSuffix(prefix, "/")
		if prefix != "" && (cleanPath == prefix || strings.HasPrefix(cleanPath, prefix+"/")) {
			return true
		}
	}
	if strings.HasSuffix(pattern, "/") {
		prefix := strings.TrimSuffix(pattern, "/")
		if prefix != "" && (cleanPath == prefix || strings.HasPrefix(cleanPath, prefix+"/")) {
			return true
		}
	}
	// The bare directory-prefix convenience applies only to wholly literal
	// patterns. A pattern carrying any glob metacharacter is matched as a glob
	// and nothing else, so the same pattern is never both glob and literal.
	if !strings.ContainsAny(pattern, "*?[") {
		if cleanPath == pattern || strings.HasPrefix(cleanPath, pattern+"/") {
			return true
		}
	}
	return false
}

// ToLogicalPath converts a native filesystem path into the slash-separated
// logical form the policy matcher is defined over. This is the only policy code
// that interprets the host separator.
func ToLogicalPath(value string) string {
	if value == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(value))
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
