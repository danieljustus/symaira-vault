package agentctx

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	mcpErr "github.com/danieljustus/OpenPass/internal/mcp/errors"
)

// writeTestConfig creates a minimal config.yaml in dir for the given agents.
func writeTestConfig(t *testing.T, dir string, agents map[string]string) {
	t.Helper()

	var b strings.Builder
	b.WriteString("agents:\n")
	for name, tier := range agents {
		b.WriteString("  " + name + ":\n")
		b.WriteString("    tier: " + tier + "\n")
	}

	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}
}

// TestLoadSuccess verifies that Load returns a valid context for a known agent.
func TestLoadSuccess(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, map[string]string{"test-agent": "safe"})

	ctx, err := Load("test-agent", dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	defer ctx.Close()

	if ctx.agentName != "test-agent" {
		t.Fatalf("agentName = %q, want %q", ctx.agentName, "test-agent")
	}
	if ctx.profile == nil {
		t.Fatal("profile is nil")
	}
	if ctx.profile.Name != "test-agent" {
		t.Fatalf("profile.Name = %q, want %q", ctx.profile.Name, "test-agent")
	}
}

// TestLoadUnknownAgent verifies that Load returns an error for a missing agent.
func TestLoadUnknownAgent(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, map[string]string{"existing-agent": "safe"})

	_, err := Load("unknown-agent", dir)
	if err == nil {
		t.Fatal("expected error for unknown agent, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error = %q, want 'not found'", err.Error())
	}
}

// TestLoadEmptyVaultDir verifies that Load handles an empty vaultDir gracefully
// by falling back to the user's home directory (will fail to find config there).
func TestLoadEmptyVaultDir(t *testing.T) {
	// This should produce an error because the home dir won't have our test config.
	_, err := Load("nonexistent", "")
	if err == nil {
		t.Fatal("expected error for empty vaultDir without config")
	}
}

// TestAgentContextNilSafety verifies that methods are safe on a nil context.
func TestAgentContextNilSafety(t *testing.T) {
	var ctx *AgentContext

	if err := ctx.Close(); err != nil {
		t.Fatalf("Close() on nil context should not error, got %v", err)
	}
	if err := ctx.EnforceTool("delete_entry"); err != nil {
		t.Fatalf("EnforceTool() on nil context should not error, got %v", err)
	}
	if err := ctx.EnforcePath("/some/path", "write"); err != nil {
		t.Fatalf("EnforcePath() on nil context should not error, got %v", err)
	}
	if err := ctx.RecordAudit("test", nil); err != nil {
		t.Fatalf("RecordAudit() on nil context should not error, got %v", err)
	}
	if _, err := ctx.BumpQuota("test_tool"); err != nil {
		t.Fatalf("BumpQuota() on nil context should not error, got %v", err)
	}
	if p := ctx.Profile(); p != nil {
		t.Fatalf("Profile() on nil context should be nil, got %v", p)
	}
}

// TestEnforceToolSafeTier verifies that safe tier blocks the expected tools.
func TestEnforceToolSafeTier(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, map[string]string{"safe-agent": "safe"})
	ctx, err := Load("safe-agent", dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	defer ctx.Close()

	blockedForSafe := []string{
		"set_entry_field", "delete_entry", "run_command",
		"execute_with_secret", "execute_api_request", "secure_input",
		"request_credential", "copy_to_clipboard", "autotype",
	}
	for _, tool := range blockedForSafe {
		err := ctx.EnforceTool(tool)
		if err == nil {
			t.Errorf("EnforceTool(%q) = nil, want MCPError", tool)
		}
		var mcpE *mcpErr.MCPError
		if !errors.As(err, &mcpE) {
			t.Errorf("EnforceTool(%q) error type = %T, want *MCPError", tool, err)
		}
		if mcpE != nil && mcpE.Code != mcpErr.ErrToolNotAllowed {
			t.Errorf("EnforceTool(%q) code = %q, want %q", tool, mcpE.Code, mcpErr.ErrToolNotAllowed)
		}
	}

	// Allowed tools should pass.
	allowed := []string{"get_entry", "list_entries", "generate_totp"}
	for _, tool := range allowed {
		if err := ctx.EnforceTool(tool); err != nil {
			t.Errorf("EnforceTool(%q) = %v, want nil", tool, err)
		}
	}
}

// TestEnforceToolStandardTier verifies that standard tier blocks the expected tools.
func TestEnforceToolStandardTier(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, map[string]string{"std-agent": "standard"})
	ctx, err := Load("std-agent", dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	defer ctx.Close()

	blockedForStandard := []string{
		"delete_entry", "run_command",
		"execute_with_secret", "execute_api_request",
	}
	for _, tool := range blockedForStandard {
		err := ctx.EnforceTool(tool)
		if err == nil {
			t.Errorf("EnforceTool(%q) = nil, want MCPError", tool)
		}
		var mcpE *mcpErr.MCPError
		if !errors.As(err, &mcpE) || mcpE.Code != mcpErr.ErrToolNotAllowed {
			t.Errorf("EnforceTool(%q) code = %q, want %q", tool, mcpE.Code, mcpErr.ErrToolNotAllowed)
		}
	}

	// Safe-only tools (like set_entry_field) should be allowed in standard.
	allowed := []string{"set_entry_field", "secure_input", "copy_to_clipboard", "get_entry"}
	for _, tool := range allowed {
		if err := ctx.EnforceTool(tool); err != nil {
			t.Errorf("EnforceTool(%q) = %v, want nil", tool, err)
		}
	}
}

// TestEnforceToolAdminTier verifies that admin tier allows all tools.
func TestEnforceToolAdminTier(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, map[string]string{"admin-agent": "admin"})
	ctx, err := Load("admin-agent", dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	defer ctx.Close()

	allTools := []string{
		"set_entry_field", "delete_entry", "run_command",
		"execute_with_secret", "execute_api_request", "secure_input",
		"request_credential", "copy_to_clipboard", "autotype",
		"get_entry", "list_entries",
	}
	for _, tool := range allTools {
		if err := ctx.EnforceTool(tool); err != nil {
			t.Errorf("EnforceTool(%q) = %v, want nil (admin tier)", tool, err)
		}
	}
}

// TestEnforceToolReadOnlyAlias verifies that "read-only" maps to the safe tier blocking.
func TestEnforceToolReadOnlyAlias(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, map[string]string{"ro-agent": "read-only"})
	ctx, err := Load("ro-agent", dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	defer ctx.Close()

	// read-only maps to safe, so set_entry_field should be blocked.
	if err := ctx.EnforceTool("set_entry_field"); err == nil {
		t.Error("EnforceTool(set_entry_field) = nil, want error for read-only alias")
	}
}

// TestEnforcePathSafeTier verifies safe tier blocks write and delete actions.
func TestEnforcePathSafeTier(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, map[string]string{"safe-agent": "safe"})
	ctx, err := Load("safe-agent", dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	defer ctx.Close()

	// write should be blocked.
	if err := ctx.EnforcePath("/test/path", "write"); err == nil {
		t.Error("EnforcePath(write) = nil, want error for safe tier")
	}
	// delete should be blocked.
	if err := ctx.EnforcePath("/test/path", "delete"); err == nil {
		t.Error("EnforcePath(delete) = nil, want error for safe tier")
	}
	// read should be allowed.
	if err := ctx.EnforcePath("/test/path", "read"); err != nil {
		t.Errorf("EnforcePath(read) = %v, want nil", err)
	}
}

// TestEnforcePathStandardTier verifies standard tier blocks delete but not write.
func TestEnforcePathStandardTier(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, map[string]string{"std-agent": "standard"})
	ctx, err := Load("std-agent", dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	defer ctx.Close()

	// write should be allowed.
	if err := ctx.EnforcePath("/test/path", "write"); err != nil {
		t.Errorf("EnforcePath(write) = %v, want nil for standard tier", err)
	}
	// delete should be blocked.
	if err := ctx.EnforcePath("/test/path", "delete"); err == nil {
		t.Error("EnforcePath(delete) = nil, want error for standard tier")
	}
	// read should be allowed.
	if err := ctx.EnforcePath("/test/path", "read"); err != nil {
		t.Errorf("EnforcePath(read) = %v, want nil", err)
	}
}

// TestEnforcePathAdminTier verifies admin tier allows all actions.
func TestEnforcePathAdminTier(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, map[string]string{"admin-agent": "admin"})
	ctx, err := Load("admin-agent", dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	defer ctx.Close()

	actions := []string{"read", "write", "delete"}
	for _, action := range actions {
		if err := ctx.EnforcePath("/test/path", action); err != nil {
			t.Errorf("EnforcePath(%q) = %v, want nil for admin tier", action, err)
		}
	}
}

// TestRecordAuditWithLogger verifies that RecordAudit writes through the audit logger.
func TestRecordAuditWithLogger(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, map[string]string{"audit-agent": "standard"})
	ctx, err := Load("audit-agent", dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	defer ctx.Close()

	// The audit.Logger should be available (created by Load).
	if ctx.auditLog == nil {
		t.Skip("audit logger not available — may be environment issue")
	}

	details := map[string]any{
		"path":   "secret/key",
		"reason": "access_granted",
		"ok":     true,
	}
	if err := ctx.RecordAudit("get", details); err != nil {
		t.Fatalf("RecordAudit() error = %v", err)
	}

	// This should not panic or return an error with nil details.
	if err := ctx.RecordAudit("list", nil); err != nil {
		t.Fatalf("RecordAudit(list) error = %v", err)
	}
}

// TestRecordAuditFallback verifies that RecordAudit falls back to file logging
// when the audit logger is unavailable (manually nil out the logger).
func TestRecordAuditFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: audit fallback test requires Unix file semantics")
	}
	dir := t.TempDir()
	writeTestConfig(t, dir, map[string]string{"fallback-agent": "safe"})
	ctx, err := Load("fallback-agent", dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	defer ctx.Close()

	// Nil the audit logger to test fallback.
	ctx.auditLog = nil

	details := map[string]any{
		"path":   "secret/key",
		"reason": "denied",
		"ok":     false,
	}
	if err := ctx.RecordAudit("delete", details); err != nil {
		t.Fatalf("RecordAudit() error = %v", err)
	}

	// Verify the fallback file exists.
	logPath := filepath.Join(dir, "audit", "fallback-agent.log")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Fatalf("fallback audit log not created at %s", logPath)
	}
}

// TestBumpQuotaNilCounter verifies BumpQuota works with no counter configured.
func TestBumpQuotaNilCounter(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, map[string]string{"quota-agent": "standard"})
	ctx, err := Load("quota-agent", dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	defer ctx.Close()

	count, err := ctx.BumpQuota("test_tool")
	if err != nil {
		t.Fatalf("BumpQuota() error = %v", err)
	}
	if count != 0 {
		t.Fatalf("BumpQuota() = %d, want 0 (no counter)", count)
	}
}

// TestBumpQuotaWithCounter verifies BumpQuota with a custom counter.
func TestBumpQuotaWithCounter(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, map[string]string{"quota-agent": "standard"})
	ctx, err := Load("quota-agent", dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	defer ctx.Close()

	mc := &mockCounter{counts: map[string]int{}}
	ctx.SetQuotaCounter(mc)

	count, err := ctx.BumpQuota("read_entry")
	if err != nil {
		t.Fatalf("BumpQuota() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("BumpQuota() = %d, want 1", count)
	}

	count, err = ctx.BumpQuota("read_entry")
	if err != nil {
		t.Fatalf("BumpQuota() error = %v", err)
	}
	if count != 2 {
		t.Fatalf("BumpQuota() = %d, want 2", count)
	}
}

// TestIsAgentMode verifies the IsAgentMode function.
func TestIsAgentMode(t *testing.T) {
	// Save and restore env.
	prev := os.Getenv(envAgent)
	defer os.Setenv(envAgent, prev)

	if err := os.Unsetenv(envAgent); err != nil {
		t.Fatalf("Unsetenv error: %v", err)
	}
	if IsAgentMode() {
		t.Error("IsAgentMode() = true, want false when env is unset")
	}

	if err := os.Setenv(envAgent, "test-agent"); err != nil {
		t.Fatalf("Setenv error: %v", err)
	}
	if !IsAgentMode() {
		t.Error("IsAgentMode() = false, want true when env is set")
	}

	if got := AgentName(); got != "test-agent" {
		t.Fatalf("AgentName() = %q, want %q", got, "test-agent")
	}
}

// TestAgentNameEmpty verifies AgentName returns empty when env is not set.
func TestAgentNameEmpty(t *testing.T) {
	prev := os.Getenv(envAgent)
	defer os.Setenv(envAgent, prev)

	os.Unsetenv(envAgent)
	if got := AgentName(); got != "" {
		t.Fatalf("AgentName() = %q, want empty string", got)
	}
}

// TestProfile verifies Profile returns the loaded profile.
func TestProfile(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, map[string]string{"prof-agent": "admin"})
	ctx, err := Load("prof-agent", dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	defer ctx.Close()

	p := ctx.Profile()
	if p == nil {
		t.Fatal("Profile() returned nil")
	}
	if p.Name != "prof-agent" {
		t.Fatalf("Profile().Name = %q, want %q", p.Name, "prof-agent")
	}
	if *p.Tier != "admin" {
		t.Fatalf("Profile().Tier = %q, want %q", *p.Tier, "admin")
	}
}

// ---------------------------------------------------------------------------
// mockCounter implements QuotaCounter for testing.
// ---------------------------------------------------------------------------

type mockCounter struct {
	counts map[string]int
}

func (m *mockCounter) Increment(toolName string) (int, error) {
	m.counts[toolName]++
	return m.counts[toolName], nil
}
