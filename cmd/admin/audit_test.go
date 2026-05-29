package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/audit"
)

func TestParseSinceDuration(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"hours", "1h", time.Hour, false},
		{"24 hours", "24h", 24 * time.Hour, false},
		{"7 days", "7d", 7 * 24 * time.Hour, false},
		{"minutes", "30m", 30 * time.Minute, false},
		{"seconds", "60s", 60 * time.Second, false},
		{"empty", "", 0, true},
		{"invalid", "abc", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSinceDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSinceDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseSinceDuration(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFilterAuditEntries(t *testing.T) {
	now := time.Now().UTC()
	entries := []audit.LogEntry{
		{Timestamp: now.Add(-1 * time.Hour).Format(time.RFC3339), Agent: "agent1", Action: "get", OK: true},
		{Timestamp: now.Add(-2 * time.Hour).Format(time.RFC3339), Agent: "agent2", Action: "set", OK: false},
		{Timestamp: now.Add(-30 * time.Minute).Format(time.RFC3339), Agent: "agent1", Action: "list", OK: true},
		{Timestamp: now.Add(-48 * time.Hour).Format(time.RFC3339), Agent: "agent3", Action: "delete", OK: true},
	}

	tests := []struct {
		name       string
		since      string
		failedOnly bool
		wantLen    int
	}{
		{"no filter", "", false, 4},
		{"since 1h", "1h", false, 1},
		{"since 3h", "3h", false, 3},
		{"failed only", "", true, 1},
		{"failed since 3h", "3h", true, 1},
		{"since 7d", "7d", false, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterAuditEntries(entries, tt.since, tt.failedOnly)
			if len(got) != tt.wantLen {
				t.Errorf("FilterAuditEntries() got %d entries, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestAuditLogPath(t *testing.T) {
	tests := []struct {
		name    string
		agent   string
		wantErr bool
	}{
		{"default", "default", false},
		{"claude-code", "claude-code", false},
		{"empty", "", false},
		{"path traversal slash", "../etc", true},
		{"path traversal backslash", "..\\etc", true},
		{"dot", ".", true},
		{"dotdot", "..", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := AuditLogPath(tt.agent)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuditLogPath(%q) error = %v, wantErr %v", tt.agent, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if path == "" {
					t.Errorf("AuditLogPath(%q) returned empty path", tt.agent)
				}
				if !strings.Contains(path, "audit-") {
					t.Errorf("AuditLogPath(%q) = %q, expected to contain 'audit-'", tt.agent, path)
				}
				home, _ := os.UserHomeDir()
				if !strings.HasPrefix(path, home) {
					t.Errorf("AuditLogPath(%q) = %q, expected to be under home dir", tt.agent, path)
				}
			}
		})
	}
}

func TestAuditLogPathPathTraversal(t *testing.T) {
	traversalAgents := []string{
		"foo/bar",
		"foo\\bar",
		"a/../b",
	}

	for _, agent := range traversalAgents {
		_, err := AuditLogPath(agent)
		if err == nil {
			t.Errorf("AuditLogPath(%q) expected error for path traversal, got nil", agent)
		}
	}
}

func TestOutputAuditJSON(t *testing.T) {
	entries := []audit.LogEntry{
		{Timestamp: time.Now().UTC().Format(time.RFC3339), Agent: "test", Action: "get", OK: true},
	}
	_ = OutputAuditJSON(AuditCmd, entries)
}

func TestOutputAuditTable(t *testing.T) {
	entries := []audit.LogEntry{
		{Timestamp: time.Now().UTC().Format(time.RFC3339), Agent: "test", Action: "get", OK: true},
	}
	_ = OutputAuditTable(AuditCmd, entries)
}

func TestOutputAuditTableEmpty(t *testing.T) {
	err := OutputAuditTable(AuditCmd, nil)
	if err != nil {
		t.Errorf("OutputAuditTable(nil) error = %v", err)
	}

	err = OutputAuditTable(AuditCmd, []audit.LogEntry{})
	if err != nil {
		t.Errorf("OutputAuditTable(empty) error = %v", err)
	}
}

func TestLoadAuditEntriesNotExist(t *testing.T) {
	entries, err := LoadAuditEntries("nonexistent-agent-12345", 10)
	if err != nil {
		t.Errorf("LoadAuditEntries(nonexistent) error = %v", err)
	}
	if entries != nil {
		t.Errorf("LoadAuditEntries(nonexistent) = %v, want nil", entries)
	}
}

func TestLoadAuditEntriesWithData(t *testing.T) {
	tmpDir := t.TempDir()
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)

	agent := "test-agent"
	path, err := AuditLogPath(agent)
	if err != nil {
		t.Fatalf("AuditLogPath error: %v", err)
	}

	// Create the audit directory and file
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir error: %v", err)
	}

	data := `{"ts":"2024-01-01T00:00:00Z","agent":"test-agent","action":"get","ok":true}` + "\n"
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("write error: %v", err)
	}

	entries, err := LoadAuditEntries(agent, 10)
	if err != nil {
		t.Errorf("LoadAuditEntries error = %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("LoadAuditEntries got %d entries, want 1", len(entries))
	}
}
