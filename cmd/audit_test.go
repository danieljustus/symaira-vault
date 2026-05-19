package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	admin "github.com/danieljustus/OpenPass/cmd/admin"
	"github.com/danieljustus/OpenPass/internal/audit"
)

func TestAuditLogPath(t *testing.T) {
	home := t.TempDir()
	_ = os.Setenv("HOME", home)
	defer func() {
		h, _ := os.UserHomeDir()
		_ = os.Setenv("HOME", h)
	}()

	path, err := admin.AuditLogPath("default")
	if err != nil {
		t.Fatalf("admin.AuditLogPath() error = %v", err)
	}

	expected := filepath.Join(home, ".openpass", "audit-default.log")
	if path != expected {
		t.Fatalf("admin.AuditLogPath() = %q, want %q", path, expected)
	}
}

func TestAuditLogPath_InvalidAgent(t *testing.T) {
	_, err := admin.AuditLogPath("../etc/passwd")
	if err == nil {
		t.Fatal("expected error for invalid agent name")
	}
}

func TestAuditLogPath_NoHomeDir(t *testing.T) {
	origHome := os.Getenv("HOME")
	origUserProfile := os.Getenv("USERPROFILE")
	_ = os.Unsetenv("HOME")
	_ = os.Unsetenv("USERPROFILE")
	defer func() {
		_ = os.Setenv("HOME", origHome)
		_ = os.Setenv("USERPROFILE", origUserProfile)
	}()

	_, err := admin.AuditLogPath("default")
	if err == nil {
		t.Fatal("expected error when home directory is unavailable")
	}
}

func TestLoadAuditEntries(t *testing.T) {
	home := t.TempDir()
	_ = os.Setenv("HOME", home)
	defer func() {
		h, _ := os.UserHomeDir()
		_ = os.Setenv("HOME", h)
	}()

	auditDir := filepath.Join(home, ".openpass")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	logFile := filepath.Join(auditDir, "audit-default.log")
	entries := []audit.LogEntry{
		{Timestamp: time.Now().UTC().Format(time.RFC3339), Agent: "default", Action: "get", Path: "test1", Transport: "stdio", OK: true},
		{Timestamp: time.Now().UTC().Format(time.RFC3339), Agent: "default", Action: "set", Path: "test2", Transport: "http", OK: false, Reason: "denied"},
	}

	f, err := os.Create(logFile)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	for _, entry := range entries {
		data, _ := json.Marshal(entry)
		fmt.Fprintln(f, string(data))
	}
	f.Close()

	loaded, err := admin.LoadAuditEntries("default", 10)
	if err != nil {
		t.Fatalf("admin.LoadAuditEntries() error = %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("admin.LoadAuditEntries() = %d entries, want 2", len(loaded))
	}
}

func TestLoadAuditEntries_MissingFile(t *testing.T) {
	home := t.TempDir()
	_ = os.Setenv("HOME", home)
	defer func() {
		h, _ := os.UserHomeDir()
		_ = os.Setenv("HOME", h)
	}()

	entries, err := admin.LoadAuditEntries("nonexistent", 10)
	if err != nil {
		t.Fatalf("admin.LoadAuditEntries() error = %v", err)
	}
	if entries != nil {
		t.Fatalf("expected nil entries for missing file, got %d", len(entries))
	}
}

func TestLoadAuditEntries_Limit(t *testing.T) {
	home := t.TempDir()
	_ = os.Setenv("HOME", home)
	defer func() {
		h, _ := os.UserHomeDir()
		_ = os.Setenv("HOME", h)
	}()

	auditDir := filepath.Join(home, ".openpass")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	logFile := filepath.Join(auditDir, "audit-default.log")
	f, err := os.Create(logFile)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	for i := 0; i < 5; i++ {
		entry := audit.LogEntry{Timestamp: time.Now().UTC().Format(time.RFC3339), Agent: "default", Action: fmt.Sprintf("action%d", i), OK: true}
		data, _ := json.Marshal(entry)
		fmt.Fprintln(f, string(data))
	}
	f.Close()

	loaded, err := admin.LoadAuditEntries("default", 3)
	if err != nil {
		t.Fatalf("admin.LoadAuditEntries() error = %v", err)
	}
	if len(loaded) != 3 {
		t.Fatalf("admin.LoadAuditEntries() = %d entries, want 3", len(loaded))
	}
	if loaded[0].Action != "action2" {
		t.Fatalf("first entry = %s, want action2", loaded[0].Action)
	}
}

func TestFilterAuditEntries_Since(t *testing.T) {
	now := time.Now().UTC()
	entries := []audit.LogEntry{
		{Timestamp: now.Add(-30 * time.Minute).Format(time.RFC3339), Agent: "default", Action: "old", OK: true},
		{Timestamp: now.Add(-5 * time.Minute).Format(time.RFC3339), Agent: "default", Action: "recent", OK: true},
		{Timestamp: now.Add(-2 * time.Hour).Format(time.RFC3339), Agent: "default", Action: "veryold", OK: true},
	}

	filtered := admin.FilterAuditEntries(entries, "1h", false)
	if len(filtered) != 2 {
		t.Fatalf("admin.FilterAuditEntries() = %d entries, want 2", len(filtered))
	}
	if filtered[0].Action != "old" {
		t.Fatalf("first entry = %s, want old", filtered[0].Action)
	}
	if filtered[1].Action != "recent" {
		t.Fatalf("second entry = %s, want recent", filtered[1].Action)
	}
}

func TestFilterAuditEntries_SinceDays(t *testing.T) {
	now := time.Now().UTC()
	entries := []audit.LogEntry{
		{Timestamp: now.Add(-25 * time.Hour).Format(time.RFC3339), Agent: "default", Action: "old", OK: true},
		{Timestamp: now.Add(-5 * time.Hour).Format(time.RFC3339), Agent: "default", Action: "recent", OK: true},
	}

	filtered := admin.FilterAuditEntries(entries, "1d", false)
	if len(filtered) != 1 {
		t.Fatalf("admin.FilterAuditEntries() = %d entries, want 1", len(filtered))
	}
	if filtered[0].Action != "recent" {
		t.Fatalf("entry = %s, want recent", filtered[0].Action)
	}
}

func TestFilterAuditEntries_FailedOnly(t *testing.T) {
	now := time.Now().UTC()
	entries := []audit.LogEntry{
		{Timestamp: now.Format(time.RFC3339), Agent: "default", Action: "get", OK: true},
		{Timestamp: now.Format(time.RFC3339), Agent: "default", Action: "set", OK: false},
		{Timestamp: now.Format(time.RFC3339), Agent: "default", Action: "list", OK: true},
	}

	filtered := admin.FilterAuditEntries(entries, "", true)
	if len(filtered) != 1 {
		t.Fatalf("admin.FilterAuditEntries() = %d entries, want 1", len(filtered))
	}
	if filtered[0].Action != "set" {
		t.Fatalf("entry = %s, want set", filtered[0].Action)
	}
}

func TestFilterAuditEntries_NoFilter(t *testing.T) {
	entries := []audit.LogEntry{
		{Timestamp: time.Now().UTC().Format(time.RFC3339), Agent: "default", Action: "get", OK: true},
		{Timestamp: time.Now().UTC().Format(time.RFC3339), Agent: "default", Action: "set", OK: false},
	}

	filtered := admin.FilterAuditEntries(entries, "", false)
	if len(filtered) != 2 {
		t.Fatalf("admin.FilterAuditEntries() = %d entries, want 2", len(filtered))
	}
}

func TestParseSinceDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"1h", time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"1d", 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			dur, err := admin.ParseSinceDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("admin.ParseSinceDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if dur != tt.expected {
				t.Fatalf("admin.ParseSinceDuration(%q) = %v, want %v", tt.input, dur, tt.expected)
			}
		})
	}
}

func TestOutputAuditJSON(t *testing.T) {
	entries := []audit.LogEntry{
		{Timestamp: "2024-01-01T00:00:00Z", Agent: "default", Action: "get", OK: true},
	}

	var buf strings.Builder
	cmd := admin.AuditCmd
	cmd.SetOut(&buf)

	if err := admin.OutputAuditJSON(cmd, entries); err != nil {
		t.Fatalf("admin.OutputAuditJSON() error = %v", err)
	}

	var result []audit.LogEntry
	if err := json.Unmarshal([]byte(buf.String()), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}
}

func TestOutputAuditTable(t *testing.T) {
	entries := []audit.LogEntry{
		{Timestamp: "2024-01-01T00:00:00Z", Agent: "default", Action: "get", Path: "test", Transport: "stdio", OK: true},
	}

	var buf strings.Builder
	cmd := admin.AuditCmd
	cmd.SetOut(&buf)

	if err := admin.OutputAuditTable(cmd, entries); err != nil {
		t.Fatalf("admin.OutputAuditTable() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "get") {
		t.Fatalf("output missing action: %q", output)
	}
	if !strings.Contains(output, "OK") {
		t.Fatalf("output missing status: %q", output)
	}
}

func TestOutputAuditTable_Empty(t *testing.T) {
	var buf strings.Builder
	cmd := admin.AuditCmd
	cmd.SetOut(&buf)

	if err := admin.OutputAuditTable(cmd, nil); err != nil {
		t.Fatalf("admin.OutputAuditTable() error = %v", err)
	}

	if !strings.Contains(buf.String(), "No audit entries found") {
		t.Fatalf("expected 'No audit entries found', got: %q", buf.String())
	}
}

func TestAuditCommand_JSON(t *testing.T) {
	resetCommandTestState()
	t.Cleanup(resetCommandTestState)

	home := t.TempDir()
	_ = os.Setenv("HOME", home)
	defer func() {
		h, _ := os.UserHomeDir()
		_ = os.Setenv("HOME", h)
	}()

	auditDir := filepath.Join(home, ".openpass")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	logFile := filepath.Join(auditDir, "audit-default.log")
	entry := audit.LogEntry{Timestamp: time.Now().UTC().Format(time.RFC3339), Agent: "default", Action: "get", Path: "test", Transport: "stdio", OK: true}
	data, _ := json.Marshal(entry)
	if err := os.WriteFile(logFile, data, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	buf := prepareRootCommandOutput(t)
	cli.RootCmd.SetArgs([]string{"audit", "--json"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })

	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	var result []audit.LogEntry
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}
}

func TestAuditCommand_Table(t *testing.T) {
	resetCommandTestState()
	t.Cleanup(resetCommandTestState)

	home := t.TempDir()
	_ = os.Setenv("HOME", home)
	defer func() {
		h, _ := os.UserHomeDir()
		_ = os.Setenv("HOME", h)
	}()

	auditDir := filepath.Join(home, ".openpass")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	logFile := filepath.Join(auditDir, "audit-default.log")
	entry := audit.LogEntry{Timestamp: time.Now().UTC().Format(time.RFC3339), Agent: "default", Action: "get", Path: "test", Transport: "stdio", OK: true}
	data, _ := json.Marshal(entry)
	if err := os.WriteFile(logFile, data, 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	buf := prepareRootCommandOutput(t)
	cli.RootCmd.SetArgs([]string{"audit"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })

	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "get") {
		t.Fatalf("output missing action: %q", output)
	}
}

func TestAuditCommand_SinceFilter(t *testing.T) {
	resetCommandTestState()
	t.Cleanup(resetCommandTestState)

	home := t.TempDir()
	_ = os.Setenv("HOME", home)
	defer func() {
		h, _ := os.UserHomeDir()
		_ = os.Setenv("HOME", h)
	}()

	auditDir := filepath.Join(home, ".openpass")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	logFile := filepath.Join(auditDir, "audit-default.log")
	now := time.Now().UTC()
	entries := []audit.LogEntry{
		{Timestamp: now.Add(-30 * time.Minute).Format(time.RFC3339), Agent: "default", Action: "old", OK: true},
		{Timestamp: now.Add(-5 * time.Minute).Format(time.RFC3339), Agent: "default", Action: "recent", OK: true},
	}
	f, _ := os.Create(logFile)
	for _, entry := range entries {
		data, _ := json.Marshal(entry)
		fmt.Fprintln(f, string(data))
	}
	f.Close()

	buf := prepareRootCommandOutput(t)
	cli.RootCmd.SetArgs([]string{"audit", "--since", "10m"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })

	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "old") {
		t.Fatalf("output should not contain 'old' entry: %q", output)
	}
	if !strings.Contains(output, "recent") {
		t.Fatalf("output missing 'recent' entry: %q", output)
	}
}

func TestAuditCommand_FailedFilter(t *testing.T) {
	resetCommandTestState()
	t.Cleanup(resetCommandTestState)

	home := t.TempDir()
	_ = os.Setenv("HOME", home)
	defer func() {
		h, _ := os.UserHomeDir()
		_ = os.Setenv("HOME", h)
	}()

	auditDir := filepath.Join(home, ".openpass")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	logFile := filepath.Join(auditDir, "audit-default.log")
	entries := []audit.LogEntry{
		{Timestamp: time.Now().UTC().Format(time.RFC3339), Agent: "default", Action: "get", OK: true},
		{Timestamp: time.Now().UTC().Format(time.RFC3339), Agent: "default", Action: "set", OK: false},
	}
	f, _ := os.Create(logFile)
	for _, entry := range entries {
		data, _ := json.Marshal(entry)
		fmt.Fprintln(f, string(data))
	}
	f.Close()

	buf := prepareRootCommandOutput(t)
	cli.RootCmd.SetArgs([]string{"audit", "--failed"})
	t.Cleanup(func() { cli.RootCmd.SetArgs(nil) })

	if err := cli.RootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "get") {
		t.Fatalf("output should not contain 'get' entry: %q", output)
	}
	if !strings.Contains(output, "set") {
		t.Fatalf("output missing 'set' entry: %q", output)
	}
}
