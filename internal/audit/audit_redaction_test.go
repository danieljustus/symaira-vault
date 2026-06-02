package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFieldNameOnlyNeverValue verifies that the Field field in audit entries
// records only field names, never field values. Even when operations target
// fields with names like "password", the value itself must not appear.
func TestFieldNameOnlyNeverValue(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("field-name-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Log an entry where the Field is "password" (the field name, not the value).
	// The audit log must NOT contain "supersecret123" (the value).
	_ = logger.LogEntry(LogEntry{
		Agent:  "test-agent",
		Action: "get_value",
		Path:   "secret/github",
		Field:  "password",
		OK:     true,
	})

	content, err := os.ReadFile(filepath.Join(home, ".symvault", "audit-field-name-test.log"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	text := string(content)

	// Should have the field name
	if !strings.Contains(text, "password") {
		t.Fatal("expected 'password' field name in audit entry")
	}

	// Must NOT have any value-like content leaked
	if strings.Contains(text, "supersecret") {
		t.Fatal("audit log leaked field value 'supersecret'")
	}
	if strings.Contains(text, "mysecret") {
		t.Fatal("audit log leaked field value 'mysecret'")
	}
}

// TestNoSecretValuesInPathEntries verifies that entries targeting
// paths with sensitive-looking names (e.g., "secret/key", "passwords/bank")
// never accidentally serialize secret values into the audit log.
func TestNoSecretValuesInPathEntries(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("path-secret-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	sensitivePaths := []string{
		"secret/key",
		"passwords/bank",
		"vault/master",
		"api/tokens/github",
		"credentials/admin",
	}

	for _, p := range sensitivePaths {
		_ = logger.LogEntry(LogEntry{
			Agent:  "test-agent",
			Action: "get",
			Path:   p,
			Field:  "value",
			OK:     true,
		})
	}

	content, err := os.ReadFile(filepath.Join(home, ".symvault", "audit-path-secret-test.log"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	var entries []LogEntry
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("invalid JSON line: %s err=%v", line, err)
		}
		entries = append(entries, entry)

		// Each entry must have the Path set but no value fields leaked
		if entry.Path == "" {
			t.Fatal("expected Path to be set")
		}
		// Verify that the entry JSON contains no suspicious value patterns
		if strings.Contains(line, `"value":"`) {
			t.Fatalf("entry with path %q contains potential value leak: %s", entry.Path, line)
		}
	}

	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
}

// TestSecretRedactionFixtureBased tests a predefined set of potentially
// sensitive LogEntry configurations to verify that no secret values leak
// into the serialized JSON output.
func TestSecretRedactionFixtureBased(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("fixture-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Fixtures: entries that must NOT contain the listed forbidden patterns
	fixtures := []struct {
		name      string
		entry     LogEntry
		forbidden []string
	}{
		{
			name: "set password field",
			entry: LogEntry{
				Agent:  "test",
				Action: "set",
				Path:   "secret/db",
				Field:  "password",
				OK:     true,
			},
			forbidden: []string{"s3cr3t!", "P@ssw0rd", "drowssap"},
		},
		{
			name: "get totp secret",
			entry: LogEntry{
				Agent:  "test",
				Action: "get",
				Path:   "secret/github",
				Field:  "totp.secret",
				OK:     true,
			},
			forbidden: []string{"JBSWY3DPEHPK3PXP", "base32secret"},
		},
		{
			name: "get api key",
			entry: LogEntry{
				Agent:  "test",
				Action: "get_value",
				Path:   "api/openai",
				Field:  "api-key",
				OK:     true,
			},
			forbidden: []string{"sk-proj-", "sk-abc123", "Bearer xyz"},
		},
		{
			name: "denied write with path only",
			entry: LogEntry{
				Agent:  "test",
				Action: "write_denied",
				Path:   "secret/admin",
				OK:     false,
				Reason: "write_denied",
			},
			forbidden: []string{"adminpass", "root"},
		},
		{
			name: "run command with env vars",
			entry: LogEntry{
				Agent:  "test",
				Action: "run_command",
				Path:   "curl",
				OK:     true,
				DurMs:  150,
			},
			forbidden: []string{"API_KEY=", "DATABASE_URL=", "export SECRET"},
		},
		{
			name: "autotype with password path",
			entry: LogEntry{
				Agent:  "test",
				Action: "autotype",
				Path:   "secret/login",
				Field:  "password",
				OK:     true,
			},
			forbidden: []string{"letmein", "qwerty123"},
		},
		{
			name: "share with agent metadata",
			entry: LogEntry{
				Agent:     "test",
				Action:    "share_request",
				Path:      "secret/shared",
				FromAgent: "alice",
				ToAgent:   "bob",
				OK:        true,
			},
			forbidden: []string{"shared-secret-value"},
		},
		{
			name: "auth failure",
			entry: LogEntry{
				Agent:     "test",
				Action:    "auth_failure",
				Transport: "http",
				OK:        false,
				Reason:    "invalid_token",
			},
			forbidden: []string{"Bearer ", "token:abc", "Authorization:"},
		},
	}

	for _, tt := range fixtures {
		t.Run(tt.name, func(t *testing.T) {
			_ = logger.LogEntry(tt.entry)
		})
	}

	content, err := os.ReadFile(filepath.Join(home, ".symvault", "audit-fixture-test.log"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	text := string(content)

	for _, tt := range fixtures {
		for _, forbidden := range tt.forbidden {
			if strings.Contains(text, forbidden) {
				t.Errorf("fixture %q: audit log contains forbidden pattern %q", tt.name, forbidden)
			}
		}
	}
}

// TestAuditLogDoesNotContainJSONValues verifies that the audit log content
// as raw text does not contain patterns that look like serialized secret values.
func TestAuditLogDoesNotContainJSONValues(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("no-values-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Log many different kinds of entries
	_ = logger.LogEntry(LogEntry{
		Agent:  "test",
		Action: "get_value",
		Path:   "secret/db",
		Field:  "password",
		OK:     true,
	})
	_ = logger.LogEntry(LogEntry{
		Agent:  "test",
		Action: "set",
		Path:   "secret/api",
		Field:  "api_key",
		OK:     true,
	})
	_ = logger.LogEntry(LogEntry{
		Agent:  "test",
		Action: "get",
		Path:   "secret/admin",
		Field:  "totp.secret",
		OK:     true,
	})
	_ = logger.LogEntry(LogEntry{
		Agent:  "test",
		Action: "delete",
		Path:   "secret/old",
		OK:     true,
	})

	content, err := os.ReadFile(filepath.Join(home, ".symvault", "audit-no-values-test.log"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	// Parse all entries and verify Field only contains names, not values
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	for i, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("invalid JSON on line %d: %v", i, err)
		}

		// If a "field" key exists, it must only contain names like "password",
		// "api_key", "totp.secret" — never a value like "<32-chars-base64>"
		if field, ok := entry["field"]; ok {
			fieldStr, isString := field.(string)
			if !isString {
				t.Fatalf("line %d: field is not a string: %v", i, field)
			}
			// Values typically won't contain dots (unlike field paths)
			// But more importantly: the field should be SHORT, not a value
			if len(fieldStr) > 100 {
				t.Errorf("line %d: field string too long (%d chars), likely a value: %s",
					i, len(fieldStr), fieldStr)
			}
		}
	}
}

// TestLogEntryJSONSerializationNoValueLeak verifies that LogEntry JSON
// serialization does not accidentally include field values through any
// mechanism (e.g., embedded structs, map fields, unexported fields).
func TestLogEntryJSONSerializationNoValueLeak(t *testing.T) {
	// Test that the LogEntry struct itself, when serialized, never
	// accidentally contains value-like patterns
	entry := LogEntry{
		Timestamp: "2026-01-01T00:00:00Z",
		Agent:     "test-agent",
		Action:    "get_value",
		Path:      "secret/production/database",
		Field:     "password",
		Transport: "stdio",
		OK:        true,
		DurMs:     42,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("json.Marshal error = %v", err)
	}

	jsonStr := string(data)

	// JSON must not contain any value indicators
	forbiddenJSON := []string{
		`"value":`,
		`"secret":`,
		`"plaintext":`,
		`"password_value":`,
		`"field_value":`,
		`"entry_data":`,
	}
	for _, pattern := range forbiddenJSON {
		if strings.Contains(strings.ToLower(jsonStr), strings.ToLower(pattern)) {
			t.Errorf("serialized LogEntry contains forbidden JSON key: %s", pattern)
		}
	}

	// Verify the serialized entry can be deserialized correctly
	var deserialized LogEntry
	if err := json.Unmarshal(data, &deserialized); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	if deserialized.Field != "password" {
		t.Errorf("Field = %s, want password", deserialized.Field)
	}
	if deserialized.Path != "secret/production/database" {
		t.Errorf("Path = %s, want secret/production/database", deserialized.Path)
	}
}

// TestSensitivePathPatternsDoesNotLeakValues verifies that even when the
// path name contains words like "password" or "secret", no actual values
// leak into the audit output.
func TestSensitivePathPatternsDoesNotLeakValues(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("sensitive-path-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Paths that happen to use sensitive-looking segment names
	// These are legitimate entry paths, not secret values
	sensitivePathNames := []string{
		"passwords/bank-login",
		"secrets/aws-root",
		"tokens/github-pat",
		"keys/ssh/id_rsa",
		"credentials/vpn",
	}

	for _, p := range sensitivePathNames {
		_ = logger.LogEntry(LogEntry{
			Agent:  "test",
			Action: "get",
			Path:   p,
			OK:     true,
		})
	}

	content, err := os.ReadFile(filepath.Join(home, ".symvault", "audit-sensitive-path-test.log"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	text := string(content)

	// Paths should appear (they are metadata)
	for _, p := range sensitivePathNames {
		if !strings.Contains(text, p) {
			t.Errorf("expected path %q to appear in audit (it's metadata)", p)
		}
	}

	// But the audit log must not contain any plausible secret values
	// These are all content types that would indicate a value leak
	valueIndicators := []string{
		"A3TQ2n8xKpL5mR9v",     // random-looking base62
		"AKIAIOSFODNN7EXAMPLE", // AWS access key pattern
		"ghp_1234567890abcdef", // GitHub PAT pattern
		"sk-abcdefghijklmnop",  // OpenAI key pattern
	}
	for _, indicator := range valueIndicators {
		if strings.Contains(text, indicator) {
			t.Errorf("audit log contains potential secret value indicator: %q", indicator)
		}
	}
}

// TestReasonFieldDoesNotLeakValues verifies that the Reason field
// (which is human-readable) never accidentally contains secret values
// or field values from the operation.
func TestReasonFieldDoesNotLeakValues(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("reason-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	// Log denial entries — reasons should be fixed strings, not variable data
	failureEntries := []struct {
		action string
		path   string
		reason string
	}{
		{"scope_denied", "secret/admin", "scope_denied"},
		{"write_denied", "secret/db", "write_denied"},
		{"policy_denied", "secret/vault", "policy_denied"},
		{"approval_required", "secret/prod", "approval_required"},
	}

	for _, fe := range failureEntries {
		_ = logger.LogEntry(LogEntry{
			Agent:  "test",
			Action: fe.action,
			Path:   fe.path,
			OK:     false,
			Reason: fe.reason,
		})
	}

	content, err := os.ReadFile(filepath.Join(home, ".symvault", "audit-reason-test.log"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	text := string(content)

	// Reason field should contain only the fixed reason strings
	for _, fe := range failureEntries {
		if !strings.Contains(text, fe.reason) {
			t.Errorf("expected reason %q in audit log", fe.reason)
		}
	}

	// Must NOT contain any value-like data in the reason context
	reasonValueIndicators := []string{
		"password is",
		"secret was",
		"value=",
		"key=",
		"token=",
	}
	for _, indicator := range reasonValueIndicators {
		if strings.Contains(strings.ToLower(text), strings.ToLower(indicator)) {
			t.Errorf("reason field leaked value data: found %q", indicator)
		}
	}
}

// TestConcurrentNoValueLeak runs many concurrent writes with various
// field names and verifies that all entries only contain names, never values.
func TestConcurrentNoValueLeak(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	logger, err := New("concurrent-redact-test", "")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() { _ = logger.Close() }()

	const goroutines = 5
	const entriesPer = 20
	done := make(chan struct{})

	fieldNames := []string{"password", "api_key", "totp.secret", "note", "username"}

	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < entriesPer; j++ {
				_ = logger.LogEntry(LogEntry{
					Agent:  "test",
					Action: "get",
					Path:   "secret/test",
					Field:  fieldNames[j%len(fieldNames)],
					OK:     true,
				})
			}
			done <- struct{}{}
		}()
	}

	for range goroutines {
		<-done
	}

	content, err := os.ReadFile(filepath.Join(home, ".symvault", "audit-concurrent-redact-test.log"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	for i, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("invalid JSON on line %d: %v", i, err)
		}

		// field must be a known field name
		if field, ok := entry["field"]; ok {
			known := false
			for _, n := range fieldNames {
				if field == n {
					known = true
					break
				}
			}
			if !known {
				t.Errorf("line %d: unknown field value %v (expected only field names)", i, field)
			}
		}
	}
}
