package mcp

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIsTTYPresent(t *testing.T) {
	// This test will return false in most CI/testing environments
	// since /dev/tty is not available
	result := IsTTYPresent()
	// Just verify it returns a boolean without panicking
	_ = result
}

func TestBuildPrompt(t *testing.T) {
	tests := []struct {
		name       string
		wantPrefix string
		req        ApprovalRequest
		wantOp     bool
	}{
		{
			name: "with operation and details",
			req: ApprovalRequest{
				Operation: "delete",
				Details:   "github/work",
				Timeout:   30 * time.Second,
			},
			wantPrefix: "\n",
			wantOp:     true,
		},
		{
			name: "with empty operation",
			req: ApprovalRequest{
				Operation: "",
				Details:   "some details",
				Timeout:   30 * time.Second,
			},
			wantPrefix: "\n",
			wantOp:     false,
		},
		{
			name: "with empty details",
			req: ApprovalRequest{
				Operation: "write",
				Details:   "",
				Timeout:   30 * time.Second,
			},
			wantPrefix: "\n",
			wantOp:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildPrompt(tt.req)
			if result == "" {
				t.Fatal("buildPrompt() returned empty string")
			}
			if result[:len(tt.wantPrefix)] != tt.wantPrefix {
				t.Errorf("buildPrompt() prefix = %q, want %q", result[:len(tt.wantPrefix)], tt.wantPrefix)
			}
			if tt.wantOp && tt.req.Operation != "" {
				if !containsString(result, tt.req.Operation) {
					t.Errorf("buildPrompt() = %q, want to contain operation %q", result, tt.req.Operation)
				}
			}
		})
	}
}

func TestBuildPrompt_Truncation(t *testing.T) {
	req := ApprovalRequest{
		Operation: "this is a very long operation name that should be truncated",
		Details:   "also some very long details that should be truncated to fit the box",
		Timeout:   30 * time.Second,
	}

	result := buildPrompt(req)
	if len(result) == 0 {
		t.Fatal("buildPrompt() returned empty string")
	}
}

func TestParseApprovalResponse(t *testing.T) {
	tests := []struct {
		name     string
		response string
		expected bool
	}{
		{"lowercase y", "y", true},
		{"uppercase Y", "Y", true},
		{"lowercase yes", "yes", true},
		{"uppercase YES", "YES", true},
		{"mixed case Yes", "Yes", true},
		{"no", "no", false},
		{"n", "n", false},
		{"NO", "NO", false},
		{"anything else", "maybe", false},
		{"empty string", "", false},
		{"with whitespace", "  y  ", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseApprovalResponse(tt.response)
			if result != tt.expected {
				t.Errorf("parseApprovalResponse(%q) = %v, want %v", tt.response, result, tt.expected)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
		maxLen int
	}{
		{"short string", "hello", "hello", 10},
		{"exact length", "hello", "hello", 5},
		{"long string", "hello world", "he...", 5},
		{"maxLen 0", "hello", "", 0},
		{"maxLen 1", "hello", "h", 1},
		{"maxLen 2", "hello", "he", 2},
		{"maxLen 3", "hello", "hel", 3},
		{"maxLen 4", "hello", "h...", 4},
		{"empty string", "", "", 5},
		{"maxLen less than 3", "hello", "he", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncate(tt.input, tt.maxLen)
			if result != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.want)
			}
		})
	}
}

func TestRequestApproval_NoTTY(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return nil, errors.New("no tty available")
	}

	req := ApprovalRequest{
		Operation: "test",
		Details:   "test details",
		Timeout:   1 * time.Second,
	}

	result := RequestApproval(req)

	if result.Approved {
		t.Error("RequestApproval() expected not approved without TTY")
	}
	if result.Error == nil {
		t.Error("RequestApproval() expected error without TTY")
	}
	if !strings.Contains(result.Error.Error(), "no TTY available") {
		t.Errorf("RequestApproval() error = %v, want no TTY available error", result.Error)
	}
}

func TestRequestApproval_DefaultTimeout(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			readString: func() (string, error) { return "", os.ErrDeadlineExceeded },
			output:     newMockOutputFile(t),
			raw:        func() (func(), error) { return func() {}, nil },
		}, nil
	}

	req := ApprovalRequest{
		Operation: "test",
		Timeout:   0,
	}

	result := RequestApproval(req)
	if result.Approved {
		t.Error("RequestApproval() expected not approved on timeout")
	}
	if result.Error == nil {
		t.Error("RequestApproval() expected timeout error")
	}
	if !strings.Contains(result.Error.Error(), "timed out after 30s") {
		t.Errorf("RequestApproval() error = %v, want default timeout error", result.Error)
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

type mockTTYDevice struct {
	readString func() (string, error)
	input      *os.File
	output     *os.File
	raw        func() (func(), error)
	closeFunc  func() error
}

func (m *mockTTYDevice) ReadString() (string, error) {
	if m.readString != nil {
		return m.readString()
	}
	return "", nil
}

func (m *mockTTYDevice) Input() *os.File {
	return m.input
}

func (m *mockTTYDevice) Output() *os.File {
	return m.output
}

func (m *mockTTYDevice) Raw() (func(), error) {
	if m.raw != nil {
		return m.raw()
	}
	return func() {}, nil
}

func (m *mockTTYDevice) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func newMockOutputFile(t *testing.T) *os.File {
	t.Helper()
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe failed: %v", err)
	}
	t.Cleanup(func() {
		_ = writeEnd.Close()
		_ = readEnd.Close()
	})
	return writeEnd
}

func TestIsTTYPresent_Error(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return nil, errors.New("no tty available")
	}

	if IsTTYPresent() {
		t.Error("IsTTYPresent() = true, want false when openTTYDevice returns error")
	}
}

func TestRequestApproval_Approved(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	tests := []struct {
		name     string
		response string
	}{
		{"yes lowercase", "yes"},
		{"y lowercase", "y"},
		{"YES uppercase", "YES"},
		{"Y uppercase", "Y"},
		{"Yes mixed", "Yes"},
		{"y with whitespace", "  y  "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			openTTYDevice = func() (ttyDevice, error) {
				return &mockTTYDevice{
					readString: func() (string, error) { return tt.response, nil },
					output:     newMockOutputFile(t),
					raw:        func() (func(), error) { return func() {}, nil },
				}, nil
			}

			req := ApprovalRequest{
				Operation: "test",
				Details:   "test details",
				Timeout:   1 * time.Second,
			}
			result := RequestApproval(req)
			if !result.Approved {
				t.Errorf("RequestApproval() approved = %v, want true", result.Approved)
			}
			if result.Error != nil {
				t.Errorf("RequestApproval() error = %v, want nil", result.Error)
			}
		})
	}
}

func TestRequestApproval_Denied(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	tests := []struct {
		name     string
		response string
	}{
		{"no lowercase", "no"},
		{"n lowercase", "n"},
		{"NO uppercase", "NO"},
		{"N uppercase", "N"},
		{"maybe", "maybe"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			openTTYDevice = func() (ttyDevice, error) {
				return &mockTTYDevice{
					readString: func() (string, error) { return tt.response, nil },
					output:     newMockOutputFile(t),
					raw:        func() (func(), error) { return func() {}, nil },
				}, nil
			}

			req := ApprovalRequest{
				Operation: "test",
				Details:   "test details",
				Timeout:   1 * time.Second,
			}
			result := RequestApproval(req)
			if result.Approved {
				t.Errorf("RequestApproval() approved = %v, want false", result.Approved)
			}
			if result.Error != nil {
				t.Errorf("RequestApproval() error = %v, want nil", result.Error)
			}
		})
	}
}

func TestRequestApproval_Timeout(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			readString: func() (string, error) { return "", os.ErrDeadlineExceeded },
			output:     newMockOutputFile(t),
			raw:        func() (func(), error) { return func() {}, nil },
		}, nil
	}

	req := ApprovalRequest{
		Operation: "test",
		Details:   "test details",
		Timeout:   1 * time.Millisecond,
	}
	result := RequestApproval(req)
	if result.Approved {
		t.Error("RequestApproval() approved = true, want false on timeout")
	}
	if result.Error == nil {
		t.Error("RequestApproval() error = nil, want timeout error")
	}
	if !strings.Contains(result.Error.Error(), "timed out") {
		t.Errorf("RequestApproval() error = %v, want timeout error", result.Error)
	}
}

func TestRequestApproval_ReadError(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			readString: func() (string, error) { return "", errors.New("read failed") },
			output:     newMockOutputFile(t),
			raw:        func() (func(), error) { return func() {}, nil },
		}, nil
	}

	req := ApprovalRequest{
		Operation: "test",
		Details:   "test details",
		Timeout:   1 * time.Second,
	}
	result := RequestApproval(req)
	if result.Approved {
		t.Error("RequestApproval() approved = true, want false on read error")
	}
	if result.Error == nil {
		t.Error("RequestApproval() error = nil, want read error")
	}
	if !strings.Contains(result.Error.Error(), "failed to read from terminal") {
		t.Errorf("RequestApproval() error = %v, want read error", result.Error)
	}
}

func TestRequestApproval_RawError(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			output: newMockOutputFile(t),
			raw:    func() (func(), error) { return nil, errors.New("raw failed") },
		}, nil
	}

	req := ApprovalRequest{
		Operation: "test",
		Details:   "test details",
		Timeout:   1 * time.Second,
	}
	result := RequestApproval(req)
	if result.Approved {
		t.Error("RequestApproval() approved = true, want false on raw error")
	}
	if result.Error == nil {
		t.Error("RequestApproval() error = nil, want raw error")
	}
	if !strings.Contains(result.Error.Error(), "failed to set terminal raw mode") {
		t.Errorf("RequestApproval() error = %v, want raw mode error", result.Error)
	}
}

func TestRequestApproval_WriteError(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	tmpfile, err := os.CreateTemp("", "mocktty")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	//nolint:errcheck // best-effort close in test
	tmpfile.Close()
	//nolint:errcheck // best-effort remove in test
	defer os.Remove(tmpfile.Name())

	readOnlyFile, err := os.Open(tmpfile.Name())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	//nolint:errcheck // best-effort close in test
	defer readOnlyFile.Close()

	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			output: readOnlyFile,
			raw:    func() (func(), error) { return func() {}, nil },
		}, nil
	}

	req := ApprovalRequest{
		Operation: "test",
		Details:   "test details",
		Timeout:   1 * time.Second,
	}
	result := RequestApproval(req)
	if result.Approved {
		t.Error("RequestApproval() approved = true, want false on write error")
	}
	if result.Error == nil {
		t.Error("RequestApproval() error = nil, want write error")
	}
	if !strings.Contains(result.Error.Error(), "failed to write to terminal") {
		t.Errorf("RequestApproval() error = %v, want write error", result.Error)
	}
}

func TestRequestApproval_DefaultTimeoutWithTTY(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			readString: func() (string, error) { return "y", nil },
			output:     newMockOutputFile(t),
			raw:        func() (func(), error) { return func() {}, nil },
		}, nil
	}

	req := ApprovalRequest{
		Operation: "test",
		Details:   "test details",
		Timeout:   0,
	}
	result := RequestApproval(req)
	if !result.Approved {
		t.Error("RequestApproval() approved = false, want true with default timeout")
	}
	if result.Error != nil {
		t.Errorf("RequestApproval() error = %v, want nil", result.Error)
	}
}

func TestIsTTYPresent_Success(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{}, nil
	}

	if !IsTTYPresent() {
		t.Error("IsTTYPresent() = false, want true when TTY is available")
	}
}

func TestRequestApproval_EmptyRequest(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			readString: func() (string, error) { return "y", nil },
			output:     newMockOutputFile(t),
			raw:        func() (func(), error) { return func() {}, nil },
		}, nil
	}

	req := ApprovalRequest{
		Operation: "",
		Details:   "",
		Timeout:   1 * time.Second,
	}
	result := RequestApproval(req)
	if !result.Approved {
		t.Errorf("RequestApproval() approved = %v, want true for empty request", result.Approved)
	}
	if result.Error != nil {
		t.Errorf("RequestApproval() error = %v, want nil", result.Error)
	}
}

func TestRequestApproval_VeryLongTimeout(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			readString: func() (string, error) { return "y", nil },
			output:     newMockOutputFile(t),
			raw:        func() (func(), error) { return func() {}, nil },
		}, nil
	}

	req := ApprovalRequest{
		Operation: "test",
		Details:   "test details",
		Timeout:   24 * time.Hour,
	}
	result := RequestApproval(req)
	if !result.Approved {
		t.Error("RequestApproval() approved = false, want true with very long timeout")
	}
	if result.Error != nil {
		t.Errorf("RequestApproval() error = %v, want nil", result.Error)
	}
}

func TestRequestApproval_ConcurrentRequests(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			readString: func() (string, error) { return "y", nil },
			output:     newMockOutputFile(t),
			raw:        func() (func(), error) { return func() {}, nil },
		}, nil
	}

	const numRequests = 10
	results := make(chan ApprovalResult, numRequests)

	for i := 0; i < numRequests; i++ {
		go func(idx int) {
			req := ApprovalRequest{
				Operation: fmt.Sprintf("operation-%d", idx),
				Details:   fmt.Sprintf("details-%d", idx),
				Timeout:   1 * time.Second,
			}
			results <- RequestApproval(req)
		}(i)
	}

	for i := 0; i < numRequests; i++ {
		result := <-results
		if !result.Approved {
			t.Errorf("RequestApproval() approved = %v, want true in concurrent request %d", result.Approved, i)
		}
		if result.Error != nil {
			t.Errorf("RequestApproval() error = %v, want nil in concurrent request %d", result.Error, i)
		}
	}
}

func TestRequestApproval_CloseError(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	closeCalled := false
	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			readString: func() (string, error) { return "y", nil },
			output:     newMockOutputFile(t),
			raw:        func() (func(), error) { return func() {}, nil },
			closeFunc: func() error {
				closeCalled = true
				return errors.New("close failed")
			},
		}, nil
	}

	req := ApprovalRequest{
		Operation: "test",
		Details:   "test details",
		Timeout:   1 * time.Second,
	}
	result := RequestApproval(req)
	if !result.Approved {
		t.Error("RequestApproval() approved = false, want true")
	}
	if result.Error != nil {
		t.Errorf("RequestApproval() error = %v, want nil", result.Error)
	}
	if !closeCalled {
		t.Error("RequestApproval() close was not called")
	}
}

func TestRequestApproval_InputNil(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			readString: func() (string, error) { return "y", nil },
			output:     newMockOutputFile(t),
			raw:        func() (func(), error) { return func() {}, nil },
			input:      nil,
		}, nil
	}

	req := ApprovalRequest{
		Operation: "test",
		Details:   "test details",
		Timeout:   1 * time.Second,
	}
	result := RequestApproval(req)
	if !result.Approved {
		t.Error("RequestApproval() approved = false, want true with nil input")
	}
	if result.Error != nil {
		t.Errorf("RequestApproval() error = %v, want nil", result.Error)
	}
}

func TestIsTimeoutError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"os.ErrDeadlineExceeded", os.ErrDeadlineExceeded, true},
		{"timeout error", &timeoutError{}, true},
		{"non-timeout error", errors.New("some error"), false},
		{"nil error", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTimeoutError(tt.err)
			if result != tt.expected {
				t.Errorf("isTimeoutError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// --- New tests for approval UX hardening ---

func TestRiskLevel_String(t *testing.T) {
	tests := []struct {
		level RiskLevel
		want  string
	}{
		{RiskLevelLow, "LOW"},
		{RiskLevelMedium, "MEDIUM"},
		{RiskLevelHigh, "HIGH"},
		{RiskLevelCritical, "CRITICAL"},
		{RiskLevel(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.level.String(); got != tt.want {
				t.Errorf("RiskLevel(%d).String() = %q, want %q", int(tt.level), got, tt.want)
			}
		})
	}
}

func TestRiskLevel_Indicator(t *testing.T) {
	tests := []struct {
		level RiskLevel
		want  string
	}{
		{RiskLevelLow, "🟢"},
		{RiskLevelMedium, "🟡"},
		{RiskLevelHigh, "🟠"},
		{RiskLevelCritical, "🔴"},
		{RiskLevel(99), "⚪"},
	}
	for _, tt := range tests {
		t.Run(tt.level.String(), func(t *testing.T) {
			if got := tt.level.Indicator(); got != tt.want {
				t.Errorf("RiskLevel(%d).Indicator() = %q, want %q", int(tt.level), got, tt.want)
			}
		})
	}
}

func TestRiskLevel_CanRemember(t *testing.T) {
	tests := []struct {
		level RiskLevel
		want  bool
	}{
		{RiskLevelLow, true},
		{RiskLevelMedium, true},
		{RiskLevelHigh, true},
		{RiskLevelCritical, false},
	}
	for _, tt := range tests {
		t.Run(tt.level.String(), func(t *testing.T) {
			if got := tt.level.CanRemember(); got != tt.want {
				t.Errorf("RiskLevel(%d).CanRemember() = %v, want %v", int(tt.level), got, tt.want)
			}
		})
	}
}

func TestParseRememberResponse(t *testing.T) {
	tests := []struct {
		name     string
		response string
		expected bool
	}{
		{"lowercase r", "r", true},
		{"uppercase R", "R", true},
		{"lowercase remember", "remember", true},
		{"uppercase REMEMBER", "REMEMBER", true},
		{"mixed case Remember", "Remember", true},
		{"y is not remember", "y", false},
		{"yes is not remember", "yes", false},
		{"no is not remember", "no", false},
		{"empty", "", false},
		{"r with whitespace", "  r  ", true},
		{"typo remmeber", "remmeber", false}, //nolint:misspell // intentional typo test
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseRememberResponse(tt.response)
			if result != tt.expected {
				t.Errorf("parseRememberResponse(%q) = %v, want %v", tt.response, result, tt.expected)
			}
		})
	}
}

func TestBuildPrompt_ContextDisplay(t *testing.T) {
	req := ApprovalRequest{
		Operation:       "set_entry_field",
		Details:         "set_entry_field on test/entry field token",
		Timeout:         30 * time.Second,
		AgentName:       "test-agent",
		WorkingDir:      "/home/user/project",
		GitBranch:       "main",
		ProjectType:     "MyApp (Go)",
		RiskLevel:       RiskLevelHigh,
		SecretsAccessed: 3,
		CanRemember:     true,
	}

	result := buildPrompt(req)

	checks := []string{
		"test-agent",
		"/home/user/project",
		"main",
		"MyApp (Go)",
		"3 accessed this session",
		"set_entry_field",
		"test/entry",
		"remember for session",
		"🟠",
	}
	for _, c := range checks {
		if !strings.Contains(result, c) {
			t.Errorf("buildPrompt() missing expected content %q in:\n%s", c, result)
		}
	}
}

func TestBuildPrompt_CriticalNoRemember(t *testing.T) {
	req := ApprovalRequest{
		Operation:   "delete_entry",
		Details:     "delete_entry on secret/entry",
		Timeout:     30 * time.Second,
		AgentName:   "test-agent",
		RiskLevel:   RiskLevelCritical,
		CanRemember: false,
	}

	result := buildPrompt(req)

	if strings.Contains(result, "remember for session") {
		t.Errorf("buildPrompt() should not offer 'remember' for critical risk:\n%s", result)
	}

	if !strings.Contains(result, "(y/n)") {
		t.Errorf("buildPrompt() should show '(y/n)' for critical risk:\n%s", result)
	}

	if !strings.Contains(result, "🔴") {
		t.Errorf("buildPrompt() should show CRITICAL risk indicator:\n%s", result)
	}
}

func TestBuildPrompt_SecretsAccessedZero(t *testing.T) {
	req := ApprovalRequest{
		Operation:       "get_entry_value",
		Timeout:         30 * time.Second,
		RiskLevel:       RiskLevelHigh,
		SecretsAccessed: 0,
		CanRemember:     true,
	}

	result := buildPrompt(req)
	if !strings.Contains(result, "0 accessed this session") {
		t.Errorf("buildPrompt() should show secrets count zero:\n%s", result)
	}
}

func TestBuildPrompt_BoxSizing(t *testing.T) {
	req := ApprovalRequest{
		Operation: "test",
		RiskLevel: RiskLevelLow,
	}

	result := buildPrompt(req)

	if !strings.HasPrefix(result, "\n╔") {
		t.Errorf("buildPrompt() should start with newline and top-left corner")
	}

	if !strings.HasSuffix(strings.TrimSpace(result), "(y/n):") {
		t.Errorf("buildPrompt() should end with prompt suffix")
	}
}

func TestCenterText(t *testing.T) {
	tests := []struct {
		text  string
		width int
		want  string
	}{
		{"hello", 11, "   hello   "},
		{"hi", 4, " hi "},
		{"abc", 5, " abc "},
		{"", 5, "     "},
		{"x", 1, "x"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_w%d", tt.text, tt.width), func(t *testing.T) {
			got := centerText(tt.text, tt.width)
			if len(got) != tt.width {
				t.Errorf("centerText(%q, %d) returned len %d, want %d", tt.text, tt.width, len(got), tt.width)
			}
			if got != tt.want {
				t.Errorf("centerText(%q, %d) = %q, want %q", tt.text, tt.width, got, tt.want)
			}
		})
	}
}

func TestRequestApproval_Remembered(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			readString: func() (string, error) { return "r", nil },
			output:     newMockOutputFile(t),
			raw:        func() (func(), error) { return func() {}, nil },
		}, nil
	}

	req := ApprovalRequest{
		Operation:   "get_entry_value",
		Details:     "test entry",
		Timeout:     1 * time.Second,
		CanRemember: true,
	}
	result := RequestApproval(req)
	if !result.Approved {
		t.Error("RequestApproval() approved = false, want true for 'r'")
	}
	if !result.Remembered {
		t.Error("RequestApproval() remembered = false, want true for 'r'")
	}
	if result.Error != nil {
		t.Errorf("RequestApproval() error = %v, want nil", result.Error)
	}
}

func TestRequestApproval_RememberIgnoredWhenNotAllowed(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	openTTYDevice = func() (ttyDevice, error) {
		return &mockTTYDevice{
			readString: func() (string, error) { return "r", nil },
			output:     newMockOutputFile(t),
			raw:        func() (func(), error) { return func() {}, nil },
		}, nil
	}

	req := ApprovalRequest{
		Operation:   "delete_entry",
		Details:     "test entry",
		Timeout:     1 * time.Second,
		CanRemember: false, // critical tool
	}
	result := RequestApproval(req)
	if !result.Approved {
		t.Error("RequestApproval() approved = false, want true")
	}
	if result.Remembered {
		t.Error("RequestApproval() remembered = true, want false when CanRemember=false")
	}
}

func TestApprovalCache(t *testing.T) {
	cache := newApprovalCache()

	key1 := approvalCacheKey("agent1", "tool_a", "path/x")
	key2 := approvalCacheKey("agent1", "tool_b", "path/x")
	key3 := approvalCacheKey("agent2", "tool_a", "path/x")

	if cache.isRemembered(key1) {
		t.Error("cache should start empty for key1")
	}

	cache.setRemembered(key1)
	if !cache.isRemembered(key1) {
		t.Error("cache should return true after setRemembered for key1")
	}

	if cache.isRemembered(key2) {
		t.Error("cache should not remember key2")
	}
	if cache.isRemembered(key3) {
		t.Error("cache should not remember key3 (different agent)")
	}

	cache.setRemembered(key2)
	if !cache.isRemembered(key2) {
		t.Error("cache should return true after setRemembered for key2")
	}
}

func TestApprovalCacheKey(t *testing.T) {
	key := approvalCacheKey("myagent", "get_entry_value", "github/token")
	expected := "myagent:get_entry_value:github/token"
	if key != expected {
		t.Errorf("approvalCacheKey() = %q, want %q", key, expected)
	}
}

// F-9: equivalent path representations must collapse to the same cache key
// so that a user who already approved "work/foo" is not re-prompted for
// "work/foo/", " work/foo ", or "work/./foo". This also removes a small
// side-channel where an adversarial agent could force repeated approval
// prompts by varying the path form.
func TestApprovalCacheKey_NormalizesPath(t *testing.T) {
	base := approvalCacheKey("agent", "get_entry_value", "work/foo")
	variants := map[string]string{
		"trailing-slash": "work/foo/",
		"double-slash":   "work//foo",
		"whitespace":     " work/foo ",
		"dot-segment":    "work/./foo",
	}
	for name, p := range variants {
		got := approvalCacheKey("agent", "get_entry_value", p)
		if got != base {
			t.Errorf("variant %q: cache key %q != base %q", name, got, base)
		}
	}
}

func TestToolRiskLevel(t *testing.T) {
	tests := []struct {
		toolName string
		want     RiskLevel
	}{
		{"list_entries", RiskLevelLow},
		{"find_entries", RiskLevelLow},
		{"get_entry", RiskLevelMedium},
		{"get_entry_metadata", RiskLevelMedium},
		{"get_entry_value", RiskLevelHigh},
		{"generate_totp", RiskLevelHigh},
		{"copy_to_clipboard", RiskLevelHigh},
		{"execute_with_secret", RiskLevelHigh},
		{"set_entry_field", RiskLevelCritical},
		{"delete_entry", RiskLevelCritical},
		{"execute_api_request", RiskLevelCritical},
		{"secure_input", RiskLevelCritical},
		{"request_credential", RiskLevelCritical},
		{"unknown_tool", RiskLevelMedium},
	}
	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			if got := toolRiskLevel(tt.toolName); got != tt.want {
				t.Errorf("toolRiskLevel(%q) = %v, want %v", tt.toolName, got, tt.want)
			}
		})
	}
}

func TestToolRiskLevel_CanRemember(t *testing.T) {
	criticalTools := []string{"set_entry_field", "delete_entry", "execute_api_request", "secure_input", "request_credential"}
	for _, name := range criticalTools {
		t.Run(name, func(t *testing.T) {
			rl := toolRiskLevel(name)
			if rl.CanRemember() {
				t.Errorf("toolRiskLevel(%q) = %v, CanRemember() = true, want false", name, rl)
			}
		})
	}

	nonCriticalTools := []string{"list_entries", "get_entry", "get_entry_value", "copy_to_clipboard"}
	for _, name := range nonCriticalTools {
		t.Run(name, func(t *testing.T) {
			rl := toolRiskLevel(name)
			if !rl.CanRemember() {
				t.Errorf("toolRiskLevel(%q) = %v, CanRemember() = false, want true", name, rl)
			}
		})
	}
}

func TestRequestApproval_RememberResponseParsing(t *testing.T) {
	if !parseApprovalResponse("r") {
		t.Error("parseApprovalResponse('r') should return true")
	}
	if !parseApprovalResponse("remember") {
		t.Error("parseApprovalResponse('remember') should return true")
	}
	if !parseApprovalResponse("R") {
		t.Error("parseApprovalResponse('R') should return true")
	}
	if !parseApprovalResponse("REMEMBER") {
		t.Error("parseApprovalResponse('REMEMBER') should return true")
	}
}

func TestBuildPrompt_LowRiskShowsRemember(t *testing.T) {
	req := ApprovalRequest{
		Operation:   "list_entries",
		Timeout:     30 * time.Second,
		RiskLevel:   RiskLevelLow,
		CanRemember: true,
	}
	result := buildPrompt(req)
	if !strings.Contains(result, "remember for session") {
		t.Errorf("buildPrompt() should offer 'remember for session' for low risk:\n%s", result)
	}
	if !strings.Contains(result, "(y/n/r") {
		t.Errorf("buildPrompt() should show (y/n/r) for low risk:\n%s", result)
	}
}

func TestBuildPrompt_MediumRiskShowsRemember(t *testing.T) {
	req := ApprovalRequest{
		Operation:   "get_entry",
		Timeout:     30 * time.Second,
		RiskLevel:   RiskLevelMedium,
		CanRemember: true,
	}
	result := buildPrompt(req)
	if !strings.Contains(result, "remember for session") {
		t.Errorf("buildPrompt() should offer 'remember for session' for medium risk:\n%s", result)
	}
}

func TestBuildPrompt_HighRiskShowsRemember(t *testing.T) {
	req := ApprovalRequest{
		Operation:   "get_entry_value",
		Timeout:     30 * time.Second,
		RiskLevel:   RiskLevelHigh,
		CanRemember: true,
	}
	result := buildPrompt(req)
	if !strings.Contains(result, "remember for session") {
		t.Errorf("buildPrompt() should offer 'remember for session' for high risk:\n%s", result)
	}
}

func TestBuildPrompt_EmptyAgentName(t *testing.T) {
	req := ApprovalRequest{
		Operation: "test",
		RiskLevel: RiskLevelLow,
	}
	result := buildPrompt(req)
	if result == "" {
		t.Fatal("buildPrompt() returned empty string")
	}
	if !strings.Contains(result, "LOW") {
		t.Errorf("buildPrompt() should show risk level")
	}
	if !strings.Contains(result, "0 accessed") {
		t.Errorf("buildPrompt() should show secrets count")
	}
}

func TestBuildPrompt_AgentNameDisplay(t *testing.T) {
	req := ApprovalRequest{
		Operation: "test",
		AgentName: "my-custom-agent",
		RiskLevel: RiskLevelLow,
	}
	result := buildPrompt(req)
	if !strings.Contains(result, "my-custom-agent") {
		t.Errorf("buildPrompt() should display agent name 'my-custom-agent', got:\n%s", result)
	}
}

func TestBuildPrompt_ProjectTypeDisplay(t *testing.T) {
	req := ApprovalRequest{
		Operation:   "test",
		RiskLevel:   RiskLevelLow,
		ProjectType: "myapp (Go)",
	}
	result := buildPrompt(req)
	if !strings.Contains(result, "myapp (Go)") {
		t.Errorf("buildPrompt() should display project type:\n%s", result)
	}
}

func TestSanitizeForSummary(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain text", "hello/world", "hello/world"},
		{"with ANSI", "\x1b[31mred\x1b[0m", "red"},
		{"with control chars", "hello\x00world", "helloworld"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeForSummary(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeForSummary(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRenderSummary(t *testing.T) {
	result := RenderSummary("get_entry_value", "github/token", "password")
	expected := "get_entry_value on github/token field password"
	if result != expected {
		t.Errorf("RenderSummary() = %q, want %q", result, expected)
	}

	resultNoField := RenderSummary("list_entries", "/", "")
	expectedNoField := "list_entries on /"
	if resultNoField != expectedNoField {
		t.Errorf("RenderSummary() = %q, want %q", resultNoField, expectedNoField)
	}
}
