package secureui

import (
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseApprovalResponse_Yes(t *testing.T) {
	tests := []string{"y", "Y", "yes", "YES", "Yes"}
	for _, resp := range tests {
		if !parseApprovalResponse(resp) {
			t.Errorf("parseApprovalResponse(%q) = false, want true", resp)
		}
	}
}

func TestParseApprovalResponse_Remember(t *testing.T) {
	tests := []string{"r", "R", "remember", "REMEMBER", "Remember"}
	for _, resp := range tests {
		if !parseApprovalResponse(resp) {
			t.Errorf("parseApprovalResponse(%q) = false, want true (remember implies approval)", resp)
		}
	}
}

func TestParseApprovalResponse_No(t *testing.T) {
	tests := []string{"n", "N", "no", "NO", "No", "", "anything", "maybe"}
	for _, resp := range tests {
		if parseApprovalResponse(resp) {
			t.Errorf("parseApprovalResponse(%q) = true, want false", resp)
		}
	}
}

func TestParseRememberResponse_Remember(t *testing.T) {
	tests := []string{"r", "R", "remember", "REMEMBER"}
	for _, resp := range tests {
		if !parseRememberResponse(resp) {
			t.Errorf("parseRememberResponse(%q) = false, want true", resp)
		}
	}
}

func TestParseRememberResponse_NotRemember(t *testing.T) {
	tests := []string{"y", "yes", "n", "no", "", "maybe", "true", "false"}
	for _, resp := range tests {
		if parseRememberResponse(resp) {
			t.Errorf("parseRememberResponse(%q) = true, want false", resp)
		}
	}
}

func TestParseApprovalResponse_Whitespace(t *testing.T) {
	if !parseApprovalResponse("  y  ") {
		t.Error("parseApprovalResponse(\"  y  \") = false, want true")
	}
	if !parseApprovalResponse("\nyes\n") {
		t.Error("parseApprovalResponse(\"\\nyes\\n\") = false, want true")
	}
}

func TestBuildApprovalPrompt_WithRemember(t *testing.T) {
	req := ApprovalRequest{
		Operation:   "set_entry_field",
		Details:     "Write password to github.token",
		CanRemember: true,
	}
	prompt := buildApprovalPrompt(req)

	if !strings.Contains(prompt, "set_entry_field") {
		t.Error("buildApprovalPrompt missing operation")
	}
	if !strings.Contains(prompt, "Write password to github.token") {
		t.Error("buildApprovalPrompt missing details")
	}
	if !strings.Contains(prompt, "r=remember") {
		t.Error("buildApprovalPrompt missing remember option")
	}
	if !strings.Contains(prompt, "MCP OPERATION APPROVAL REQUIRED") {
		t.Error("buildApprovalPrompt missing header")
	}
}

func TestBuildApprovalPrompt_WithoutRemember(t *testing.T) {
	req := ApprovalRequest{
		Operation:   "delete_entry",
		Details:     "Delete github.token",
		CanRemember: false,
	}
	prompt := buildApprovalPrompt(req)

	if strings.Contains(prompt, "remember") {
		t.Error("buildApprovalPrompt should not contain 'remember' when CanRemember=false")
	}
	if !strings.Contains(prompt, "y/n") {
		t.Error("buildApprovalPrompt missing y/n option")
	}
}

func TestBuildApprovalPrompt_EmptyFields(t *testing.T) {
	req := ApprovalRequest{}
	prompt := buildApprovalPrompt(req)

	if !strings.Contains(prompt, "MCP OPERATION APPROVAL REQUIRED") {
		t.Error("buildApprovalPrompt missing header")
	}
	if !strings.Contains(prompt, "Approve this operation?") {
		t.Error("buildApprovalPrompt missing approval question")
	}
}

func TestBuildApprovalDescription_WithRemember(t *testing.T) {
	req := ApprovalRequest{
		Operation:   "add_credential",
		Details:     "Add AWS key",
		CanRemember: true,
	}
	desc := buildApprovalDescription(req)

	if !strings.Contains(desc, "add_credential") {
		t.Error("buildApprovalDescription missing operation")
	}
	if !strings.Contains(desc, "Add AWS key") {
		t.Error("buildApprovalDescription missing details")
	}
	if !strings.Contains(desc, "remember for session") {
		t.Error("buildApprovalDescription missing remember option")
	}
}

func TestBuildApprovalDescription_WithoutRemember(t *testing.T) {
	req := ApprovalRequest{
		Operation:   "rotate_key",
		Details:     "Rotate API key",
		CanRemember: false,
	}
	desc := buildApprovalDescription(req)

	if strings.Contains(desc, "remember") {
		t.Error("buildApprovalDescription should not contain 'remember' when CanRemember=false")
	}
	if !strings.Contains(desc, "'y' to approve or 'n' to deny") {
		t.Error("buildApprovalDescription missing y/n instruction")
	}
}

func TestBuildApprovalDescription_EmptyFields(t *testing.T) {
	req := ApprovalRequest{}
	desc := buildApprovalDescription(req)

	if !strings.Contains(desc, "MCP Operation Approval Required") {
		t.Error("buildApprovalDescription missing header")
	}
}

func TestOrDefault_WithDefault(t *testing.T) {
	got := orDefault("", "fallback")
	if got != "fallback" {
		t.Errorf("orDefault(\"\", \"fallback\") = %q, want fallback", got)
	}
}

func TestOrDefault_WithValue(t *testing.T) {
	got := orDefault("actual", "fallback")
	if got != "actual" {
		t.Errorf("orDefault(\"actual\", \"fallback\") = %q, want actual", got)
	}
}

func TestOrDefault_EmptyDefault(t *testing.T) {
	got := orDefault("", "")
	if got != "" {
		t.Errorf("orDefault(\"\", \"\") = %q, want empty", got)
	}
}

func TestTruncate_ShortString(t *testing.T) {
	got := truncate("hello")
	if got != "hello" {
		t.Errorf("truncate(\"hello\") = %q, want hello", got)
	}
}

func TestTruncate_LongString(t *testing.T) {
	long := strings.Repeat("a", 60)
	got := truncate(long)
	if len(got) != 50 {
		t.Errorf("truncate(long string) length = %d, want 50", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("truncate(long string) should end with ..., got %q", got)
	}
}

func TestTruncate_ExactlyMax(t *testing.T) {
	s := strings.Repeat("b", 50)
	got := truncate(s)
	if got != s {
		t.Errorf("truncate(exact 50 chars) = %q, want %q", got, s)
	}
}

func TestTruncate_EmptyString(t *testing.T) {
	got := truncate("")
	if got != "" {
		t.Errorf("truncate(\"\") = %q, want empty", got)
	}
}

func TestPromptApproval_NoneBackend(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "none")
	_, err := PromptApproval(ApprovalRequest{Operation: "test"})
	if err == nil || !strings.Contains(err.Error(), "no secure input backend available") {
		t.Errorf("PromptApproval() err = %v, want ErrUnavailable", err)
	}
}

func TestPromptApproval_DefaultTimeout(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "gui")
	old := defaultRunner
	defer func() { defaultRunner = old }()

	mr := &mockRunner{
		available: guiAvailableMap(),
		out:       []byte("y\n"),
	}
	defaultRunner = mr

	result, err := PromptApproval(ApprovalRequest{
		Operation: "test_op",
		Details:   "test details",
	})
	if err != nil {
		t.Fatalf("PromptApproval() err = %v", err)
	}
	if !result.Approved {
		t.Error("expected Approved=true for 'y' response")
	}
	if mr.calledTime != defaultTimeout {
		t.Errorf("default timeout not applied: got %v, want %v", mr.calledTime, defaultTimeout)
	}
}

func TestPromptApproval_Approved(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "gui")
	old := defaultRunner
	defer func() { defaultRunner = old }()

	defaultRunner = &mockRunner{
		available: guiAvailableMap(),
		out:       []byte("yes\n"),
	}

	result, err := PromptApproval(ApprovalRequest{Operation: "test"})
	if err != nil {
		t.Fatalf("PromptApproval() err = %v", err)
	}
	if !result.Approved {
		t.Error("expected Approved=true for 'yes' response")
	}
}

func TestPromptApproval_Denied(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "gui")
	old := defaultRunner
	defer func() { defaultRunner = old }()

	defaultRunner = &mockRunner{
		available: guiAvailableMap(),
		out:       []byte("n\n"),
	}

	result, err := PromptApproval(ApprovalRequest{Operation: "test"})
	if err != nil {
		t.Fatalf("PromptApproval() err = %v", err)
	}
	if result.Approved {
		t.Error("expected Approved=false for 'n' response")
	}
}

func TestPromptApproval_Remembered(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "gui")
	old := defaultRunner
	defer func() { defaultRunner = old }()

	defaultRunner = &mockRunner{
		available: guiAvailableMap(),
		out:       []byte("r\n"),
	}

	result, err := PromptApproval(ApprovalRequest{
		Operation:   "test",
		CanRemember: true,
	})
	if err != nil {
		t.Fatalf("PromptApproval() err = %v", err)
	}
	if !result.Approved {
		t.Error("expected Approved=true for 'r' response")
	}
	if !result.Remembered {
		t.Error("expected Remembered=true for 'r' response")
	}
}

func TestPromptApproval_EmptyResponseIsDenied(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Mock GUI runner does not work on Windows")
	}
	t.Setenv("OPENPASS_SECUREUI", "gui")
	old := defaultRunner
	defer func() { defaultRunner = old }()

	defaultRunner = &mockRunner{
		available: guiAvailableMap(),
		out:       []byte(""),
	}

	result, err := PromptApproval(ApprovalRequest{Operation: "test"})
	if err != nil {
		t.Fatalf("PromptApproval() err = %v", err)
	}
	if result.Approved {
		t.Error("expected Approved=false for empty response")
	}
}

func TestPromptApproval_CustomTimeout(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "gui")
	old := defaultRunner
	defer func() { defaultRunner = old }()

	mr := &mockRunner{
		available: guiAvailableMap(),
		out:       []byte("y\n"),
	}
	defaultRunner = mr

	customTimeout := 30 * time.Second
	result, err := PromptApproval(ApprovalRequest{
		Operation: "test",
		Timeout:   customTimeout,
	})
	if err != nil {
		t.Fatalf("PromptApproval() err = %v", err)
	}
	if !result.Approved {
		t.Error("expected Approved=true")
	}
	if mr.calledTime != customTimeout {
		t.Errorf("timeout = %v, want %v", mr.calledTime, customTimeout)
	}
}

func TestPromptApproval_TTYBackend(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "tty")
	oldOpen := openTTYDevice
	defer func() { openTTYDevice = oldOpen }()
	openTTYDevice = func() (ttyDevice, error) {
		return &fakeTTY{value: "y"}, nil
	}

	result, err := PromptApproval(ApprovalRequest{
		Operation: "test_op",
		Details:   "test details",
	})
	if err != nil {
		t.Fatalf("PromptApproval() err = %v", err)
	}
	if !result.Approved {
		t.Error("expected Approved=true for 'y' response")
	}
}

func TestPromptApproval_TTYBackend_Denied(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "tty")
	oldOpen := openTTYDevice
	defer func() { openTTYDevice = oldOpen }()
	openTTYDevice = func() (ttyDevice, error) {
		return &fakeTTY{value: "n"}, nil
	}

	result, err := PromptApproval(ApprovalRequest{Operation: "test"})
	if err != nil {
		t.Fatalf("PromptApproval() err = %v", err)
	}
	if result.Approved {
		t.Error("expected Approved=false for 'n' response")
	}
}

func TestPromptApproval_TTYBackend_Remember(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "tty")
	oldOpen := openTTYDevice
	defer func() { openTTYDevice = oldOpen }()
	openTTYDevice = func() (ttyDevice, error) {
		return &fakeTTY{value: "remember"}, nil
	}

	result, err := PromptApproval(ApprovalRequest{
		Operation:   "test",
		CanRemember: true,
	})
	if err != nil {
		t.Fatalf("PromptApproval() err = %v", err)
	}
	if !result.Approved {
		t.Error("expected Approved=true for 'remember' response")
	}
	if !result.Remembered {
		t.Error("expected Remembered=true for 'remember' response")
	}
}

func TestPromptApproval_TTYBackend_NoTTY(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "tty")
	oldOpen := openTTYDevice
	defer func() { openTTYDevice = oldOpen }()
	openTTYDevice = func() (ttyDevice, error) {
		return nil, &testError{msg: "no tty"}
	}

	_, err := PromptApproval(ApprovalRequest{Operation: "test"})
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("PromptApproval() err = %v, want ErrUnavailable", err)
	}
}

func TestPromptApproval_GUIBackend_UserCanceled(t *testing.T) {
	t.Setenv("OPENPASS_SECUREUI", "gui")
	old := defaultRunner
	defer func() { defaultRunner = old }()

	defaultRunner = &mockRunner{
		available: guiAvailableMap(),
		err:       &testError{msg: "exit status 1"},
	}

	_, err := PromptApproval(ApprovalRequest{Operation: "test"})
	if !errors.Is(err, ErrCanceled) {
		t.Errorf("PromptApproval() err = %v, want ErrCanceled", err)
	}
}

func TestApprovalRequest_Fields(t *testing.T) {
	req := ApprovalRequest{
		Operation:   "set_field",
		Details:     "Update password",
		Timeout:     10 * time.Second,
		CanRemember: true,
	}

	if req.Operation != "set_field" {
		t.Errorf("Operation = %q, want set_field", req.Operation)
	}
	if req.Details != "Update password" {
		t.Errorf("Details = %q, want Update password", req.Details)
	}
	if req.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v, want 10s", req.Timeout)
	}
	if !req.CanRemember {
		t.Error("CanRemember should be true")
	}
}

func TestApprovalResult_Fields(t *testing.T) {
	result := ApprovalResult{
		Approved:   true,
		Remembered: true,
	}

	if !result.Approved {
		t.Error("Approved should be true")
	}
	if !result.Remembered {
		t.Error("Remembered should be true")
	}
}

func TestBuildApprovalPrompt_OperationTruncation(t *testing.T) {
	longOp := strings.Repeat("x", 100)
	req := ApprovalRequest{Operation: longOp, CanRemember: false}
	prompt := buildApprovalPrompt(req)

	// The operation should be truncated to 50 chars
	if !strings.Contains(prompt, "...") {
		t.Error("long operation should be truncated")
	}
}

func TestBuildApprovalDescription_DetailsTruncation(t *testing.T) {
	longDetails := strings.Repeat("y", 100)
	req := ApprovalRequest{Details: longDetails}
	desc := buildApprovalDescription(req)

	// Description should contain the full details (no truncation in description)
	if !strings.Contains(desc, longDetails) {
		t.Error("buildApprovalDescription should contain full details")
	}
}

// testError is a simple error implementation for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
