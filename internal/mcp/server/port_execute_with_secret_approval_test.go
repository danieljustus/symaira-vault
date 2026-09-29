package server

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/config"
)

// This exercises the production Go execute_with_secret approval intent through
// a synthetic TTY; it never opens a real terminal or resolves a secret.
func TestPortExecuteWithSecretApprovalPrompt(t *testing.T) {
	original := openTTYDevice
	defer func() { openTTYDevice = original }()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	openCount := 0
	openTTYDevice = func() (ttyDevice, error) {
		openCount++
		return &mockTTYDevice{
			readString: func() (string, error) { return "y", nil },
			output:     writer,
			raw:        func() (func(), error) { return func() {}, nil },
		}, nil
	}

	profile := config.AgentProfile{
		Name:            "approval-fixture-agent",
		ApprovalMode:    config.StrPtr("prompt"),
		ApprovalTimeout: config.DurationPtr(73 * time.Second),
	}
	srv := newTestServer(t, profile, "stdio")
	environment := map[string]string{
		"PLAIN":   "literal-approval-secret",
		"API_KEY": "resolved-approval-secret",
	}
	command := []string{"curl", "--header=resolved-approval-secret", "literal-approval-secret"}
	if err := srv.checkExecuteWithSecretApproval(context.Background(), command, environment); err != nil {
		t.Fatalf("checkExecuteWithSecretApproval: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	firstPrompt, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	prompt := string(firstPrompt)
	for _, want := range []string{
		"approval-fixture-agent",
		"execute_with_secret",
		"(y/n/r, r=remember for session)",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("Go approval prompt missing %q: %s", want, prompt)
		}
	}

	if openCount != 3 {
		t.Fatalf("TTY opens = %d, want the two capability checks + one prompt", openCount)
	}
}
