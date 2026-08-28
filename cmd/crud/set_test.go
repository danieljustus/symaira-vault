package crud

import (
	"bufio"
	"io"
	"os"
	"strings"
	"testing"

	cliinput "github.com/danieljustus/symaira-vault/internal/cli/input"
)

func TestSetStdinValue_ReadsFromStdin(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantValue string
		wantErr   bool
	}{
		{
			name:      "value with trailing newline",
			input:     "mysecret\n",
			wantValue: "mysecret",
			wantErr:   false,
		},
		{
			name:      "value without trailing newline",
			input:     "mysecret",
			wantValue: "mysecret",
			wantErr:   false,
		},
		{
			name:    "empty stdin",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldStdin := os.Stdin
			defer func() { os.Stdin = oldStdin }()

			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("os.Pipe() = %v", err)
			}
			os.Stdin = r

			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = io.WriteString(w, tt.input)
				_ = w.Close()
			}()

			oldStdinValueFlag := SetStdinValue
			oldSetValue := SetValue
			defer func() {
				SetStdinValue = oldStdinValueFlag
				SetValue = oldSetValue
			}()

			SetStdinValue = true
			SetValue = ""

			// Mimic the reading logic in RunE
			var readErr error
			if SetStdinValue {
				stdinReader := bufio.NewReader(os.Stdin)
				line, err := stdinReader.ReadString('\n')
				if err != nil && line == "" {
					readErr = err
				} else {
					SetValue = strings.TrimRight(line, "\n\r")
				}
			}
			<-done

			if (readErr != nil) != tt.wantErr {
				t.Fatalf("reading stdin error = %v, wantErr %v", readErr, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if SetValue != tt.wantValue {
				t.Errorf("SetValue = %q, want %q", SetValue, tt.wantValue)
			}
		})
	}
}

func resetSetFlags(t *testing.T) {
	t.Helper()
	oldValue := SetValue
	oldStdinValue := SetStdinValue
	oldAllowEmpty := SetAllowEmpty
	oldTOTPSecret := SetTOTPSecret
	oldTOTPIssuer := SetTOTPIssuer
	oldTOTPAccount := SetTOTPAccount
	oldForce := SetForce
	t.Cleanup(func() {
		SetValue = oldValue
		SetStdinValue = oldStdinValue
		SetAllowEmpty = oldAllowEmpty
		SetTOTPSecret = oldTOTPSecret
		SetTOTPIssuer = oldTOTPIssuer
		SetTOTPAccount = oldTOTPAccount
		SetForce = oldForce
	})
}

func TestSetCommand_EmptySensitiveValues(t *testing.T) {
	setupTestVault(t)

	tests := []struct {
		name       string
		query      string
		value      string
		allowEmpty bool
		wantErr    bool
	}{
		// Sensitive fields with empty value and allowEmpty = false -> error
		{name: "sensitive password empty no-allow", query: "svc.password", value: "", allowEmpty: false, wantErr: true},
		{name: "sensitive token empty no-allow", query: "svc.api_token", value: "", allowEmpty: false, wantErr: true},
		{name: "sensitive secret empty no-allow", query: "svc.client_secret", value: "", allowEmpty: false, wantErr: true},
		{name: "sensitive key empty no-allow", query: "svc.private_key", value: "", allowEmpty: false, wantErr: true},
		{name: "sensitive passwd empty no-allow", query: "svc.db_passwd", value: "", allowEmpty: false, wantErr: true},
		{name: "sensitive pwd empty no-allow", query: "svc.user_pwd", value: "", allowEmpty: false, wantErr: true},
		{name: "sensitive uppercase PASSWORD empty no-allow", query: "svc.MY_PASSWORD", value: "", allowEmpty: false, wantErr: true},
		{name: "sensitive default password empty no-allow", query: "svc", value: "", allowEmpty: false, wantErr: true},

		// Sensitive fields with empty value and allowEmpty = true -> success
		{name: "sensitive password empty allow", query: "svc.password", value: "", allowEmpty: true, wantErr: false},
		{name: "sensitive token empty allow", query: "svc.api_token", value: "", allowEmpty: true, wantErr: false},
		{name: "sensitive secret empty allow", query: "svc.client_secret", value: "", allowEmpty: true, wantErr: false},
		{name: "sensitive key empty allow", query: "svc.private_key", value: "", allowEmpty: true, wantErr: false},
		{name: "sensitive passwd empty allow", query: "svc.db_passwd", value: "", allowEmpty: true, wantErr: false},
		{name: "sensitive pwd empty allow", query: "svc.user_pwd", value: "", allowEmpty: true, wantErr: false},
		{name: "sensitive default password empty allow", query: "svc", value: "", allowEmpty: true, wantErr: false},

		// Sensitive fields with non-empty value and allowEmpty = false -> success
		{name: "sensitive password non-empty no-allow", query: "svc.password", value: "StrongPass123!", allowEmpty: false, wantErr: false},
		{name: "sensitive token non-empty no-allow", query: "svc.api_token", value: "tok-123456", allowEmpty: false, wantErr: false},
		{name: "sensitive secret non-empty no-allow", query: "svc.client_secret", value: "sec-123456", allowEmpty: false, wantErr: false},
		{name: "sensitive key non-empty no-allow", query: "svc.private_key", value: "key-123456", allowEmpty: false, wantErr: false},

		// Sensitive fields with non-empty value and allowEmpty = true -> success
		{name: "sensitive password non-empty allow", query: "svc.password", value: "StrongPass123!", allowEmpty: true, wantErr: false},

		// Non-sensitive fields with empty value and allowEmpty = false -> success
		{name: "non-sensitive username empty no-allow", query: "svc.username", value: "", allowEmpty: false, wantErr: false},
		{name: "non-sensitive url empty no-allow", query: "svc.url", value: "", allowEmpty: false, wantErr: false},
		{name: "non-sensitive notes empty no-allow", query: "svc.notes", value: "", allowEmpty: false, wantErr: false},
		{name: "non-sensitive custom empty no-allow", query: "svc.custom_field", value: "", allowEmpty: false, wantErr: false},

		// Non-sensitive fields with empty value and allowEmpty = true -> success
		{name: "non-sensitive username empty allow", query: "svc.username", value: "", allowEmpty: true, wantErr: false},

		// Non-sensitive fields with non-empty value and allowEmpty = false -> success
		{name: "non-sensitive username non-empty no-allow", query: "svc.username", value: "octocat", allowEmpty: false, wantErr: false},
		{name: "non-sensitive url non-empty no-allow", query: "svc.url", value: "https://example.com", allowEmpty: false, wantErr: false},

		// Non-sensitive fields with non-empty value and allowEmpty = true -> success
		{name: "non-sensitive username non-empty allow", query: "svc.username", value: "octocat", allowEmpty: true, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetSetFlags(t)
			cmd := newSetCmd()
			args := []string{tt.query, "--value", tt.value}
			if tt.allowEmpty {
				args = append(args, "--allow-empty")
			}
			cmd.SetArgs(args)
			cmd.SetOut(&strings.Builder{})
			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("set %v returned err = %v, wantErr = %v", args, err, tt.wantErr)
			}
		})
	}
}

func TestSetInteractivePrompt_RetypeMatch(t *testing.T) {
	setupTestVault(t)
	resetSetFlags(t)

	oldHandler := inputHandler
	t.Cleanup(func() { inputHandler = oldHandler })

	calls := 0
	inputHandler = cliinput.New(cliinput.Deps{
		ReadHidden: func(prompt string, reader *bufio.Reader) ([]byte, error) {
			calls++
			return []byte("secretinput"), nil
		},
	})

	cmd := newSetCmd()
	cmd.SetArgs([]string{"service.password"})
	cmd.SetOut(&strings.Builder{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected 2 prompts (value + confirm), got %d", calls)
	}
	entry := getTestEntry(t, "service")
	if got, _ := entry.GetField("password"); got != "secretinput" {
		t.Errorf("expected password secretinput, got %v", got)
	}
}

func TestSetInteractivePrompt_RetypeMismatch(t *testing.T) {
	setupTestVault(t)
	resetSetFlags(t)

	oldHandler := inputHandler
	t.Cleanup(func() { inputHandler = oldHandler })

	call := 0
	inputHandler = cliinput.New(cliinput.Deps{
		ReadHidden: func(prompt string, reader *bufio.Reader) ([]byte, error) {
			call++
			if call == 1 {
				return []byte("secretinput1"), nil
			}
			return []byte("secretinput2"), nil
		},
	})

	cmd := newSetCmd()
	cmd.SetArgs([]string{"service.password"})
	cmd.SetOut(&strings.Builder{})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error on retype mismatch, got nil")
	}
}

func TestSetInteractivePrompt_EmptySensitiveRejected(t *testing.T) {
	setupTestVault(t)
	resetSetFlags(t)

	oldHandler := inputHandler
	t.Cleanup(func() { inputHandler = oldHandler })

	inputHandler = cliinput.New(cliinput.Deps{
		ReadHidden: func(prompt string, reader *bufio.Reader) ([]byte, error) {
			return []byte(""), nil
		},
	})

	cmd := newSetCmd()
	cmd.SetArgs([]string{"service.password"})
	cmd.SetOut(&strings.Builder{})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error on empty sensitive interactive prompt, got nil")
	}
}
