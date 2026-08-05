package crud

import (
	"io"
	"os"
	"testing"

	"github.com/danieljustus/symaira-vault/internal/vault"
)

func resetAddFlags(t *testing.T) {
	t.Helper()
	old := struct {
		value                               string
		stdinValue, stdinTOTP, generate     bool
		length                              int
		username, url, notes                string
		totpSecret, totpIssuer, totpAccount string
		force                               bool
		typ, usageHint, expiresAt           string
		autoRotate                          bool
	}{
		AddValue, AddStdinValue, AddStdinTOTP, AddGenerate,
		AddLength, AddUsername, AddURL, AddNotes,
		AddTOTPSecret, AddTOTPIssuer, AddTOTPAccount,
		AddForce, AddType, AddUsageHint, AddExpiresAt, AddAutoRotate,
	}
	t.Cleanup(func() {
		AddValue, AddStdinValue, AddStdinTOTP, AddGenerate = old.value, old.stdinValue, old.stdinTOTP, old.generate
		AddLength, AddUsername, AddURL, AddNotes = old.length, old.username, old.url, old.notes
		AddTOTPSecret, AddTOTPIssuer, AddTOTPAccount = old.totpSecret, old.totpIssuer, old.totpAccount
		AddForce, AddType, AddUsageHint, AddExpiresAt, AddAutoRotate = old.force, old.typ, old.usageHint, old.expiresAt, old.autoRotate
	})
}

func TestAddCommand_ValueCreatesEntry(t *testing.T) {
	resetAddFlags(t)
	setupTestVault(t)

	cmd := newAddCmd()
	cmd.SetArgs([]string{
		"github",
		"--value", "StrongPass123!",
		"--username", "octocat",
		"--url", "https://github.com",
		"--notes", "primary account",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	entry := getTestEntry(t, "github")
	if got, _ := entry.GetField("password"); got != "StrongPass123!" {
		t.Errorf("password = %q, want explicit value", got)
	}
	if got, _ := entry.GetField("username"); got != "octocat" {
		t.Errorf("username = %q, want octocat", got)
	}
	if got, _ := entry.GetField("url"); got != "https://github.com" {
		t.Errorf("url = %q, want GitHub URL", got)
	}
}

func TestAddCommand_GenerateCreatesPasswordEntry(t *testing.T) {
	resetAddFlags(t)
	setupTestVault(t)

	cmd := newAddCmd()
	cmd.SetArgs([]string{"generated", "--generate", "--length", "24"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	entry := getTestEntry(t, "generated")
	value, ok := entry.Data[vault.PrimaryFieldForType(vault.SecretTypePassword)].(string)
	if !ok {
		t.Fatalf("generated password has type %T, want string", entry.Data[vault.PrimaryFieldForType(vault.SecretTypePassword)])
	}
	if len(value) != 24 {
		t.Errorf("generated password length = %d, want 24", len(value))
	}
}

func TestReadStdinValues_AcceptsEOFWithData(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		setValueFlag bool
		setTOTPFlag  bool
		wantValue    string
		wantTOTP     string
		wantErr      bool
	}{
		{
			name:         "value with trailing newline",
			input:        "secret\n",
			setValueFlag: true,
			wantValue:    "secret",
			wantErr:      false,
		},
		{
			name:         "value without trailing newline",
			input:        "secret",
			setValueFlag: true,
			wantValue:    "secret",
			wantErr:      false,
		},
		{
			name:         "empty stdin",
			input:        "",
			setValueFlag: true,
			wantErr:      true,
		},
		{
			name:        "totp secret without trailing newline",
			input:       "totp-secret",
			setTOTPFlag: true,
			wantTOTP:    "totp-secret",
			wantErr:     false,
		},
		{
			name:         "value and totp without trailing newlines",
			input:        "value\ntotp",
			setValueFlag: true,
			setTOTPFlag:  true,
			wantValue:    "value",
			wantTOTP:     "totp",
			wantErr:      false,
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

			oldValueFlag, oldTOTPFlag := AddStdinValue, AddStdinTOTP
			oldAddValue, oldAddTOTPSecret := AddValue, AddTOTPSecret
			defer func() {
				AddStdinValue, AddStdinTOTP = oldValueFlag, oldTOTPFlag
				AddValue, AddTOTPSecret = oldAddValue, oldAddTOTPSecret
			}()

			AddStdinValue = tt.setValueFlag
			AddStdinTOTP = tt.setTOTPFlag

			err = readStdinValues()
			<-done

			if (err != nil) != tt.wantErr {
				t.Fatalf("readStdinValues() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if AddValue != tt.wantValue {
				t.Errorf("AddValue = %q, want %q", AddValue, tt.wantValue)
			}
			if AddTOTPSecret != tt.wantTOTP {
				t.Errorf("AddTOTPSecret = %q, want %q", AddTOTPSecret, tt.wantTOTP)
			}
		})
	}
}
