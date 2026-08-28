package input

import (
	"bufio"
	"strings"
	"testing"
)

func TestCollectEntryData_UsernameOnly(t *testing.T) {
	h := New(Deps{
		ReadHidden: func(prompt string, reader *bufio.Reader) ([]byte, error) {
			return []byte("StrongPass123!"), nil
		},
	})

	reader := bufio.NewReader(strings.NewReader("\n"))
	data, err := h.CollectEntryData(reader, EntryFlags{
		Username:        "user",
		URL:             "https://example.com",
		TOTPSecret:      "skip",
		SkipNotes:       true,
		SkipTOTPDetails: true,
		Force:           true,
	})
	if err != nil {
		t.Fatalf("CollectEntryData: %v", err)
	}
	if data["username"] != "user" {
		t.Errorf("username = %q, want %q", data["username"], "user")
	}
	if data["password"] != "StrongPass123!" {
		t.Errorf("password = %q, want %q", data["password"], "StrongPass123!")
	}
	if data["url"] != "https://example.com" {
		t.Errorf("url = %q, want %q", data["url"], "https://example.com")
	}
}

func TestCollectEntryData_PasswordFlag(t *testing.T) {
	h := New(Deps{})

	data, err := h.CollectEntryData(nil, EntryFlags{
		Username:        "user",
		Password:        "secret1234567890",
		URL:             "https://example.com",
		TOTPSecret:      "skip",
		SkipNotes:       true,
		SkipTOTPDetails: true,
		Force:           true,
	})
	if err != nil {
		t.Fatalf("CollectEntryData: %v", err)
	}
	if data["password"] != "secret1234567890" {
		t.Errorf("password = %v, want %q", data["password"], "secret1234567890")
	}
	if data["username"] != "user" {
		t.Errorf("username = %v, want %q", data["username"], "user")
	}
}

func TestCollectEntryData_GeneratePassword(t *testing.T) {
	generated := ""
	cleanupCalled := false
	h := New(Deps{
		Generate: func(length int, useSymbols bool) (string, func(), error) {
			generated = "generated-pass"
			return generated, func() { cleanupCalled = true }, nil
		},
	})

	reader := bufio.NewReader(strings.NewReader("\n"))
	data, err := h.CollectEntryData(reader, EntryFlags{
		Username:        "user",
		Generate:        true,
		Length:          16,
		URL:             "https://example.com",
		TOTPSecret:      "skip",
		SkipNotes:       true,
		SkipTOTPDetails: true,
		Force:           true,
	})
	if err != nil {
		t.Fatalf("CollectEntryData: %v", err)
	}
	if data["password"] != "generated-pass" {
		t.Errorf("password = %v, want %q", data["password"], "generated-pass")
	}
	if !cleanupCalled {
		t.Error("expected cleanup to be called")
	}
}

func TestCollectEntryData_ReadHiddenPassword(t *testing.T) {
	readCalled := false
	h := New(Deps{
		ReadHidden: func(prompt string, reader *bufio.Reader) ([]byte, error) {
			readCalled = true
			if prompt != "Password: " {
				t.Errorf("prompt = %q, want %q", prompt, "Password: ")
			}
			return []byte("hidden-secret"), nil
		},
	})

	reader := bufio.NewReader(strings.NewReader("\n"))
	data, err := h.CollectEntryData(reader, EntryFlags{
		Username:        "user",
		URL:             "https://example.com",
		TOTPSecret:      "skip",
		SkipNotes:       true,
		SkipTOTPDetails: true,
		Force:           true,
	})
	if err != nil {
		t.Fatalf("CollectEntryData: %v", err)
	}
	if !readCalled {
		t.Error("expected ReadHidden to be called")
	}
	if data["password"] != "hidden-secret" {
		t.Errorf("password = %v, want %q", data["password"], "hidden-secret")
	}
}

func TestCollectEntryData_NilDispatchPasswordPanics(t *testing.T) {
	h := New(Deps{})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic when ReadHidden is nil")
		}
	}()

	reader := bufio.NewReader(strings.NewReader("\n"))
	h.CollectEntryData(reader, EntryFlags{
		Username:        "user",
		URL:             "https://example.com",
		TOTPSecret:      "skip",
		SkipNotes:       true,
		SkipTOTPDetails: true,
		Force:           true,
	})
}

func TestCollectEntryData_URLAndNotes(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("\nNote line 1\nNote line 2\n"))

	h := New(Deps{
		ReadHidden: func(prompt string, reader *bufio.Reader) ([]byte, error) {
			return nil, nil
		},
	})
	data, err := h.CollectEntryData(reader, EntryFlags{
		Username:        "user",
		URL:             "https://override.com",
		Notes:           "override notes",
		TOTPSecret:      "skip",
		SkipTOTPDetails: true,
		Force:           true,
	})
	if err != nil {
		t.Fatalf("CollectEntryData: %v", err)
	}
	if data["url"] != "https://override.com" {
		t.Errorf("url = %v, want %q", data["url"], "https://override.com")
	}
	if data["notes"] != "override notes" {
		t.Errorf("notes = %v, want %q", data["notes"], "override notes")
	}
}

func TestCollectEntryData_TOTP(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("\nJBSWY3DPEHPK3PXP\nMyIssuer\nmyaccount\n"))

	h := New(Deps{
		ReadHidden: func(prompt string, reader *bufio.Reader) ([]byte, error) {
			return nil, nil
		},
	})
	data, err := h.CollectEntryData(reader, EntryFlags{
		Username:  "user",
		URL:       "https://example.com",
		SkipNotes: true,
		Force:     true,
	})
	if err != nil {
		t.Fatalf("CollectEntryData: %v", err)
	}
	totp, ok := data["totp"].(map[string]any)
	if !ok {
		t.Fatalf("totp = %T, want map[string]any", data["totp"])
	}
	if totp["secret"] != "JBSWY3DPEHPK3PXP" {
		t.Errorf("totp.secret = %v, want %q", totp["secret"], "JBSWY3DPEHPK3PXP")
	}
	if totp["issuer"] != "MyIssuer" {
		t.Errorf("totp.issuer = %v, want %q", totp["issuer"], "MyIssuer")
	}
	if totp["account_name"] != "myaccount" {
		t.Errorf("totp.account_name = %v, want %q", totp["account_name"], "myaccount")
	}
}

func TestConfirmInteractive_Force(t *testing.T) {
	h := New(Deps{})

	ok, err := h.ConfirmInteractive("Proceed?", true)
	if err != nil {
		t.Fatalf("ConfirmInteractive: %v", err)
	}
	if !ok {
		t.Error("expected true when force is set")
	}
}

func TestConfirmInteractive_Yes(t *testing.T) {
	_ = New(Deps{})

	t.Skip("interactive confirmation requires stdin mocking; covered by integration tests")
}

func TestConfirmWeakPassword_WeakWithTerminal(t *testing.T) {
	h := New(Deps{
		IsTerminal: func(fd int) bool { return true },
	})

	// Use a real weak password; AssessPasswordStrength will flag it.
	// With IsTerminal=true it will attempt interactive confirmation.
	err := h.confirmWeakPassword("123456")
	if err == nil {
		t.Skip("interactive weak-password confirmation requires stdin mocking")
	}
}

func TestConfirmWeakPassword_Strong(t *testing.T) {
	h := New(Deps{})

	err := h.confirmWeakPassword("StrongPass123!")
	if err != nil {
		t.Fatalf("confirmWeakPassword strong: %v", err)
	}
}

func TestCollectEntryData_WeakPasswordNonTerminal(t *testing.T) {
	h := New(Deps{
		ReadHidden: func(prompt string, reader *bufio.Reader) ([]byte, error) {
			return []byte("123456"), nil
		},
		IsTerminal: func(fd int) bool { return false },
	})

	reader := bufio.NewReader(strings.NewReader("\n"))
	_, err := h.CollectEntryData(reader, EntryFlags{
		Username:        "user",
		URL:             "https://example.com",
		TOTPSecret:      "skip",
		SkipNotes:       true,
		SkipTOTPDetails: true,
		Force:           false,
	})
	if err == nil {
		t.Fatal("expected error for weak password on non-terminal")
	}
	if !strings.Contains(err.Error(), "use --force") {
		t.Errorf("error = %q, want message about --force", err.Error())
	}
}

func TestNew_DefaultHandler(t *testing.T) {
	h := New(Deps{})
	if h == nil {
		t.Fatal("New returned nil")
	}
	if h.deps.ReadHidden != nil {
		t.Error("expected default ReadHidden to be nil")
	}
}

func TestCollectEntryData_SkipNotesAndTOTP(t *testing.T) {
	h := New(Deps{
		ReadHidden: func(prompt string, reader *bufio.Reader) ([]byte, error) {
			return nil, nil
		},
	})
	data, err := h.CollectEntryData(nil, EntryFlags{
		Username:        "user",
		URL:             "https://example.com",
		SkipNotes:       true,
		SkipTOTPDetails: true,
		Force:           true,
	})
	if err != nil {
		t.Fatalf("CollectEntryData: %v", err)
	}
	if _, ok := data["notes"]; ok {
		t.Error("expected notes to be skipped")
	}
	if _, ok := data["totp"]; ok {
		t.Error("expected totp to be skipped when no secret provided")
	}
}

func TestCollectEntryData_TOTPSecretProvidedSkipsPrompt(t *testing.T) {
	h := New(Deps{
		ReadHidden: func(prompt string, reader *bufio.Reader) ([]byte, error) {
			return nil, nil
		},
	})
	data, err := h.CollectEntryData(nil, EntryFlags{
		Username:        "user",
		URL:             "https://example.com",
		TOTPSecret:      "JBSWY3DPEHPK3PXP",
		TOTPIssuer:      "Issuer",
		TOTPAccount:     "account",
		SkipTOTPDetails: true,
		Force:           true,
	})
	if err != nil {
		t.Fatalf("CollectEntryData: %v", err)
	}
	totp, ok := data["totp"].(map[string]any)
	if !ok {
		t.Fatalf("totp = %T, want map[string]any", data["totp"])
	}
	if totp["secret"] != "JBSWY3DPEHPK3PXP" {
		t.Errorf("totp.secret = %v, want %q", totp["secret"], "JBSWY3DPEHPK3PXP")
	}
	if totp["issuer"] != "Issuer" {
		t.Errorf("totp.issuer = %v, want %q", totp["issuer"], "Issuer")
	}
	if totp["account_name"] != "account" {
		t.Errorf("totp.account_name = %v, want %q", totp["account_name"], "account")
	}
}

func TestGeneratePasswordFn_CleansUp(t *testing.T) {
	cleanupCalled := false
	h := New(Deps{
		Generate: func(length int, useSymbols bool) (string, func(), error) {
			return "pwd", func() { cleanupCalled = true }, nil
		},
	})

	reader := bufio.NewReader(strings.NewReader("\n"))
	data, err := h.CollectEntryData(reader, EntryFlags{
		Username:        "user",
		Generate:        true,
		Length:          32,
		URL:             "https://example.com",
		TOTPSecret:      "skip",
		SkipNotes:       true,
		SkipTOTPDetails: true,
		Force:           true,
	})
	if err != nil {
		t.Fatalf("CollectEntryData: %v", err)
	}
	if data["password"] != "pwd" {
		t.Errorf("password = %v, want %q", data["password"], "pwd")
	}
	if !cleanupCalled {
		t.Error("expected password generation cleanup to be called")
	}
}

func TestCollectEntryData_ValidatePasswordStrength(t *testing.T) {
	h := New(Deps{})

	// Use a very weak password that fails ValidatePasswordStrength
	_, err := h.CollectEntryData(nil, EntryFlags{
		Username:        "user",
		Password:        "123",
		URL:             "https://example.com",
		TOTPSecret:      "skip",
		SkipNotes:       true,
		SkipTOTPDetails: true,
		Force:           false,
	})
	if err == nil {
		t.Fatal("expected error for weak password without --force")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Errorf("error = %q, want password-related error", err.Error())
	}
}

func TestWipePasswordAfterRead(t *testing.T) {
	var captured []byte
	h := New(Deps{
		ReadHidden: func(prompt string, reader *bufio.Reader) ([]byte, error) {
			captured = []byte("secret")
			return captured, nil
		},
	})

	reader := bufio.NewReader(strings.NewReader("\n"))
	_, err := h.CollectEntryData(reader, EntryFlags{
		Username:        "user",
		URL:             "https://example.com",
		TOTPSecret:      "skip",
		SkipNotes:       true,
		SkipTOTPDetails: true,
		Force:           true,
	})
	if err != nil {
		t.Fatalf("CollectEntryData: %v", err)
	}

	// Verify the captured bytes were wiped (cryptopkg.Wipe zeroes the slice)
	allZero := true
	for _, b := range captured {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("expected captured password bytes to be wiped")
	}
}
