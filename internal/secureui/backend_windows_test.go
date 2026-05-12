//go:build windows

package secureui

import (
	"errors"
	"strings"
	"testing"
)

func TestPowershellBackend_HiddenUsesGetCredential(t *testing.T) {
	mr := &mockRunner{
		available: map[string]string{"powershell.exe": `C:\powershell.exe`},
		out:       []byte("the-secret\r\n"),
	}
	b := newGUIBackend(mr)
	if b == nil {
		t.Fatal("newGUIBackend returned nil")
	}
	value, err := b.prompt(PromptRequest{Path: "p", Field: "f", Hidden: true})
	if err != nil {
		t.Fatalf("prompt err = %v", err)
	}
	if value != "the-secret" {
		t.Errorf("value = %q, want the-secret", value)
	}
	joined := strings.Join(mr.calledArgs, " ")
	if !strings.Contains(joined, "Get-Credential") {
		t.Errorf("hidden mode should use Get-Credential; args = %v", mr.calledArgs)
	}
}

func TestPowershellBackend_NotHiddenUsesInputBox(t *testing.T) {
	mr := &mockRunner{
		available: map[string]string{"powershell.exe": `C:\powershell.exe`},
		out:       []byte("v\r\n"),
	}
	b := newGUIBackend(mr)
	_, _ = b.prompt(PromptRequest{Path: "p", Field: "f", Hidden: false})
	joined := strings.Join(mr.calledArgs, " ")
	if !strings.Contains(joined, "InputBox") {
		t.Errorf("non-hidden mode should use InputBox; args = %v", mr.calledArgs)
	}
}

func TestPowershellBackend_Canceled(t *testing.T) {
	mr := &mockRunner{
		available: map[string]string{"powershell.exe": `C:\powershell.exe`},
		err:       errors.New("exit status 1"),
	}
	b := newGUIBackend(mr)
	_, err := b.prompt(PromptRequest{Path: "p", Field: "f", Hidden: true})
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("err = %v, want ErrCanceled", err)
	}
}

func TestPsQuote(t *testing.T) {
	cases := map[string]string{
		"hello":         "'hello'",
		"it's":          "'it''s'",
		"none'here'too": "'none''here''too'",
	}
	for in, want := range cases {
		if got := psQuote(in); got != want {
			t.Errorf("psQuote(%q) = %q, want %q", in, got, want)
		}
	}
}
