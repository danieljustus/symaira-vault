//go:build darwin

package secureui

import (
	"errors"
	"strings"
	"testing"
)

func TestOsaQuote(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`hello`, `"hello"`},
		{`he said "hi"`, `"he said \"hi\""`},
		{`back\slash`, `"back\\slash"`},
		{"line1\nline2", `"line1\nline2"`},
	}
	for _, tc := range cases {
		if got := osaQuote(tc.in); got != tc.want {
			t.Errorf("osaQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestOsascriptBackend_BuildsScript(t *testing.T) {
	mr := &mockRunner{
		available: map[string]string{"osascript": "/usr/bin/osascript"},
		out:       []byte("the-secret\n"),
	}
	b := newGUIBackend(mr)
	if b == nil {
		t.Fatal("newGUIBackend returned nil with osascript present")
	}
	value, err := b.prompt(PromptRequest{
		Title:       "Symaira Vault",
		Path:        "github",
		Field:       "token",
		Description: "for CI",
		Hidden:      true,
	})
	if err != nil {
		t.Fatalf("prompt err = %v", err)
	}
	if value != "the-secret" {
		t.Errorf("value = %q, want the-secret", value)
	}
	if mr.calledName != "osascript" {
		t.Errorf("called %q, want osascript", mr.calledName)
	}
	if len(mr.calledArgs) != 2 || mr.calledArgs[0] != "-e" {
		t.Fatalf("args = %v, want [-e SCRIPT]", mr.calledArgs)
	}
	script := mr.calledArgs[1]
	for _, want := range []string{"display dialog", "with hidden answer", "github", "token", "for CI", "Symaira Vault"} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q in:\n%s", want, script)
		}
	}
}

func TestOsascriptBackend_NotHidden(t *testing.T) {
	mr := &mockRunner{
		available: map[string]string{"osascript": "/usr/bin/osascript"},
		out:       []byte("v\n"),
	}
	b := newGUIBackend(mr)
	_, _ = b.prompt(PromptRequest{Path: "p", Field: "f", Hidden: false})
	if strings.Contains(mr.calledArgs[1], "with hidden answer") {
		t.Error("script should not include 'with hidden answer' when Hidden=false")
	}
}

func TestOsascriptBackend_UserCanceled(t *testing.T) {
	mr := &mockRunner{
		available: map[string]string{"osascript": "/usr/bin/osascript"},
		err:       errors.New("exit status 1"),
	}
	b := newGUIBackend(mr)
	_, err := b.prompt(PromptRequest{Path: "p", Field: "f"})
	// With the new implementation, a plain "exit status 1" error without stderr
	// content is treated as cancellation for backward compatibility.
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("err = %v, want ErrCanceled", err)
	}
}

func TestOsascriptBackend_Unavailable(t *testing.T) {
	mr := &mockRunner{available: map[string]string{}}
	if b := newGUIBackend(mr); b != nil {
		t.Errorf("newGUIBackend should return nil when osascript missing, got %T", b)
	}
}
