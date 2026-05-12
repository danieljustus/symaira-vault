//go:build linux || freebsd || openbsd || netbsd

package secureui

import (
	"errors"
	"strings"
	"testing"
)

func TestLinuxGUIBackend_PrefersZenity(t *testing.T) {
	mr := &mockRunner{
		available: map[string]string{
			"zenity":  "/usr/bin/zenity",
			"kdialog": "/usr/bin/kdialog",
		},
		out: []byte("the-secret\n"),
	}
	b := newGUIBackend(mr)
	if b == nil {
		t.Fatal("newGUIBackend returned nil with zenity present")
	}
	value, err := b.prompt(PromptRequest{Path: "github", Field: "token", Description: "for CI", Hidden: true})
	if err != nil {
		t.Fatalf("prompt err = %v", err)
	}
	if value != "the-secret" {
		t.Errorf("value = %q, want the-secret", value)
	}
	if mr.calledName != "/usr/bin/zenity" {
		t.Errorf("called %q, want /usr/bin/zenity", mr.calledName)
	}
	joined := strings.Join(mr.calledArgs, " ")
	for _, want := range []string{"--entry", "--hide-text", "--text=", "--title="} {
		if !strings.Contains(joined, want) {
			t.Errorf("zenity args missing %q: %v", want, mr.calledArgs)
		}
	}
}

func TestLinuxGUIBackend_KDialogFallback(t *testing.T) {
	mr := &mockRunner{
		available: map[string]string{"kdialog": "/usr/bin/kdialog"},
		out:       []byte("the-secret\n"),
	}
	b := newGUIBackend(mr)
	if b == nil {
		t.Fatal("newGUIBackend returned nil with kdialog present")
	}
	_, err := b.prompt(PromptRequest{Path: "p", Field: "f", Hidden: true})
	if err != nil {
		t.Fatalf("prompt err = %v", err)
	}
	if mr.calledArgs[0] != "--password" {
		t.Errorf("kdialog hidden arg = %v, want --password", mr.calledArgs[0])
	}
}

func TestLinuxGUIBackend_Canceled(t *testing.T) {
	mr := &mockRunner{
		available: map[string]string{"zenity": "/usr/bin/zenity"},
		err:       errors.New("exit status 1"),
	}
	b := newGUIBackend(mr)
	_, err := b.prompt(PromptRequest{Path: "p", Field: "f"})
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("err = %v, want ErrCanceled", err)
	}
}

func TestLinuxGUIBackend_Unavailable(t *testing.T) {
	mr := &mockRunner{available: map[string]string{}}
	if b := newGUIBackend(mr); b != nil {
		t.Errorf("newGUIBackend should return nil when no tool present, got %T", b)
	}
}

func TestSanitizeOneLine(t *testing.T) {
	if got := sanitizeOneLine("a\nb\rc"); got != "a b c" {
		t.Errorf("sanitizeOneLine = %q, want %q", got, "a b c")
	}
}
