package envutil

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestGetenv(t *testing.T) {
	t.Run("primary set", func(t *testing.T) {
		t.Setenv("SYMVAULT_TEST", "new")
		t.Setenv("OPENPASS_TEST", "old")
		if got := Getenv("SYMVAULT_TEST", "OPENPASS_TEST"); got != "new" {
			t.Errorf("Getenv() = %q, want %q", got, "new")
		}
	})

	t.Run("only legacy set", func(t *testing.T) {
		resetDeprecationWarning()
		os.Unsetenv("SYMVAULT_TEST")
		t.Setenv("OPENPASS_TEST", "old")
		_ = captureStderr(func() {
			if got := Getenv("SYMVAULT_TEST", "OPENPASS_TEST"); got != "old" {
				t.Errorf("Getenv() = %q, want %q", got, "old")
			}
		})
	})

	t.Run("neither set", func(t *testing.T) {
		os.Unsetenv("SYMVAULT_TEST")
		os.Unsetenv("OPENPASS_TEST")
		if got := Getenv("SYMVAULT_TEST", "OPENPASS_TEST"); got != "" {
			t.Errorf("Getenv() = %q, want empty", got)
		}
	})

	t.Run("primary empty legacy set", func(t *testing.T) {
		resetDeprecationWarning()
		t.Setenv("SYMVAULT_TEST", "")
		t.Setenv("OPENPASS_TEST", "old")
		_ = captureStderr(func() {
			if got := Getenv("SYMVAULT_TEST", "OPENPASS_TEST"); got != "old" {
				t.Errorf("Getenv() = %q, want %q", got, "old")
			}
		})
	})
}

func TestUnsetenv(t *testing.T) {
	t.Run("unsets both", func(t *testing.T) {
		t.Setenv("SYMVAULT_TEST", "new")
		t.Setenv("OPENPASS_TEST", "old")
		Unsetenv("SYMVAULT_TEST", "OPENPASS_TEST")
		if os.Getenv("SYMVAULT_TEST") != "" {
			t.Error("SYMVAULT_TEST should be unset")
		}
		if os.Getenv("OPENPASS_TEST") != "" {
			t.Error("OPENPASS_TEST should be unset")
		}
	})
}

func captureStderr(fn func()) string {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	stderr := os.Stderr
	os.Stderr = w
	defer func() {
		os.Stderr = stderr
		w.Close()
		r.Close()
	}()

	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		io.Copy(&buf, r)
		close(done)
	}()

	fn()
	w.Close()
	<-done
	return buf.String()
}

func TestGetenvDeprecationWarning(t *testing.T) {
	t.Run("warns once when legacy var is consumed", func(t *testing.T) {
		resetDeprecationWarning()
		os.Unsetenv("SYMVAULT_DEPTEST")
		t.Setenv("OPENPASS_DEPTEST", "legacy-value")

		out1 := captureStderr(func() {
			got := Getenv("SYMVAULT_DEPTEST", "OPENPASS_DEPTEST")
			if got != "legacy-value" {
				t.Fatalf("Getenv() = %q, want %q", got, "legacy-value")
			}
		})
		if !strings.Contains(out1, "WARNING:") {
			t.Error("expected deprecation warning on stderr")
		}
		if !strings.Contains(out1, "OPENPASS_DEPTEST") {
			t.Error("expected legacy var name in warning")
		}
		if !strings.Contains(out1, "2026-05-26") {
			t.Error("expected removal timeline in warning")
		}

		out2 := captureStderr(func() {
			got := Getenv("SYMVAULT_DEPTEST", "OPENPASS_DEPTEST")
			if got != "legacy-value" {
				t.Fatalf("Getenv() = %q, want %q", got, "legacy-value")
			}
		})
		if out2 != "" {
			t.Error("deprecation warning printed more than once")
		}
	})

	t.Run("no warning when primary var is used", func(t *testing.T) {
		resetDeprecationWarning()
		t.Setenv("SYMVAULT_NOWARN", "primary-value")
		os.Unsetenv("OPENPASS_NOWARN")

		out := captureStderr(func() {
			got := Getenv("SYMVAULT_NOWARN", "OPENPASS_NOWARN")
			if got != "primary-value" {
				t.Fatalf("Getenv() = %q, want %q", got, "primary-value")
			}
		})
		if out != "" {
			t.Error("unexpected output on stderr when primary var is used")
		}
	})
}
