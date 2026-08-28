package output

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestNewPrinter_Text(t *testing.T) {
	h := New(Deps{})
	printer, err := h.NewPrinter("text")
	if err != nil {
		t.Fatalf("NewPrinter: %v", err)
	}
	if printer == nil {
		t.Fatal("expected non-nil printer")
	}
}

func TestNewPrinter_JSON(t *testing.T) {
	h := New(Deps{})
	printer, err := h.NewPrinter("json")
	if err != nil {
		t.Fatalf("NewPrinter: %v", err)
	}
	if printer == nil {
		t.Fatal("expected non-nil printer")
	}
}

func TestNewPrinter_YAML(t *testing.T) {
	h := New(Deps{})
	printer, err := h.NewPrinter("yaml")
	if err != nil {
		t.Fatalf("NewPrinter: %v", err)
	}
	if printer == nil {
		t.Fatal("expected non-nil printer")
	}
}

func TestNewPrinter_InvalidFormat(t *testing.T) {
	h := New(Deps{})
	_, err := h.NewPrinter("xml")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !strings.Contains(err.Error(), "unknown output format") {
		t.Errorf("error = %q, want 'unknown output format'", err.Error())
	}
}

func TestNewPrinter_EmptyFormatDefaultsToText(t *testing.T) {
	h := New(Deps{})
	printer, err := h.NewPrinter("")
	if err != nil {
		t.Fatalf("NewPrinter: %v", err)
	}
	if printer == nil {
		t.Fatal("expected non-nil printer for empty format")
	}
}

func TestPrintResult_QuietMode(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = oldStdout })

	h := New(Deps{
		Quiet: func() bool { return true },
	})
	err = h.PrintResult("hello")
	if err != nil {
		t.Fatalf("PrintResult: %v", err)
	}

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	if buf.Len() != 0 {
		t.Errorf("expected no output in quiet mode, got %q", buf.String())
	}
}

func TestPrintResult_TextMode(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = oldStdout })

	h := New(Deps{
		Quiet: func() bool { return false },
	})
	err = h.PrintResult("hello world")
	if err != nil {
		t.Fatalf("PrintResult: %v", err)
	}

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	got := strings.TrimSpace(buf.String())
	if got != "hello world" {
		t.Errorf("PrintResult = %q, want %q", got, "hello world")
	}
}

func TestPrintResult_JSONMode(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = oldStdout })

	h := New(Deps{
		Quiet:  func() bool { return false },
		Format: func() string { return "json" },
	})
	err = h.PrintResult(map[string]string{"key": "value"})
	if err != nil {
		t.Fatalf("PrintResult: %v", err)
	}

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	if !strings.Contains(buf.String(), `"key"`) || !strings.Contains(buf.String(), `"value"`) {
		t.Errorf("PrintResult JSON missing expected content, got %q", buf.String())
	}
}

func TestPrintJSON_QuietMode(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = oldStdout })

	h := New(Deps{
		Quiet: func() bool { return true },
	})
	h.PrintJSON(map[string]string{"key": "value"})

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	if buf.Len() != 0 {
		t.Errorf("expected no output in quiet mode, got %q", buf.String())
	}
}

func TestPrintJSON_NotQuiet(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = oldStdout })

	h := New(Deps{
		Quiet: func() bool { return false },
	})
	h.PrintJSON(map[string]string{"key": "value"})

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	if !strings.Contains(buf.String(), `"key"`) || !strings.Contains(buf.String(), `"value"`) {
		t.Errorf("PrintJSON missing expected content, got %q", buf.String())
	}
}

func TestWantJSONOutput_FormatJSON(t *testing.T) {
	h := New(Deps{
		Format: func() string { return "json" },
	})
	if !h.WantJSONOutput(false) {
		t.Error("expected true when format is json")
	}
}

func TestWantJSONOutput_FlagJSON(t *testing.T) {
	h := New(Deps{
		Format: func() string { return "text" },
	})
	if !h.WantJSONOutput(true) {
		t.Error("expected true when flagJSON is true")
	}
}

func TestWantJSONOutput_TextFormatNoFlag(t *testing.T) {
	h := New(Deps{
		Format: func() string { return "text" },
	})
	if h.WantJSONOutput(false) {
		t.Error("expected false when format is text and flagJSON is false")
	}
}

func TestWantJSONOutput_NilFormatDeps(t *testing.T) {
	h := New(Deps{})
	if h.WantJSONOutput(false) {
		t.Error("expected false with nil Format and flagJSON false")
	}
	if !h.WantJSONOutput(true) {
		t.Error("expected true with nil Format and flagJSON true")
	}
}

func TestPrintResult_YAMLMode(t *testing.T) {
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = oldStdout })

	h := New(Deps{
		Quiet:  func() bool { return false },
		Format: func() string { return "yaml" },
	})
	err = h.PrintResult(map[string]string{"key": "value"})
	if err != nil {
		t.Fatalf("PrintResult: %v", err)
	}

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	if !strings.Contains(buf.String(), "key:") || !strings.Contains(buf.String(), "value") {
		t.Errorf("PrintResult YAML missing expected content, got %q", buf.String())
	}
}
