package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	cli "github.com/danieljustus/OpenPass/internal/cli"
)

func TestNewPrinter_ValidFormats(t *testing.T) {
	tests := []struct {
		format   string
		wantType string
	}{
		{"text", "cmd.TextPrinter"},
		{"json", "cmd.JSONPrinter"},
		{"yaml", "cmd.YAMLPrinter"},
		{"", "cmd.TextPrinter"},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			p, err := NewPrinter(tt.format)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			typeName := fmt.Sprintf("%T", p)
			if typeName != tt.wantType {
				t.Errorf("NewPrinter(%q) type = %s, want %s", tt.format, typeName, tt.wantType)
			}
		})
	}
}

func TestNewPrinter_InvalidFormat(t *testing.T) {
	_, err := NewPrinter("csv")
	if err == nil {
		t.Error("expected error for invalid format, got nil")
	}
	if !strings.Contains(err.Error(), "csv") {
		t.Errorf("error should mention invalid format: %v", err)
	}
}

func TestJSONPrinter_Print(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	quietMode = false

	p := JSONPrinter{}
	data := map[string]string{"key": "value"}
	if err := p.Print(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), `"key":"value"`) {
		t.Errorf("expected JSON output, got: %s", string(out))
	}
}

func TestYAMLPrinter_Print(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	quietMode = false

	p := YAMLPrinter{}
	data := map[string]string{"key": "value"}
	if err := p.Print(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), "key: value") {
		t.Errorf("expected YAML output, got: %s", string(out))
	}
}

func TestTextPrinter_Print(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	quietMode = false

	p := TextPrinter{}
	if err := p.Print("hello"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)
	if string(out) != "hello\n" {
		t.Errorf("expected 'hello\\n', got: %q", string(out))
	}
}

func TestPrintResult(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	quietMode = false
	cli.OutputFormat = "json"

	data := map[string]string{"test": "data"}
	if err := PrintResult(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), `"test":"data"`) {
		t.Errorf("expected JSON output, got: %s", string(out))
	}

	cli.OutputFormat = "text" // reset
}

func TestPrintJSON_MarshalError(t *testing.T) {
	stderr := captureStderr(func() {
		PrintJSON(make(chan int))
	})
	if !strings.Contains(stderr, "JSON encoding error") {
		t.Errorf("expected JSON encoding error in stderr, got: %s", stderr)
	}
}
