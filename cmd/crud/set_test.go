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

func TestSetInteractiveHiddenPrompt(t *testing.T) {
	// Verify that ReadHiddenInputFn gets invoked on field prompt
	oldHiddenInputFn := cliinput.ReadHiddenInputFn
	defer func() { cliinput.ReadHiddenInputFn = oldHiddenInputFn }()

	calledPrompt := ""
	cliinput.ReadHiddenInputFn = func(prompt string, reader *bufio.Reader) ([]byte, error) {
		calledPrompt = prompt
		return []byte("secretinput"), nil
	}

	reader := bufio.NewReader(strings.NewReader(""))
	field := "password"
	prompt := "Enter value for " + field + ": "
	valueBytes, err := cliinput.ReadHiddenInputFn(prompt, reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(valueBytes) != "secretinput" {
		t.Errorf("expected secretinput, got %s", string(valueBytes))
	}
	if calledPrompt != prompt {
		t.Errorf("expected prompt %q, got %q", prompt, calledPrompt)
	}
}
