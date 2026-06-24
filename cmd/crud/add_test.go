package crud

import (
	"io"
	"os"
	"testing"
)

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
