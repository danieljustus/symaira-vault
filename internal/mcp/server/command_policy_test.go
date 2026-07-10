package server

import (
	"math"
	"strings"
	"testing"
)

func TestParseCommandTimeoutSeconds(t *testing.T) {
	tests := []struct {
		name    string
		raw     any
		want    int
		wantErr string
	}{
		{name: "missing uses default", raw: nil, want: 30},
		{name: "minimum", raw: float64(1), want: 1},
		{name: "maximum", raw: float64(300), want: 300},
		{name: "numeric string", raw: "45", want: 45},
		{name: "zero", raw: float64(0), wantErr: "between 1 and 300"},
		{name: "negative", raw: float64(-1), wantErr: "between 1 and 300"},
		{name: "fractional", raw: float64(1.5), wantErr: "whole number"},
		{name: "nan", raw: math.NaN(), wantErr: "finite"},
		{name: "infinity", raw: math.Inf(1), wantErr: "finite"},
		{name: "too large", raw: float64(301), wantErr: "between 1 and 300"},
		{name: "invalid string", raw: "not-a-number", wantErr: "numeric"},
		{name: "unsupported type", raw: true, wantErr: "numeric"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCommandTimeoutSeconds(tt.raw)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("parseCommandTimeoutSeconds() error = %v", err)
				}
				if got != tt.want {
					t.Fatalf("parseCommandTimeoutSeconds() = %d, want %d", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatal("parseCommandTimeoutSeconds() expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
