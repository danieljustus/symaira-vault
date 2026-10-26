package config

import (
	"path/filepath"
	"testing"
)

// TestAuditMaxBackupsRoundTrip drives the real LoadFromBytes -> SaveTo ->
// Load chain (#1430). An explicit zero ("retain no rotated backups", the same
// value SYMVAULT_AUDIT_MAX_BACKUPS=0 already accepts) must survive a save
// instead of silently reverting to the default of five, while an absent field
// keeps that documented default.
func TestAuditMaxBackupsRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want int
	}{
		{name: "omitted", yaml: "audit: {}\n", want: 5},
		{name: "zero", yaml: "audit:\n  maxBackups: 0\n", want: 0},
		{name: "positive", yaml: "audit:\n  maxBackups: 7\n", want: 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadFromBytes([]byte("vault: {}\n" + tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Audit.MaxBackups; got != tc.want {
				t.Fatalf("LoadFromBytes: maxBackups = %d, want %d", got, tc.want)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := cfg.SaveTo(path); err != nil {
				t.Fatal(err)
			}
			loaded, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := loaded.Audit.MaxBackups; got != tc.want {
				t.Fatalf("SaveTo -> Load: maxBackups = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestAuditMaxAgeDaysRoundTrip (#1442): an explicit maxAgeDays: 0 ("no
// age-based rotation or deletion") must survive a save instead of reverting
// to the default of 30 days.
func TestAuditMaxAgeDaysRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want int
	}{
		{name: "omitted", yaml: "audit: {}\n", want: 30},
		{name: "zero", yaml: "audit:\n  maxAgeDays: 0\n", want: 0},
		{name: "positive", yaml: "audit:\n  maxAgeDays: 90\n", want: 90},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadFromBytes([]byte("vault: {}\n" + tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Audit.MaxAgeDays; got != tc.want {
				t.Fatalf("LoadFromBytes: maxAgeDays = %d, want %d", got, tc.want)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := cfg.SaveTo(path); err != nil {
				t.Fatal(err)
			}
			loaded, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := loaded.Audit.MaxAgeDays; got != tc.want {
				t.Fatalf("SaveTo -> Load: maxAgeDays = %d, want %d", got, tc.want)
			}
		})
	}
}
