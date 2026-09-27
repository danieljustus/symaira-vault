package main

import (
	"path/filepath"
	"testing"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/diff"
)

// This is a synthetic validator unit input, not CLI parity evidence.
func validatorInput() liveReport {
	report := liveReport{Head: "unit-test-head", Success: true, MutationRejected: true}
	for _, seed := range []string{"missing", "null", "empty", "unmanaged", "registered", "zero", "malformed"} {
		for _, mode := range []string{"text", "json", "yaml", "json-quiet", "yaml-quiet", "json-alias", "quiet", "extra"} {
			result := diff.Result{FilesBefore: []diff.ManifestEntry{{Path: "home", Type: "directory"}}, Files: []diff.ManifestEntry{{Path: "home", Type: "directory"}}}
			negative := seed == "malformed"
			if negative {
				result.ExitCode, result.Stderr = 1, []byte("error")
			} else if mode == "yaml" {
				result.Stdout = []byte("count: 0\ndevices: []\n")
			}
			report.Cases = append(report.Cases, liveCase{ID: seed + "/" + mode, Success: true, Negative: negative, Native: map[string]diff.Result{"go": result, "rust": result}})
		}
	}
	return report
}

func TestReportValidationRejectsFalsePass(t *testing.T) {
	if err := validateObservations(validatorInput(), "unit-test-head"); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*liveReport){
		"wrong-head":          func(r *liveReport) { r.Head = "other" },
		"failed-report":       func(r *liveReport) { r.Success = false },
		"no-mutation-control": func(r *liveReport) { r.MutationRejected = false },
		"empty":               func(r *liveReport) { r.Cases = nil },
		"missing":             func(r *liveReport) { r.Cases = r.Cases[1:] },
		"duplicate":           func(r *liveReport) { r.Cases[1] = r.Cases[0] },
		"failed-case":         func(r *liveReport) { r.Cases[0].Success = false },
		"no-observations":     func(r *liveReport) { r.Cases[0].Native = nil },
		"wrong-output": func(r *liveReport) {
			v := r.Cases[0].Native["rust"]
			v.Stdout = []byte("wrong")
			r.Cases[0].Native["rust"] = v
		},
		"mutation": func(r *liveReport) { v := r.Cases[0].Native["rust"]; v.Files = nil; r.Cases[0].Native["rust"] = v },
		"timeout":  func(r *liveReport) { v := r.Cases[0].Native["rust"]; v.TimedOut = true; r.Cases[0].Native["rust"] = v },
		"negative-success": func(r *liveReport) {
			for i := range r.Cases {
				if r.Cases[i].Negative {
					v := r.Cases[i].Native["rust"]
					v.ExitCode = 0
					r.Cases[i].Native["rust"] = v
					return
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := validatorInput()
			mutate(&r)
			if err := validateObservations(r, "unit-test-head"); err == nil {
				t.Fatal("accepted false PASS")
			}
		})
	}
	if err := validateReport(filepath.Join(t.TempDir(), "missing.json"), "unit-test-head"); err == nil {
		t.Fatal("accepted missing report")
	}
}
