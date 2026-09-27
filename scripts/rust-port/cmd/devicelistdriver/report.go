package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/diff"
	"gopkg.in/yaml.v3"
)

type liveReport struct {
	Head             string     `json:"head"`
	Success          bool       `json:"success"`
	MutationRejected bool       `json:"mutation_rejected"`
	Cases            []liveCase `json:"cases"`
}

type liveCase struct {
	ID       string                 `json:"id"`
	Success  bool                   `json:"success"`
	Negative bool                   `json:"negative"`
	Native   map[string]diff.Result `json:"native"`
}

func validateReport(path, head string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-selected report path
	if err != nil {
		return fmt.Errorf("read required report: %w", err)
	}
	var report liveReport
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("decode report: %w", err)
	}
	return validateObservations(report, head)
}

func validateObservations(report liveReport, head string) error {
	if head == "" || report.Head != head || !report.Success || !report.MutationRejected {
		return fmt.Errorf("report provenance, success, or mutation control is invalid")
	}
	expected := make(map[string]bool)
	for _, seed := range []string{"missing", "null", "empty", "unmanaged", "registered", "zero", "malformed"} {
		for _, mode := range []string{"text", "json", "yaml", "json-quiet", "yaml-quiet", "json-alias", "quiet", "extra"} {
			expected[seed+"/"+mode] = seed == "malformed"
		}
	}
	if len(report.Cases) != len(expected) {
		return fmt.Errorf("report has %d cases, want %d", len(report.Cases), len(expected))
	}
	for _, observed := range report.Cases {
		negative, exists := expected[observed.ID]
		if !exists || !observed.Success || observed.Negative != negative {
			return fmt.Errorf("invalid, duplicate or failed case %q", observed.ID)
		}
		delete(expected, observed.ID)
		goResult, goOK := observed.Native["go"]
		rustResult, rustOK := observed.Native["rust"]
		if !goOK || !rustOK {
			return fmt.Errorf("missing native observations: %s", observed.ID)
		}
		for _, result := range []diff.Result{goResult, rustResult} {
			if result.TimedOut || result.Signal != "" || len(result.FilesBefore) == 0 || !reflect.DeepEqual(result.FilesBefore, result.Files) {
				return fmt.Errorf("timeout, signal or changed sandbox: %s", observed.ID)
			}
			if negative && (result.ExitCode == 0 || len(result.Stdout) != 0 || len(result.Stderr) == 0) {
				return fmt.Errorf("invalid negative result: %s", observed.ID)
			}
			if !negative && result.ExitCode != 0 {
				return fmt.Errorf("failed positive case: %s", observed.ID)
			}
		}
		if !negative {
			if strings.HasSuffix(observed.ID, "/yaml") {
				// yaml.v3 and serde_yaml_ng indent sequences and quote scalars differently;
				// compare parsed values while preserving field and scalar-type parity.
				var goValue, rustValue any
				if err := yaml.Unmarshal(goResult.Stdout, &goValue); err != nil {
					return fmt.Errorf("parse Go YAML %s: %w", observed.ID, err)
				}
				if err := yaml.Unmarshal(rustResult.Stdout, &rustValue); err != nil {
					return fmt.Errorf("parse Rust YAML %s: %w", observed.ID, err)
				}
				if !reflect.DeepEqual(goValue, rustValue) {
					return fmt.Errorf("YAML values differ: %s", observed.ID)
				}
			} else if err := diff.Compare(diff.Case{ID: observed.ID}, goResult, rustResult); err != nil {
				return fmt.Errorf("report mismatch %s: %w", observed.ID, err)
			}
		}
	}
	return nil
}
