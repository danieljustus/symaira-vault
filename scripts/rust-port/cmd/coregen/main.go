// Command coregen freezes pure Go domain contracts for the staged Rust port.
package main

import (
	"bytes"
	"encoding/json"
	stderrors "errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	corekitexitcodes "github.com/danieljustus/symaira-corekit/exitcodes"

	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
)

type fixture struct {
	SchemaVersion   int              `json:"schema_version"`
	Oracle          oracle           `json:"oracle"`
	ExitCodes       []namedInt       `json:"exit_codes"`
	ErrorKinds      []namedInt       `json:"error_kinds"`
	Cases           []errorCase      `json:"cases"`
	ExitResolutions []exitResolution `json:"exit_resolutions"`
	CorekitMappings []codeMapping    `json:"corekit_mappings"`
	CorekitReverse  []codeMapping    `json:"corekit_reverse_mappings"`
}

type oracle struct {
	Commit  string `json:"commit"`
	Release string `json:"release"`
}

type namedInt struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

type errorCase struct {
	Name              string `json:"name"`
	Code              int    `json:"code"`
	Kind              int    `json:"kind"`
	Message           string `json:"message"`
	CauseKind         string `json:"cause_kind,omitempty"`
	CauseMessage      string `json:"cause_message,omitempty"`
	Hint              string `json:"hint,omitempty"`
	Error             string `json:"error"`
	Formatted         string `json:"formatted"`
	EffectiveExitCode int    `json:"effective_exit_code"`
	IsNotFound        bool   `json:"is_not_found"`
	IsWriteError      bool   `json:"is_write_error"`
}

type exitResolution struct {
	Name string `json:"name"`
	Code int    `json:"code"`
}

type codeMapping struct {
	Vault   int `json:"vault"`
	Corekit int `json:"corekit"`
}

func main() {
	output := flag.String("output", "testdata/port/core/error-contract.json", "fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit for a new fixture")
	release := flag.String("oracle-release", "", "Go oracle release for a new fixture")
	flag.Parse()

	meta := oracle{Commit: *commit, Release: *release}
	if *check {
		existing, err := readFixture(*output)
		if err != nil {
			fatal("read existing fixture: %v", err)
		}
		meta = existing.Oracle
	}
	if meta.Commit == "" || meta.Release == "" {
		fatal("--oracle-commit and --oracle-release are required when generating a fixture")
	}

	generated := buildFixture(meta)
	content, err := marshalFixture(generated)
	if err != nil {
		fatal("encode fixture: %v", err)
	}
	if *check {
		existing, err := os.ReadFile(*output) // #nosec G304 -- explicit operator-selected fixture path
		if err != nil {
			fatal("read fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("error-contract fixture is stale; run make core-fixtures-generate")
		}
		fmt.Printf("PASS error-contract fixture (%d cases)\n", len(generated.Cases))
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(*output, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%d cases)\n", *output, len(generated.Cases))
}

func buildFixture(meta oracle) fixture {
	readCause := stderrors.New("disk read")
	writeCause := stderrors.New("disk full")
	cases := []namedError{
		{"new", errorspkg.NewCLIError(errorspkg.ExitLocked, "vault locked", stderrors.New("passphrase missing"))},
		{"not_found", errorspkg.NotFound("entry %q not found", "github")},
		{"field_not_found", errorspkg.Wrap(errorspkg.ExitNotFound, errorspkg.ErrFieldNotFound, nil, "field %q missing", "token")},
		{"read_failed", errorspkg.ReadFailed(readCause, "cannot read entry")},
		{"read_failed_nil", errorspkg.ReadFailed(nil, "cannot read entry without cause")},
		{"write_failed", errorspkg.WriteFailed(writeCause, "cannot write entry")},
		{"write_failed_nil", errorspkg.WriteFailed(nil, "cannot write entry without cause")},
		{"not_initialized", errorspkg.NotInitialized("vault not initialized at %s", "/vault")},
		{"new_vault_not_initialized", errorspkg.NewVaultNotInitialized()},
		{"locked", errorspkg.Locked("session expired")},
		{"permission_denied", errorspkg.PermissionDenied("agent cannot write")},
		{"invalid_input", errorspkg.InvalidInput("length must be positive")},
		{"config_error", errorspkg.ConfigError("config value is invalid")},
		{"internal", errorspkg.Internal("unexpected state")},
		{"already_exists", errorspkg.AlreadyExists("entry already exists")},
		{"custom_hint", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "operation failed", nil).WithHint("Run symvault doctor")},
		{"sentinel_priority", errorspkg.NewCLIError(errorspkg.ExitGeneralError, "locked wrapper", fmt.Errorf("outer: %w", errorspkg.ErrVaultLocked))},
	}

	resultCases := make([]errorCase, 0, len(cases))
	for _, item := range cases {
		resultCases = append(resultCases, describeError(item.Name, item.Error))
	}

	return fixture{
		SchemaVersion: 1,
		Oracle:        meta,
		ExitCodes: []namedInt{
			{"success", int(errorspkg.ExitSuccess)},
			{"general", int(errorspkg.ExitGeneralError)},
			{"not_found", int(errorspkg.ExitNotFound)},
			{"not_initialized", int(errorspkg.ExitNotInitialized)},
			{"locked", int(errorspkg.ExitLocked)},
			{"permission_denied", int(errorspkg.ExitPermissionDenied)},
			{"config", int(errorspkg.ExitConfigError)},
			{"doctor_warn", int(errorspkg.ExitDoctorWarn)},
			{"doctor_fail", int(errorspkg.ExitDoctorFail)},
			{"invalid_input", int(errorspkg.ExitInvalidInput)},
			{"usage", int(errorspkg.ExitUsage)},
			{"update_available", int(errorspkg.ExitUpdateAvailable)},
		},
		ErrorKinds: []namedInt{
			{"none", int(errorspkg.ErrKindNone)},
			{"not_found", int(errorspkg.ErrNotFound)},
			{"field_not_found", int(errorspkg.ErrFieldNotFound)},
			{"read_failed", int(errorspkg.ErrReadFailed)},
			{"write_failed", int(errorspkg.ErrWriteFailed)},
		},
		Cases: resultCases,
		ExitResolutions: []exitResolution{
			{"nil", int(errorspkg.ExitCodeFromError(nil))},
			{"plain", int(errorspkg.ExitCodeFromError(stderrors.New("plain")))},
			{"entry_not_found", int(errorspkg.ExitCodeFromError(fmt.Errorf("outer: %w", errorspkg.ErrEntryNotFound)))},
			{"vault_not_initialized", int(errorspkg.ExitCodeFromError(fmt.Errorf("outer: %w", errorspkg.ErrVaultNotInitialized)))},
			{"vault_locked", int(errorspkg.ExitCodeFromError(fmt.Errorf("outer: %w", errorspkg.ErrVaultLocked)))},
			{"permission_denied", int(errorspkg.ExitCodeFromError(fmt.Errorf("outer: %w", errorspkg.ErrPermissionDenied)))},
		},
		CorekitMappings: corekitMappings(),
		CorekitReverse:  corekitReverseMappings(),
	}
}

type namedError struct {
	Name  string
	Error *errorspkg.CLIError
}

func describeError(name string, value *errorspkg.CLIError) errorCase {
	return errorCase{
		Name:              name,
		Code:              int(value.Code),
		Kind:              int(value.Kind),
		Message:           value.Message,
		CauseKind:         causeKind(value.Cause),
		CauseMessage:      causeMessage(value.Cause),
		Hint:              value.Hint,
		Error:             value.Error(),
		Formatted:         errorspkg.FormatCLIError(value),
		EffectiveExitCode: int(errorspkg.ExitCodeFromError(value)),
		IsNotFound:        errorspkg.IsNotFound(value),
		IsWriteError:      errorspkg.IsWriteError(value),
	}
}

func causeKind(err error) string {
	switch {
	case stderrors.Is(err, errorspkg.ErrEntryNotFound):
		return "entry_not_found"
	case stderrors.Is(err, errorspkg.ErrVaultNotInitialized):
		return "vault_not_initialized"
	case stderrors.Is(err, errorspkg.ErrVaultLocked):
		return "vault_locked"
	case stderrors.Is(err, errorspkg.ErrPermissionDenied):
		return "permission_denied"
	case err != nil:
		return "other"
	default:
		return ""
	}
}

func causeMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func corekitMappings() []codeMapping {
	codes := []errorspkg.ExitCode{
		errorspkg.ExitSuccess,
		errorspkg.ExitGeneralError,
		errorspkg.ExitNotFound,
		errorspkg.ExitNotInitialized,
		errorspkg.ExitLocked,
		errorspkg.ExitPermissionDenied,
		errorspkg.ExitConfigError,
		errorspkg.ExitDoctorWarn,
		errorspkg.ExitDoctorFail,
		errorspkg.ExitInvalidInput,
		errorspkg.ExitUpdateAvailable,
	}
	result := make([]codeMapping, 0, len(codes))
	for _, code := range codes {
		result = append(result, codeMapping{Vault: int(code), Corekit: int(errorspkg.ToCorekitExitCode(code))})
	}
	return result
}

func corekitReverseMappings() []codeMapping {
	codes := []corekitexitcodes.ExitCode{0, 1, 2, 4, 5, 9, 42}
	result := make([]codeMapping, 0, len(codes))
	for _, code := range codes {
		result = append(result, codeMapping{
			Vault:   int(errorspkg.FromCorekitExitCode(code)),
			Corekit: int(code),
		})
	}
	return result
}

func marshalFixture(value fixture) ([]byte, error) {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}

func readFixture(path string) (fixture, error) {
	content, err := os.ReadFile(path) // #nosec G304 -- explicit operator-selected fixture path
	if err != nil {
		return fixture{}, err
	}
	var value fixture
	if err := json.Unmarshal(content, &value); err != nil {
		return fixture{}, err
	}
	if value.SchemaVersion != 1 {
		return fixture{}, fmt.Errorf("unsupported schema_version %d", value.SchemaVersion)
	}
	return value, nil
}

func fatal(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}
