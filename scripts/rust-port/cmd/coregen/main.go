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
	maskingpkg "github.com/danieljustus/symaira-vault/internal/mcp/masking"
	redactpkg "github.com/danieljustus/symaira-vault/internal/redact"
	templatepkg "github.com/danieljustus/symaira-vault/internal/template"
	taintpkg "github.com/danieljustus/symaira-vault/internal/vault/taint"
)

type oracle struct {
	Commit  string `json:"commit"`
	Release string `json:"release"`
}

type headerOnly struct {
	SchemaVersion int    `json:"schema_version"`
	Oracle        oracle `json:"oracle"`
}

// ---------------------------------------------------------------------------
// Error taxonomy fixture
// ---------------------------------------------------------------------------

type errorFixture struct {
	SchemaVersion   int              `json:"schema_version"`
	Oracle          oracle           `json:"oracle"`
	ExitCodes       []namedInt       `json:"exit_codes"`
	ErrorKinds      []namedInt       `json:"error_kinds"`
	Cases           []errorCase      `json:"cases"`
	ExitResolutions []exitResolution `json:"exit_resolutions"`
	CorekitMappings []codeMapping    `json:"corekit_mappings"`
	CorekitReverse  []codeMapping    `json:"corekit_reverse_mappings"`
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

type namedError struct {
	Name  string
	Error *errorspkg.CLIError
}

func buildErrorFixture(meta oracle) errorFixture {
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

	return errorFixture{
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

// ---------------------------------------------------------------------------
// Secret reference fixture
// ---------------------------------------------------------------------------

type secretRefFixture struct {
	SchemaVersion    int               `json:"schema_version"`
	Oracle           oracle            `json:"oracle"`
	ParseRefCases    []parseRefCase    `json:"parse_ref_cases"`
	ParseHandleCases []parseHandleCase `json:"parse_handle_cases"`
}

type parseRefCase struct {
	Name         string `json:"name"`
	Input        string `json:"input"`
	Valid        bool   `json:"valid"`
	Path         string `json:"path"`
	Field        string `json:"field"`
	ErrorMessage string `json:"error_message,omitempty"`
}

type parseHandleCase struct {
	Name       string `json:"name"`
	Input      string `json:"input"`
	Valid      bool   `json:"valid"`
	Path       string `json:"path"`
	Field      string `json:"field"`
	StringRepr string `json:"string_repr,omitempty"`
}

func buildSecretRefFixture(meta oracle) secretRefFixture {
	refInputs := []struct {
		name  string
		input string
	}{
		{"op_full_path", "op://work/aws/password"},
		{"op_simple_path", "op://github/token"},
		{"op_nested_path", "op://work/team/aws/password"},
		{"op_two_segments", "op://work/aws"},
		{"op_deeply_nested", "op://org/team/project/service/api/key"},
		{"op_trailing_slash", "op://work/aws/"},
		{"op_single_segment", "op://work"},
		{"op_empty_rest", "op://"},
		{"op_slash_only", "op:///"},
		{"op_leading_slash", "op:///github"},
		{"dot_notation_nested", "work/aws.password"},
		{"dot_notation_simple", "github.token"},
		{"dot_notation_deep", "work/team/aws.password"},
		{"dot_in_field", "work/aws.api.key"},
		{"dot_minimal", "a.b"},
		{"dot_missing_field", "work/aws"},
		{"dot_leading_dot", ".password"},
		{"dot_trailing_dot", "work/aws."},
		{"empty", ""},
		{"plain_word", "notavalidref"},
		{"field_only", "password"},
		{"invalid_scheme", "://path/field"},
		{"missing_slashes", "op:path/field"},
	}

	refCases := make([]parseRefCase, 0, len(refInputs))
	for _, tc := range refInputs {
		parsed, err := templatepkg.ParseRef(tc.input)
		c := parseRefCase{
			Name:  tc.name,
			Input: tc.input,
			Valid: err == nil,
		}
		if err == nil {
			c.Path = parsed.Path
			c.Field = parsed.Field
		} else {
			c.ErrorMessage = err.Error()
		}
		refCases = append(refCases, c)
	}

	handleInputs := []struct {
		name  string
		input string
	}{
		{"handle_full_path", "op://work/aws/password"},
		{"handle_simple_path", "op://github/token"},
		{"handle_nested_path", "op://work/team/aws/password"},
		{"handle_two_segments", "op://work/aws"},
		{"handle_path_only", "op://work"},
		{"handle_personal_notes", "op://personal/notes"},
		{"handle_trailing_slash", "op://personal/notes/"},
		{"handle_single", "op://single"},
		{"handle_empty", ""},
		{"handle_prefix_only", "op://"},
		{"handle_prefix_slash", "op:///"},
		{"handle_not_handle", "not-a-handle"},
		{"handle_invalid_scheme", "://path/field"},
		{"handle_dot_notation", "work/aws.password"},
	}

	handleCases := make([]parseHandleCase, 0, len(handleInputs))
	for _, tc := range handleInputs {
		h, ok := taintpkg.ParseSecretHandle(tc.input)
		c := parseHandleCase{
			Name:  tc.name,
			Input: tc.input,
			Valid: ok,
		}
		if ok {
			c.Path = h.Path
			c.Field = h.Field
			c.StringRepr = h.String()
		}
		handleCases = append(handleCases, c)
	}

	return secretRefFixture{
		SchemaVersion:    1,
		Oracle:           meta,
		ParseRefCases:    refCases,
		ParseHandleCases: handleCases,
	}
}

// ---------------------------------------------------------------------------
// Secret redaction fixture
// ---------------------------------------------------------------------------

type redactFixture struct {
	SchemaVersion   int              `json:"schema_version"`
	Oracle          oracle           `json:"oracle"`
	Constants       redactConstants  `json:"constants"`
	ExactValueCases []exactValueCase `json:"exact_value_cases"`
	EntropyCases    []entropyCase    `json:"entropy_cases"`
	ScannerCases    []scannerCase    `json:"scanner_cases"`
	TruthyCases     []truthyCase     `json:"truthy_cases"`
}

type redactConstants struct {
	Marker                string  `json:"marker"`
	BlockedText           string  `json:"blocked_text"`
	MinExactValueLen      int     `json:"min_exact_value_len"`
	MaxExactValueCount    int     `json:"max_exact_value_count"`
	MaxExactMatchSpans    int     `json:"max_exact_match_spans"`
	MaxExactScanWork      int64   `json:"max_exact_scan_work"`
	MinTokenLen           int     `json:"min_token_len"`
	MinEntropyBitsPerChar float64 `json:"min_entropy_bits_per_char"`
}

type exactValueCase struct {
	Name             string   `json:"name"`
	Secrets          []string `json:"secrets"`
	Input            string   `json:"input"`
	ExpectedRedacted string   `json:"expected_redacted"`
	ExpectedCount    int      `json:"expected_count"`
}

type entropyCase struct {
	Name             string `json:"name"`
	Input            string `json:"input"`
	ExpectedRedacted string `json:"expected_redacted"`
	ExpectedCount    int    `json:"expected_count"`
}

type scannerFinding struct {
	Detector   string `json:"detector"`
	Confidence string `json:"confidence"`
	Count      int    `json:"count"`
}

type scannerAuditEvent struct {
	Detector      string `json:"detector"`
	Channel       string `json:"channel"`
	Confidence    string `json:"confidence"`
	RedactedCount int    `json:"redacted_count"`
	Blocked       bool   `json:"blocked"`
	CorrelationID string `json:"correlation_id"`
}

type scannerCase struct {
	Name            string              `json:"name"`
	Detectors       []string            `json:"detectors"`
	Secrets         []string            `json:"secrets,omitempty"`
	Strict          bool                `json:"strict"`
	CorrelationID   string              `json:"correlation_id,omitempty"`
	Channel         string              `json:"channel,omitempty"`
	Input           string              `json:"input"`
	ExpectedText    string              `json:"expected_text"`
	ExpectedBlocked bool                `json:"expected_blocked"`
	Findings        []scannerFinding    `json:"findings"`
	AuditEvents     []scannerAuditEvent `json:"audit_events"`
}

type truthyCase struct {
	Input    string `json:"input"`
	Expected bool   `json:"expected"`
}

func buildRedactFixture(meta oracle) redactFixture {
	exactInputs := []struct {
		name    string
		secrets []string
		input   string
	}{
		{
			name:    "single_secret",
			secrets: []string{"sup3r-s3cret-value-xyz"},
			input:   "the password is sup3r-s3cret-value-xyz and that's it",
		},
		{
			name:    "repeat_secret",
			secrets: []string{"sup3r-s3cret-value-xyz"},
			input:   "token=sup3r-s3cret-value-xyz and repeat sup3r-s3cret-value-xyz end",
		},
		{
			name:    "multiple_secrets",
			secrets: []string{"first-secret-token", "second-secret-key"},
			input:   "first: first-secret-token, second: second-secret-key",
		},
		{
			name:    "overlap_short_first",
			secrets: []string{"short", "short-with-sensitive-suffix"},
			input:   "overlap=short-with-sensitive-suffix standalone=short",
		},
		{
			name:    "overlap_long_first",
			secrets: []string{"short-with-sensitive-suffix", "short"},
			input:   "overlap=short-with-sensitive-suffix standalone=short",
		},
		{
			name:    "equal_partial_short_first",
			secrets: []string{"abcd", "bcde"},
			input:   "abcde",
		},
		{
			name:    "equal_partial_long_first",
			secrets: []string{"bcde", "abcd"},
			input:   "abcde",
		},
		{
			name:    "unequal_partial",
			secrets: []string{"abcdef", "defgh"},
			input:   "abcdefgh",
		},
		{
			name:    "unequal_partial_reverse",
			secrets: []string{"defgh", "abcdef"},
			input:   "abcdefgh",
		},
		{
			name:    "containment",
			secrets: []string{"secret-value", "cret-val"},
			input:   "prefix secret-value suffix",
		},
		{
			name:    "containment_reverse",
			secrets: []string{"cret-val", "secret-value"},
			input:   "prefix secret-value suffix",
		},
		{
			name:    "adjacent_nonoverlap",
			secrets: []string{"abcd", "efgh"},
			input:   "abcdefgh",
		},
		{
			name:    "repeated_occurrences",
			secrets: []string{"abcd"},
			input:   "abcd--abcd",
		},
		{
			name:    "duplicates",
			secrets: []string{"abcd", "abcd", "bcde"},
			input:   "abcde abcd",
		},
		{
			name:    "utf8_surrounding_text",
			secrets: []string{"sëcret", "ëcret"},
			input:   "🔐sëcret🚀",
		},
		{
			name:    "self_overlap",
			secrets: []string{"abab"},
			input:   "ababab",
		},
		{
			name:    "short_and_empty_ignored",
			secrets: []string{"", "a", "ab", "abc"},
			input:   "ab is short and empty is nothing",
		},
		{
			name:    "no_match",
			secrets: []string{"absent-secret-token"},
			input:   "clean text without secrets",
		},
		{
			name:    "empty_input",
			secrets: []string{"any-secret-token"},
			input:   "",
		},
	}

	exactCases := make([]exactValueCase, 0, len(exactInputs))
	for _, tc := range exactInputs {
		values := make([]string, 0, len(tc.secrets))
		for _, value := range tc.secrets {
			if len(value) >= 4 {
				values = append(values, value)
			}
		}
		redacted, count := maskingpkg.RedactKnownSecrets(tc.input, values, redactpkg.Marker)
		exactCases = append(exactCases, exactValueCase{
			Name:             tc.name,
			Secrets:          tc.secrets,
			Input:            tc.input,
			ExpectedRedacted: redacted,
			ExpectedCount:    count,
		})
	}

	entropyInputs := []struct {
		name  string
		input string
	}{
		{
			name:  "high_entropy_token",
			input: "config value: kQ7#zM2$pL9@rT4!vX8&wY6^bN3*cJ1~ end",
		},
		{
			name:  "ordinary_prose",
			input: "This is a perfectly ordinary sentence about deploying the release pipeline on Friday afternoon.",
		},
		{
			name:  "short_token",
			input: "short=aB3$kZ9",
		},
		{
			name:  "uuid_v4",
			input: "request_id=f47ac10b-58cc-4372-a567-0e02b2c3d479",
		},
		{
			name:  "sha256_hash",
			input: "checksum=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:  "base64_payload",
			input: "payload=VGhpcyBpcyBqdXN0IGEgcGxhaW4gRW5nbGlzaCBzZW50ZW5jZSBlbmNvZGVkIGFzIGJhc2U2NA==",
		},
		{
			name:  "long_numeric_identifier",
			input: "order_id=12345678901234567890123456789012",
		},
		{
			name:  "empty_input",
			input: "",
		},
	}

	entropyCases := make([]entropyCase, 0, len(entropyInputs))
	for _, tc := range entropyInputs {
		d := redactpkg.NewEntropyDetector()
		redacted, count, err := d.Redact(tc.input)
		if err != nil {
			panic(fmt.Sprintf("entropy detector failed unexpectedly: %v", err))
		}
		entropyCases = append(entropyCases, entropyCase{
			Name:             tc.name,
			Input:            tc.input,
			ExpectedRedacted: redacted,
			ExpectedCount:    count,
		})
	}

	scanInputs := []struct {
		name          string
		detectors     []string
		secrets       []string
		strict        bool
		correlationID string
		channel       string
		input         string
	}{
		{
			name:      "no_detectors",
			detectors: []string{},
			input:     "hello world",
		},
		{
			name:          "exact_non_strict",
			detectors:     []string{"exact_value"},
			secrets:       []string{"redactmesoftvalue1"},
			strict:        false,
			correlationID: "corr-2",
			channel:       "test.stdout",
			input:         "output containing redactmesoftvalue1 here, and more text after",
		},
		{
			name:          "exact_strict",
			detectors:     []string{"exact_value"},
			secrets:       []string{"blockmehardvalue1"},
			strict:        true,
			correlationID: "corr-1",
			channel:       "test.stdout",
			input:         "output containing blockmehardvalue1 here",
		},
		{
			name:          "entropy_non_strict",
			detectors:     []string{"entropy_heuristic"},
			strict:        false,
			correlationID: "corr-3",
			channel:       "test.channel",
			input:         "value: kQ7#zM2$pL9@rT4!vX8&wY6^bN3*cJ1~ end",
		},
		{
			name:          "entropy_strict",
			detectors:     []string{"entropy_heuristic"},
			strict:        true,
			correlationID: "corr-4",
			channel:       "test.channel",
			input:         "value: kQ7#zM2$pL9@rT4!vX8&wY6^bN3*cJ1~ end",
		},
		{
			name:          "both_non_strict",
			detectors:     []string{"exact_value", "entropy_heuristic"},
			secrets:       []string{"mysecretpassword"},
			strict:        false,
			correlationID: "corr-5",
			channel:       "test.stdout",
			input:         "pass: mysecretpassword, blob: kQ7#zM2$pL9@rT4!vX8&wY6^bN3*cJ1~",
		},
		{
			name:          "both_strict",
			detectors:     []string{"exact_value", "entropy_heuristic"},
			secrets:       []string{"mysecretpassword"},
			strict:        true,
			correlationID: "corr-6",
			channel:       "test.stdout",
			input:         "pass: mysecretpassword, blob: kQ7#zM2$pL9@rT4!vX8&wY6^bN3*cJ1~",
		},
		{
			name:      "json_structure",
			detectors: []string{"exact_value"},
			secrets:   []string{"topsecretvalue1"},
			input:     `{"stdout":"login ok, token=topsecretvalue1","exit_code":0}`,
		},
		{
			name:      "multiline",
			detectors: []string{"exact_value"},
			secrets:   []string{"multilinesecretval"},
			input:     "line one\nline two multilinesecretval\nline three (truncat",
		},
		{
			name:      "no_matches",
			detectors: []string{"exact_value", "entropy_heuristic"},
			secrets:   []string{"absentpassword"},
			strict:    true,
			input:     "normal text with no secrets",
		},
	}

	scanCases := make([]scannerCase, 0, len(scanInputs))
	for _, tc := range scanInputs {
		var detectors []redactpkg.Detector
		for _, dname := range tc.detectors {
			switch dname {
			case "exact_value":
				detectors = append(detectors, redactpkg.NewExactValueDetector(tc.secrets))
			case "entropy_heuristic":
				detectors = append(detectors, redactpkg.NewEntropyDetector())
			default:
				panic("unknown detector: " + dname)
			}
		}

		sc := redactpkg.NewScanner(detectors...)
		sc.Channel = tc.channel
		emittedEvents := make([]scannerAuditEvent, 0)
		sc.Audit = func(e redactpkg.AuditEvent) {
			emittedEvents = append(emittedEvents, scannerAuditEvent{
				Detector:      e.Detector,
				Channel:       e.Channel,
				Confidence:    e.Confidence.String(),
				RedactedCount: e.RedactedCount,
				Blocked:       e.Blocked,
				CorrelationID: e.CorrelationID,
			})
		}

		res, err := sc.Scan(tc.input, redactpkg.ScanOptions{
			Strict:        tc.strict,
			CorrelationID: tc.correlationID,
		})
		if err != nil {
			panic(fmt.Sprintf("scanner failed unexpectedly: %v", err))
		}

		findings := make([]scannerFinding, 0, len(res.Findings))
		for _, f := range res.Findings {
			findings = append(findings, scannerFinding{
				Detector:   f.Detector,
				Confidence: f.Confidence.String(),
				Count:      f.Count,
			})
		}

		scanCases = append(scanCases, scannerCase{
			Name:            tc.name,
			Detectors:       tc.detectors,
			Secrets:         tc.secrets,
			Strict:          tc.strict,
			CorrelationID:   tc.correlationID,
			Channel:         tc.channel,
			Input:           tc.input,
			ExpectedText:    res.Text,
			ExpectedBlocked: res.Blocked,
			Findings:        findings,
			AuditEvents:     emittedEvents,
		})
	}

	truthyInputs := []string{
		"1", "t", "T", "true", "TRUE", "True", "yes", "YES", "Yes", "on", "ON", "On",
		"", "0", "false", "no", "off", "random", "TRUE ",
	}
	truthyCases := make([]truthyCase, 0, len(truthyInputs))
	for _, in := range truthyInputs {
		truthyCases = append(truthyCases, truthyCase{
			Input:    in,
			Expected: evaluateTruthy(in),
		})
	}

	return redactFixture{
		SchemaVersion: 1,
		Oracle:        meta,
		Constants: redactConstants{
			Marker:                redactpkg.Marker,
			BlockedText:           "[REDACTED: output withheld]",
			MinExactValueLen:      redactpkg.MinExactValueLen,
			MaxExactValueCount:    redactpkg.MaxExactValueCount,
			MaxExactMatchSpans:    redactpkg.MaxExactMatchSpans,
			MaxExactScanWork:      redactpkg.MaxExactScanWork,
			MinTokenLen:           redactpkg.MinTokenLen,
			MinEntropyBitsPerChar: redactpkg.MinEntropyBitsPerChar,
		},
		ExactValueCases: exactCases,
		EntropyCases:    entropyCases,
		ScannerCases:    scanCases,
		TruthyCases:     truthyCases,
	}
}

func evaluateTruthy(v string) bool {
	switch v {
	case "1", "t", "T", "true", "TRUE", "True", "yes", "YES", "Yes", "on", "ON", "On":
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// Main / CLI entry point
// ---------------------------------------------------------------------------

func main() {
	output := flag.String("output", "", "legacy single fixture path")
	errorOutput := flag.String("error-output", "", "error fixture path")
	secretRefOutput := flag.String("secret-ref-output", "", "secret ref fixture path")
	redactOutput := flag.String("redact-output", "", "redact fixture path")
	cryptoOutput := flag.String("crypto-output", "", "password/TOTP fixture path")
	kind := flag.String("kind", "all", "fixture kind to generate or check: all, error, secret_ref, redact, crypto")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit for a new fixture")
	release := flag.String("oracle-release", "", "Go oracle release for a new fixture")
	flag.Parse()

	if *errorOutput == "" {
		if *output != "" && (*kind == "error" || *kind == "all") {
			*errorOutput = *output
		} else {
			*errorOutput = "testdata/port/core/error-contract.json"
		}
	}
	if *secretRefOutput == "" {
		*secretRefOutput = "testdata/port/core/secret-ref-contract.json"
	}
	if *redactOutput == "" {
		*redactOutput = "testdata/port/core/redact-contract.json"
	}
	if *cryptoOutput == "" {
		*cryptoOutput = "testdata/port/core/password-totp-contract.json"
	}

	meta := oracle{Commit: *commit, Release: *release}
	if *check || meta.Commit == "" || meta.Release == "" {
		existing, err := readHeader(*errorOutput)
		if err == nil {
			meta = existing.Oracle
		}
	}
	if meta.Commit == "" || meta.Release == "" {
		fatal("--oracle-commit and --oracle-release are required when generating a new fixture")
	}

	runError := *kind == "all" || *kind == "error"
	runSecretRef := *kind == "all" || *kind == "secret_ref"
	runRedact := *kind == "all" || *kind == "redact"
	runCrypto := *kind == "all" || *kind == "crypto"

	if runError {
		processFixture(*errorOutput, *check, "error-contract", func() ([]byte, int, error) {
			f := buildErrorFixture(meta)
			b, err := marshalJSON(f)
			return b, len(f.Cases), err
		})
	}

	if runSecretRef {
		processFixture(*secretRefOutput, *check, "secret-ref-contract", func() ([]byte, int, error) {
			f := buildSecretRefFixture(meta)
			b, err := marshalJSON(f)
			return b, len(f.ParseRefCases) + len(f.ParseHandleCases), err
		})
	}

	if runRedact {
		processFixture(*redactOutput, *check, "redact-contract", func() ([]byte, int, error) {
			f := buildRedactFixture(meta)
			b, err := marshalJSON(f)
			return b, len(f.ExactValueCases) + len(f.EntropyCases) + len(f.ScannerCases), err
		})
	}

	if runCrypto {
		processFixture(*cryptoOutput, *check, "password-totp-contract", func() ([]byte, int, error) {
			f := buildCryptoFixture(meta)
			b, err := marshalJSON(f)
			return b, len(f.PasswordCases) + len(f.StrengthCases) + len(f.TOTPSecretCases) + len(f.TOTPParamCases) + len(f.TOTPCases), err
		})
	}
}

func processFixture(path string, check bool, label string, gen func() ([]byte, int, error)) {
	content, count, err := gen()
	if err != nil {
		fatal("generate %s fixture: %v", label, err)
	}

	if check {
		existing, err := os.ReadFile(path) // #nosec G304 -- explicit operator-selected fixture path
		if err != nil {
			fatal("read %s fixture (%s): %v", label, path, err)
		}
		if !bytes.Equal(existing, content) {
			fatal("%s fixture (%s) is stale; run make core-fixtures-generate", label, path)
		}
		fmt.Printf("PASS %s fixture (%d cases)\n", label, count)
		return
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		fatal("create fixture directory for %s: %v", path, err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		fatal("write fixture %s: %v", path, err)
	}
	fmt.Printf("WROTE %s (%d cases)\n", path, count)
}

func marshalJSON(value any) ([]byte, error) {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(content, '\n'), nil
}

func readHeader(path string) (headerOnly, error) {
	content, err := os.ReadFile(path) // #nosec G304 -- explicit operator-selected fixture path
	if err != nil {
		return headerOnly{}, err
	}
	var value headerOnly
	if err := json.Unmarshal(content, &value); err != nil {
		return headerOnly{}, err
	}
	if value.SchemaVersion != 1 {
		return headerOnly{}, fmt.Errorf("unsupported schema_version %d", value.SchemaVersion)
	}
	return value, nil
}

func fatal(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}
