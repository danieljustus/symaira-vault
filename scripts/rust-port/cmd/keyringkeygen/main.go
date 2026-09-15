// Command keyringkeygen freezes the SESSION-002 keyring-key contract: how a
// composite "service|account" key is split, which keys can name a native
// keychain item at all, and the in-memory backend's observable semantics.
//
// Deliberately pure. The native keychain round-trip stays a macOS-gated
// diagnostic; this row's addressing rules are platform-independent and must be
// verifiable on every OS, which is the part that was missing.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/danieljustus/symaira-vault/internal/session"
	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit  = "6ce94b43"
	pinnedOracleRelease = "unreleased"
)

var productionSources = []string{
	"internal/session/memory_keyring.go",
	"internal/session/oskeyring.go",
}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

// splitCase pins the pure decomposition of a composite key.
type splitCase struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Key         string `json:"key"`
	Service     string `json:"service"`
	Account     string `json:"account"`
	// NativelyAddressable reports whether the key can name a native keychain
	// item. A key without a separator cannot: it would land under an empty
	// service, where every such key collides.
	NativelyAddressable bool `json:"natively_addressable"`
}

// backendStep is one operation against the in-memory backend and its result.
// Error text is not part of the contract -- the two implementations word their
// errors differently -- but the outcome class is.
type backendStep struct {
	Op      string `json:"op"`
	Key     string `json:"key"`
	Value   string `json:"value,omitempty"`
	Outcome string `json:"outcome"`
	Got     string `json:"got,omitempty"`
}

type backendCase struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Steps       []backendStep `json:"steps"`
}

// divergentCase records a scripted sequence where the Go in-memory backend is
// known NOT to behave as opaque storage, so the two implementations disagree
// by construction. The set is pinned exactly rather than normalised away; see
// docs/rust-port/session-002-memory-backend-adjudication.md.
type divergentCase struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Steps       []backendStep `json:"steps"`
	// RustOutcome is what a plain key-value store produces for the same
	// script, recorded so the divergence cannot quietly change shape.
	RustOutcomes []string `json:"rust_outcomes"`
}

type fixture struct {
	SchemaVersion int         `json:"schema_version"`
	Oracle        oracle      `json:"oracle"`
	SplitCases    []splitCase `json:"split_cases"`
	// BackendCases use only the accounts where the Go in-memory backend is
	// genuinely opaque. Both implementations must match these exactly.
	BackendCases []backendCase `json:"backend_cases"`
	// DivergentCases are the session-account scripts where it is not.
	DivergentCases []divergentCase `json:"divergent_cases"`
}

func splitInputs() []struct{ name, description, key string } {
	return []struct{ name, description, key string }{
		{"production_session", "the shape every production call site builds", "symvault:/home/u/.symvault|session"},
		{"production_identity", "the identity account uses the same service", "symvault:/home/u/.symvault|identity"},
		{"production_wrap_key", "and so does the wrap key", "symvault:/home/u/.symvault|wrap-key"},
		{"service_contains_separator", "a vault path may contain the separator; the LAST one splits", "symvault:/home/a|b|session"},
		{"service_contains_many_separators", "still the last one, however many there are", "a|b|c|d|account"},
		{"empty_service", "a leading separator yields an empty service, not an error", "|account"},
		{"empty_account", "a trailing separator yields an empty account, not an error", "service|"},
		{"separator_only", "both halves empty", "|"},
		{"no_separator", "cannot name a native item: it would land under an empty service", "session"},
		{"empty_key", "the empty key has no separator either", ""},
		{"unicode_service", "non-ASCII survives the split unchanged", "symvault:/home/ü/vält|session"},
		{"windows_path_service", "a Windows vault path is just a service string", `symvault:C:\Users\u\.symvault|session`},
	}
}

func buildSplitCases() []splitCase {
	inputs := splitInputs()
	cases := make([]splitCase, 0, len(inputs))
	for _, input := range inputs {
		service, account, addressable := session.SplitKeyringKey(input.key)
		cases = append(cases, splitCase{
			Name: input.name, Description: input.description, Key: input.key,
			Service: service, Account: account, NativelyAddressable: addressable,
		})
	}
	return cases
}

// run executes one step against the backend and records the observable result.
func run(backend session.KeyringBackend, step backendStep) backendStep {
	switch step.Op {
	case "set":
		if err := backend.Set(step.Key, step.Value); err != nil {
			step.Outcome = "error"
			return step
		}
		step.Outcome = "ok"
	case "get":
		got, err := backend.Get(step.Key)
		switch {
		case errors.Is(err, session.ErrKeyringNotFound):
			step.Outcome = "not_found"
		case err != nil:
			step.Outcome = "error"
		default:
			step.Outcome = "found"
			step.Got = got
		}
	case "delete":
		if err := backend.Delete(step.Key); err != nil {
			step.Outcome = "error"
			return step
		}
		step.Outcome = "ok"
	default:
		step.Outcome = "unsupported"
	}
	return step
}

// buildBackendCases scripts the accounts where the Go in-memory backend is
// opaque storage -- wrap-key and identity. Both implementations must agree on
// every step.
func buildBackendCases() []backendCase {
	const svc = "symvault:/v"
	wrap := svc + "|wrap-key"
	ident := svc + "|identity"
	other := "symvault:/other|wrap-key"

	scripts := []struct {
		name, description string
		steps             []backendStep
	}{
		{
			"round_trip", "set, read back, delete, and the entry is gone",
			[]backendStep{
				{Op: "get", Key: wrap},
				{Op: "set", Key: wrap, Value: "first"},
				{Op: "get", Key: wrap},
				{Op: "delete", Key: wrap},
				{Op: "get", Key: wrap},
			},
		},
		{
			"set_replaces", "a second set replaces rather than appends",
			[]backendStep{
				{Op: "set", Key: wrap, Value: "first"},
				{Op: "set", Key: wrap, Value: "second"},
				{Op: "get", Key: wrap},
			},
		},
		{
			"delete_is_idempotent", "deleting an absent entry succeeds, and deleting twice succeeds",
			[]backendStep{
				{Op: "delete", Key: wrap},
				{Op: "set", Key: wrap, Value: "value"},
				{Op: "delete", Key: wrap},
				{Op: "delete", Key: wrap},
				{Op: "get", Key: wrap},
			},
		},
		{
			"accounts_are_independent", "two accounts under one service do not collide",
			[]backendStep{
				{Op: "set", Key: wrap, Value: "w"},
				{Op: "set", Key: ident, Value: "i"},
				{Op: "get", Key: wrap},
				{Op: "get", Key: ident},
				{Op: "delete", Key: wrap},
				{Op: "get", Key: ident},
			},
		},
		{
			"services_are_independent", "the same account under two vaults does not collide",
			[]backendStep{
				{Op: "set", Key: wrap, Value: "a"},
				{Op: "set", Key: other, Value: "b"},
				{Op: "get", Key: wrap},
				{Op: "get", Key: other},
			},
		},
		{
			"empty_value_round_trips", "an empty value is stored, not treated as absent",
			[]backendStep{
				{Op: "set", Key: wrap, Value: ""},
				{Op: "get", Key: wrap},
			},
		},
		{
			"binary_payload_round_trips", "the value is bytes, not text: NUL and non-ASCII survive",
			[]backendStep{
				{Op: "set", Key: ident, Value: "a\x00b-\u00e4\u00f6\u00fc"},
				{Op: "get", Key: ident},
			},
		},
	}

	cases := make([]backendCase, 0, len(scripts))
	for _, script := range scripts {
		backend := session.NewMemoryKeyringBackend()
		steps := make([]backendStep, 0, len(script.steps))
		for _, step := range script.steps {
			steps = append(steps, run(backend, step))
		}
		cases = append(cases, backendCase{Name: script.name, Description: script.description, Steps: steps})
	}
	return cases
}

// buildDivergentCases records the session account, where the Go in-memory
// backend is not opaque storage: Set accepts any value, but Get parses it as a
// session document, enforces its own TTL and DELETES the entry when the parse
// fails. A value the backend just accepted is therefore destroyed on the first
// read. A plain key-value store -- which is what the Rust side is, and what
// KeyringBackend's own documentation describes -- returns the value.
//
// Recorded rather than normalised away. rustOutcomes is the plain-store result
// for the same script, so the divergence can neither grow nor shrink unnoticed.
func buildDivergentCases() []divergentCase {
	const sessionKey = "symvault:/v|session"
	scripts := []struct {
		name, description string
		steps             []backendStep
		rustOutcomes      []string
	}{
		{
			"session_account_discards_an_opaque_value",
			"Set accepts the value; Get cannot parse it as a session and deletes it",
			[]backendStep{
				{Op: "set", Key: sessionKey, Value: "opaque-value"},
				{Op: "get", Key: sessionKey},
			},
			[]string{"ok", "found"},
		},
		{
			"session_account_second_read_confirms_the_delete",
			"the entry is gone after the failed read, not merely unreadable",
			[]backendStep{
				{Op: "set", Key: sessionKey, Value: "opaque-value"},
				{Op: "get", Key: sessionKey},
				{Op: "get", Key: sessionKey},
			},
			[]string{"ok", "found", "found"},
		},
	}

	cases := make([]divergentCase, 0, len(scripts))
	for _, script := range scripts {
		backend := session.NewMemoryKeyringBackend()
		steps := make([]backendStep, 0, len(script.steps))
		for _, step := range script.steps {
			steps = append(steps, run(backend, step))
		}
		cases = append(cases, divergentCase{
			Name: script.name, Description: script.description,
			Steps: steps, RustOutcomes: script.rustOutcomes,
		})
	}
	return cases
}

func repositoryRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate keyring key generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..")), nil
}

func resolveOracle(commit, release string) (oracle, error) {
	if commit != "" && commit != pinnedOracleCommit {
		return oracle{}, fmt.Errorf("oracle commit %q is not the pinned commit %q", commit, pinnedOracleCommit)
	}
	if release != "" && release != pinnedOracleRelease {
		return oracle{}, fmt.Errorf("oracle release %q is not the pinned release %q", release, pinnedOracleRelease)
	}
	root, err := repositoryRoot()
	if err != nil {
		return oracle{}, err
	}
	sources := append([]string(nil), productionSources...)
	sort.Strings(sources)
	sourceDigest, err := provenance.Digest(root, sources)
	if err != nil {
		return oracle{}, fmt.Errorf("hash production sources: %w", err)
	}
	resolved, err := provenance.Verify(root, pinnedOracleCommit, sources)
	if err != nil {
		return oracle{}, err
	}
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/keyringkeygen/main.go"})
	if err != nil {
		return oracle{}, fmt.Errorf("hash generator: %w", err)
	}
	return oracle{
		Commit: pinnedOracleCommit, CommitSHA: resolved, Release: pinnedOracleRelease,
		SourceFiles: sources, SourceDigest: sourceDigest, GeneratorDigest: generatorDigest,
	}, nil
}

func main() {
	output := flag.String("output", "testdata/port/session/keyring-keys.json", "fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit for a new fixture")
	release := flag.String("oracle-release", "", "Go oracle release for a new fixture")
	flag.Parse()

	meta, err := resolveOracle(*commit, *release)
	if err != nil {
		fatal("resolve oracle metadata: %v", err)
	}

	generated := fixture{
		SchemaVersion:  1,
		Oracle:         meta,
		SplitCases:     buildSplitCases(),
		BackendCases:   buildBackendCases(),
		DivergentCases: buildDivergentCases(),
	}
	content, err := marshal(generated)
	if err != nil {
		fatal("encode fixture: %v", err)
	}

	if *check {
		existing, readErr := os.ReadFile(*output) // #nosec G304 -- repository fixture path
		if readErr != nil {
			fatal("read fixture: %v", readErr)
		}
		if !bytes.Equal(existing, content) {
			fatal("keyring-key fixture is stale; run make keyring-key-fixtures-generate")
		}
		fmt.Printf("PASS keyring-key fixture (%d split, %d backend, %d pinned divergences)\n",
			len(generated.SplitCases), len(generated.BackendCases), len(generated.DivergentCases))
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(*output, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%d split, %d backend, %d pinned divergences)\n", *output,
		len(generated.SplitCases), len(generated.BackendCases), len(generated.DivergentCases))
}

func marshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}
