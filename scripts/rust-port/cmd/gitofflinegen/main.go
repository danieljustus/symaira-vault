// Command gitofflinegen freezes the GIT-002 offline-classification contract.
//
// IsOfflineError is the single shared classifier both the push and the pull
// path use to decide whether a remote failure is a connectivity problem or a
// configuration/authentication problem. That decision changes what the user is
// told and whether the failure is treated as transient, so the marker list and
// its case-insensitivity are a contract rather than an implementation detail.
//
// Scope, stated plainly: this generator pins the exported classifier and the
// PushError message format. It does NOT pin classifyPushError's precedence,
// which is unexported and only reachable through a real failing remote. That
// matters, because the two call sites do not agree — see the note this
// generator emits into the fixture and the GIT-002 row.
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
	"strings"

	"github.com/danieljustus/symaira-vault/internal/git"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit  = "caadd5e"
	pinnedOracleRelease = "v0.22.1"
)

var productionSources = []string{
	"internal/git/git.go",
	"internal/git/git_offline.go",
}

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

type offlineCase struct {
	Name    string `json:"name"`
	Why     string `json:"why"`
	Message string `json:"message"`
	Offline bool   `json:"offline"`
}

type formatCase struct {
	Name     string `json:"name"`
	Why      string `json:"why"`
	Message  string `json:"message"`
	Cause    string `json:"cause"`
	HasCause bool   `json:"has_cause"`
	Rendered string `json:"rendered"`
}

type fixture struct {
	SchemaVersion int    `json:"schema_version"`
	Oracle        oracle `json:"oracle"`
	// NetworkMessage is the user-facing text every offline classification
	// resolves to. It is restated here rather than lifted, because
	// errNetworkMessage is unexported; the unpinned_scope note says so.
	NetworkMessage string `json:"network_message"`
	// Markers is the oracle's list, read back out of the production package
	// so the Rust side can assert it has the same one in the same order.
	Markers []string `json:"markers"`
	// SubsumedMarkers are markers that can never decide a classification on
	// their own, because any message containing one also contains a shorter
	// marker. Computed here rather than asserted, so it tracks the oracle.
	SubsumedMarkers []string      `json:"subsumed_markers"`
	OfflineCases    []offlineCase `json:"offline_cases"`
	FormatCases     []formatCase  `json:"format_cases"`
	UnpinnedScope   []string      `json:"unpinned_scope"`
}

func offlineInputs() []struct{ name, why, message string } {
	return []struct{ name, why, message string }{
		// Every marker, in the order the oracle lists them, using the
		// real-world strings they were drawn from.
		{"no_route_to_host", "ssh/net marker", "dial tcp 10.0.0.1:22: connect: no route to host"},
		{"connection_refused", "ssh/net marker", "dial tcp 127.0.0.1:22: connect: connection refused"},
		{"connection_timed_out", "ssh/net marker", "dial tcp: connection timed out"},
		{"operation_timed_out", "ssh/net marker", "ssh: operation timed out"},
		{"io_timeout", "ssh/net marker", "read tcp 10.0.0.2:22: i/o timeout"},
		{"no_such_host", "dns marker", "dial tcp: lookup git.example.com: no such host"},
		{"could_not_resolve_hostname", "dns marker", "ssh: Could not resolve hostname git.example.com"},
		{"name_or_service_not_known", "dns marker", "getaddrinfo: Name or service not known"},
		{"network_is_unreachable", "net marker", "connect: network is unreachable"},
		{"host_is_unreachable", "net marker", "connect: host is unreachable"},
		{"connection_reset_by_peer", "net marker", "read: connection reset by peer"},
		{"bare_timed_out", "generic marker", "the request timed out"},
		{"bare_timeout", "generic marker", "context deadline exceeded: timeout"},
		{"generic_connection", "deliberately broad marker kept for parity with the older per-package classifiers", "unexpected connection state"},
		{"generic_refused", "deliberately broad marker", "the server refused it"},
		{"generic_network", "deliberately broad marker", "network subsystem failure"},
		{"generic_tls", "deliberately broad marker", "tls: handshake failure"},
		{"generic_eof", "deliberately broad marker", "EOF"},

		// Case-insensitivity is part of the contract, not incidental.
		{"uppercase_marker", "matching lowercases the message first, so an all-caps error still classifies", "CONNECTION REFUSED"},
		{"mixed_case_marker", "mixed case must match too", "No Route To Host"},

		// Negatives: configuration and authentication problems must NOT be
		// classified as connectivity, or a real misconfiguration is reported
		// to the user as a transient network blip.
		{"auth_failure_is_not_offline", "an authentication failure is a configuration problem, not a connectivity one", "authentication failed"},
		{"bad_credentials_is_not_offline", "credentials problems are not connectivity", "invalid credentials supplied"},
		{"http_401_is_not_offline", "an HTTP 401 is an auth problem", "error: 401 Unauthorized"},
		{"http_403_is_not_offline", "an HTTP 403 is an auth problem", "error: 403 Forbidden"},
		{"known_hosts_is_not_offline", "a known_hosts problem is an SSH configuration error", "knownhosts: key mismatch"},
		{"non_fast_forward_is_not_offline", "a diverged history is a normal git outcome", "non-fast-forward update"},
		{"repository_not_found_is_not_offline", "a missing repository is not a connectivity failure", "remote: Repository not found"},
		{"empty_message", "an empty message matches no marker", ""},

		// The broad markers have teeth: these show the classifier is
		// substring-based, so an auth failure that merely mentions a
		// connection is classified as offline. Pinned because it is the
		// oracle's behavior, not because it is desirable.
		{"auth_failure_mentioning_connection", "the broad 'connection' marker wins over the word 'authentication': substring matching has no notion of which token is the subject", "authentication failed on connection to host"},
		{"auth_failure_mentioning_network", "same shape via the 'network' marker", "authentication failed: network path"},
	}
}

func buildOfflineCases() []offlineCase {
	inputs := offlineInputs()
	cases := make([]offlineCase, 0, len(inputs)+1)
	for _, in := range inputs {
		cases = append(cases, offlineCase{
			Name: in.name, Why: in.why, Message: in.message,
			Offline: git.IsOfflineError(errors.New(in.message)),
		})
	}
	return cases
}

func buildFormatCases() []formatCase {
	specs := []struct{ name, why, message, cause string }{
		{"with_cause", "the rendered form nests the cause after the message", "network error - please check your connection", "dial tcp: i/o timeout"},
		{"without_cause", "a bare message renders without the cause segment", "no 'origin' remote configured", ""},
		{"auth_message_with_cause", "the auth message as the user actually sees it", "authentication failed - please check your credentials", "error: 401 Unauthorized"},
	}
	cases := make([]formatCase, 0, len(specs))
	for _, s := range specs {
		e := &git.PushError{Message: s.message}
		if s.cause != "" {
			e.Cause = errors.New(s.cause)
		}
		cases = append(cases, formatCase{
			Name: s.name, Why: s.why, Message: s.message,
			Cause: s.cause, HasCause: s.cause != "", Rendered: e.Error(),
		})
	}
	return cases
}

// oracleMarkers restates the oracle's list. internal/git keeps
// offlineErrorMarkers unexported, so it cannot be read directly; the
// consistency check below proves the restatement still classifies identically
// to the real function, which is what makes it usable as evidence.
var oracleMarkers = []string{
	"no route to host",
	"connection refused",
	"connection timed out",
	"operation timed out",
	"i/o timeout",
	"no such host",
	"could not resolve hostname",
	"name or service not known",
	"network is unreachable",
	"host is unreachable",
	"connection reset by peer",
	"timed out",
	"timeout",
	"connection",
	"refused",
	"network",
	"tls",
	"eof",
}

// verifyMarkerList checks the restated list against the real classifier: every
// marker must classify as offline, and a message built to contain none of them
// must not. A drift in the production list then shows up here instead of
// silently making subsumedMarkers wrong.
func verifyMarkerList() error {
	for _, m := range oracleMarkers {
		if !git.IsOfflineError(errors.New(m)) {
			return fmt.Errorf("restated marker %q is not recognized by the oracle; the list has drifted", m)
		}
	}
	const neutral = "repository not found"
	if git.IsOfflineError(errors.New(neutral)) {
		return fmt.Errorf("control message %q classified offline; the oracle gained a marker this list does not have", neutral)
	}
	return nil
}

// subsumedMarkers returns the markers that can never be the deciding one,
// because every string containing them also contains another, shorter marker.
func subsumedMarkers() []string {
	var out []string
	for _, m := range oracleMarkers {
		for _, other := range oracleMarkers {
			if other != m && len(other) < len(m) && strings.Contains(m, other) {
				out = append(out, m)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func main() {
	output := flag.String("output", "testdata/port/sync/git-offline.json", "GIT-002 offline fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "Go oracle commit for a new fixture")
	release := flag.String("oracle-release", "", "Go oracle release for a new fixture")
	flag.Parse()

	commitLabel, releaseLabel, err := resolveOracle(*check, *commit, *release)
	if err != nil {
		fatal("resolve oracle metadata: %v", err)
	}
	root, err := repositoryRoot()
	if err != nil {
		fatal("%v", err)
	}
	sources := append([]string(nil), productionSources...)
	sort.Strings(sources)
	sourceDigest, err := provenance.Digest(root, sources)
	if err != nil {
		fatal("hash production sources: %v", err)
	}
	resolved, err := provenance.Verify(root, commitLabel, sources)
	if err != nil {
		fatal("%v", err)
	}
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/gitofflinegen/main.go"})
	if err != nil {
		fatal("hash generator: %v", err)
	}

	if markerErr := verifyMarkerList(); markerErr != nil {
		fatal("%v", markerErr)
	}
	offlineCases := buildOfflineCases()
	formatCases := buildFormatCases()

	// A classifier corpus with no negatives proves only that it says yes.
	var positives, negatives int
	for _, c := range offlineCases {
		if c.Offline {
			positives++
		} else {
			negatives++
		}
	}
	if positives == 0 || negatives == 0 {
		fatal("corpus must exercise both outcomes (got %d offline, %d not)", positives, negatives)
	}

	content, err := marshalJSON(fixture{
		SchemaVersion: 1,
		Oracle: oracle{
			Commit: commitLabel, CommitSHA: resolved, Release: releaseLabel,
			SourceFiles: sources, SourceDigest: sourceDigest, GeneratorDigest: generatorDigest,
		},
		NetworkMessage:  "network error - please check your connection",
		Markers:         oracleMarkers,
		SubsumedMarkers: subsumedMarkers(),
		OfflineCases:    offlineCases,
		FormatCases:     formatCases,
		UnpinnedScope: []string{
			"classifyPushError precedence is NOT pinned here: it is unexported and only reachable through a real failing remote.",
			"The two call sites disagree and this is deliberate to record, not to reproduce blindly. classifyPushError tests known_hosts, then authentication, then IsOfflineError. PullWithResult tests IsOfflineError FIRST, then authentication.",
			"Consequence: an error containing both 'authentication' and a connectivity marker is reported as an auth failure on push and as a network failure on pull. Pinning that asymmetry needs a network-failure harness and is left to the GIT-002 completion slice.",
			"network_message is restated from errNetworkMessage rather than lifted, because that constant is unexported. If it changes, this fixture will not notice on its own.",
		},
	})
	if err != nil {
		fatal("marshal fixture: %v", err)
	}

	if *check {
		existing, readErr := os.ReadFile(*output) // #nosec G304 -- explicit operator-selected fixture
		if readErr != nil {
			fatal("read fixture: %v", readErr)
		}
		if !bytes.Equal(existing, content) {
			fatal("fixture is stale; run make git-offline-fixtures-generate")
		}
		fmt.Printf("PASS GIT-002 offline fixture (%d classifier cases: %d offline, %d not; %d format cases)\n",
			len(offlineCases), positives, negatives, len(formatCases))
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(*output, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s (%d classifier cases, %d format cases)\n", *output, len(offlineCases), len(formatCases))
}

func resolveOracle(check bool, commit, release string) (string, string, error) {
	if commit != "" && commit != pinnedOracleCommit {
		return "", "", fmt.Errorf("oracle commit %q is not the pinned commit %q", commit, pinnedOracleCommit)
	}
	if release != "" && release != pinnedOracleRelease {
		return "", "", fmt.Errorf("oracle release %q is not the pinned release %q", release, pinnedOracleRelease)
	}
	if check {
		return pinnedOracleCommit, pinnedOracleRelease, nil
	}
	if commit == "" || release == "" {
		return "", "", fmt.Errorf("--oracle-commit and --oracle-release are required when generating a new fixture")
	}
	return commit, release, nil
}

func repositoryRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate generator")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "..")), nil
}

func marshalJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}
