// Command biometricgen freezes the non-interactive half of SESSION-003: the
// macOS Keychain OSStatus -> error contract, the no-op biometric manager and
// the Touch ID passphrase item layout.
//
// The production functions are unexported (and the Touch ID store is cgo), so
// the generator compiles the pinned, byte-verified production files
// (keychain_status.go and biometric.go) UNMODIFIED into a scratch module next
// to a one-line exporting shim and a driver, and records what that real code
// does. The layout facts come from parsing the pinned touchid_darwin.go with
// go/parser and matching its Objective-C preamble; they are source facts, not
// run results, because exercising that file needs Touch ID hardware.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/provenance"
)

const (
	pinnedOracleCommit  = "d13e5d0b"
	pinnedOracleRelease = "unreleased"
)

// copied into the scratch module unmodified.
var scratchSources = []string{
	"internal/session/keychain_status.go",
	"internal/session/biometric.go",
}

// parsed, never compiled.
var layoutSource = "internal/session/touchid_darwin.go"

const exportShim = `package session

// KeychainStatusError exposes the unexported production mapping to the driver.
func KeychainStatusError(status int) error { return keychainStatusError(status) }
`

const driverMain = `package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"oraclescratch/session"
)

type sentinel struct {
	name string
	err  error
}

var sentinels = []sentinel{
	{"ErrBiometricNotAvailable", session.ErrBiometricNotAvailable},
	{"ErrBiometricFailed", session.ErrBiometricFailed},
	{"ErrBiometricNotConfigured", session.ErrBiometricNotConfigured},
	{"ErrKeychainDuplicateItem", session.ErrKeychainDuplicateItem},
	{"ErrKeychainItemNotFound", session.ErrKeychainItemNotFound},
	{"ErrKeychainNoSuchKeychain", session.ErrKeychainNoSuchKeychain},
	{"ErrKeychainInvalid", session.ErrKeychainInvalid},
	{"ErrKeychainLocked", session.ErrKeychainLocked},
	{"ErrKeychainReadOnly", session.ErrKeychainReadOnly},
	{"ErrKeychainInteractionNotAllowed", session.ErrKeychainInteractionNotAllowed},
	{"ErrKeychainMissingEntitlement", session.ErrKeychainMissingEntitlement},
	{"ErrKeychainInternal", session.ErrKeychainInternal},
	{"ErrKeychainUnexpectedStatus", session.ErrKeychainUnexpectedStatus},
}

type result struct {
	Ok        bool     ` + "`json:\"ok\"`" + `
	Message   string   ` + "`json:\"message,omitempty\"`" + `
	Sentinels []string ` + "`json:\"sentinels\"`" + `
}

func classify(err error) result {
	if err == nil {
		return result{Ok: true, Sentinels: []string{}}
	}
	matched := []string{}
	for _, s := range sentinels {
		if errors.Is(err, s.err) {
			matched = append(matched, s.name)
		}
	}
	return result{Message: err.Error(), Sentinels: matched}
}

type statusCase struct {
	Status int ` + "`json:\"status\"`" + `
	result
}

type opCase struct {
	Op string ` + "`json:\"op\"`" + `
	result
	Bool   *bool ` + "`json:\"bool,omitempty\"`" + `
	Loaded *int  ` + "`json:\"loaded_len,omitempty\"`" + `
}

type output struct {
	Sentinels []struct {
		Name    string ` + "`json:\"name\"`" + `
		Message string ` + "`json:\"message\"`" + `
	} ` + "`json:\"sentinels\"`" + `
	Statuses []statusCase ` + "`json:\"statuses\"`" + `
	Noop     []opCase     ` + "`json:\"noop_manager\"`" + `
}

func main() {
	var out output
	for _, s := range sentinels {
		out.Sentinels = append(out.Sentinels, struct {
			Name    string ` + "`json:\"name\"`" + `
			Message string ` + "`json:\"message\"`" + `
		}{s.name, s.err.Error()})
	}
	for _, status := range []int{
		0, -4, -50, -108, -128, -25291, -25292, -25293, -25294, -25295, -25299, -25300, -25308, -26275, -34018,
		1, -1, 4, -25301, -34019, 2147483647, -2147483648,
	} {
		out.Statuses = append(out.Statuses, statusCase{Status: status, result: classify(session.KeychainStatusError(status))})
	}

	ctx := context.Background()
	m := session.NewBiometricManager(nil, nil)
	boolp := func(b bool) *bool { return &b }
	add := func(op string, err error, b *bool) {
		out.Noop = append(out.Noop, opCase{Op: op, result: classify(err), Bool: b})
	}
	add("authenticator.is_available", nil, boolp(m.Authenticator().IsAvailable()))
	add("authenticator.authenticate", m.Authenticator().Authenticate(ctx, "reason"), nil)
	add("store.is_available", nil, boolp(m.PassphraseStore().IsAvailable()))
	add("store.save", m.PassphraseStore().Save(ctx, "/vault", []byte("pw")), nil)
	loaded, loadErr := m.PassphraseStore().Load(ctx, "/vault")
	n := len(loaded)
	out.Noop = append(out.Noop, opCase{Op: "store.load", result: classify(loadErr), Loaded: &n})
	add("store.delete", m.PassphraseStore().Delete("/vault"), nil)
	// Passing nil restores the no-op fallback.
	m.SetAuthenticator(nil)
	m.SetPassphraseStore(nil)
	add("after_nil_reset.authenticator.is_available", nil, boolp(m.Authenticator().IsAvailable()))
	add("after_nil_reset.store.is_available", nil, boolp(m.PassphraseStore().IsAvailable()))

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
`

type oracle struct {
	Commit          string   `json:"commit"`
	CommitSHA       string   `json:"commit_sha"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}

type layout struct {
	Account       string            `json:"account"`
	ServicePrefix string            `json:"service_prefix"`
	ServiceNames  []serviceName     `json:"service_names"`
	LoadReason    string            `json:"load_reason"`
	Assertions    []sourceAssertion `json:"source_assertions"`
}

type serviceName struct {
	Vault   string `json:"vault"`
	Service string `json:"service"`
}

// sourceAssertion is a fact read from the pinned Objective-C preamble or Go
// body. Matched must be true for every entry: the generator refuses to write a
// fixture whose pinned source no longer says what the Rust port encodes.
type sourceAssertion struct {
	Name    string `json:"name"`
	Meaning string `json:"meaning"`
	Matched bool   `json:"matched"`
}

type fixture struct {
	SchemaVersion int             `json:"schema_version"`
	Oracle        oracle          `json:"oracle"`
	Driver        json.RawMessage `json:"driver"`
	Layout        layout          `json:"layout"`
}

func repositoryRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		fatal("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			fatal("repository root not found")
		}
		dir = parent
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}

func runDriver(root string) (json.RawMessage, error) {
	scratch, err := os.MkdirTemp("", "symvault-biometricgen-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	write := func(rel, content string) error {
		path := filepath.Join(scratch, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return err
		}
		return os.WriteFile(path, []byte(content), 0o600)
	}
	if err := write("go.mod", "module oraclescratch\n\ngo 1.26\n"); err != nil {
		return nil, err
	}
	for _, src := range scratchSources {
		content, err := os.ReadFile(filepath.Join(root, src)) // #nosec G304 -- fixed production inputs
		if err != nil {
			return nil, err
		}
		if err := write(filepath.Join("session", filepath.Base(src)), string(content)); err != nil {
			return nil, err
		}
	}
	if err := write("session/export_shim.go", exportShim); err != nil {
		return nil, err
	}
	if err := write("main.go", driverMain); err != nil {
		return nil, err
	}
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = scratch
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod", "GO111MODULE=on", "CGO_ENABLED=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("scratch driver: %w: %s", err, stderr.String())
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, stdout.Bytes()); err != nil {
		return nil, err
	}
	return json.RawMessage(compact.Bytes()), nil
}

func stringConst(file *ast.File, name string) (string, error) {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, id := range vs.Names {
				if id.Name != name || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return "", fmt.Errorf("%s is not a string literal", name)
				}
				return strconv.Unquote(lit.Value)
			}
		}
	}
	return "", fmt.Errorf("const %s not found", name)
}

// serviceNameShape verifies biometricServiceName is exactly
// `return currentBiometricServicePrefix + vaultDir`, so evaluating it here is
// reading the function, not guessing it.
func serviceNameShape(file *ast.File) error {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "biometricServiceName" {
			continue
		}
		if len(fn.Body.List) != 1 {
			return fmt.Errorf("biometricServiceName has %d statements", len(fn.Body.List))
		}
		ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("biometricServiceName does not return one value")
		}
		bin, ok := ret.Results[0].(*ast.BinaryExpr)
		if !ok || bin.Op != token.ADD {
			return fmt.Errorf("biometricServiceName is not a concatenation")
		}
		x, okx := bin.X.(*ast.Ident)
		y, oky := bin.Y.(*ast.Ident)
		if !okx || !oky || x.Name != "currentBiometricServicePrefix" || y.Name != "vaultDir" {
			return fmt.Errorf("biometricServiceName is not prefix+vaultDir")
		}
		return nil
	}
	return fmt.Errorf("biometricServiceName not found")
}

func between(source, from, to string) string {
	start := strings.Index(source, from)
	if start < 0 {
		return ""
	}
	end := strings.Index(source[start:], to)
	if end < 0 {
		return source[start:]
	}
	return source[start : start+end]
}

func buildLayout(root string) (layout, error) {
	raw, err := os.ReadFile(filepath.Join(root, layoutSource)) // #nosec G304 -- fixed production input
	if err != nil {
		return layout{}, err
	}
	source := string(raw)
	file, err := parser.ParseFile(token.NewFileSet(), layoutSource, raw, parser.ParseComments)
	if err != nil {
		return layout{}, err
	}
	account, err := stringConst(file, "biometricAccount")
	if err != nil {
		return layout{}, err
	}
	prefix, err := stringConst(file, "currentBiometricServicePrefix")
	if err != nil {
		return layout{}, err
	}
	if err := serviceNameShape(file); err != nil {
		return layout{}, err
	}
	vaults := []string{"/fixture/vault", "/Users/u/.symvault", "", "C:\\Users\\u\\.symvault", "/home/ü/vält", "a|b"}
	names := make([]serviceName, 0, len(vaults))
	for _, vault := range vaults {
		names = append(names, serviceName{Vault: vault, Service: prefix + vault})
	}

	store := between(source, "int touch_id_store_passphrase", "int touch_id_load_passphrase")
	load := between(source, "int touch_id_load_passphrase", "int touch_id_delete_passphrase")
	del := between(source, "int touch_id_delete_passphrase", "*/")
	update := between(source, "static OSStatus symaira_biometric_update", "int touch_id_store_passphrase")
	query := between(source, "static CFMutableDictionaryRef symaira_biometric_query", "// symaira_biometric_scope_to_default_keychain")
	loadGo := between(source, "func (t *touchIDPassphraseStore) loadFromService", "func (t *touchIDPassphraseStore) Delete")
	saveGo := between(source, "func (t *touchIDPassphraseStore) Save", "func (t *touchIDPassphraseStore) Load")

	exists := strings.Index(load, "kSecReturnData, kCFBooleanFalse")
	prompt := strings.Index(load, "evaluatePolicy:")
	reason := regexp.MustCompile(`C\.CString\("([^"]*)"\)`).FindStringSubmatch(loadGo)
	loadReason := ""
	if len(reason) == 2 {
		loadReason = reason[1]
	}

	assertions := []sourceAssertion{
		{"item_class_generic_password", "the item is a kSecClassGenericPassword", strings.Contains(query, "kSecClass, kSecClassGenericPassword")},
		{"item_attributes_service_account_only", "the lookup key is exactly service + account", strings.Contains(query, "kSecAttrService, service") && strings.Contains(query, "kSecAttrAccount, account") && !strings.Contains(query, "kSecAttrLabel")},
		{"value_is_raw_passphrase_bytes", "kSecValueData is the passphrase bytes with no go-keyring prefix or encoding", regexp.MustCompile(`CFDataCreate\(NULL, \(const UInt8 \*\)passphrase_c, \(CFIndex\)strlen\(passphrase_c\)\)`).MatchString(store) && !strings.Contains(store, "go-keyring")},
		{"store_accessible_when_unlocked_this_device_only", "new items are kSecAttrAccessibleWhenUnlockedThisDeviceOnly", strings.Contains(store, "kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly")},
		{"store_deletes_before_add", "Save first deletes any existing item, then adds", regexp.MustCompile(`SecItemDelete\(query\);[\s\S]*SecItemAdd\(query, NULL\)`).MatchString(store)},
		{"store_duplicate_updates_in_place", "errSecDuplicateItem after the add falls back to an in-place update", strings.Contains(store, "if (status == errSecDuplicateItem)") && strings.Contains(store, "symaira_biometric_update(service_c, account_c, data)")},
		{"update_replaces_value_data_only", "the in-place update changes kSecValueData and nothing else", strings.Contains(update, "kSecValueData, data") && !strings.Contains(update, "kSecAttrAccessible")},
		{"update_scoped_to_default_keychain", "the update matches only the default keychain (kSecMatchSearchList)", strings.Contains(update, "symaira_biometric_scope_to_default_keychain(matchQuery)")},
		{"load_checks_item_before_prompt", "Load verifies the item exists (no data returned) BEFORE showing the biometric prompt", exists >= 0 && prompt > exists},
		{"load_missing_item_is_not_configured", "errSecItemNotFound becomes ErrBiometricNotConfigured, not a keychain error", regexp.MustCompile(`if status == errSecItemNotFound \{\s*return nil, ErrBiometricNotConfigured`).MatchString(loadGo)},
		{"load_prompt_timeout_30s", "the biometric prompt gives up after 30 seconds", strings.Contains(load, "30 * NSEC_PER_SEC")},
		{"load_prompt_failure_is_auth_failed", "an unavailable policy, timeout or rejection all return errSecAuthFailed", strings.Count(load, "return errSecAuthFailed;") >= 4},
		{"delete_missing_item_is_success", "deleting an absent item succeeds", regexp.MustCompile(`if \(status == errSecItemNotFound\) \{\s*return errSecSuccess;`).MatchString(del)},
		{"passphrase_is_c_string", "save and load go through NUL-terminated C strings, so a passphrase is cut at its first NUL byte", strings.Contains(saveGo, "C.CString(string(passphrase))") && strings.Contains(loadGo, "C.GoString(out)")},
		{"save_requires_availability", "Save refuses without biometric hardware before touching the keychain", regexp.MustCompile(`if !touchIDAvailable\(\) \{\s*return ErrBiometricNotAvailable`).MatchString(saveGo)},
	}
	for _, a := range assertions {
		if !a.Matched {
			return layout{}, fmt.Errorf("pinned source no longer satisfies layout assertion %s (%s)", a.Name, a.Meaning)
		}
	}
	return layout{Account: account, ServicePrefix: prefix, ServiceNames: names, LoadReason: loadReason, Assertions: assertions}, nil
}

func buildOracle(root string) (oracle, error) {
	sources := append([]string(nil), scratchSources...)
	sources = append(sources, layoutSource)
	sort.Strings(sources)
	digest, err := provenance.Digest(root, sources)
	if err != nil {
		return oracle{}, fmt.Errorf("hash production sources: %w", err)
	}
	resolved, err := provenance.Verify(root, pinnedOracleCommit, sources)
	if err != nil {
		return oracle{}, err
	}
	generatorDigest, err := provenance.Digest(root, []string{"scripts/rust-port/cmd/biometricgen/main.go"})
	if err != nil {
		return oracle{}, fmt.Errorf("hash generator: %w", err)
	}
	return oracle{Commit: pinnedOracleCommit, CommitSHA: resolved, Release: pinnedOracleRelease, SourceFiles: sources, SourceDigest: digest, GeneratorDigest: generatorDigest}, nil
}

func main() {
	output := flag.String("output", "testdata/port/session/biometric.json", "fixture path")
	check := flag.Bool("check", false, "fail if the fixture differs")
	commit := flag.String("oracle-commit", "", "pinned oracle commit")
	release := flag.String("oracle-release", "", "pinned oracle release")
	flag.Parse()
	if *commit != "" && *commit != pinnedOracleCommit {
		fatal("oracle commit %q is not the pinned commit %q", *commit, pinnedOracleCommit)
	}
	if *release != "" && *release != pinnedOracleRelease {
		fatal("oracle release %q is not the pinned release %q", *release, pinnedOracleRelease)
	}
	_ = runtime.GOOS // the fixture deliberately records no host: it describes the pinned sources only.
	root := repositoryRoot()
	meta, err := buildOracle(root)
	if err != nil {
		fatal("provenance: %v", err)
	}
	driver, err := runDriver(root)
	if err != nil {
		fatal("%v", err)
	}
	lay, err := buildLayout(root)
	if err != nil {
		fatal("%v", err)
	}
	var pretty bytes.Buffer
	enc := json.NewEncoder(&pretty)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(fixture{SchemaVersion: 1, Oracle: meta, Driver: driver, Layout: lay}); err != nil {
		fatal("encode fixture: %v", err)
	}
	content := pretty.Bytes()
	path := *output
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	if *check {
		existing, err := os.ReadFile(path) // #nosec G304 -- repository fixture path
		if err != nil {
			fatal("read fixture: %v", err)
		}
		if !bytes.Equal(existing, content) {
			fatal("biometric fixture is stale; run make biometric-fixtures-generate")
		}
		fmt.Println("PASS biometric fixture")
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		fatal("create fixture directory: %v", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		fatal("write fixture: %v", err)
	}
	fmt.Printf("WROTE %s\n", *output)
}
