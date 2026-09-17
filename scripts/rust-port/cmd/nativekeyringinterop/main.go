// Command nativekeyringinterop proves the Go↔Rust OS-keyring boundary on an
// explicitly disposable hosted runner. It stores only generated fixture bytes
// under a unique service/account and requires the caller to run the three
// stages in order: write, Rust update, then verify.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/danieljustus/symaira-vault/internal/session"
)

const (
	reportEnv = "SYMVAULT_NATIVE_KEYRING_INTEROP_REPORT"

	// These are synthetic bytes chosen to exercise binary-safe storage. They
	// are never a passphrase, vault value, or user-provided credential.
	goPayloadText    = "go-written\x00binary\xff\n|fixture"
	rustPayloadText  = "rust-updated\x00binary\xfe\r|fixture"
	interopAccount   = "cross-language-binary"
	reportSchemaVers = 1
)

type report struct {
	SchemaVersion int    `json:"schema_version"`
	Key           string `json:"key"`
	GoPayload     []int  `json:"go_payload"`
	RustPayload   []int  `json:"rust_payload"`
}

func authorized() error {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("SYMVAULT_DISPOSABLE_NATIVE_RUNNER") != "1" {
		return errors.New("cross-language keyring probe requires explicit disposable-runner authorization")
	}
	return nil
}

func reportPath() (string, error) {
	path := os.Getenv(reportEnv)
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s must be an absolute path", reportEnv)
	}
	if _, err := os.Stat(path); err == nil {
		return "", fmt.Errorf("refusing to overwrite existing report %q", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect report path: %w", err)
	}
	return path, nil
}

func asInts(value []byte) []int {
	result := make([]int, len(value))
	for i, b := range value {
		result[i] = int(b)
	}
	return result
}

func asBytes(value []int) ([]byte, error) {
	result := make([]byte, len(value))
	for i, n := range value {
		if n < 0 || n > 255 {
			return nil, fmt.Errorf("payload byte %d out of range", i)
		}
		result[i] = byte(n)
	}
	return result, nil
}

func readReport(path string) (report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return report{}, fmt.Errorf("read interop report: %w", err)
	}
	var value report
	if err := json.Unmarshal(data, &value); err != nil {
		return report{}, fmt.Errorf("decode interop report: %w", err)
	}
	if value.SchemaVersion != reportSchemaVers || value.Key == "" {
		return report{}, errors.New("interop report has invalid schema or key")
	}
	if _, err := asBytes(value.GoPayload); err != nil {
		return report{}, fmt.Errorf("invalid Go payload: %w", err)
	}
	if _, err := asBytes(value.RustPayload); err != nil {
		return report{}, fmt.Errorf("invalid Rust payload: %w", err)
	}
	return value, nil
}

func writeStage() (err error) {
	path, err := reportPath()
	if err != nil {
		return err
	}
	backend := session.NewOSKeyring()
	key := fmt.Sprintf("symvault:rust-cross-language-%d-%d|%s", os.Getpid(), time.Now().UnixNano(), interopAccount)
	if _, getErr := backend.Get(key); !errors.Is(getErr, session.ErrKeyringNotFound) {
		return fmt.Errorf("native namespace preflight must be missing: %w", getErr)
	}
	written := false
	defer func() {
		if written {
			if cleanupErr := backend.Delete(key); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("native cleanup: %w", cleanupErr))
			}
		}
	}()

	goPayload := []byte(goPayloadText)
	rustPayload := []byte(rustPayloadText)
	if err := backend.Set(key, string(goPayload)); err != nil {
		return fmt.Errorf("Go native set: %w", err)
	}
	written = true
	got, err := backend.Get(key)
	if err != nil {
		return fmt.Errorf("Go native read-back: %w", err)
	}
	if got != string(goPayload) {
		return errors.New("Go native read-back mismatch")
	}
	value := report{SchemaVersion: reportSchemaVers, Key: key, GoPayload: asInts(goPayload), RustPayload: asInts(rustPayload)}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode interop report: %w", err)
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create interop report: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write interop report: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close interop report: %w", err)
	}
	written = false
	return nil
}

func verifyStage() (err error) {
	path := os.Getenv(reportEnv)
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%s must be an absolute path", reportEnv)
	}
	value, err := readReport(path)
	if err != nil {
		return err
	}
	backend := session.NewOSKeyring()
	defer func() {
		if cleanupErr := backend.Delete(value.Key); cleanupErr != nil && !errors.Is(cleanupErr, session.ErrKeyringNotFound) {
			err = errors.Join(err, fmt.Errorf("native cleanup: %w", cleanupErr))
		}
	}()
	expected, _ := asBytes(value.RustPayload)
	got, err := backend.Get(value.Key)
	if err != nil {
		return fmt.Errorf("Go read after Rust update: %w", err)
	}
	if got != string(expected) {
		return errors.New("Go read after Rust update mismatch")
	}
	if err := backend.Delete(value.Key); err != nil {
		return fmt.Errorf("Go native delete: %w", err)
	}
	missing := false
	if _, getErr := backend.Get(value.Key); errors.Is(getErr, session.ErrKeyringNotFound) {
		missing = true
	} else if getErr != nil {
		return fmt.Errorf("Go post-delete read: %w", getErr)
	}
	if !missing {
		return errors.New("Go native entry remained after delete")
	}
	return nil
}

func run(mode string) error {
	if err := authorized(); err != nil {
		return err
	}
	switch mode {
	case "write":
		return writeStage()
	case "verify":
		return verifyStage()
	default:
		return fmt.Errorf("mode must be write or verify, got %q", mode)
	}
}

func main() {
	mode := ""
	if len(os.Args) == 2 {
		mode = os.Args[1]
	}
	err := run(mode)
	report := map[string]any{
		"mode":       mode,
		"goos":       runtime.GOOS,
		"goarch":     runtime.GOARCH,
		"go_version": runtime.Version(),
		"backend":    "Go NewOSKeyring",
		"passed":     err == nil,
	}
	if err != nil {
		report["error"] = err.Error()
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(report); encodeErr != nil {
		fmt.Fprintln(os.Stderr, encodeErr)
		os.Exit(1)
	}
	if err != nil {
		os.Exit(1)
	}
}
