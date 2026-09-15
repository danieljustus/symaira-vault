// Command nativekeyringprobe exercises the real Go OS backend on disposable CI.
// It does not disable the production fallback/test policy: NewOSKeyring is the
// explicit native adapter. This is resource evidence, not Rust keyring parity.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/danieljustus/symaira-vault/internal/session"
)

func probe() (err error) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("SYMVAULT_DISPOSABLE_NATIVE_RUNNER") != "1" {
		return errors.New("native keyring probe requires explicit disposable-runner authorization")
	}
	backend := session.NewOSKeyring()
	key := fmt.Sprintf("symvault:rust-port-native-probe-%d-%d|session", os.Getpid(), time.Now().UnixNano())
	if _, getErr := backend.Get(key); !errors.Is(getErr, session.ErrKeyringNotFound) {
		return fmt.Errorf("native namespace preflight (must be missing): %w", getErr)
	}
	written := false
	defer func() {
		if written {
			deleteErr := backend.Delete(key)
			if deleteErr != nil && !errors.Is(deleteErr, session.ErrKeyringNotFound) {
				err = errors.Join(err, fmt.Errorf("native cleanup: %w", deleteErr))
			}
		}
	}()
	for _, payload := range []string{"generated-test-only-ä\n|value", "replacement-test-value"} {
		if err = backend.Set(key, payload); err != nil {
			return fmt.Errorf("native set: %w", err)
		}
		written = true
		got, getErr := backend.Get(key)
		if getErr != nil {
			return fmt.Errorf("native get: %w", getErr)
		}
		if got != payload {
			return errors.New("native readback mismatch")
		}
	}
	if err = backend.Delete(key); err != nil {
		return fmt.Errorf("native delete: %w", err)
	}
	written = false
	if _, err = backend.Get(key); !errors.Is(err, session.ErrKeyringNotFound) {
		return errors.New("native entry remained after delete")
	}
	return nil
}

func main() {
	err := probe()
	report := map[string]any{"goos": runtime.GOOS, "goarch": runtime.GOARCH, "go_version": runtime.Version(), "backend": "Go NewOSKeyring", "passed": err == nil, "rust_parity": false}
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
