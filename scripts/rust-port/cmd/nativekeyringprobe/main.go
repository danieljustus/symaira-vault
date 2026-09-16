// Command nativekeyringprobe exercises the real Go OS backend on disposable CI.
// It does not disable the production fallback/test policy: NewOSKeyring is the
// explicit native adapter.
//
// Two modes:
//
//   - roundtrip (default): Go writes, reads back and deletes its own entry.
//     This is resource evidence for the Go backend alone.
//   - write / verify: one half of a CROSS-implementation exchange, where Go
//     writes a value that the Rust adapter reads, or reads back a value the
//     Rust adapter wrote. Until this existed the probe reported
//     `rust_parity: false`, because the two implementations each round-tripped
//     their own entry and neither ever read what the other had written — two
//     independent smokes rather than a parity check.
//
// Payloads cross the process boundary as hex so a byte sequence that is not
// valid UTF-8 survives argv intact; the point of the exchange is byte parity,
// and Go's backend takes a string while Rust's takes a byte slice.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/danieljustus/symaira-vault/internal/session"
)

func authorized() error {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("SYMVAULT_DISPOSABLE_NATIVE_RUNNER") != "1" {
		return errors.New("native keyring probe requires explicit disposable-runner authorization")
	}
	return nil
}

// roundtrip is the original Go-only evidence: set, read back, replace, delete.
func roundtrip() (err error) {
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

// write stores payload under key and leaves it for the other implementation.
// The namespace must be unused, so a collision fails here rather than silently
// overwriting something.
func write(key string, payload []byte) error {
	backend := session.NewOSKeyring()
	if _, getErr := backend.Get(key); !errors.Is(getErr, session.ErrKeyringNotFound) {
		return fmt.Errorf("cross-exchange namespace preflight (must be missing): %w", getErr)
	}
	if err := backend.Set(key, string(payload)); err != nil {
		return fmt.Errorf("cross-exchange set: %w", err)
	}
	return nil
}

// verify reads back what the other implementation wrote, compares it byte for
// byte, then removes the entry and confirms it is gone.
//
// The deferred delete is a safety net for the failure paths, so a mismatch
// still leaves no entry behind; the happy path deletes explicitly so the
// removal itself is checked rather than assumed.
func verify(key string, want []byte) (err error) {
	backend := session.NewOSKeyring()
	removed := false
	defer func() {
		if removed {
			return
		}
		deleteErr := backend.Delete(key)
		if deleteErr != nil && !errors.Is(deleteErr, session.ErrKeyringNotFound) {
			err = errors.Join(err, fmt.Errorf("cross-exchange cleanup: %w", deleteErr))
		}
	}()

	got, getErr := backend.Get(key)
	if getErr != nil {
		return fmt.Errorf("cross-exchange get: %w", getErr)
	}
	if got != string(want) {
		return fmt.Errorf("cross-exchange mismatch: read %d bytes (%s), want %d bytes (%s)",
			len(got), hex.EncodeToString([]byte(got)), len(want), hex.EncodeToString(want))
	}
	if deleteErr := backend.Delete(key); deleteErr != nil {
		return fmt.Errorf("cross-exchange delete: %w", deleteErr)
	}
	removed = true
	if _, absentErr := backend.Get(key); !errors.Is(absentErr, session.ErrKeyringNotFound) {
		return fmt.Errorf("cross-exchange entry remained after delete: %w", absentErr)
	}
	return nil
}

func run(mode, key, payloadHex string) error {
	if err := authorized(); err != nil {
		return err
	}
	switch mode {
	case "roundtrip":
		return roundtrip()
	case "write", "verify":
		if key == "" {
			return errors.New("-key is required for a cross-exchange mode")
		}
		payload, decodeErr := hex.DecodeString(payloadHex)
		if decodeErr != nil {
			return fmt.Errorf("decode -hex: %w", decodeErr)
		}
		if len(payload) == 0 {
			return errors.New("-hex must carry a payload")
		}
		if mode == "write" {
			return write(key, payload)
		}
		return verify(key, payload)
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
}

func main() {
	mode := flag.String("mode", "roundtrip", "roundtrip, write, or verify")
	key := flag.String("key", "", "service|account key for a cross-exchange mode")
	payloadHex := flag.String("hex", "", "hex-encoded payload for a cross-exchange mode")
	flag.Parse()

	err := run(*mode, *key, *payloadHex)
	report := map[string]any{
		"goos": runtime.GOOS, "goarch": runtime.GOARCH, "go_version": runtime.Version(),
		"backend": "Go NewOSKeyring", "mode": *mode, "passed": err == nil,
		// True only for the halves that actually cross implementations. The
		// Go-only roundtrip keeps claiming nothing about Rust.
		"rust_parity": err == nil && (*mode == "write" || *mode == "verify"),
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
