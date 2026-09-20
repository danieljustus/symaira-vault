package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"filippo.io/age"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/testutil"
)

// TestReencryptJournalGoRustLiveAcceptance runs both recovery directions on
// one disposable vault. The Go side uses the production staging, commit, and
// journal persistence functions; the Rust side uses Store::open, which is the
// normal recovery entry point.
func TestReencryptJournalGoRustIntegration(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	repo := filepath.Clean(filepath.Join(filepath.Dir(source), "../.."))
	target := cargoTargetDir(repo)
	output, err := runSearchIndexCommandWithTimeout(crosslangBuildTimeout, repo, target, "cargo", "build", "--locked", "-p", "symvault-store", "--example", "reencrypt-journal-adapter")
	if err != nil {
		t.Fatalf("build Rust re-encryption adapter: %v\n%s", err, output)
	}
	binary := filepath.Join(target, "debug", "examples", "reencrypt-journal-adapter")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}

	callRust := func(root string, identity string, action string) (string, error) {
		return runSearchIndexCommand(root, "", binary,
			"--action", action,
			"--root", root,
			"--identity", identity,
			"--path", "cross-language",
		)
	}

	t.Run("go_production_journal_rust_open", func(t *testing.T) {
		root, identity := initTestVault(t)
		mustWriteEntry(t, root, identity, "cross-language", map[string]interface{}{"value": "go-production"})
		FlushManifestUpdates()

		candidates, err := collectReencryptCandidates(entriesDir(root))
		if err != nil {
			t.Fatal(err)
		}
		defer closeReencryptCandidates(candidates)
		if len(candidates) != 1 {
			t.Fatalf("production candidate count = %d, want 1", len(candidates))
		}
		journal := newReencryptJournal(root, candidates)
		if err := journal.persist(root); err != nil {
			t.Fatal(err)
		}
		ciphertext, err := ReencryptBytes(candidates[0].raw, identity, []*age.X25519Recipient{identity.Recipient()})
		if err != nil {
			t.Fatal(err)
		}
		staged, err := reencryptStage(candidates[0], ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if err := reencryptCommit(staged); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(reencryptJournalPath(root)); err != nil {
			t.Fatalf("Go production journal missing before Rust open: %v", err)
		}

		output, err := callRust(root, identity.String(), "read")
		if err != nil {
			t.Fatalf("Rust Store::open recovery: %v\n%s", err, output)
		}
		var got Entry
		if err := json.Unmarshal([]byte(output), &got); err != nil {
			t.Fatalf("decode Rust recovered entry: %v\n%s", err, output)
		}
		if got.Data["value"] != "go-production" {
			t.Fatalf("Rust recovered value = %v", got.Data["value"])
		}
		if _, err := os.Stat(reencryptJournalPath(root)); !os.IsNotExist(err) {
			t.Fatalf("Go journal remains after Rust recovery: %v", err)
		}
		assertNoReencryptTemps(t, root)
	})

	t.Run("rust_production_shape_go_open", func(t *testing.T) {
		root, identity := initTestVault(t)
		mustWriteEntry(t, root, identity, "cross-language", map[string]interface{}{"value": "rust-shaped"})
		FlushManifestUpdates()
		if output, err := callRust(root, identity.String(), "prepare-rust-crash"); err != nil {
			t.Fatalf("Rust crash fixture: %v\n%s", err, output)
		}
		if _, err := os.Stat(reencryptJournalPath(root)); err != nil {
			t.Fatalf("Rust crash journal missing: %v", err)
		}
		if _, err := Open(root, identity); err != nil {
			t.Fatalf("Go Open recovery: %v", err)
		}
		got, err := ReadEntry(root, "cross-language", identity)
		if err != nil {
			t.Fatal(err)
		}
		if got.Data["value"] != "rust-shaped" {
			t.Fatalf("Go recovered value = %v", got.Data["value"])
		}
		if _, err := os.Stat(reencryptJournalPath(root)); !os.IsNotExist(err) {
			t.Fatalf("Rust journal remains after Go recovery: %v", err)
		}
		assertNoReencryptTemps(t, root)
	})

	t.Run("rust_production_journal_go_open", func(t *testing.T) {
		// This subtest launches the actual Rust CLI re-encryption command. The
		// store example above intentionally remains a recovery adapter; this test
		// proves only production journal publication followed by Go recovery. The
		// binary is supplied by the explicit cross-language gate so ordinary Go
		// tests do not build Rust as a side effect.
		rawBinary := os.Getenv("SYMVAULT_RUST_BINARY")
		if rawBinary == "" {
			t.Fatal("SYMVAULT_RUST_BINARY is required for the production Rust crash gate")
		}
		rustBinary, absErr := filepath.Abs(rawBinary)
		if absErr != nil {
			t.Fatalf("resolve SYMVAULT_RUST_BINARY: %v", absErr)
		}
		if runtime.GOOS == "windows" && filepath.Ext(rustBinary) == "" {
			rustBinary += ".exe"
		}
		if info, statErr := os.Stat(rustBinary); statErr != nil || !info.Mode().IsRegular() {
			t.Fatalf("SYMVAULT_RUST_BINARY is not a regular file: %s", rustBinary)
		}

		root, identity, passphrase, expectedValue := initPassphraseReencryptVault(t)
		newIdentity := testutil.TempIdentity(t)
		cmd := exec.Command(
			rustBinary,
			"--vault", root,
			"recipients", "add", newIdentity.Recipient().String(), "--reencrypt",
		)
		cmd.Dir = root
		cmd.Env = append(os.Environ(),
			"CI=1",
			"SYMVAULT_TEST_KEYRING=memory",
			"SYMVAULT_ALLOW_ENV_PASSPHRASE=1",
			"SYMVAULT_PASSPHRASE="+string(passphrase),
			"HOME="+filepath.Join(root, "home"),
			"USERPROFILE="+filepath.Join(root, "home"),
		)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatalf("start production Rust re-encryption: %v", err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		waited := false
		wait := func() error {
			if waited {
				return nil
			}
			waited = true
			return <-done
		}
		defer func() {
			if !waited {
				_ = cmd.Process.Kill()
				_ = <-done
			}
		}()

		journal := reencryptJournalPath(root)
		deadline := time.Now().Add(15 * time.Second)
		killed := false
		for time.Now().Before(deadline) {
			if _, err := os.Stat(journal); err == nil {
				if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
					t.Fatalf("kill production Rust re-encryption: %v", err)
				}
				killed = true
				break
			} else if !os.IsNotExist(err) {
				t.Fatalf("inspect production Rust journal: %v", err)
			}
			select {
			case err := <-done:
				waited = true
				t.Fatalf("production Rust re-encryption exited before journal kill: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
			default:
			}
			time.Sleep(time.Millisecond)
		}
		if !killed {
			_ = cmd.Process.Kill()
			_ = wait()
			t.Fatalf("production Rust re-encryption did not publish a journal before deadline\nstdout=%s\nstderr=%s", stdout.String(), stderr.String())
		}
		if err := wait(); err == nil {
			t.Fatalf("production Rust re-encryption unexpectedly succeeded after kill")
		}

		if _, err := Open(root, identity); err != nil {
			t.Fatalf("Go Open recovery after actual Rust crash: %v", err)
		}
		for i := 0; i < 8; i++ {
			path := fmt.Sprintf("cross-language-%02d", i)
			got, err := ReadEntry(root, path, identity)
			if err != nil {
				t.Fatalf("read recovered entry %s after actual Rust crash: %v", path, err)
			}
			value, ok := got.Data["value"].(string)
			if !ok || value != expectedValue {
				t.Fatalf("recovered value for %s differs from full fixture", path)
			}
		}
		if _, err := os.Stat(journal); !os.IsNotExist(err) {
			t.Fatalf("production Rust journal remains after Go recovery: %v", err)
		}
		assertNoReencryptTemps(t, root)
	})
}

// initPassphraseReencryptVault makes a Go vault that the Rust CLI can unlock
// through its normal passphrase path. Several large entries widen the bounded
// journal-observation window without adding a production-only pause hook.
func initPassphraseReencryptVault(t *testing.T) (string, *age.X25519Identity, []byte, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "entries"), 0o700); err != nil {
		t.Fatal(err)
	}
	identity := testutil.TempIdentity(t)
	passphrase := []byte("cross-language production passphrase")
	if err := vaultcrypto.SaveIdentity(identity, filepath.Join(root, "identity.age"), cloneBytes(passphrase), 10); err != nil {
		t.Fatalf("save passphrase identity: %v", err)
	}
	cfg := vaultconfig.Default()
	cfg.VaultDir = root
	cfg.Vault = &vaultconfig.VaultConfig{FormatVersion: 1, ScryptWorkFactor: 10}
	if err := cfg.SaveTo(filepath.Join(root, "config.yaml")); err != nil {
		t.Fatalf("save passphrase config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "recipients.txt"), []byte(identity.Recipient().String()+"\n"), 0o600); err != nil {
		t.Fatalf("write recipients: %v", err)
	}
	// Keep the fixture large enough to expose journal publication, while
	// avoiding an unnecessary multi-dozen-megabyte encryption delay on CI.
	large := string(bytes.Repeat([]byte("rust-production-"), 32*1024))
	for i := 0; i < 8; i++ {
		path := fmt.Sprintf("cross-language-%02d", i)
		mustWriteEntry(t, root, identity, path, map[string]interface{}{"value": large})
	}
	FlushManifestUpdates()
	return root, identity, passphrase, large
}
