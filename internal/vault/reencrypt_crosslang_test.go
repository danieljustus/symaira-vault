package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"filippo.io/age"
)

// TestReencryptJournalGoRustLiveAcceptance runs both recovery directions on
// one disposable vault. The Go side uses the production staging, commit, and
// journal persistence functions; the Rust side uses Store::open, which is the
// normal recovery entry point.
func TestReencryptJournalGoRustLiveAcceptance(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	repo := filepath.Clean(filepath.Join(filepath.Dir(source), "../.."))
	target := cargoTargetDir(repo)
	output, err := runSearchIndexCommandWithTimeout(5*time.Minute, repo, target, "cargo", "build", "--locked", "-p", "symvault-store", "--example", "reencrypt-journal-adapter")
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
}
