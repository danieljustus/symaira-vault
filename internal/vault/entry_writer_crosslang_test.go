package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"filippo.io/age"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/testutil"
)

// This harness executes the Rust process and the production Go writer/reader.
// Encryption bytes and wall-clock timestamps are not compared across writers;
// payload, path, version, recipient access, and manifest integrity are exact.
func TestEntryWriterGoRustLiveAcceptance(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source")
	}
	repo := filepath.Clean(filepath.Join(filepath.Dir(source), "../.."))
	target := os.Getenv("CARGO_TARGET_DIR")
	if target == "" {
		target = filepath.Join(repo, "target")
	}
	output, err := runSearchIndexCommand(repo, target, "cargo", "build", "--locked", "-p", "symvault-store", "--example", "entry-writer-adapter")
	if err != nil {
		t.Fatalf("build Rust writer: %v\n%s", err, output)
	}
	binary := filepath.Join(target, "debug", "examples", "entry-writer-adapter")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	call := func(t *testing.T, root string, identity *age.X25519Identity, action, path string, entry *Entry) ([]byte, error) {
		t.Helper()
		request, marshalErr := json.Marshal(map[string]any{
			"action": action, "root": root, "identity": identity.String(),
			"path": path, "entry": entry, "now": "2026-09-08T10:11:12Z",
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary)
		cmd.Dir = root
		cmd.Stdin = bytes.NewReader(request)
		cmd.WaitDelay = time.Second
		return cmd.CombinedOutput()
	}
	mustCall := func(t *testing.T, root string, identity *age.X25519Identity, action, path string, entry *Entry, result any) {
		t.Helper()
		out, callErr := call(t, root, identity, action, path, entry)
		if callErr != nil {
			t.Fatalf("Rust %s: %v: %s", action, callErr, out)
		}
		if err := json.Unmarshal(out, result); err != nil {
			t.Fatalf("decode Rust %s: %v", action, err)
		}
	}

	for _, pseudonymize := range []bool{false, true} {
		for _, writer := range []string{"go", "rust", "go-single", "rust-single"} {
			t.Run(fmt.Sprintf("%s_write_pseudonym_%t", writer, pseudonymize), func(t *testing.T) {
				singleRecipient := writer == "go-single" || writer == "rust-single"
				root := t.TempDir()
				identity, other := testutil.TempIdentity(t), testutil.TempIdentity(t)
				cfg := vaultconfig.Default()
				cfg.VaultDir = root
				cfg.Vault = &vaultconfig.VaultConfig{PseudonymizePaths: pseudonymize}
				if err := Init(root, identity, cfg); err != nil {
					t.Fatal(err)
				}
				// Duplicate recipients and the writer identity must be harmless.
				recipients := fmt.Sprintf("# test recipients\n%s\n%s\n%s\n", other.Recipient(), identity.Recipient(), other.Recipient())
				if err := os.WriteFile(filepath.Join(root, "recipients.txt"), []byte(recipients), 0o600); err != nil {
					t.Fatal(err)
				}
				logical := "nested.name/service.v1"
				entry := &Entry{Data: map[string]any{"label": "cross-language-publication"}}
				input, _ := json.Marshal(entry)
				if writer == "go" || writer == "go-single" {
					write := WriteEntryWithRecipients
					if singleRecipient {
						write = WriteEntry
					}
					if err := write(root, logical, entry, identity); err != nil {
						t.Fatal(err)
					}
					FlushManifestUpdates()
				} else {
					var response map[string]string
					action, caseID := "write", "rust_write_entry_with_recipients"
					if singleRecipient {
						action, caseID = "write-single", "rust_write_entry_single_recipient"
					}
					mustCall(t, root, identity, action, logical, entry, &response)
					if response["case_id"] != caseID {
						t.Fatalf("wrong Rust action: %v", response)
					}
				}
				after, _ := json.Marshal(entry)
				if !bytes.Equal(input, after) {
					t.Fatal("writer mutated input")
				}
				storage := entryStoragePath(root, logical, identity, cfg)
				ciphertext, err := os.ReadFile(storage)
				if err != nil {
					t.Fatalf("Go-derived storage path: %v", err)
				}
				if pseudonymize {
					if _, err := os.Stat(filepath.Join(root, "entries", "nested.name")); !os.IsNotExist(err) {
						t.Fatal("pseudonymized writer exposed logical directory")
					}
				}
				// Pseudonym names depend on the writer identity in Go too. Test
				// second-recipient decryption at the known storage path, not by
				// falsely requiring another identity to derive the same filename.
				plaintext, err := vaultcrypto.Decrypt(ciphertext, other)
				if singleRecipient {
					if err == nil {
						vaultcrypto.Wipe(plaintext)
						t.Fatal("single-recipient entry leaked to configured recipient")
					}
					plaintext, err = vaultcrypto.Decrypt(ciphertext, identity)
				}
				if err != nil {
					t.Fatalf("second recipient cannot decrypt entry: %v", err)
				}
				defer vaultcrypto.Wipe(plaintext)
				var decrypted Entry
				if err := json.Unmarshal(plaintext, &decrypted); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(decrypted.Data, entry.Data) || decrypted.Metadata.Version != 1 {
					t.Fatal("stored payload or version differs")
				}
				wantClassification := int32(0)
				if singleRecipient {
					wantClassification = 2 // Go's Confidential class for ordinary strings.
				}
				if int32(decrypted.Classification) != wantClassification {
					t.Fatalf("classification differs: got %d want %d", decrypted.Classification, wantClassification)
				}
				if pseudonymize && decrypted.Path != logical {
					t.Fatal("logical path missing from pseudonymized entry")
				}
				goRead, err := ReadEntry(root, logical, identity)
				if err != nil {
					t.Fatal(err)
				}
				var rustRead Entry
				mustCall(t, root, identity, "read", logical, &Entry{}, &rustRead)
				if !reflect.DeepEqual(goRead, &rustRead) {
					t.Fatal("Go and Rust entry readers differ")
				}
				if (writer == "rust" || writer == "rust-single") && goRead.Metadata.Updated.Format(time.RFC3339) != "2026-09-08T10:11:12Z" {
					t.Fatal("explicit Rust clock not persisted")
				}
				goManifest, err := LoadManifest(root, other)
				if err != nil {
					t.Fatalf("second recipient cannot decrypt manifest: %v", err)
				}
				var rustManifest Manifest
				mustCall(t, root, other, "manifest", "", &Entry{}, &rustManifest)
				if !reflect.DeepEqual(goManifest, &rustManifest) {
					t.Fatal("Go and Rust manifest readers differ")
				}
				hash := fmt.Sprintf("%x", sha256.Sum256(ciphertext))
				if got := goManifest.Entries[logical]; got.SHA256 != hash || got.Size != int64(len(ciphertext)) {
					t.Fatal("manifest does not describe published ciphertext")
				}
				goVerify, err := VerifyManifestIntegrity(root, identity)
				if err != nil || goVerify.OK != 1 || len(goVerify.Missing)+len(goVerify.Tampered)+len(goVerify.Unknown) != 0 {
					t.Fatalf("Go integrity verification failed: %v", err)
				}
				var rustVerify ManifestVerifyResult
				mustCall(t, root, identity, "verify", "", &Entry{}, &rustVerify)
				if rustVerify.OK != 1 || len(rustVerify.Missing)+len(rustVerify.Tampered)+len(rustVerify.Unknown) != 0 {
					t.Fatal("Rust integrity verification failed")
				}
				// An out-of-band raw candidate must remain visible to integrity
				// verification even when configured entry names are pseudonymized.
				if err := os.WriteFile(filepath.Join(root, "entries", "unregistered.age"), ciphertext, 0o600); err != nil {
					t.Fatal(err)
				}
				goVerify, err = VerifyManifestIntegrity(root, identity)
				if err != nil {
					t.Fatal(err)
				}
				mustCall(t, root, identity, "verify", "", &Entry{}, &rustVerify)
				wantUnknown := []string{"unregistered.age"}
				if !reflect.DeepEqual(goVerify.Unknown, wantUnknown) || !reflect.DeepEqual(rustVerify.Unknown, wantUnknown) {
					t.Fatalf("unregistered raw candidate missing from integrity report: go=%#v rust=%#v", goVerify.Unknown, rustVerify.Unknown)
				}
			})
		}
	}

	for _, writer := range []string{"go", "rust"} {
		t.Run(writer+"_invalid_recipient_unchanged", func(t *testing.T) {
			root := t.TempDir()
			identity := testutil.TempIdentity(t)
			cfg := vaultconfig.Default()
			cfg.VaultDir = root
			if err := Init(root, identity, cfg); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "recipients.txt"), []byte("invalid-recipient\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			snapshot := func() map[string]string {
				files := map[string]string{}
				if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					rel, err := filepath.Rel(root, path)
					if err != nil {
						return err
					}
					info, err := d.Info()
					if err != nil {
						return err
					}
					value := info.Mode().String()
					if !d.IsDir() {
						data, err := os.ReadFile(path)
						if err != nil {
							return err
						}
						value += fmt.Sprintf(":%x", sha256.Sum256(data))
					}
					files[rel] = value
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				return files
			}
			before := snapshot()
			entry := &Entry{Data: map[string]any{"label": "negative"}}
			if writer == "go" {
				if err := WriteEntryWithRecipients(root, "new/deep/entry.v1", entry, identity); err == nil {
					t.Fatal("Go accepted invalid recipient")
				}
			} else if _, err := call(t, root, identity, "write", "new/deep/entry.v1", entry); err == nil {
				t.Fatal("Rust accepted invalid recipient")
			}
			if !reflect.DeepEqual(before, snapshot()) {
				t.Fatal("invalid recipient changed filesystem")
			}
		})
	}
}
