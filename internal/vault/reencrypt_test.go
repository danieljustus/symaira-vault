package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/config"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/testutil"
)

// initTestVault creates and initializes a temp vault, returning the dir and identity.
func initTestVault(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	cfg := config.Default()
	cfg.VaultDir = vaultDir
	if err := Init(vaultDir, identity, cfg); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	return vaultDir, identity
}

func TestReencryptAll_NilIdentity(t *testing.T) {
	vaultDir := t.TempDir()
	recipient := testutil.TempIdentity(t).Recipient()

	err := ReencryptAll(vaultDir, nil, []*age.X25519Recipient{recipient})
	if !errors.Is(err, vaultcrypto.ErrNilIdentity) {
		t.Errorf("ReencryptAll(nil identity) error = %v, want ErrNilIdentity", err)
	}
}

func TestReencryptAll_NoRecipients(t *testing.T) {
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)

	err := ReencryptAll(vaultDir, identity, nil)
	if err == nil {
		t.Error("ReencryptAll(no recipients) = nil, want error")
	}
}

func TestReencryptAll_EmptyVault(t *testing.T) {
	vaultDir, identity := initTestVault(t)
	recipient := testutil.TempIdentity(t).Recipient()

	err := ReencryptAll(vaultDir, identity, []*age.X25519Recipient{recipient})
	if err != nil {
		t.Errorf("ReencryptAll(empty vault) = %v, want nil", err)
	}
}

func TestReencryptAll_MultipleEntries(t *testing.T) {
	vaultDir, identity1 := initTestVault(t)
	identity2 := testutil.TempIdentity(t)

	// Write multiple entries encrypted with identity1.
	entries := map[string]map[string]any{
		"github/password": {"username": "alice", "password": "gh-secret"},
		"aws/access-key":  {"access_key": "AKIA123", "secret_key": "wJalr"},
		"db/postgres":     {"host": "db.example.com", "port": "5432", "password": "pg-secret"},
	}
	for name, data := range entries {
		if err := WriteEntry(vaultDir, name, &Entry{Data: data}, identity1); err != nil {
			t.Fatalf("WriteEntry(%s) error = %v", name, err)
		}
	}

	// Re-encrypt with both identities as recipients.
	recipients := []*age.X25519Recipient{
		identity1.Recipient(),
		identity2.Recipient(),
	}
	if err := ReencryptAll(vaultDir, identity1, recipients); err != nil {
		t.Fatalf("ReencryptAll() error = %v", err)
	}

	// Both identities must be able to read every entry.
	for name, wantData := range entries {
		for _, id := range []*age.X25519Identity{identity1, identity2} {
			got, err := ReadEntry(vaultDir, name, id)
			if err != nil {
				t.Errorf("ReadEntry(%s, %s) error = %v", name, id.Recipient().String()[:12], err)
				continue
			}
			for k, want := range wantData {
				if got.Data[k] != want {
					t.Errorf("ReadEntry(%s, %s).Data[%s] = %v, want %v",
						name, id.Recipient().String()[:12], k, got.Data[k], want)
				}
			}
		}
	}
}

func TestReencryptAll_MissingIdentity(t *testing.T) {
	vaultDir, identity1 := initTestVault(t)
	identity2 := testutil.TempIdentity(t)

	// Write an entry with identity1.
	if err := WriteEntry(vaultDir, "test/entry", &Entry{Data: map[string]any{"key": "val"}}, identity1); err != nil {
		t.Fatalf("WriteEntry() error = %v", err)
	}

	// Re-encrypt with only identity2 as recipient (identity1 is NOT a recipient).
	recipients := []*age.X25519Recipient{identity2.Recipient()}
	if err := ReencryptAll(vaultDir, identity1, recipients); err != nil {
		t.Fatalf("ReencryptAll() error = %v", err)
	}

	// identity1 must NOT be able to read (it's no longer a recipient).
	_, err := ReadEntry(vaultDir, "test/entry", identity1)
	if err == nil {
		t.Error("ReadEntry(original identity) after re-encrypt without it = nil, want error")
	}

	// identity2 must be able to read.
	got, err := ReadEntry(vaultDir, "test/entry", identity2)
	if err != nil {
		t.Fatalf("ReadEntry(new identity) error = %v", err)
	}
	if got.Data["key"] != "val" {
		t.Errorf("Data[key] = %v, want val", got.Data["key"])
	}
}

func TestReencryptAll_UnreadableEntry(t *testing.T) {
	vaultDir, identity := initTestVault(t)
	recipient := testutil.TempIdentity(t).Recipient()

	// Write a valid entry.
	if err := WriteEntry(vaultDir, "good/entry", &Entry{Data: map[string]any{"k": "v"}}, identity); err != nil {
		t.Fatalf("WriteEntry() error = %v", err)
	}

	// Place a corrupt (not valid age) .age file in entries/.
	badPath := filepath.Join(entriesDir(vaultDir), "bad", "corrupt.age")
	if err := os.MkdirAll(filepath.Dir(badPath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(badPath, []byte("not-a-valid-age-file"), 0o600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	// ReencryptAll must return an error because the corrupt file fails decryption.
	err := ReencryptAll(vaultDir, identity, []*age.X25519Recipient{recipient})
	if err == nil {
		t.Error("ReencryptAll(corrupt file) = nil, want error")
	}
}

func TestReencryptAll_WalkError(t *testing.T) {
	// Vault dir exists but entries/ is missing — walk should fail.
	vaultDir := t.TempDir()
	identity := testutil.TempIdentity(t)
	recipient := testutil.TempIdentity(t).Recipient()

	err := ReencryptAll(vaultDir, identity, []*age.X25519Recipient{recipient})
	if err == nil {
		t.Error("ReencryptAll(missing entries dir) = nil, want error")
	}
}

func TestReencryptAll_NestedDirectories(t *testing.T) {
	vaultDir, identity1 := initTestVault(t)
	identity2 := testutil.TempIdentity(t)

	// Write entries in nested subdirectories.
	entries := map[string]map[string]any{
		"work/prod/db":     {"host": "prod-db.internal", "password": "s3cret"},
		"work/staging/api": {"url": "https://staging.api", "token": "tok123"},
		"personal/email":   {"email": "alice@example.com", "password": "mail-pw"},
	}
	for name, data := range entries {
		if err := WriteEntry(vaultDir, name, &Entry{Data: data}, identity1); err != nil {
			t.Fatalf("WriteEntry(%s) error = %v", name, err)
		}
	}

	// Re-encrypt including both identities.
	recipients := []*age.X25519Recipient{
		identity1.Recipient(),
		identity2.Recipient(),
	}
	if err := ReencryptAll(vaultDir, identity1, recipients); err != nil {
		t.Fatalf("ReencryptAll() error = %v", err)
	}

	// Verify all entries readable by both identities.
	for name, wantData := range entries {
		got, err := ReadEntry(vaultDir, name, identity2)
		if err != nil {
			t.Errorf("ReadEntry(%s, identity2) error = %v", name, err)
			continue
		}
		for k, want := range wantData {
			if got.Data[k] != want {
				t.Errorf("ReadEntry(%s).Data[%s] = %v, want %v", name, k, got.Data[k], want)
			}
		}
	}
}

func TestReencryptFile_SingleFile(t *testing.T) {
	vaultDir, identity1 := initTestVault(t)
	identity2 := testutil.TempIdentity(t)

	// Write a single entry.
	entryData := map[string]any{"secret": "value123"}
	if err := WriteEntry(vaultDir, "single/entry", &Entry{Data: entryData}, identity1); err != nil {
		t.Fatalf("WriteEntry() error = %v", err)
	}

	// Re-encrypt with only identity2 as recipient.
	if err := ReencryptAll(vaultDir, identity1, []*age.X25519Recipient{identity2.Recipient()}); err != nil {
		t.Fatalf("ReencryptAll() error = %v", err)
	}

	// identity1 can no longer read.
	_, err := ReadEntry(vaultDir, "single/entry", identity1)
	if err == nil {
		t.Error("ReadEntry(original) after re-encrypt = nil, want error")
	}

	// identity2 can read.
	got, err := ReadEntry(vaultDir, "single/entry", identity2)
	if err != nil {
		t.Fatalf("ReadEntry(new) error = %v", err)
	}
	if got.Data["secret"] != "value123" {
		t.Errorf("Data[secret] = %v, want value123", got.Data["secret"])
	}
}

func TestReencryptBytes_CrossLanguageSeam(t *testing.T) {
	vaultDir := t.TempDir()
	identity1 := testutil.TempIdentity(t)
	identity2 := testutil.TempIdentity(t)
	removed := testutil.TempIdentity(t)
	plaintext := []byte("side-effect-free re-encryption seam")
	source, err := vaultcrypto.EncryptWithRecipients(plaintext, identity1.Recipient())
	if err != nil {
		t.Fatalf("encrypt source: %v", err)
	}
	got, err := ReencryptBytes(source, identity1, []*age.X25519Recipient{
		identity1.Recipient(),
		identity2.Recipient(),
	})
	if err != nil {
		t.Fatalf("ReencryptBytes: %v", err)
	}
	for _, identity := range []*age.X25519Identity{identity1, identity2} {
		decrypted, err := vaultcrypto.Decrypt(got, identity)
		if err != nil || string(decrypted) != string(plaintext) {
			t.Errorf("retained identity decrypt = %q, %v; want %q", decrypted, err, plaintext)
		}
	}
	if _, err := vaultcrypto.Decrypt(got, removed); err == nil {
		t.Fatal("removed identity decrypted re-encrypted content")
	}
	entries, err := os.ReadDir(vaultDir)
	if err != nil {
		t.Fatalf("read seam vault directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("ReencryptBytes wrote %d files", len(entries))
	}
}

func TestReencryptAll_SymlinkEntryRejected(t *testing.T) {
	vaultDir, identity := initTestVault(t)
	outside := filepath.Join(t.TempDir(), "outside.age")
	if err := os.WriteFile(outside, []byte("outside bytes"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	link := filepath.Join(entriesDir(vaultDir), "symlink.age")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := ReencryptAll(vaultDir, identity, []*age.X25519Recipient{testutil.TempIdentity(t).Recipient()}); err == nil {
		t.Fatal("ReencryptAll accepted symlink entry")
	}
	got, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("read outside file: %v", err)
	}
	if string(got) != "outside bytes" {
		t.Fatalf("outside file changed to %q", got)
	}
}

func TestReencryptAll_RollsBackOnStagingFailure(t *testing.T) {
	vaultDir, identity := initTestVault(t)
	writeReencryptTestEntries(t, vaultDir, identity)
	before := snapshotReencryptTestFiles(t, vaultDir)
	restoreReencryptHooks(t)
	calls := 0
	original := reencryptStage
	reencryptStage = func(candidate *reencryptCandidate, ciphertext []byte) (*reencryptStaged, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("injected staging failure")
		}
		return original(candidate, ciphertext)
	}
	if err := ReencryptAll(vaultDir, identity, []*age.X25519Recipient{testutil.TempIdentity(t).Recipient()}); err == nil {
		t.Fatal("ReencryptAll accepted injected staging failure")
	}
	assertReencryptTestFilesUnchanged(t, vaultDir, before)
	assertNoReencryptTemps(t, entriesDir(vaultDir))
}

func TestReencryptAll_RollsBackOnCommitFailure(t *testing.T) {
	vaultDir, identity := initTestVault(t)
	writeReencryptTestEntries(t, vaultDir, identity)
	before := snapshotReencryptTestFiles(t, vaultDir)
	restoreReencryptHooks(t)
	calls := 0
	original := reencryptCommit
	reencryptCommit = func(item *reencryptStaged) error {
		calls++
		if calls == 2 {
			return errors.New("injected commit failure")
		}
		return original(item)
	}
	if err := ReencryptAll(vaultDir, identity, []*age.X25519Recipient{testutil.TempIdentity(t).Recipient()}); err == nil {
		t.Fatal("ReencryptAll accepted injected commit failure")
	}
	assertReencryptTestFilesUnchanged(t, vaultDir, before)
	assertNoReencryptTemps(t, entriesDir(vaultDir))
}

func TestReencryptAll_RollsBackOnManifestFailure(t *testing.T) {
	vaultDir, identity := initTestVault(t)
	writeReencryptTestEntries(t, vaultDir, identity)
	before := snapshotReencryptTestFiles(t, vaultDir)
	restoreReencryptHooks(t)
	reencryptRebuildManifest = func(string, *age.X25519Identity) error {
		return errors.New("injected manifest failure")
	}
	if err := ReencryptAll(vaultDir, identity, []*age.X25519Recipient{testutil.TempIdentity(t).Recipient()}); err == nil {
		t.Fatal("ReencryptAll accepted injected manifest failure")
	}
	assertReencryptTestFilesUnchanged(t, vaultDir, before)
	assertNoReencryptTemps(t, entriesDir(vaultDir))
}

func TestReencryptAll_PreservesModesAndManifestHashes(t *testing.T) {
	vaultDir, identity := initTestVault(t)
	writeReencryptTestEntries(t, vaultDir, identity)
	onePath := filepath.Join(entriesDir(vaultDir), "one.age")
	if err := os.Chmod(onePath, 0o640); err != nil {
		t.Fatalf("chmod entry: %v", err)
	}
	newIdentity := testutil.TempIdentity(t)
	if err := ReencryptAll(vaultDir, identity, []*age.X25519Recipient{newIdentity.Recipient()}); err != nil {
		t.Fatalf("ReencryptAll: %v", err)
	}
	if info, err := os.Stat(onePath); err != nil {
		t.Fatalf("stat entry: %v", err)
	} else if info.Mode().Perm() != 0o640 {
		t.Errorf("entry mode = %o, want 640", info.Mode().Perm())
	}
	manifest, err := LoadManifest(vaultDir, identity)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	for _, name := range []string{"one", "two"} {
		data, err := os.ReadFile(filepath.Join(entriesDir(vaultDir), name+entryExtAge))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		hash := sha256.Sum256(data)
		if got, want := manifest.Entries[name].SHA256, hex.EncodeToString(hash[:]); got != want {
			t.Errorf("manifest hash for %s = %q, want %q", name, got, want)
		}
	}
}

func TestReencryptAll_FinalReplacementDetected(t *testing.T) {
	vaultDir, identity := initTestVault(t)
	writeReencryptTestEntries(t, vaultDir, identity)
	restoreReencryptHooks(t)
	original := reencryptCommit
	replaced := false
	reencryptCommit = func(item *reencryptStaged) error {
		if !replaced {
			replaced = true
			path := item.candidate.path
			if err := os.Rename(path, path+".raced-original"); err != nil {
				return err
			}
			if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
				return err
			}
		}
		return original(item)
	}
	if err := ReencryptAll(vaultDir, identity, []*age.X25519Recipient{testutil.TempIdentity(t).Recipient()}); err == nil {
		t.Fatal("ReencryptAll accepted final-name replacement race")
	}
	if _, err := os.Stat(filepath.Join(entriesDir(vaultDir), "one.age.raced-original")); err != nil {
		t.Fatalf("original raced file missing: %v", err)
	}
}

func restoreReencryptHooks(t *testing.T) {
	t.Helper()
	stage, commit, rollback, cleanup, rebuild := reencryptStage, reencryptCommit, reencryptRollback, reencryptCleanup, reencryptRebuildManifest
	t.Cleanup(func() {
		reencryptStage, reencryptCommit, reencryptRollback, reencryptCleanup, reencryptRebuildManifest = stage, commit, rollback, cleanup, rebuild
	})
}

func writeReencryptTestEntries(t *testing.T, vaultDir string, identity *age.X25519Identity) {
	t.Helper()
	for name, value := range map[string]string{"one": "first", "two": "second"} {
		if err := WriteEntry(vaultDir, name, &Entry{Data: map[string]any{"value": value}}, identity); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	FlushManifestUpdates()
}

func snapshotReencryptTestFiles(t *testing.T, vaultDir string) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	for _, name := range []string{"one.age", "two.age", manifestFileName} {
		path := filepath.Join(vaultDir, name)
		if name != manifestFileName {
			path = filepath.Join(entriesDir(vaultDir), name)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("snapshot %s: %v", name, err)
		}
		result[name] = data
	}
	return result
}

func assertReencryptTestFilesUnchanged(t *testing.T, vaultDir string, before map[string][]byte) {
	t.Helper()
	for name, want := range before {
		path := filepath.Join(vaultDir, name)
		if name != manifestFileName {
			path = filepath.Join(entriesDir(vaultDir), name)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read rollback file %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("rollback changed %s", name)
		}
	}
}

func assertNoReencryptTemps(t *testing.T, root string) {
	t.Helper()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(info.Name(), ".reencrypt-") {
			t.Errorf("temporary/backup file left behind: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk for temporary files: %v", err)
	}
}
