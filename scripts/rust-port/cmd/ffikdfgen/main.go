// Command ffikdfgen generates and verifies the Go oracle fixture used by the
// mobile FFI's opt-in scrypt identity migration.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"

	"filippo.io/age"

	vaultconfig "github.com/danieljustus/symaira-vault/internal/config"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

const (
	oracleCommit  = "caadd5e"
	oracleRelease = "v0.22.1"
	identity      = "AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL"
	passphrase    = "rust-interop-fixture-passphrase-v1" // #nosec G101 -- deterministic public fixture input.
)

var oracleFiles = []string{
	"internal/config/schema.go",
	"internal/crypto/argon2id.go",
	"internal/crypto/keygen.go",
	"internal/crypto/symmetric.go",
	"internal/vault/vault.go",
}

type fixture struct {
	SchemaVersion int    `json:"schema_version"`
	Oracle        oracle `json:"oracle"`
	Identity      string `json:"identity"`
	Recipient     string `json:"recipient"`
	Ciphertext    string `json:"ciphertext"`
	PassphraseLen int    `json:"passphrase_length"`
}

type oracle struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFile   string   `json:"generator_file"`
	GeneratorDigest string   `json:"generator_digest"`
}

func rootDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate ffikdfgen")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}

func digestFiles(names []string, read func(string) ([]byte, error)) (string, error) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, name := range sorted {
		data, err := read(name)
		if err != nil {
			return "", err
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(data)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func provenance(root string) (oracle, error) {
	sourceDigest, err := digestFiles(oracleFiles, func(name string) ([]byte, error) {
		return exec.Command("git", "-C", root, "show", oracleCommit+":"+name).Output()
	})
	if err != nil {
		return oracle{}, fmt.Errorf("read pinned Go source: %w", err)
	}
	const generatorFile = "scripts/rust-port/cmd/ffikdfgen/main.go"
	generatorDigest, err := digestFiles([]string{generatorFile}, func(name string) ([]byte, error) {
		return os.ReadFile(filepath.Join(root, name))
	})
	if err != nil {
		return oracle{}, err
	}
	return oracle{
		Commit:          oracleCommit,
		Release:         oracleRelease,
		SourceFiles:     append([]string(nil), oracleFiles...),
		SourceDigest:    sourceDigest,
		GeneratorFile:   generatorFile,
		GeneratorDigest: generatorDigest,
	}, nil
}

func build(root string) (fixture, error) {
	meta, err := provenance(root)
	if err != nil {
		return fixture{}, err
	}
	id, err := age.ParseX25519Identity(identity)
	if err != nil {
		return fixture{}, err
	}
	ciphertext, err := vaultcrypto.EncryptWithPassphrase([]byte(identity), []byte(passphrase), 18)
	if err != nil {
		return fixture{}, err
	}
	return fixture{
		SchemaVersion: 1,
		Oracle:        meta,
		Identity:      identity,
		Recipient:     id.Recipient().String(),
		Ciphertext:    base64.StdEncoding.EncodeToString(ciphertext),
		PassphraseLen: len(passphrase),
	}, nil
}

func verifyGoMigration(value fixture) error {
	ciphertext, err := base64.StdEncoding.DecodeString(value.Ciphertext)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "symvault-ffi-kdf-oracle-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	err = os.MkdirAll(filepath.Join(dir, "entries"), 0o700)
	if err != nil {
		return err
	}
	cfg := vaultconfig.Default()
	cfg.VaultDir = dir
	cfg.Vault = &vaultconfig.VaultConfig{
		FormatVersion:    1,
		ScryptWorkFactor: 18,
		AutoMigrateKDF:   true,
		Argon2idTime:     1,
		Argon2idMemory:   32,
		Argon2idThreads:  1,
	}
	err = cfg.SaveTo(filepath.Join(dir, "config.yaml"))
	if err != nil {
		return err
	}
	identityPath := filepath.Join(dir, "identity.age")
	err = os.WriteFile(identityPath, ciphertext, 0o600)
	if err != nil {
		return err
	}
	_, err = vaultpkg.OpenWithPassphrase(dir, []byte(passphrase))
	if err != nil {
		return fmt.Errorf("go OpenWithPassphrase migration: %w", err)
	}
	backup, err := os.ReadFile(identityPath + ".bak")
	if err != nil || !equal(backup, ciphertext) {
		return errors.New("go migration did not preserve the original identity backup")
	}
	reopened, err := vaultcrypto.LoadIdentityWithArgon2id(identityPath, []byte(passphrase))
	if err != nil || reopened.String() != value.Identity {
		return errors.New("go migration output did not decrypt to the fixture identity")
	}
	return nil
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func verify(root string, value fixture) error {
	meta, err := provenance(root)
	if err != nil {
		return err
	}
	want, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	got, err := json.Marshal(value.Oracle)
	if err != nil {
		return err
	}
	if value.SchemaVersion != 1 || !equal(got, want) {
		return errors.New("fixture provenance changed; regenerate from the pinned Go oracle")
	}
	if value.Identity != identity || value.PassphraseLen != len(passphrase) || value.Ciphertext == "" {
		return errors.New("fixture fields do not match the pinned mobile KDF case")
	}
	id, err := age.ParseX25519Identity(value.Identity)
	if err != nil || id.Recipient().String() != value.Recipient {
		return errors.New("fixture identity and recipient do not match")
	}
	return verifyGoMigration(value)
}

func main() {
	output := flag.String("output", "testdata/port/ffi/kdf-migration.json", "fixture path")
	check := flag.Bool("check", false, "verify fixture provenance and Go migration behavior")
	flag.Parse()
	root := rootDir()
	if *check {
		data, err := os.ReadFile(*output)
		if err != nil {
			panic(err)
		}
		var value fixture
		if err := json.Unmarshal(data, &value); err != nil {
			panic(err)
		}
		if err := verify(root, value); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL FFI KDF fixture:", err)
			os.Exit(1)
		}
		fmt.Println("PASS FFI KDF fixture (Go OpenWithPassphrase migrated and reopened the identity)")
		return
	}
	value, err := build(root)
	if err != nil {
		panic(err)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		panic(err)
	}
	if err := os.WriteFile(*output, data, 0o600); err != nil {
		panic(err)
	}
	fmt.Println("WROTE", *output)
}
