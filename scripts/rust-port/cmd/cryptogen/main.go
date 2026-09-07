// Command cryptogen creates safe, Go-oracle crypto vectors for the Rust port.
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
	"path/filepath"
	"sort"

	"filippo.io/age"

	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
)

const (
	oracleCommit  = "caadd5e"
	oracleRelease = "v0.22.1"
	passphrase    = "rust-interop-fixture-passphrase-v1"
	sourceRoot    = "internal/crypto"
)

var sourceFiles = []string{
	"internal/crypto/age.go",
	"internal/crypto/argon2id.go",
	"internal/crypto/keygen.go",
	"internal/crypto/symmetric.go",
	"internal/crypto/interop.go",
	"internal/vault/reencrypt.go",
}

type fixture struct {
	SchemaVersion  int             `json:"schema_version"`
	Oracle         oracle          `json:"oracle"`
	Identities     []identityCase  `json:"identities"`
	AgeCases       []ageCase       `json:"age_cases"`
	ScryptCases    []envelopeCase  `json:"scrypt_cases"`
	Argon2idCases  []envelopeCase  `json:"argon2id_cases"`
	ZeroKeyCases   []zeroKeyCase   `json:"zero_key_cases"`
	MalformedCases []malformedCase `json:"malformed_cases"`
}
type oracle struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorDigest string   `json:"generator_digest"`
}
type identityCase struct {
	Name        string `json:"name"`
	Identity    string `json:"identity"`
	Recipient   string `json:"recipient"`
	Fingerprint string `json:"fingerprint"`
}
type ageCase struct {
	Name       string   `json:"name"`
	Plaintext  string   `json:"plaintext"`
	Ciphertext string   `json:"ciphertext"`
	Recipients []string `json:"recipients"`
}
type envelopeCase struct {
	Name       string                    `json:"name"`
	Plaintext  string                    `json:"plaintext"`
	Ciphertext string                    `json:"ciphertext"`
	Params     *cryptopkg.Argon2idParams `json:"params,omitempty"`
}
type zeroKeyCase struct {
	Name             string `json:"name"`
	Ciphertext       string `json:"ciphertext"`
	PassphraseLength int    `json:"passphrase_length"`
}
type malformedCase struct {
	Name  string `json:"name"`
	Input string `json:"input"`
}

func digestFiles(root string, names []string) (string, error) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, name := range sorted {
		data, err := os.ReadFile(filepath.Join(root, name))
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
func rootDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return filepath.Clean(cwd)
}
func generatorDigest(root string) (string, error) {
	return digestFiles(root, []string{"scripts/rust-port/cmd/cryptogen/main.go"})
}
func b64(value []byte) string { return base64.StdEncoding.EncodeToString(value) }
func mustID(value string) *age.X25519Identity {
	id, err := age.ParseX25519Identity(value)
	if err != nil {
		panic(err)
	}
	return id
}

func build(root string) (fixture, error) {
	sourceDigest, err := digestFiles(root, sourceFiles)
	if err != nil {
		return fixture{}, err
	}
	generatorDigest, err := generatorDigest(root)
	if err != nil {
		return fixture{}, err
	}
	fixed := []string{
		"AGE-SECRET-KEY-1HS3YTK69EJH0ZYM8ANNNDWQMPT7ZMLPYGTMC47F5T4EDJ5N7EYMQ4L5CDL",
		"AGE-SECRET-KEY-18HD87KNMWKY3RW97YR2PYU6HGWDZXAGW6JF74LNNHUA6A8K5ZF9QTWUTK3",
		"AGE-SECRET-KEY-15KR576PHDPLRQS08427S6X2G492S6GTVELZ6WHN8AKMWW90T0HES2KQ597",
	}
	ids := make([]identityCase, 0, len(fixed))
	parsed := make([]*age.X25519Identity, 0, len(fixed))
	for i, value := range fixed {
		id := mustID(value)
		parsed = append(parsed, id)
		recipient := id.Recipient().String()
		ids = append(ids, identityCase{Name: fmt.Sprintf("fixed_%d", i+1), Identity: value, Recipient: recipient, Fingerprint: cryptopkg.Fingerprint(recipient)})
	}
	plaintext := "safe Rust/Go age interoperability vector — no production data"
	multi, err := cryptopkg.EncryptWithRecipients([]byte(plaintext), parsed[0].Recipient(), parsed[1].Recipient())
	if err != nil {
		return fixture{}, err
	}
	scrypt, err := cryptopkg.EncryptWithPassphrase([]byte("legacy scrypt envelope"), []byte(passphrase), 12)
	if err != nil {
		return fixture{}, err
	}
	argonParams := cryptopkg.Argon2idParams{Time: 1, Memory: 32, Threads: 1}
	argon, err := cryptopkg.EncryptWithPassphraseArgon2id([]byte("current argon2id envelope"), []byte(passphrase), argonParams)
	if err != nil {
		return fixture{}, err
	}
	zero, err := cryptopkg.EncryptZeroKeyFixture(parsed[0], 23, argonParams)
	if err != nil {
		return fixture{}, err
	}
	return fixture{
		SchemaVersion:  1,
		Oracle:         oracle{Commit: oracleCommit, Release: oracleRelease, SourceFiles: sourceFiles, SourceDigest: sourceDigest, GeneratorDigest: generatorDigest},
		Identities:     ids,
		AgeCases:       []ageCase{{Name: "two_recipients", Plaintext: plaintext, Ciphertext: b64(multi), Recipients: []string{ids[0].Recipient, ids[1].Recipient}}},
		ScryptCases:    []envelopeCase{{Name: "legacy_work_factor_12", Plaintext: "legacy scrypt envelope", Ciphertext: b64(scrypt)}},
		Argon2idCases:  []envelopeCase{{Name: "current_tiny_fixture_params", Plaintext: "current argon2id envelope", Ciphertext: b64(argon), Params: &argonParams}},
		ZeroKeyCases:   []zeroKeyCase{{Name: "historical_zero_key_length_23", Ciphertext: b64(zero), PassphraseLength: 23}},
		MalformedCases: []malformedCase{{Name: "empty", Input: ""}, {Name: "not_age", Input: "not an age envelope\n"}, {Name: "bad_stanza", Input: "age-encryption.org/v1\n-> argon2id bad\n!!!\n--- header end\n"}},
	}, nil
}

func verify(root, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var got fixture
	if err = json.Unmarshal(data, &got); err != nil {
		return fmt.Errorf("decode fixture: %w", err)
	}
	expected, err := build(root)
	if err != nil {
		return err
	}
	if got.SchemaVersion != 1 || got.Oracle.Commit != oracleCommit || got.Oracle.Release != oracleRelease || got.Oracle.SourceDigest != expected.Oracle.SourceDigest || got.Oracle.GeneratorDigest != expected.Oracle.GeneratorDigest {
		return errors.New("crypto fixture provenance or schema drift; regenerate from the Go oracle")
	}
	for _, tc := range got.Identities {
		id, err := age.ParseX25519Identity(tc.Identity)
		if err != nil || id.Recipient().String() != tc.Recipient || cryptopkg.Fingerprint(tc.Recipient) != tc.Fingerprint {
			return fmt.Errorf("identity vector %q failed production verification", tc.Name)
		}
	}
	id := mustID(got.Identities[0].Identity)
	for _, tc := range got.AgeCases {
		cipher, err := base64.StdEncoding.DecodeString(tc.Ciphertext)
		if err != nil {
			return err
		}
		plain, err := cryptopkg.Decrypt(cipher, id)
		if err != nil || string(plain) != tc.Plaintext {
			return fmt.Errorf("age vector %q failed production verification", tc.Name)
		}
	}
	for _, tc := range got.ScryptCases {
		cipher, err := base64.StdEncoding.DecodeString(tc.Ciphertext)
		if err != nil {
			return err
		}
		plain, err := cryptopkg.DecryptWithPassphrase(cipher, []byte(passphrase))
		if err != nil || string(plain) != tc.Plaintext {
			return fmt.Errorf("scrypt vector %q failed production verification", tc.Name)
		}
	}
	for _, tc := range got.Argon2idCases {
		cipher, err := base64.StdEncoding.DecodeString(tc.Ciphertext)
		if err != nil {
			return err
		}
		plain, err := cryptopkg.DecryptWithPassphraseArgon2id(cipher, []byte(passphrase))
		if err != nil || string(plain) != tc.Plaintext {
			return fmt.Errorf("argon2id vector %q failed production verification", tc.Name)
		}
	}
	return nil
}

func main() {
	output := flag.String("output", "testdata/port/crypto/age-kdf.json", "fixture path")
	check := flag.Bool("check", false, "verify fixture provenance and production decryptability")
	flag.Parse()
	root := rootDir()
	if *check {
		if err := verify(root, *output); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL crypto fixture: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("PASS crypto fixture (Go production verification)\n")
		return
	}
	value, err := build(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL generate crypto fixture: %v\n", err)
		os.Exit(1)
	}
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	content = append(content, '\n')
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		panic(err)
	}
	if err := os.WriteFile(*output, content, 0o600); err != nil {
		panic(err)
	}
	fmt.Printf("WROTE %s\n", *output)
}
