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
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
)

import (
	"filippo.io/age"

	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

const (
	oracleCommit  = "caadd5e"
	oracleRelease = "v0.22.1"
	passphrase    = "rust-interop-fixture-passphrase-v1" // #nosec G101 -- deterministic non-secret fixture input.
)

var oracleSourceFiles = []string{
	"internal/crypto/age.go",
	"internal/crypto/argon2id.go",
	"internal/crypto/keygen.go",
	"internal/crypto/symmetric.go",
	"internal/vault/reencrypt.go",
}

var generatorFiles = []string{
	"internal/crypto/interop.go",
	"scripts/rust-port/cmd/cryptogen/main.go",
	"scripts/rust-port/cmd/cryptoverify/main.go",
}

var (
	requiredIdentityNames  = []string{"fixed_1", "fixed_2", "fixed_3"}
	requiredAgeNames       = []string{"two_recipients", "three_recipients"}
	requiredScryptNames    = []string{"legacy_work_factor_12"}
	requiredArgonNames     = []string{"current_tiny_fixture_params"}
	requiredZeroNames      = []string{"historical_zero_key_length_23"}
	requiredMalformedNames = []string{"empty", "not_age", "bad_stanza"}
	requiredLimitNames     = []string{
		"scrypt_work_factor_zero",
		"scrypt_work_factor_above_max",
		"argon2_time_zero",
		"argon2_time_above_max",
		"argon2_memory_zero",
		"argon2_memory_above_max",
		"argon2_threads_zero",
		"argon2_threads_above_max",
		"argon2_memory_below_threads",
	}
	requiredWrongPassphraseNames = []string{
		"age_wrong_identity",
		"scrypt_wrong_passphrase",
		"argon2id_wrong_passphrase",
	}
	requiredMigrationNames = []string{
		"legacy_scrypt",
		"current_argon2id",
		"unknown_envelope",
	}
)

type fixture struct {
	SchemaVersion        int                   `json:"schema_version"`
	Oracle               oracle                `json:"oracle"`
	Identities           []identityCase        `json:"identities"`
	AgeCases             []ageCase             `json:"age_cases"`
	ScryptCases          []envelopeCase        `json:"scrypt_cases"`
	Argon2idCases        []envelopeCase        `json:"argon2id_cases"`
	ZeroKeyCases         []zeroKeyCase         `json:"zero_key_cases"`
	ReencryptCases       []reencryptCase       `json:"reencrypt_cases"`
	MalformedCases       []malformedCase       `json:"malformed_cases"`
	LimitCases           []limitCase           `json:"limit_cases"`
	WrongPassphraseCases []wrongPassphraseCase `json:"wrong_passphrase_cases"`
	MigrationCases       []migrationCase       `json:"migration_cases"`
}

type oracle struct {
	Commit          string   `json:"commit"`
	Release         string   `json:"release"`
	SourceFiles     []string `json:"source_files"`
	SourceDigest    string   `json:"source_digest"`
	GeneratorFiles  []string `json:"generator_files"`
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
type reencryptCase struct {
	Name                  string   `json:"name"`
	Plaintext             string   `json:"plaintext"`
	SourceIdentity        string   `json:"source_identity"`
	SourceCiphertext      string   `json:"source_ciphertext"`
	SourceRecipients      []string `json:"source_recipients"`
	ReencryptedCiphertext string   `json:"reencrypted_ciphertext"`
	Recipients            []string `json:"recipients"`
	RemovedRecipient      string   `json:"removed_recipient"`
	RemovedIdentity       string   `json:"removed_identity"`
}
type malformedCase struct {
	Name          string `json:"name"`
	Input         string `json:"input"`
	ExpectedClass string `json:"expected_class"`
}
type limitCase struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	WorkFactor    uint8  `json:"work_factor"`
	Time          uint32 `json:"time"`
	Memory        uint32 `json:"memory"`
	Threads       uint8  `json:"threads"`
	ExpectedClass string `json:"expected_class"`
}
type wrongPassphraseCase struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Ciphertext    string `json:"ciphertext"`
	ExpectedClass string `json:"expected_class"`
}
type migrationCase struct {
	Name           string `json:"name"`
	Input          string `json:"input"`
	Format         string `json:"format"`
	NeedsMigration bool   `json:"needs_migration"`
}

func digestFiles(root string, names []string) (string, error) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, name := range sorted {
		data, err := os.ReadFile(filepath.Join(root, name)) // #nosec G304 -- source names are fixed by the generator.
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

func pinnedDigest(root string, revision string, names []string) (string, error) {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, name := range sorted {
		cmd := exec.Command("git", "-C", root, "show", revision+":"+name) // #nosec G204 -- revision and names are fixed constants.
		data, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("read pinned oracle file %s: %w", name, err)
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(data)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func rootDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate cryptogen")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}

func authoritativeOracle(root string) (oracle, error) {
	sourceDigest, err := pinnedDigest(root, oracleCommit, oracleSourceFiles)
	if err != nil {
		return oracle{}, err
	}
	generatorDigest, err := digestFiles(root, generatorFiles)
	if err != nil {
		return oracle{}, err
	}
	return oracle{
		Commit:          oracleCommit,
		Release:         oracleRelease,
		SourceFiles:     append([]string(nil), oracleSourceFiles...),
		SourceDigest:    sourceDigest,
		GeneratorFiles:  append([]string(nil), generatorFiles...),
		GeneratorDigest: generatorDigest,
	}, nil
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
	meta, err := authoritativeOracle(root)
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

	twoPlaintext := "safe Rust/Go age interoperability vector — two recipients"
	two, err := cryptopkg.EncryptWithRecipients([]byte(twoPlaintext), parsed[0].Recipient(), parsed[1].Recipient())
	if err != nil {
		return fixture{}, err
	}
	threePlaintext := "safe Rust/Go age interoperability vector — three recipients"
	three, err := cryptopkg.EncryptWithRecipients([]byte(threePlaintext), parsed[0].Recipient(), parsed[1].Recipient(), parsed[2].Recipient())
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

	addPlaintext := "re-encryption add recipient"
	addSource, err := cryptopkg.EncryptWithRecipients([]byte(addPlaintext), parsed[0].Recipient())
	if err != nil {
		return fixture{}, err
	}
	addRecipients := []*age.X25519Recipient{parsed[0].Recipient(), parsed[1].Recipient()}
	addReencrypted, err := vaultpkg.ReencryptBytes(addSource, parsed[0], addRecipients)
	if err != nil {
		return fixture{}, err
	}
	removePlaintext := "re-encryption remove recipient"
	removeSourceRecipients := []*age.X25519Recipient{parsed[0].Recipient(), parsed[1].Recipient(), parsed[2].Recipient()}
	removeSource, err := cryptopkg.EncryptWithRecipients([]byte(removePlaintext), removeSourceRecipients...)
	if err != nil {
		return fixture{}, err
	}
	removeRecipients := []*age.X25519Recipient{parsed[0].Recipient(), parsed[1].Recipient()}
	removeReencrypted, err := vaultpkg.ReencryptBytes(removeSource, parsed[0], removeRecipients)
	if err != nil {
		return fixture{}, err
	}
	reencryptCases := []reencryptCase{
		{Name: "add_recipient", Plaintext: addPlaintext, SourceIdentity: ids[0].Identity, SourceCiphertext: b64(addSource), SourceRecipients: []string{ids[0].Recipient}, ReencryptedCiphertext: b64(addReencrypted), Recipients: []string{ids[0].Recipient, ids[1].Recipient}, RemovedRecipient: ids[2].Recipient, RemovedIdentity: ids[2].Identity},
		{Name: "remove_recipient", Plaintext: removePlaintext, SourceIdentity: ids[0].Identity, SourceCiphertext: b64(removeSource), SourceRecipients: []string{ids[0].Recipient, ids[1].Recipient, ids[2].Recipient}, ReencryptedCiphertext: b64(removeReencrypted), Recipients: []string{ids[0].Recipient, ids[1].Recipient}, RemovedRecipient: ids[2].Recipient, RemovedIdentity: ids[2].Identity},
	}
	return fixture{
		SchemaVersion: 1,
		Oracle:        meta,
		Identities: []identityCase{
			ids[0], ids[1], ids[2],
		},
		AgeCases: []ageCase{
			{Name: "two_recipients", Plaintext: twoPlaintext, Ciphertext: b64(two), Recipients: []string{ids[0].Recipient, ids[1].Recipient}},
			{Name: "three_recipients", Plaintext: threePlaintext, Ciphertext: b64(three), Recipients: []string{ids[0].Recipient, ids[1].Recipient, ids[2].Recipient}},
		},
		ScryptCases:    []envelopeCase{{Name: "legacy_work_factor_12", Plaintext: "legacy scrypt envelope", Ciphertext: b64(scrypt)}},
		Argon2idCases:  []envelopeCase{{Name: "current_tiny_fixture_params", Plaintext: "current argon2id envelope", Ciphertext: b64(argon), Params: &argonParams}},
		ZeroKeyCases:   []zeroKeyCase{{Name: "historical_zero_key_length_23", Ciphertext: b64(zero), PassphraseLength: 23}},
		ReencryptCases: reencryptCases,
		MalformedCases: []malformedCase{
			{Name: "empty", Input: "", ExpectedClass: "malformed_envelope"},
			{Name: "not_age", Input: "not an age envelope\n", ExpectedClass: "malformed_envelope"},
			{Name: "bad_stanza", Input: "age-encryption.org/v1\n-> argon2id bad\n!!!\n--- header end\n", ExpectedClass: "malformed_envelope"},
		},
		LimitCases: []limitCase{
			{Name: "scrypt_work_factor_zero", Kind: "scrypt", WorkFactor: 0, ExpectedClass: "parameter_bounds"},
			{Name: "scrypt_work_factor_above_max", Kind: "scrypt", WorkFactor: 23, ExpectedClass: "parameter_bounds"},
			{Name: "argon2_time_zero", Kind: "argon2id", Time: 0, Memory: 32, Threads: 1, ExpectedClass: "parameter_bounds"},
			{Name: "argon2_time_above_max", Kind: "argon2id", Time: 17, Memory: 32, Threads: 1, ExpectedClass: "parameter_bounds"},
			{Name: "argon2_memory_zero", Kind: "argon2id", Time: 1, Memory: 0, Threads: 1, ExpectedClass: "parameter_bounds"},
			{Name: "argon2_memory_above_max", Kind: "argon2id", Time: 1, Memory: 2_097_153, Threads: 1, ExpectedClass: "parameter_bounds"},
			{Name: "argon2_threads_zero", Kind: "argon2id", Time: 1, Memory: 32, Threads: 0, ExpectedClass: "parameter_bounds"},
			{Name: "argon2_threads_above_max", Kind: "argon2id", Time: 1, Memory: 64, Threads: 17, ExpectedClass: "parameter_bounds"},
			{Name: "argon2_memory_below_threads", Kind: "argon2id", Time: 1, Memory: 4, Threads: 2, ExpectedClass: "parameter_bounds"},
		},
		WrongPassphraseCases: []wrongPassphraseCase{
			{Name: "age_wrong_identity", Kind: "age", Ciphertext: b64(two), ExpectedClass: "wrong_passphrase_or_key"},
			{Name: "scrypt_wrong_passphrase", Kind: "scrypt", Ciphertext: b64(scrypt), ExpectedClass: "wrong_passphrase_or_key"},
			{Name: "argon2id_wrong_passphrase", Kind: "argon2id", Ciphertext: b64(argon), ExpectedClass: "wrong_passphrase_or_key"},
		},
		MigrationCases: []migrationCase{
			{Name: "legacy_scrypt", Input: "age-encryption.org/v1\n-> scrypt abc 12\n--- header end\n", Format: "scrypt", NeedsMigration: true},
			{Name: "current_argon2id", Input: "age-encryption.org/v1\n-> argon2id abc t=1,m=32,p=1\n--- header end\n", Format: "argon2id", NeedsMigration: false},
			{Name: "unknown_envelope", Input: "not an age envelope\n", Format: "unknown", NeedsMigration: false},
		},
	}, nil
}

func exactNames(got []string, want []string) error {
	if len(got) != len(want) {
		return fmt.Errorf("case cardinality %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			return fmt.Errorf("case %d named %q, want %q", i, got[i], want[i])
		}
	}
	return nil
}

func validateFixture(value fixture, expected oracle) error {
	if value.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schema_version %d", value.SchemaVersion)
	}
	if value.Oracle.Commit != expected.Commit || value.Oracle.Release != expected.Release ||
		value.Oracle.SourceDigest != expected.SourceDigest || value.Oracle.GeneratorDigest != expected.GeneratorDigest ||
		!sameStrings(value.Oracle.SourceFiles, expected.SourceFiles) || !sameStrings(value.Oracle.GeneratorFiles, expected.GeneratorFiles) {
		return errors.New("crypto fixture provenance or schema drift; regenerate from the pinned Go oracle")
	}
	groups := []struct {
		got  []string
		want []string
	}{
		{identityNames(value.Identities), requiredIdentityNames},
		{ageNames(value.AgeCases), requiredAgeNames},
		{envelopeNames(value.ScryptCases), requiredScryptNames},
		{envelopeNames(value.Argon2idCases), requiredArgonNames},
		{zeroNames(value.ZeroKeyCases), requiredZeroNames},
		{malformedNames(value.MalformedCases), requiredMalformedNames},
		{limitNames(value.LimitCases), requiredLimitNames},
		{wrongNames(value.WrongPassphraseCases), requiredWrongPassphraseNames},
		{migrationNames(value.MigrationCases), requiredMigrationNames},
	}
	for _, group := range groups {
		if err := exactNames(group.got, group.want); err != nil {
			return err
		}
	}
	for _, tc := range value.AgeCases {
		if len(tc.Recipients) < 2 || tc.Plaintext == "" || tc.Ciphertext == "" {
			return fmt.Errorf("age case %q is incomplete", tc.Name)
		}
	}
	for _, tc := range value.MalformedCases {
		if tc.ExpectedClass != "malformed_envelope" {
			return fmt.Errorf("malformed case %q has unexpected class %q", tc.Name, tc.ExpectedClass)
		}
	}
	for _, tc := range value.LimitCases {
		if tc.ExpectedClass != "parameter_bounds" || (tc.Kind != "scrypt" && tc.Kind != "argon2id") {
			return fmt.Errorf("limit case %q is incomplete", tc.Name)
		}
	}
	for _, tc := range value.WrongPassphraseCases {
		if tc.ExpectedClass != "wrong_passphrase_or_key" || tc.Ciphertext == "" {
			return fmt.Errorf("wrong-passphrase case %q is incomplete", tc.Name)
		}
	}
	for _, tc := range value.MigrationCases {
		if tc.Format != "scrypt" && tc.Format != "argon2id" && tc.Format != "unknown" {
			return fmt.Errorf("migration case %q has unknown format %q", tc.Name, tc.Format)
		}
	}
	return nil
}

func sameStrings(a, b []string) bool {
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
func identityNames(v []identityCase) []string {
	r := make([]string, len(v))
	for i := range v {
		r[i] = v[i].Name
	}
	return r
}
func ageNames(v []ageCase) []string {
	r := make([]string, len(v))
	for i := range v {
		r[i] = v[i].Name
	}
	return r
}
func envelopeNames(v []envelopeCase) []string {
	r := make([]string, len(v))
	for i := range v {
		r[i] = v[i].Name
	}
	return r
}
func zeroNames(v []zeroKeyCase) []string {
	r := make([]string, len(v))
	for i := range v {
		r[i] = v[i].Name
	}
	return r
}
func malformedNames(v []malformedCase) []string {
	r := make([]string, len(v))
	for i := range v {
		r[i] = v[i].Name
	}
	return r
}
func limitNames(v []limitCase) []string {
	r := make([]string, len(v))
	for i := range v {
		r[i] = v[i].Name
	}
	return r
}
func wrongNames(v []wrongPassphraseCase) []string {
	r := make([]string, len(v))
	for i := range v {
		r[i] = v[i].Name
	}
	return r
}
func migrationNames(v []migrationCase) []string {
	r := make([]string, len(v))
	for i := range v {
		r[i] = v[i].Name
	}
	return r
}

func verify(root, path string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- the path is the explicit fixture selected by the generator.
	if err != nil {
		return err
	}
	var got fixture
	if err = json.Unmarshal(data, &got); err != nil {
		return fmt.Errorf("decode fixture: %w", err)
	}
	expected, err := authoritativeOracle(root)
	if err != nil {
		return err
	}
	if err := validateFixture(got, expected); err != nil {
		return err
	}

	identities := make(map[string]*age.X25519Identity, len(got.Identities))
	for _, tc := range got.Identities {
		id, parseErr := age.ParseX25519Identity(tc.Identity)
		if parseErr != nil || id.Recipient().String() != tc.Recipient || cryptopkg.Fingerprint(tc.Recipient) != tc.Fingerprint {
			return fmt.Errorf("identity vector %q failed production verification", tc.Name)
		}
		identities[tc.Recipient] = id
	}
	for _, tc := range got.AgeCases {
		cipher, decodeErr := base64.StdEncoding.DecodeString(tc.Ciphertext)
		if decodeErr != nil {
			return fmt.Errorf("age vector %q: %w", tc.Name, decodeErr)
		}
		for _, recipient := range tc.Recipients {
			id := identities[recipient]
			if id == nil {
				return fmt.Errorf("age vector %q references unknown recipient", tc.Name)
			}
			plain, decryptErr := cryptopkg.Decrypt(cipher, id)
			if decryptErr != nil || string(plain) != tc.Plaintext {
				return fmt.Errorf("age vector %q failed production verification for %s", tc.Name, recipient)
			}
		}
	}
	for _, tc := range got.ScryptCases {
		cipher, decodeErr := base64.StdEncoding.DecodeString(tc.Ciphertext)
		if decodeErr != nil {
			return decodeErr
		}
		plain, decryptErr := cryptopkg.DecryptWithPassphrase(cipher, []byte(passphrase))
		if decryptErr != nil || string(plain) != tc.Plaintext {
			return fmt.Errorf("scrypt vector %q failed production verification", tc.Name)
		}
	}
	for _, tc := range got.Argon2idCases {
		cipher, decodeErr := base64.StdEncoding.DecodeString(tc.Ciphertext)
		if decodeErr != nil {
			return decodeErr
		}
		plain, decryptErr := cryptopkg.DecryptWithPassphraseArgon2id(cipher, []byte(passphrase))
		if decryptErr != nil || string(plain) != tc.Plaintext {
			return fmt.Errorf("argon2id vector %q failed production verification", tc.Name)
		}
	}
	for _, tc := range got.ReencryptCases {
		source, err := base64.StdEncoding.DecodeString(tc.SourceCiphertext)
		if err != nil {
			return err
		}
		stored, err := base64.StdEncoding.DecodeString(tc.ReencryptedCiphertext)
		if err != nil {
			return err
		}
		sourceIdentity, err := age.ParseX25519Identity(tc.SourceIdentity)
		if err != nil {
			return fmt.Errorf("re-encryption vector %q has invalid source identity: %w", tc.Name, err)
		}
		recipients, err := cryptopkg.ParseRecipients(tc.Recipients)
		if err != nil {
			return fmt.Errorf("re-encryption vector %q has invalid recipients: %w", tc.Name, err)
		}
		seen := make(map[string]struct{}, len(tc.Recipients))
		for _, recipient := range tc.Recipients {
			if _, ok := seen[recipient]; ok {
				return fmt.Errorf("re-encryption vector %q does not have exact unique recipients", tc.Name)
			}
			seen[recipient] = struct{}{}
		}
		if len(recipients) < 2 {
			return fmt.Errorf("re-encryption vector %q needs multiple recipients", tc.Name)
		}
		if _, ok := seen[tc.RemovedRecipient]; ok {
			return fmt.Errorf("re-encryption vector %q removed recipient is retained", tc.Name)
		}
		regenerated, err := vaultpkg.ReencryptBytes(source, sourceIdentity, recipients)
		if err != nil {
			return fmt.Errorf("re-encryption vector %q failed production seam: %w", tc.Name, err)
		}
		for _, ciphertext := range [][]byte{stored, regenerated} {
			plain, err := cryptopkg.Decrypt(ciphertext, sourceIdentity)
			if err != nil || string(plain) != tc.Plaintext {
				return fmt.Errorf("re-encryption vector %q failed retained source verification", tc.Name)
			}
			cryptopkg.Wipe(plain)
		}
		removed, err := cryptopkg.ValidateRecipient(tc.RemovedRecipient)
		if err != nil {
			return fmt.Errorf("re-encryption vector %q has invalid removed recipient: %w", tc.Name, err)
		}
		removedIdentity, err := age.ParseX25519Identity(tc.RemovedIdentity)
		if err != nil || removed.String() != removedIdentity.Recipient().String() {
			return fmt.Errorf("re-encryption vector %q removed identity does not match recipient", tc.Name)
		}
		if _, err := cryptopkg.Decrypt(stored, removedIdentity); err == nil {
			return fmt.Errorf("re-encryption vector %q removed recipient still decrypts", tc.Name)
		}
	}
	for _, tc := range got.ZeroKeyCases {
		cipher, decodeErr := base64.StdEncoding.DecodeString(tc.Ciphertext)
		if decodeErr != nil {
			return decodeErr
		}
		if _, recoverErr := cryptopkg.RecoverZeroKeyIdentity(cipher, tc.PassphraseLength); recoverErr != nil {
			return fmt.Errorf("zero-key vector %q failed production verification", tc.Name)
		}
	}
	for _, tc := range got.MalformedCases {
		if _, decryptErr := cryptopkg.Decrypt([]byte(tc.Input), identities[got.Identities[0].Recipient]); decryptErr == nil {
			return fmt.Errorf("malformed vector %q was accepted by production", tc.Name)
		}
	}
	for _, tc := range got.WrongPassphraseCases {
		cipher, decodeErr := base64.StdEncoding.DecodeString(tc.Ciphertext)
		if decodeErr != nil {
			return decodeErr
		}
		var decryptErr error
		switch tc.Kind {
		case "age":
			decryptErr = func() error { _, err := cryptopkg.Decrypt(cipher, identities[got.Identities[2].Recipient]); return err }()
		case "scrypt":
			_, decryptErr = cryptopkg.DecryptWithPassphrase(cipher, []byte("wrong-passphrase"))
		case "argon2id":
			_, decryptErr = cryptopkg.DecryptWithPassphraseArgon2id(cipher, []byte("wrong-passphrase"))
		default:
			return fmt.Errorf("wrong-passphrase vector %q has unknown kind %q", tc.Name, tc.Kind)
		}
		if decryptErr == nil {
			return fmt.Errorf("wrong-passphrase vector %q was accepted by production", tc.Name)
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
		fmt.Printf("PASS crypto fixture (Go production verification: %d identities, %d age, %d malformed, %d limits, %d wrong-passphrase, %d migration)\n", len(requiredIdentityNames), len(requiredAgeNames), len(requiredMalformedNames), len(requiredLimitNames), len(requiredWrongPassphraseNames), len(requiredMigrationNames))
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
