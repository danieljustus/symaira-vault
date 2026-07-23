package health

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"gopkg.in/yaml.v3"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/ui/render"
	"github.com/danieljustus/symaira-vault/internal/vault"
	"github.com/danieljustus/symaira-vault/internal/vault/taint"
)

const recipientsListHint = "run `symvault recipients list`"

func checkRecipients(vaultDir string, _ Options) Result {
	r := Result{ID: "recipients.count", Name: "Recipients"}
	rm := vault.NewRecipientsManager(vaultDir)
	recipients, err := rm.ListRecipients()
	if err != nil {
		if !rm.RecipientsFileExists() {
			r.Status = StatusWarn
			r.Message = "no recipients file — single-device risk"
			r.Hint = "add a backup recipient: `symvault recipients add <age1...>`"
			return r
		}
		r.Status = StatusWarn
		r.Message = "cannot read recipients: " + err.Error()
		return r
	}
	count := len(recipients)
	if count <= 1 {
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("%d recipient (self only) — if identity is lost, vault is unrecoverable", count)
		r.Hint = "add a backup recipient: `symvault recipients add <age1...>`"
	} else {
		r.Status = StatusOK
		r.Message = fmt.Sprintf("%d recipients configured", count)
	}
	return r
}

func checkRecipientsRecovery(vaultDir string, _ Options) Result {
	r := Result{ID: "recipients.recovery", Name: "Recipient decrypt test"}

	rm := vault.NewRecipientsManager(vaultDir)

	if !rm.RecipientsFileExists() {
		r.Status = StatusOK
		r.Message = "no external recipients to test"
		return r
	}

	rawStrings, err := rm.LoadRecipientStrings()
	if err != nil {
		r.Status = StatusFail
		r.Message = "cannot read recipients: " + err.Error()
		r.Hint = recipientsListHint
		return r
	}

	if len(rawStrings) == 0 {
		r.Status = StatusOK
		r.Message = "no external recipients to test"
		return r
	}

	recipients := make([]*age.X25519Recipient, 0, len(rawStrings))
	for _, rs := range rawStrings {
		rec, recErr := vaultcrypto.ValidateRecipient(rs)
		if recErr != nil {
			r.Status = StatusFail
			r.Message = fmt.Sprintf("invalid recipient: %s (%s)", rs, recErr.Error())
			r.Hint = recipientsListHint
			return r
		}
		recipients = append(recipients, rec)
	}

	testIdentity, err := vaultcrypto.GenerateIdentity()
	if err != nil {
		r.Status = StatusFail
		r.Message = "generate test identity: " + err.Error()
		r.Hint = recipientsListHint
		return r
	}

	allRecipients := make([]*age.X25519Recipient, 0, 1+len(recipients))
	allRecipients = append(allRecipients, testIdentity.Recipient())
	allRecipients = append(allRecipients, recipients...)

	testBlob := make([]byte, 32)
	if _, randErr := rand.Read(testBlob); randErr != nil {
		r.Status = StatusFail
		r.Message = "generate test data: " + randErr.Error()
		r.Hint = recipientsListHint
		return r
	}

	ciphertext, err := vaultcrypto.EncryptWithRecipients(testBlob, allRecipients...)
	if err != nil {
		r.Status = StatusFail
		r.Message = "encryption failed: " + err.Error()
		r.Hint = recipientsListHint
		return r
	}

	decrypted, err := vaultcrypto.Decrypt(ciphertext, testIdentity)
	if err != nil {
		r.Status = StatusFail
		r.Message = "decryption failed: " + err.Error()
		r.Hint = recipientsListHint
		return r
	}

	if !bytes.Equal(decrypted, testBlob) {
		r.Status = StatusFail
		r.Message = "decrypted data does not match original"
		r.Hint = recipientsListHint
		return r
	}

	// Count stanzas (lines starting with "-> X25519" before "---")
	lines := strings.Split(string(ciphertext), "\n")
	stanzaCount := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "---") {
			break
		}
		if strings.HasPrefix(line, "-> X25519") {
			stanzaCount++
		}
	}

	expectedCount := len(allRecipients)
	if stanzaCount != expectedCount {
		r.Status = StatusFail
		r.Message = fmt.Sprintf("expected %d stanzas, got %d", expectedCount, stanzaCount)
		r.Hint = recipientsListHint
		return r
	}

	r.Status = StatusOK
	r.Message = fmt.Sprintf("all %d recipients can participate in encryption", len(recipients))
	return r
}

func checkScryptBenchmark(vaultDir string, _ Options) Result {
	r := Result{ID: "crypto.scrypt.benchmark", Name: "Scrypt KDF performance"}

	// Only applies to vaults whose identity.age is still on the legacy
	// scrypt KDF. Argon2id vaults (the default for every newly created
	// vault, and after `migrate kdf`) never read ScryptWorkFactor, so
	// benchmarking scrypt against them produced a permanent false-positive
	// warning on fast hardware (#683) even though the value is unused.
	if raw, readErr := os.ReadFile(filepath.Join(vaultDir, "identity.age")); readErr == nil { //#nosec G304 -- fixed filename under vaultDir, the trusted vault path from the caller
		if vaultcrypto.DetectEncryptedIdentityFormat(raw) == vaultcrypto.Argon2idStanzaType {
			r.Status = StatusOK
			r.Message = "using argon2id KDF — scrypt work factor does not apply"
			return r
		}
	}

	wf, elapsed, err := vaultcrypto.BenchmarkScryptWorkFactor(vaultcrypto.ScryptBenchmarkTarget)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "scrypt benchmark failed: " + err.Error()
		return r
	}

	configPath := filepath.Join(vaultDir, "config.yaml")
	current := vaultcrypto.DefaultScryptWorkFactor
	if cfg, err := configpkg.Load(configPath); err == nil && cfg.Vault != nil && cfg.Vault.ScryptWorkFactor > 0 {
		current = cfg.Vault.ScryptWorkFactor
	}
	explicit := scryptWorkFactorIsExplicit(configPath)

	return scryptBenchmarkResult(current, wf, elapsed, explicit)
}

// scryptBenchmarkResult is the pure comparison behind checkScryptBenchmark,
// split out so slow-machine / fast-machine / boundary cases can be unit
// tested deterministically without depending on real scrypt timing (#683's
// "Tests decken langsame und schnelle Maschinen sowie Grenzwerte ab").
// current is the effective configured work factor (explicit or default); wf
// is what BenchmarkScryptWorkFactor recommends for this machine; explicit
// reports whether current came from a config.yaml key the user set.
func scryptBenchmarkResult(current, wf int, elapsed time.Duration, explicit bool) Result {
	r := Result{ID: "crypto.scrypt.benchmark", Name: "Scrypt KDF performance"}
	switch {
	case wf == current:
		r.Status = StatusOK
		r.Message = fmt.Sprintf("config work factor %d matches recommendation (%d, %.0fms)", current, wf, elapsed.Seconds()*1000)
	case wf > current:
		r.Status = StatusWarn
		if explicit {
			r.Message = fmt.Sprintf("explicitly configured work factor %d is below this machine's recommended %d (%.0fms to reach the %s target)", current, wf, elapsed.Seconds()*1000, vaultcrypto.ScryptBenchmarkTarget)
		} else {
			r.Message = fmt.Sprintf("default work factor %d is below this machine's recommended %d (%.0fms to reach the %s target)", current, wf, elapsed.Seconds()*1000, vaultcrypto.ScryptBenchmarkTarget)
		}
		r.Hint = fmt.Sprintf("set vault.scrypt_work_factor: %d in config.yaml, then run `symvault migrate kdf` — changing the config value alone does not re-encrypt the existing identity.age", wf)
	default:
		r.Status = StatusOK
		r.Message = fmt.Sprintf("config work factor %d exceeds recommendation (benchmark: %d, %.0fms)", current, wf, elapsed.Seconds()*1000)
	}
	return r
}

// scryptWorkFactorIsExplicit reports whether config.yaml has a
// vault.scrypt_work_factor key present, as opposed to the value coming from
// the compiled-in default because the key is absent. This lets the doctor
// message distinguish an implicit legacy default from a value the user
// deliberately chose (#683's "doctor unterscheidet zwischen implizitem
// Legacy-Default und bewusst konfiguriertem Work Factor").
func scryptWorkFactorIsExplicit(configPath string) bool {
	data, err := os.ReadFile(configPath) //#nosec G304 -- fixed filename under vaultDir, the trusted vault path from the caller
	if err != nil {
		return false
	}
	var doc struct {
		Vault struct {
			ScryptWorkFactor *int `yaml:"scrypt_work_factor"`
		} `yaml:"vault"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return false
	}
	return doc.Vault.ScryptWorkFactor != nil
}

func checkKDFModern(vaultDir string, _ Options) Result {
	r := Result{ID: "crypto.kdf.modern", Name: "KDF modernity"}

	raw, readErr := os.ReadFile(filepath.Join(vaultDir, "identity.age")) // #nosec G304 — fixed filename under vaultDir, the trusted vault path from the caller
	if readErr != nil {
		r.Status = StatusWarn
		r.Message = "cannot read identity.age"
		return r
	}
	detected := vaultcrypto.DetectEncryptedIdentityFormat(raw)
	if detected == "" {
		r.Status = StatusWarn
		r.Message = "identity.age has no recognized KDF stanza"
		return r
	}

	var formatVersion int
	if cfg, cfgErr := configpkg.Load(filepath.Join(vaultDir, "config.yaml")); cfgErr == nil && cfg.Vault != nil {
		formatVersion = cfg.Vault.FormatVersion
	}

	fileIsArgon2id := detected == vaultcrypto.Argon2idStanzaType
	configClaimsArgon2id := formatVersion >= 2
	if fileIsArgon2id != configClaimsArgon2id {
		r.Status = StatusWarn
		if fileIsArgon2id {
			r.Message = "identity.age is argon2id but config.FormatVersion < 2 — config is out of sync with the on-disk file"
		} else {
			r.Message = "identity.age is scrypt but config.FormatVersion >= 2 — config is out of sync with the on-disk file"
		}
		r.Hint = "restore the correct identity.age, or run `symvault migrate kdf` to reconcile the file with the config"
		return r
	}

	if !fileIsArgon2id {
		r.Status = StatusWarn
		r.Message = "using scrypt KDF (format v1) — argon2id is recommended for 2025+"
		r.Hint = "run `symvault migrate kdf` after backing up your vault"
		return r
	}
	r.Status = StatusOK
	r.Message = "using argon2id KDF (format v2)"
	return r
}

func checkPasswordStrength(vaultDir string, _ Options) Result {
	r := Result{ID: "password.strength", Name: "Weak password detection"}

	paths, err := vault.List(vaultDir, "", nil)
	if err != nil {
		r.Status = StatusWarn
		r.Message = msgSessionNeeded
		r.Hint = hintSessionNeeded
		return r
	}

	var weakCount int
	var examplePaths []string
	for _, path := range paths {
		entry, err := vault.ReadEntry(vaultDir, path, nil)
		if err != nil {
			continue
		}
		pwd, ok := entry.GetField("password")
		if !ok {
			continue
		}
		pwdStr, ok := pwd.(string)
		if !ok || pwdStr == "" {
			continue
		}
		s := vaultcrypto.AssessPasswordStrength(pwdStr)
		if s.Weak {
			weakCount++
			if len(examplePaths) < 5 {
				safePath := render.ForTerminalLine(
					taint.Wrap(path, taint.Provenance{Source: "doctor.path"}),
					80,
				)
				examplePaths = append(examplePaths, safePath)
			}
		}
	}

	if weakCount > 0 {
		examples := strings.Join(examplePaths, ", ")
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("%d entries with weak passwords", weakCount)
		r.Hint = fmt.Sprintf("review and strengthen: %s", examples)
	} else {
		r.Status = StatusOK
		r.Message = "all entries meet password strength requirements"
	}
	return r
}

func checkPasswordReuse(vaultDir string, _ Options) Result {
	r := Result{ID: "password.reuse", Name: "Password reuse detection"}

	paths, err := vault.List(vaultDir, "", nil)
	if err != nil {
		r.Status = StatusWarn
		r.Message = msgSessionNeeded
		r.Hint = "run `symvault unlock` to decrypt entries for password reuse analysis"
		return r
	}

	hashToPaths := make(map[string][]string)
	for _, path := range paths {
		entry, err := vault.ReadEntry(vaultDir, path, nil)
		if err != nil {
			continue
		}
		pwd, ok := entry.GetField("password")
		if !ok {
			continue
		}
		pwdStr, ok := pwd.(string)
		if !ok || pwdStr == "" {
			continue
		}
		h := sha256.Sum256([]byte(pwdStr))
		hashHex := hex.EncodeToString(h[:])
		safePath := render.ForTerminalLine(
			taint.Wrap(path, taint.Provenance{Source: "doctor.path"}),
			80,
		)
		hashToPaths[hashHex] = append(hashToPaths[hashHex], safePath)
	}

	var reusedGroups [][]string
	for _, ec := range hashToPaths {
		if len(ec) > 1 {
			reusedGroups = append(reusedGroups, ec)
		}
	}

	if len(reusedGroups) > 0 {
		sort.Slice(reusedGroups, func(i, j int) bool {
			return len(reusedGroups[i]) > len(reusedGroups[j])
		})
		r.Status = StatusWarn
		if len(reusedGroups) == 1 {
			sort.Strings(reusedGroups[0])
			r.Message = fmt.Sprintf("%d entries share the same password", len(reusedGroups[0]))
			r.Hint = fmt.Sprintf("entries: %s", strings.Join(reusedGroups[0], ", "))
		} else {
			r.Message = fmt.Sprintf("%d sets of entries with shared passwords", len(reusedGroups))
			if len(reusedGroups) > 3 {
				r.Hint = fmt.Sprintf("top groups: %s", formatReuseGroups(reusedGroups[:3]))
			} else {
				r.Hint = formatReuseGroups(reusedGroups)
			}
		}
	} else {
		r.Status = StatusOK
		r.Message = "no reused passwords detected"
	}
	return r
}

func formatReuseGroups(groups [][]string) string {
	var parts []string
	for _, g := range groups {
		sort.Strings(g)
		entries := strings.Join(g, ", ")
		if len(g) > 5 {
			entries = strings.Join(g[:5], ", ") + fmt.Sprintf(", ... (%d total)", len(g))
		}
		parts = append(parts, fmt.Sprintf("%d entries: %s", len(g), entries))
	}
	return strings.Join(parts, "; ")
}
