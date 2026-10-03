package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unsafe"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const ageArgon2idLabel = "symvault-argon2id-v1"

// Argon2idStanzaType is the age stanza type identifier for argon2id-encrypted identities.
const Argon2idStanzaType = "argon2id"

type argon2idRecipient struct {
	passphrase []byte
	params     Argon2idParams
}

// NewArgon2idRecipient builds an age.Recipient that derives its wrapping key
// from the passphrase via Argon2id.
//
// The passphrase is copied into a buffer owned by the recipient. This is
// deliberate: callers alias their secret with unsafe.String and Wipe it
// immediately after construction, so the recipient must not retain a reference
// to the caller's backing array — otherwise key derivation (which happens later,
// inside age.Encrypt) would run over zeroed memory and the passphrase would be
// silently ignored.
func NewArgon2idRecipient(passphrase string, params Argon2idParams) age.Recipient {
	params = resolveArgon2idParams(params)
	if params.Time == 0 && params.Memory == 0 && params.Threads == 0 {
		params = DefaultArgon2idParams()
	}
	return &argon2idRecipient{
		passphrase: append([]byte(nil), passphrase...),
		params:     params,
	}
}

func (r *argon2idRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	salt, err := GenerateArgon2idSalt()
	if err != nil {
		return nil, err
	}

	l, err := Argon2idDeriveKey(r.passphrase, salt, r.params)
	if err != nil {
		return nil, fmt.Errorf("argon2id derive key: %w", err)
	}

	kdf := hkdf.New(sha256.New, l, salt, []byte(ageArgon2idLabel))
	wrapKey := make([]byte, Argon2idKeyLen)
	if _, readErr := io.ReadFull(kdf, wrapKey); readErr != nil {
		return nil, fmt.Errorf("hkdf expand: %w", readErr)
	}

	aead, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("create aead: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	body := aead.Seal(nonce, nonce, fileKey, nil)

	params := fmt.Sprintf("t=%d,m=%d,p=%d", r.params.Time, r.params.Memory, r.params.Threads)

	return []*age.Stanza{{
		Type: Argon2idStanzaType,
		Args: []string{
			base64.RawStdEncoding.EncodeToString(salt),
			params,
		},
		Body: body,
	}}, nil
}

type argon2idIdentity struct {
	passphrase []byte
	legacy     bool
}

// NewArgon2idIdentity builds an age.Identity that derives its unwrapping key
// from the passphrase via Argon2id. The passphrase is copied into a buffer
// owned by the identity for the same reason as NewArgon2idRecipient: callers
// Wipe their copy immediately, and Unwrap runs later inside age.Decrypt.
func NewArgon2idIdentity(passphrase string) age.Identity {
	return &argon2idIdentity{
		passphrase: append([]byte(nil), passphrase...),
	}
}

func (id *argon2idIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	return unwrapArgon2idStanzas(stanzas, id.passphrase, id.legacy)
}

// preflightArgon2id validates the entire matching stanza set before any KDF.
func preflightArgon2id(stanzas []*age.Stanza, legacy bool) error {
	count := 0
	var work uint64
	limit := uint64(AutomaticArgon2MaxMemory * AutomaticArgon2MaxTime)
	if legacy {
		limit = uint64(MaxArgon2idMemory * MaxArgon2idTime)
	}
	for _, s := range stanzas {
		if s.Type != Argon2idStanzaType {
			continue
		}
		count++
		if count > argon2MaxStanzas {
			return ErrArgon2Policy
		}
		if len(s.Args) != 2 || len(s.Args[0]) != 22 || len(s.Body) != 44 {
			return ErrArgon2Malformed
		}
		salt, err := base64.RawStdEncoding.Strict().DecodeString(s.Args[0])
		if err != nil || len(salt) != SaltLen {
			return ErrArgon2Malformed
		}
		params, err := parseArgon2idParams(s.Args[1])
		if err != nil {
			return err
		}
		if !legacy {
			if err := validateAutomaticArgon2(params); err != nil {
				return err
			}
		}
		work += uint64(argon2EffectiveMemory(params)) * uint64(params.Time)
		if work > limit {
			return ErrArgon2Policy
		}
	}
	return nil
}

func unwrapArgon2idStanzas(stanzas []*age.Stanza, passphrase []byte, legacy bool) ([]byte, error) {
	if err := preflightArgon2id(stanzas, legacy); err != nil {
		return nil, err
	}
	for _, s := range stanzas {
		if s.Type != Argon2idStanzaType {
			continue
		}
		salt, _ := base64.RawStdEncoding.Strict().DecodeString(s.Args[0])
		params, _ := parseArgon2idParams(s.Args[1])
		l, err := deriveArgon2idKey(passphrase, salt, params, legacy)
		if err != nil {
			return nil, err
		}
		kdf := hkdf.New(sha256.New, l, salt, []byte(ageArgon2idLabel))
		wrapKey := make([]byte, Argon2idKeyLen)
		_, err = io.ReadFull(kdf, wrapKey)
		Wipe(l)
		if err != nil {
			return nil, err
		}
		aead, err := chacha20poly1305.New(wrapKey)
		Wipe(wrapKey)
		if err != nil {
			return nil, err
		}
		fileKey, err := aead.Open(nil, s.Body[:12], s.Body[12:], nil)
		if err == nil && len(fileKey) == 16 {
			return fileKey, nil
		}
		Wipe(fileKey)
	}
	return nil, age.ErrIncorrectIdentity
}

// InspectArgon2idPolicy classifies header budgets without allocating a KDF.
// Header classification alone does not authenticate the encrypted identity.
func InspectArgon2idPolicy(raw []byte) (bool, error) {
	inspector := &argon2PolicyInspector{}
	_, err := age.Decrypt(bytes.NewReader(raw), inspector)
	if !inspector.called {
		return false, ErrArgon2Malformed
	}
	if inspector.err != nil {
		return false, inspector.err
	}
	_ = err // The inspector intentionally supplies no file key.
	return inspector.needsMigration, nil
}

type argon2PolicyInspector struct {
	called, needsMigration bool
	err                    error
}

func (i *argon2PolicyInspector) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	i.called = true
	matching := false
	for _, stanza := range stanzas {
		matching = matching || stanza.Type == Argon2idStanzaType
	}
	if !matching {
		i.err = ErrArgon2Malformed
		return nil, age.ErrIncorrectIdentity
	}
	i.err = preflightArgon2id(stanzas, true)
	if i.err == nil {
		i.needsMigration = errors.Is(preflightArgon2id(stanzas, false), ErrArgon2Policy)
	}
	return nil, age.ErrIncorrectIdentity
}

// MaxZeroKeyPassphraseLen bounds the historical zero-key recovery hint before
// it can allocate a zero-filled buffer or enter Argon2id.
const MaxZeroKeyPassphraseLen = 1024

// Zero-key recovery errors are deliberately fixed and contain no decrypted
// identity, recipient, or age parser details.
var (
	ErrZeroKeyAuthority     = errors.New("zero-key authority is invalid")
	ErrZeroKeyPassphraseLen = errors.New("zero-key length is invalid")
	ErrZeroKeyRecovery      = errors.New("zero-key recovery failed")
)

// ZeroKeyAuthority is the caller-owned public contract used to authorize a
// recovered identity. At least one field must be supplied independently of the
// encrypted envelope. When both are supplied they must describe the same
// canonical recipient.
type ZeroKeyAuthority struct {
	ExpectedRecipient   string
	ExpectedFingerprint string
}

// NewZeroKeyAuthority constructs an authority from an expected recipient and
// optional Go-compatible fingerprint. The values must come from outside the
// encrypted identity envelope.
func NewZeroKeyAuthority(expectedRecipient, expectedFingerprint string) ZeroKeyAuthority {
	return ZeroKeyAuthority{
		ExpectedRecipient:   expectedRecipient,
		ExpectedFingerprint: expectedFingerprint,
	}
}

// ZeroKeyAuthorityForRecipient constructs recipient-only authority.
func ZeroKeyAuthorityForRecipient(expectedRecipient string) ZeroKeyAuthority {
	return NewZeroKeyAuthority(expectedRecipient, "")
}

// ZeroKeyAuthorityForFingerprint constructs fingerprint-only authority.
func ZeroKeyAuthorityForFingerprint(expectedFingerprint string) ZeroKeyAuthority {
	return NewZeroKeyAuthority("", expectedFingerprint)
}

func validPublicKeyFingerprint(value string) bool {
	if len(value) != 39 {
		return false
	}
	groups := strings.Split(value, " ")
	if len(groups) != 8 {
		return false
	}
	for _, group := range groups {
		if len(group) != 4 {
			return false
		}
		for _, b := range []byte(group) {
			if (b < '0' || b > '9') && (b < 'A' || b > 'F') {
				return false
			}
		}
	}
	return true
}

func validateZeroKeyAuthority(authority ZeroKeyAuthority) error {
	expectedRecipient := strings.TrimSpace(authority.ExpectedRecipient)
	expectedFingerprint := authority.ExpectedFingerprint
	if expectedRecipient == "" && expectedFingerprint == "" {
		return ErrZeroKeyAuthority
	}
	if expectedRecipient != "" {
		recipient, err := ValidateRecipient(expectedRecipient)
		if err != nil || recipient.String() != expectedRecipient {
			return ErrZeroKeyAuthority
		}
		if expectedFingerprint != "" {
			if !validPublicKeyFingerprint(expectedFingerprint) || Fingerprint(expectedRecipient) != expectedFingerprint {
				return ErrZeroKeyAuthority
			}
		}
		return nil
	}
	if !validPublicKeyFingerprint(expectedFingerprint) {
		return ErrZeroKeyAuthority
	}
	return nil
}

func validateRecoveredZeroKeyIdentity(identity *age.X25519Identity, authority ZeroKeyAuthority) error {
	if identity == nil {
		return ErrZeroKeyRecovery
	}
	public := identity.Recipient().String()
	recipient, err := ValidateRecipient(public)
	if err != nil || recipient.String() != public || !validPublicKeyFingerprint(Fingerprint(public)) {
		return ErrZeroKeyRecovery
	}
	if expected := strings.TrimSpace(authority.ExpectedRecipient); expected != "" && expected != public {
		return ErrZeroKeyRecovery
	}
	if expected := authority.ExpectedFingerprint; expected != "" && expected != Fingerprint(public) {
		return ErrZeroKeyRecovery
	}
	return nil
}

// zeroKeyArgon2idIdentity is an age.Identity that derives the wrap key from
// Argon2id(zeros[n], salt, params) instead of from a real passphrase. It is
// the recovery counterpart to argon2idIdentity for files wrapped under the
// pre-#476 zero-key bug. The recovered identity is checked against the
// caller-supplied authority by RecoverZeroKeyIdentity.
type zeroKeyArgon2idIdentity struct {
	n int
}

func (z *zeroKeyArgon2idIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if z.n <= 0 || z.n > MaxZeroKeyPassphraseLen {
		return nil, ErrZeroKeyPassphraseLen
	}
	zeros := make([]byte, z.n)
	defer Wipe(zeros)
	return unwrapArgon2idStanzas(stanzas, zeros, false)
}

// RecoverZeroKeyIdentity attempts to decrypt an age file (typically
// identity.age) that was wrapped under the pre-#476 zero-key bug. The
// passphrase length is only an unwrap hint; the caller must provide an
// independent public authority and the recovered recipient must match it.
// Authority and length are validated before the zero-filled allocation or KDF.
func RecoverZeroKeyIdentity(raw []byte, n int, authority ZeroKeyAuthority) (*age.X25519Identity, error) {
	return RecoverZeroKeyIdentityWithAuthorities(raw, n, []ZeroKeyAuthority{authority})
}

// RecoverZeroKeyIdentityWithAuthorities derives once and checks the recovered
// identity against all independently trusted public authorities afterwards.
func RecoverZeroKeyIdentityWithAuthorities(raw []byte, n int, authorities []ZeroKeyAuthority) (*age.X25519Identity, error) {
	if len(authorities) == 0 {
		return nil, ErrZeroKeyAuthority
	}
	for _, authority := range authorities {
		if err := validateZeroKeyAuthority(authority); err != nil {
			return nil, err
		}
	}
	if n <= 0 || n > MaxZeroKeyPassphraseLen {
		return nil, ErrZeroKeyPassphraseLen
	}
	r, err := age.Decrypt(bytes.NewReader(raw), &zeroKeyArgon2idIdentity{n: n})
	if err != nil {
		if IsArgon2ResourceError(err) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrZeroKeyRecovery, ErrDecryptionFailed)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, ErrZeroKeyRecovery
	}
	defer Wipe(plaintext)
	parsed, err := age.ParseX25519Identity(strings.TrimSpace(string(plaintext)))
	if err != nil {
		return nil, ErrZeroKeyRecovery
	}
	for _, authority := range authorities {
		if validateRecoveredZeroKeyIdentity(parsed, authority) == nil {
			return parsed, nil
		}
	}
	return nil, ErrZeroKeyRecovery
}

func parseArgon2idParams(s string) (Argon2idParams, error) {
	var params Argon2idParams
	if len(s) > 64 {
		return params, ErrArgon2Malformed
	}
	parts := strings.Split(s, ",")
	if len(parts) != 3 {
		return params, ErrArgon2Malformed
	}
	seen := byte(0)
	for _, part := range parts {
		if len(part) < 3 || part[1] != '=' {
			return params, ErrArgon2Malformed
		}
		for _, c := range part[2:] {
			if c < '0' || c > '9' {
				return params, ErrArgon2Malformed
			}
		}
		val, err := parseUint32(part[2:])
		if err != nil {
			return params, ErrArgon2Malformed
		}
		var bit byte
		switch part[0] {
		case 't':
			bit = 1
			params.Time = val
		case 'm':
			bit = 2
			params.Memory = val
		case 'p':
			bit = 4
			if val > math.MaxUint8 {
				return params, ErrArgon2Bounds
			}
			params.Threads = uint8(val) // #nosec G115 -- checked above
		default:
			return params, ErrArgon2Malformed
		}
		if seen&bit != 0 {
			return params, ErrArgon2Malformed
		}
		seen |= bit
	}
	if err := validateArgon2idParams(params); err != nil {
		return params, fmt.Errorf("%w: %w", ErrArgon2Bounds, err)
	}
	return params, nil
}

func parseUint32(s string) (uint32, error) {
	if len(s) == 0 {
		return 0, fmt.Errorf("invalid number: %q", s)
	}
	u, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %q: %w", s, err)
	}
	return uint32(u), nil // #nosec G115 — ParseUint with bitSize 32 guarantees value fits in uint32
}

func EncryptWithKey(plaintext []byte, key []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, ErrEmptyPlaintext
	}
	if len(key) != Argon2idKeyLen {
		return nil, fmt.Errorf("key must be %d bytes, got %d", Argon2idKeyLen, len(key))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create aead: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func DecryptWithKey(ciphertext []byte, key []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, ErrEmptyCiphertext
	}
	if len(key) != Argon2idKeyLen {
		return nil, fmt.Errorf("key must be %d bytes, got %d", Argon2idKeyLen, len(key))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create aead: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

func EncryptWithPassphraseArgon2id(plaintext []byte, passphrase []byte, params Argon2idParams) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, ErrEmptyPlaintext
	}
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase is empty")
	}

	// #nosec G103 — intentional: unsafe.String avoids heap-copying the passphrase
	// so that the subsequent Wipe() clears the only copy in memory.
	recipient := NewArgon2idRecipient(unsafe.String(unsafe.SliceData(passphrase), len(passphrase)), params)
	Wipe(passphrase)

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, fmt.Errorf("create encryptor: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("write plaintext: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close encryptor: %w", err)
	}

	return buf.Bytes(), nil
}

func DecryptWithPassphraseArgon2id(ciphertext []byte, passphrase []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, ErrEmptyCiphertext
	}
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase is empty")
	}

	// #nosec G103 — intentional: unsafe.String avoids heap-copying the passphrase
	// so that the subsequent Wipe() clears the only copy in memory.
	identity := NewArgon2idIdentity(unsafe.String(unsafe.SliceData(passphrase), len(passphrase)))
	Wipe(passphrase)

	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		if IsArgon2ResourceError(err) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read decrypted data: %w", err)
	}

	return plaintext, nil
}
