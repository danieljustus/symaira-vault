package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const ageArgon2idLabel = "openpass-argon2id-v1"

const argon2idStanzaType = "argon2id"

type argon2idRecipient struct {
	passphrase string
	params     Argon2idParams
}

func NewArgon2idRecipient(passphrase string, params Argon2idParams) age.Recipient {
	params = resolveArgon2idParams(params)
	if params.Time == 0 && params.Memory == 0 && params.Threads == 0 {
		params = DefaultArgon2idParams()
	}
	return &argon2idRecipient{
		passphrase: passphrase,
		params:     params,
	}
}

func (r *argon2idRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	salt, err := GenerateArgon2idSalt()
	if err != nil {
		return nil, err
	}

	l := argon2.IDKey([]byte(r.passphrase), salt, r.params.Time, r.params.Memory, r.params.Parallelism(), Argon2idKeyLen)

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
		Type: argon2idStanzaType,
		Args: []string{
			base64.RawStdEncoding.EncodeToString(salt),
			params,
		},
		Body: body,
	}}, nil
}

type argon2idIdentity struct {
	passphrase string
}

func NewArgon2idIdentity(passphrase string) age.Identity {
	return &argon2idIdentity{
		passphrase: passphrase,
	}
}

func (id *argon2idIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, s := range stanzas {
		if s.Type != argon2idStanzaType {
			continue
		}
		if len(s.Args) < 2 {
			continue
		}

		salt, err := base64.RawStdEncoding.DecodeString(s.Args[0])
		if err != nil {
			continue
		}

		params, err := parseArgon2idParams(s.Args[1])
		if err != nil {
			continue
		}

		l := argon2.IDKey([]byte(id.passphrase), salt, params.Time, params.Memory, params.Parallelism(), Argon2idKeyLen)

		kdf := hkdf.New(sha256.New, l, salt, []byte(ageArgon2idLabel))
		wrapKey := make([]byte, Argon2idKeyLen)
		if _, readErr := io.ReadFull(kdf, wrapKey); readErr != nil {
			continue
		}

		aead, err := chacha20poly1305.New(wrapKey)
		if err != nil {
			continue
		}

		nonceSize := aead.NonceSize()
		if len(s.Body) < nonceSize {
			continue
		}

		nonce, ciphertext := s.Body[:nonceSize], s.Body[nonceSize:]
		fileKey, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			continue
		}

		return fileKey, nil
	}

	return nil, errors.New("argon2id: no matching stanza found")
}

func parseArgon2idParams(s string) (Argon2idParams, error) {
	var params Argon2idParams
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) < 3 || part[1] != '=' {
			return params, fmt.Errorf("invalid params format: %q", s)
		}
		key := part[0]
		val := part[2:]
		var err error
		switch key {
		case 't':
			params.Time, err = parseUint32(val)
		case 'm':
			params.Memory, err = parseUint32(val)
		case 'p':
			var tp uint32
			tp, err = parseUint32(val)
			params.Threads = uint8(tp)
		default:
			err = fmt.Errorf("unknown param key: %c", key)
		}
		if err != nil {
			return params, fmt.Errorf("invalid params: %w", err)
		}
	}
	if params.Time == 0 || params.Memory == 0 || params.Threads == 0 {
		return params, errors.New("incomplete argon2id params")
	}
	return params, nil
}

func parseUint32(s string) (uint32, error) {
	var n uint32
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid number: %q", s)
		}
		n = n*10 + uint32(c-'0')
	}
	return n, nil
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

	recipient := NewArgon2idRecipient(string(passphrase), params)
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

	identity := NewArgon2idIdentity(string(passphrase))
	Wipe(passphrase)

	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read decrypted data: %w", err)
	}

	return plaintext, nil
}
