package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"unicode"

	"filippo.io/age"

	vaultcrypto "github.com/danieljustus/symaira-vault/internal/crypto"
)

// Account conservatively before json.Marshal builds its whole output buffer.
func marshalIndexBounded(doc *indexDoc) ([]byte, error) {
	if _, fits := retainedDataCost(doc, maxSearchIndexPlaintextBytes); !fits {
		return nil, ErrVaultResourceLimit
	}
	raw, err := json.Marshal(doc)
	if len(raw) > maxSearchIndexPlaintextBytes {
		vaultcrypto.Wipe(raw)
		return nil, ErrVaultResourceLimit
	}
	return raw, err
}

func decodeIndexCiphertext(ct, key []byte) (indexDoc, error) {
	release, err := vaultReadAdmission.acquire()
	if err != nil {
		return indexDoc{}, err
	}
	defer release()
	return decodeIndexCiphertextAdmitted(ct, key)
}

func decodeIndexCiphertextAdmitted(ct, key []byte) (indexDoc, error) {
	if len(ct) > maxSearchIndexPlaintextBytes+28 {
		return indexDoc{}, ErrVaultResourceLimit
	}
	raw, err := vaultcrypto.DecryptWithKey(ct, key)
	if err != nil {
		return indexDoc{}, err
	}
	defer vaultcrypto.Wipe(raw)
	if validationErr := validateIndexJSON(raw); validationErr != nil {
		return indexDoc{}, validationErr
	}
	var doc indexDoc
	err = json.Unmarshal(raw, &doc)
	if err == nil {
		if _, fits := retainedDataCost(&doc, maxSearchIndexPlaintextBytes); !fits {
			err = ErrVaultResourceLimit
		}
	}
	return doc, err
}

func readIndexSnapshot(vaultDir string, identity *age.X25519Identity) (indexDoc, []byte, []byte, error) {
	release, err := vaultReadAdmission.acquire()
	if err != nil {
		return indexDoc{}, nil, nil, err
	}
	defer release()
	raw, err := readRootedFileLimited(vaultDir, ".search-index", maxSearchIndexPlaintextBytes+28+17)
	if err != nil {
		return indexDoc{}, nil, nil, err
	}
	var salt, ct []byte
	if len(raw) > 1 && raw[0] == indexFormatVersion {
		if len(raw) < 18 {
			return indexDoc{}, nil, nil, errors.New("truncated search index")
		}
		salt, ct = raw[1:17], raw[17:]
	} else {
		ct = raw
	}
	key := deriveIndexKey(identity, salt)
	defer vaultcrypto.Wipe(key)
	doc, err := decodeIndexCiphertextAdmitted(ct, key)
	return doc, salt, ct, err
}

// Bound raw JSON node expansion before materializing any index maps.
func validateIndexJSON(raw []byte) error {
	return validateRetainedJSON(raw, maxSearchIndexPlaintextBytes, maxSearchIndexPlaintextBytes)
}

func validateRetainedJSON(raw []byte, rawLimit, retainedLimit int) error {
	if len(raw) > rawLimit {
		return ErrVaultResourceLimit
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	remaining := retainedLimit
	var visit func(int) error
	consume := func(cost int) error {
		if cost > remaining {
			return ErrVaultResourceLimit
		}
		remaining -= cost
		return nil
	}
	visit = func(depth int) error {
		if depth > maxEntryEnvelopeDepth {
			return ErrVaultResourceLimit
		}
		if err := consume(256); err != nil {
			return err
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch token := token.(type) {
		case string:
			if len(token) > maxEntryValueBytes {
				return ErrVaultResourceLimit
			}
			return consume(6 * len(token))
		case json.Delim:
			for decoder.More() {
				if token == '{' {
					keyToken, keyErr := decoder.Token()
					if keyErr != nil {
						return keyErr
					}
					key, ok := keyToken.(string)
					if !ok {
						return errors.New("index object key is not a string")
					}
					if len(key) > maxEntryValueBytes {
						return ErrVaultResourceLimit
					}
					if budgetErr := consume(256 + 6*len(key)); budgetErr != nil {
						return budgetErr
					}
				}
				if visitErr := visit(depth + 1); visitErr != nil {
					return visitErr
				}
			}
			_, err = decoder.Token()
		}
		return err
	}
	return visit(0) // authoritative Unmarshal also rejects trailing JSON/type errors
}

// Stream token boundaries and check before retaining each new token/binding.
// The reservation includes the forward/reverse maps and temporary dedup set.
func uniqueTokensBounded(values []string, path string, remaining int) ([]string, error) {
	seen := make(map[string]struct{})
	var tokens []string
	var word strings.Builder
	flush := func() error {
		if word.Len() == 0 {
			return nil
		}
		token := word.String()
		word.Reset()
		if _, ok := seen[token]; ok {
			return nil
		}
		cost := 1280 + 12*len(token) + 12*len(path)
		if cost > remaining {
			return ErrVaultResourceLimit
		}
		remaining -= cost
		seen[token] = struct{}{}
		tokens = append(tokens, token)
		return nil
	}
	for _, value := range values {
		for _, r := range value {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' {
				word.WriteRune(r)
			} else if err := flush(); err != nil {
				return nil, err
			}
		}
		if err := flush(); err != nil {
			return nil, err
		}
	}
	return tokens, nil
}

func addToTokenIndexBounded(doc *indexDoc, values []string, path string) error {
	used, fits := retainedDataCost(doc, maxSearchIndexPlaintextBytes)
	if !fits {
		return ErrVaultResourceLimit
	}
	tokens, err := uniqueTokensBounded(values, path, maxSearchIndexPlaintextBytes-used)
	if err != nil {
		return err
	}
	for _, token := range tokens {
		if doc.TokenIndex[token] == nil {
			doc.TokenIndex[token] = make(map[string]struct{})
		}
		doc.TokenIndex[token][path] = struct{}{}
	}
	doc.PathTokens[path] = tokens
	return nil
}

func addToHostIndexBounded(doc *indexDoc, hosts []string, path string) error {
	used, fits := retainedDataCost(doc, maxSearchIndexPlaintextBytes)
	if !fits {
		return ErrVaultResourceLimit
	}
	for _, host := range hosts {
		cost := 1024 + 12*len(host) + 12*len(path)
		if cost > maxSearchIndexPlaintextBytes-used {
			return ErrVaultResourceLimit
		}
		used += cost
	}
	addToHostIndex(doc.HostIndex, doc.PathHosts, hosts, path)
	return nil
}
