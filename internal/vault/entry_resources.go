package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	maxEntryEnvelopeDepth  = 34
	maxEntryEnvelopeKeys   = 4096
	maxEntryEnvelopeValues = 65_536
)

// ErrVaultResourceLimit is deliberately independent of paths and entry values.
var ErrVaultResourceLimit = errors.New("vault resource limit exceeded")

// validateEntryEnvelope counts raw JSON before typed decoding can merge keys or
// allocate metadata and forward-compatible unknown values.
func validateEntryEnvelope(raw []byte, batches ...*vaultReadBatch) error {
	if len(raw) > maxEntryPlaintextBytesV1 {
		return ErrVaultResourceLimit
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	keys, values, cost := 0, 0, 0
	if err := validateEnvelopeValue(decoder, 0, &keys, &values, &cost); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("entry has trailing JSON")
		}
		return err
	}
	if len(batches) != 0 {
		return batches[0].consumeDecoded(cost)
	}
	return nil
}

func validateEnvelopeValue(decoder *json.Decoder, depth int, keys, values, cost *int) error {
	*values++
	*cost += 256
	if depth > maxEntryEnvelopeDepth || *values > maxEntryEnvelopeValues {
		return ErrVaultResourceLimit
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch value := token.(type) {
	case string:
		*cost += 6 * len(value)
		if len(value) > maxEntryValueBytes {
			return ErrVaultResourceLimit
		}
	case json.Delim:
		switch value {
		case '{':
			for decoder.More() {
				*keys++
				if *keys > maxEntryEnvelopeKeys {
					return ErrVaultResourceLimit
				}
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return keyErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("entry object key is not a string")
				}
				*cost += 256 + 6*len(key)
				if len(key) > maxEntryValueBytes {
					return ErrVaultResourceLimit
				}
				if validationErr := validateEnvelopeValue(decoder, depth+1, keys, values, cost); validationErr != nil {
					return validationErr
				}
			}
			_, err = decoder.Token()
		case '[':
			items := 0
			for decoder.More() {
				items++
				if items > maxEntryArrayItems {
					return ErrVaultResourceLimit
				}
				if validationErr := validateEnvelopeValue(decoder, depth+1, keys, values, cost); validationErr != nil {
					return validationErr
				}
			}
			_, err = decoder.Token()
		}
	}
	return err
}
