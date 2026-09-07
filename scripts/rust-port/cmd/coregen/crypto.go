package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
)

type cryptoFixture struct {
	SchemaVersion   int              `json:"schema_version"`
	Oracle          oracle           `json:"oracle"`
	PasswordCases   []passwordCase   `json:"password_cases"`
	StrengthCases   []strengthCase   `json:"strength_cases"`
	TOTPSecretCases []totpSecretCase `json:"totp_secret_cases"`
	TOTPParamCases  []totpParamCase  `json:"totp_param_cases"`
	TOTPCases       []totpCase       `json:"totp_cases"`
}

type passwordCase struct {
	Name        string `json:"name"`
	Length      int    `json:"length"`
	UseSymbols  bool   `json:"use_symbols"`
	ReaderBytes string `json:"reader_bytes,omitempty"`
	Expected    string `json:"expected,omitempty"`
	Error       string `json:"error,omitempty"`
}

type strengthCase struct {
	Name    string   `json:"name"`
	Input   string   `json:"input"`
	Weak    bool     `json:"weak"`
	Message string   `json:"message,omitempty"`
	Entropy float64  `json:"entropy"`
	Missing []string `json:"missing,omitempty"`
}

type totpSecretCase struct {
	Name  string `json:"name"`
	Input string `json:"input"`
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

type totpParamCase struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
	Valid     bool   `json:"valid"`
	Error     string `json:"error,omitempty"`
}

type totpCase struct {
	Name         string `json:"name"`
	Secret       string `json:"secret"`
	Algorithm    string `json:"algorithm"`
	Digits       int    `json:"digits"`
	Period       int    `json:"period"`
	UnixTime     int64  `json:"unix_time"`
	Valid        bool   `json:"valid"`
	Code         string `json:"code,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	ResultPeriod int    `json:"result_period,omitempty"`
	Error        string `json:"error,omitempty"`
}

var cryptoProductionSources = []string{
	"internal/crypto/password.go",
	"internal/crypto/totp.go",
}

func cryptoOracle(meta oracle) oracle {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("locate crypto generator")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	sources := append([]string(nil), cryptoProductionSources...)
	sort.Strings(sources)
	sourceDigest, err := digestCryptoFiles(root, sources)
	if err != nil {
		panic(fmt.Sprintf("hash crypto sources: %v", err))
	}
	generatorDigest, err := digestCryptoFiles(root, []string{
		"scripts/rust-port/cmd/coregen/main.go",
		"scripts/rust-port/cmd/coregen/crypto.go",
	})
	if err != nil {
		panic(fmt.Sprintf("hash crypto generators: %v", err))
	}
	meta.SourceFiles = sources
	meta.SourceDigest = sourceDigest
	meta.GeneratorDigest = generatorDigest
	return meta
}

func digestCryptoFiles(root string, files []string) (string, error) {
	hash := sha256.New()
	for _, name := range files {
		content, err := os.ReadFile(filepath.Join(root, name)) // #nosec G304 -- fixed inputs
		if err != nil {
			return "", err
		}
		_, _ = hash.Write([]byte(name))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(content)
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func buildCryptoFixture(meta oracle) cryptoFixture {
	meta = cryptoOracle(meta)
	passwordInputs := []struct {
		name       string
		length     int
		useSymbols bool
		reader     []byte
	}{
		{"default_length", 0, false, deterministicPasswordBytes(64)},
		{"symbols", 32, true, deterministicPasswordBytes(96)},
		{"letters_and_digits", 32, false, deterministicPasswordBytes(64)},
		{"maximum_length", cryptopkg.MaxPasswordLength, false, deterministicPasswordBytes(2048)},
		{"over_maximum", cryptopkg.MaxPasswordLength + 1, false, nil},
	}
	passwordCases := make([]passwordCase, 0, len(passwordInputs))
	for _, input := range passwordInputs {
		result := passwordCase{
			Name:        input.name,
			Length:      input.length,
			UseSymbols:  input.useSymbols,
			ReaderBytes: base64.StdEncoding.EncodeToString(input.reader),
		}
		password, cleanup, err := cryptopkg.GeneratePasswordWithReader(
			input.length,
			input.useSymbols,
			bytes.NewReader(input.reader),
		)
		if err != nil {
			result.Error = err.Error()
		} else {
			// SecureString's cleanup releases its backing storage; copy the
			// fixture value before invoking the required production cleanup.
			result.Expected = strings.Clone(password)
		}
		if cleanup != nil {
			cleanup()
		}
		passwordCases = append(passwordCases, result)
	}

	strengthInputs := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"short", "123"},
		{"lowercase_only", "abcdefghij"},
		{"strong", "StrongP@ssw0rd123"},
		{"unicode_strong", "HelloW0rld!日本語テスト"},
		{"unicode_symbol", "Abcdefghi1😀"},
		{"short_non_latin", "日本語テスト"},
		{"unicode_decimal_digits_across_scripts", "Aa١१১๑１xyz!!!"},
		{"unicode_non_decimal_numerics", "Aabcdef½²①xyz!!!"},
		{"unicode_decimal_digits", "Aa१२３４５xyz!!!"},
		{"non_latin_low_entropy", "あいうえおあいうえお"},
		{"exact_length_mixed", "Abcdefghi1"},
	}
	strengthCases := make([]strengthCase, 0, len(strengthInputs))
	for _, input := range strengthInputs {
		assessment := cryptopkg.AssessPasswordStrength(input.input)
		strengthCases = append(strengthCases, strengthCase{
			Name:    input.name,
			Input:   input.input,
			Weak:    assessment.Weak,
			Message: assessment.Message,
			Entropy: assessment.Entropy,
			Missing: assessment.Missing,
		})
	}

	secretInputs := []struct {
		name  string
		input string
	}{
		{"valid", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"},
		{"valid_spaced", "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ"},
		{"valid_lowercase", "gezdgnbvgy3tqojqgezdgnbvgy3tqojq"},
		{"invalid", "not-valid-base32!!!"},
		{"too_short", "A"},
		{"too_long", strings.Repeat("A", 257)},
		{"all_same_bytes", strings.Repeat("A", 32)},
		{"sequential_bytes", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sequentialBytes(16))},
		{"exactly_16_bytes", base32.StdEncoding.EncodeToString([]byte("Symaira16Bytes!!"))},
	}
	secretCases := make([]totpSecretCase, 0, len(secretInputs))
	for _, input := range secretInputs {
		err := cryptopkg.ValidateTOTPSecret(input.input)
		result := totpSecretCase{Name: input.name, Input: input.input, Valid: err == nil}
		if err != nil {
			result.Error = err.Error()
		}
		secretCases = append(secretCases, result)
	}

	paramInputs := []struct {
		name      string
		algorithm string
		digits    int
		period    int
	}{
		{"sha1_six_30", "SHA1", 6, 30},
		{"sha256_six_30", "SHA256", 6, 30},
		{"sha512_eight_60", "SHA512", 8, 60},
		{"case_insensitive", "sha1", 8, 3600},
		{"defaults_allowed", "", 0, 0},
		{"invalid_algorithm", "MD5", 6, 30},
		{"invalid_digits", "SHA1", 7, 30},
		{"negative_period", "SHA1", 6, -1},
		{"period_too_large", "SHA1", 6, 3601},
	}
	paramCases := make([]totpParamCase, 0, len(paramInputs))
	for _, input := range paramInputs {
		err := cryptopkg.ValidateTOTPParams(input.algorithm, input.digits, input.period)
		result := totpParamCase{
			Name: input.name, Algorithm: input.algorithm, Digits: input.digits,
			Period: input.period, Valid: err == nil,
		}
		if err != nil {
			result.Error = err.Error()
		}
		paramCases = append(paramCases, result)
	}

	totpInputs := []struct {
		name      string
		secret    string
		algorithm string
		digits    int
		period    int
		unixTime  int64
	}{
		{"rfc6238_t0", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA1", 6, 30, 0},
		{"rfc6238_t59", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA1", 8, 30, 59},
		{"sha256_fixed_clock", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA256", 6, 30, 1111111109},
		{"sha512_fixed_clock", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA512", 6, 30, 1234567890},
		{"defaults", "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ", "", 0, 0, 2000000000},
		{"custom_period", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA1", 6, 60, 2000000001},
		{"negative_clock", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA1", 6, 30, -1},
		{"invalid_secret", "not-valid-base32!!!", "SHA1", 6, 30, 0},
		{"empty_decoded_secret", "A", "SHA1", 6, 30, 0},
		{"invalid_params", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "MD5", 6, 30, 0},
	}
	totpCases := make([]totpCase, 0, len(totpInputs))
	for _, input := range totpInputs {
		result := totpCase{
			Name: input.name, Secret: input.secret, Algorithm: input.algorithm,
			Digits: input.digits, Period: input.period, UnixTime: input.unixTime,
		}
		code, err := cryptopkg.GenerateTOTPAt(
			input.secret, input.algorithm, input.digits, input.period,
			time.Unix(input.unixTime, 0).UTC(),
		)
		result.Valid = err == nil
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Code = code.Code
			result.ExpiresAt = code.ExpiresAt.Unix()
			result.ResultPeriod = code.Period
		}
		totpCases = append(totpCases, result)
	}

	return cryptoFixture{
		SchemaVersion:   1,
		Oracle:          meta,
		PasswordCases:   passwordCases,
		StrengthCases:   strengthCases,
		TOTPSecretCases: secretCases,
		TOTPParamCases:  paramCases,
		TOTPCases:       totpCases,
	}
}

func deterministicPasswordBytes(length int) []byte {
	result := make([]byte, length)
	for i := range result {
		result[i] = byte(i % 64)
	}
	return result
}

func sequentialBytes(length int) []byte {
	result := make([]byte, length)
	for i := range result {
		result[i] = byte(i)
	}
	return result
}
