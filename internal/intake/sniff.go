package intake

import (
	"bytes"
	"encoding/json"
	"strings"
)

// sniffPrefixes are magic-byte prefixes for binary formats we accept as
// exact-file attachments (screenshots, scans, archives). Content sniffing
// deliberately wins over file extensions.
var sniffPrefixes = []struct {
	prefix []byte
	st     SourceType
}{
	{[]byte("\x89PNG\r\n\x1a\n"), SourceTypeImage},
	{[]byte("\xff\xd8\xff"), SourceTypeImage},
	{[]byte("%PDF-"), SourceTypePDF},
	{[]byte("PK\x03\x04"), SourceTypeArchive},
	{[]byte("PK\x05\x06"), SourceTypeArchive},
}

// Sniff classifies source content by magic bytes and structure, never by
// file extension alone.
func Sniff(data []byte, name string) SourceType {
	for _, p := range sniffPrefixes {
		if bytes.HasPrefix(data, p.prefix) {
			return p.st
		}
	}

	// PEM-encoded certificates and private keys.
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		if bytes.Contains(trimmed, []byte("CERTIFICATE")) {
			return SourceTypeCert
		}
		return SourceTypeKey
	}

	// JSON documents: first non-whitespace byte is '{' or '['.
	first := firstNonSpace(data)
	if first == '{' || first == '[' {
		if json.Valid(data) {
			return SourceTypeJSON
		}
	}

	// KEY=VALUE env-style files: at least one line matches KEY=VALUE or
	// KEY: VALUE with a plausible key name.
	if looksLikeEnv(data) {
		return SourceTypeEnv
	}

	// Non-empty text without binary bytes.
	if looksLikeText(data) {
		return SourceTypeText
	}

	return SourceTypeOther
}

func firstNonSpace(data []byte) byte {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		}
		return b
	}
	return 0
}

func looksLikeEnv(data []byte) bool {
	lines := 0
	matches := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines++
		if isEnvLine(line) {
			matches++
		}
	}
	return lines > 0 && matches*2 >= lines
}

func isEnvLine(line string) bool {
	// Env-style files separate key and value with '='. Lines like
	// "username: alice" belong to plain-text credential files, not .env.
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		return false
	}
	key := strings.TrimSpace(line[:i])
	return validEnvKey(key)
}

func validEnvKey(key string) bool {
	if key == "" {
		return false
	}
	for _, r := range key {
		if r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// looksLikeText reports whether data is printable text and free of binary
// control bytes. Empty input is not text.
func looksLikeText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		if b == 0 {
			return false
		}
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' && b != 0x1b {
			return false
		}
	}
	return true
}
