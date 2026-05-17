package agentskill

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest represents the YAML frontmatter of a managed skill file.
// Fields with the "managed_" prefix are the OpenPass sentinel set.
type Manifest struct {
	// Name is the skill name (always "openpass").
	Name string `yaml:"name"`

	// Description is a short description of the skill.
	Description string `yaml:"description"`

	// ManagedBy is the sentinel value ("openpass") that marks this file as managed.
	ManagedBy string `yaml:"managed_by"`

	// ManagedVersion is the OpenPass version that installed this skill.
	ManagedVersion string `yaml:"managed_version"`

	// ManagedHash is "sha256:" + hex-encoded SHA-256 of the body.
	ManagedHash string `yaml:"managed_hash"`

	// ManagedInstalledAt is the install timestamp (RFC3339).
	ManagedInstalledAt string `yaml:"managed_installed_at"`

	// ManagedProfileTier is the agent profile tier at install time.
	ManagedProfileTier string `yaml:"managed_profile_tier"`
}

var (
	// ErrNoFrontmatter is returned when no YAML frontmatter is found.
	ErrNoFrontmatter = errors.New("no frontmatter found")

	// ErrUnmanagedFile is returned when a skill file exists without the sentinel.
	ErrUnmanagedFile = errors.New("skill file exists without managed sentinel")

	// ErrBadHashFormat is returned when the hash format is invalid.
	ErrBadHashFormat = errors.New("invalid hash format")
)

// ParseManifest extracts the Manifest from a skill file's YAML frontmatter.
// It expects the standard frontmatter format:
//
//	---
//	key: value
//	...
//	---
//	<body>
func ParseManifest(data []byte) (*Manifest, error) {
	if !bytes.HasPrefix(data, []byte("---\n")) && !bytes.HasPrefix(data, []byte("---\r\n")) {
		return nil, fmt.Errorf("%w: missing opening ---", ErrNoFrontmatter)
	}

	rest := data[4:]
	if bytes.HasPrefix(data, []byte("---\r\n")) {
		rest = data[5:]
	}

	idx := findFrontmatterClose(rest)
	if idx < 0 {
		return nil, fmt.Errorf("%w: missing closing ---", ErrNoFrontmatter)
	}

	yamlPart := rest[:idx]

	var manifest Manifest
	if err := yaml.Unmarshal(yamlPart, &manifest); err != nil {
		return nil, fmt.Errorf("parse frontmatter yaml: %w", err)
	}

	return &manifest, nil
}

// findFrontmatterClose finds the closing --- in frontmatter content.
// Returns the index of \n in \n---\n, or -1 if not found.
func findFrontmatterClose(data []byte) int {
	idx := bytes.Index(data, []byte("\n---\n"))
	if idx >= 0 {
		return idx
	}
	idx = bytes.Index(data, []byte("\n---\r\n"))
	if idx >= 0 {
		return idx
	}
	idx = bytes.Index(data, []byte("\n---"))
	if idx >= 0 {
		return idx
	}
	return -1
}

// FindSentinel reports whether the data contains a managed_by: openpass sentinel.
func FindSentinel(data []byte) bool {
	manifest, err := ParseManifest(data)
	if err != nil {
		return false
	}
	return manifest.ManagedBy == SentinelValue
}

// ExtractBody returns the body content after the YAML frontmatter.
// Returns an error if no valid frontmatter is found.
func ExtractBody(data []byte) ([]byte, error) {
	if !bytes.HasPrefix(data, []byte("---\n")) && !bytes.HasPrefix(data, []byte("---\r\n")) {
		return nil, fmt.Errorf("%w: missing opening ---", ErrNoFrontmatter)
	}

	rest := data[4:]
	if bytes.HasPrefix(data, []byte("---\r\n")) {
		rest = data[5:]
	}

	idx := findFrontmatterClose(rest)
	if idx < 0 {
		return nil, fmt.Errorf("%w: missing closing ---", ErrNoFrontmatter)
	}

	after := idx + len("\n---")
	for after < len(rest) && (rest[after] == '\n' || rest[after] == '\r') {
		after++
	}

	if after >= len(rest) {
		return []byte{}, nil
	}

	return rest[after:], nil
}

// HashBytes computes "sha256:" + hex-encoded SHA-256 hash of the input.
func HashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// VerifyHash parses the frontmatter, extracts the body, recomputes the hash,
// and compares it with the stored hash. Returns nil on match.
func VerifyHash(data []byte) error {
	manifest, err := ParseManifest(data)
	if err != nil {
		return err
	}

	body, err := ExtractBody(data)
	if err != nil {
		return err
	}

	got := HashBytes(body)
	if got != manifest.ManagedHash {
		return fmt.Errorf("hash mismatch: got %s, want %s", got, manifest.ManagedHash)
	}
	return nil
}

// ParseHashValue extracts the hex portion from a "sha256:..." hash string.
// Returns an error if the prefix is missing.
func ParseHashValue(hashStr string) (string, error) {
	if !strings.HasPrefix(hashStr, "sha256:") {
		return "", fmt.Errorf("%w: missing sha256: prefix in %q", ErrBadHashFormat, hashStr)
	}
	hexVal := strings.TrimPrefix(hashStr, "sha256:")
	if hexVal == "" {
		return "", fmt.Errorf("%w: empty hash value", ErrBadHashFormat)
	}
	return hexVal, nil
}
