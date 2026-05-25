package template

import (
	"context"
	"errors"
	"fmt"
	"strings"

	vaultsvc "github.com/danieljustus/symaira-vault/internal/vaultsvc"
)

// ParsedRef holds the components of a parsed secret reference.
type ParsedRef struct {
	// Path is the vault entry path.
	Path string
	// Field is the field name within the entry.
	Field string
}

// ParseRef parses a secret reference string into its path and field components.
//
// Supported syntax:
//   - op://path/field     (explicit op:// prefix)
//   - path.field          (dot notation shorthand)
//
// Examples:
//   - "op://work/aws/password" -> Path="work/aws", Field="password"
//   - "work/aws.password"      -> Path="work/aws", Field="password"
func ParseRef(ref string) (*ParsedRef, error) {
	if ref == "" {
		return nil, fmt.Errorf("%w: empty reference", ErrInvalidRef)
	}

	// Handle op:// prefix
	if strings.HasPrefix(ref, "op://") {
		rest := strings.TrimPrefix(ref, "op://")
		// Split on last '/' to separate path from field
		idx := strings.LastIndex(rest, "/")
		if idx == -1 || idx == len(rest)-1 {
			return nil, fmt.Errorf("%w: missing field in op:// reference: %s", ErrInvalidRef, ref)
		}
		return &ParsedRef{
			Path:  rest[:idx],
			Field: rest[idx+1:],
		}, nil
	}

	// Handle dot notation: path.field
	idx := strings.LastIndex(ref, ".")
	if idx == -1 || idx == 0 || idx == len(ref)-1 {
		return nil, fmt.Errorf("%w: expected path.field or op://path/field syntax, got: %s", ErrInvalidRef, ref)
	}

	return &ParsedRef{
		Path:  ref[:idx],
		Field: ref[idx+1:],
	}, nil
}

// ResolveRef resolves a secret reference against the given vault service.
// It parses the reference, looks up the entry in the vault, and returns the field value as a string.
func ResolveRef(ctx context.Context, svc vaultsvc.Service, ref string) (string, error) {
	parsed, err := ParseRef(ref)
	if err != nil {
		return "", err
	}

	value, err := svc.GetField(parsed.Path, parsed.Field)
	if err != nil {
		return "", fmt.Errorf("resolve ref %q: %w", ref, err)
	}

	// Convert to string
	switch v := value.(type) {
	case string:
		return v, nil
	case nil:
		return "", errors.New("resolved value is nil")
	default:
		return fmt.Sprintf("%v", v), nil
	}
}
