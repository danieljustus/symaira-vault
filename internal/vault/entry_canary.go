package vault

import (
	"errors"
	"fmt"
	"sync"

	"filippo.io/age"
)

// WithoutCanary returns a copy of the entry with the canary flag cleared.
func (e *Entry) WithoutCanary() *Entry {
	if e == nil {
		return nil
	}
	cp := cloneEntry(e)
	cp.Canary = false
	return cp
}

// IsCanary returns whether this entry is a honeytoken/canary entry.
func (e *Entry) IsCanary() bool {
	return e != nil && e.Canary
}

var canaryPaths = struct {
	mu    sync.RWMutex
	paths map[string]bool
}{
	paths: make(map[string]bool),
}

// MarkCanaryPath adds a path to the in-memory canary set.
func MarkCanaryPath(path string) {
	canaryPaths.mu.Lock()
	canaryPaths.paths[path] = true
	canaryPaths.mu.Unlock()
}

// UnmarkCanaryPath removes a path from the in-memory canary set.
func UnmarkCanaryPath(path string) {
	canaryPaths.mu.Lock()
	delete(canaryPaths.paths, path)
	canaryPaths.mu.Unlock()
}

// IsCanaryPath checks if the given path is a known canary entry.
func IsCanaryPath(path string) bool {
	canaryPaths.mu.RLock()
	_, ok := canaryPaths.paths[path]
	canaryPaths.mu.RUnlock()
	return ok
}

// SetEntryCanary marks or unmarks an existing vault entry as a canary/honeytoken.
func SetEntryCanary(vaultDir, path string, identity *age.X25519Identity, canary bool) error {
	if identity == nil {
		return errors.New("nil identity")
	}
	entry, err := ReadEntry(vaultDir, path, identity)
	if err != nil {
		return fmt.Errorf("read entry for canary update: %w", err)
	}
	entry.Canary = canary
	if err := WriteEntry(vaultDir, path, entry, identity); err != nil {
		return fmt.Errorf("write entry for canary update: %w", err)
	}
	if canary {
		MarkCanaryPath(path)
	} else {
		UnmarkCanaryPath(path)
	}
	return nil
}

// DefaultCanaryEntries returns a set of default canary entry configurations.
func DefaultCanaryEntries() []struct {
	Path string
	Data map[string]any
} {
	return []struct {
		Path string
		Data map[string]any
	}{
		{
			Path: ".canary/aws-root-key",
			Data: map[string]any{
				"username":   "aws-root",
				"access_key": "AKIA12345678CANARY",
				"secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYCANARYKEY",
				"region":     "us-east-1",
			},
		},
		{
			Path: ".canary/github-admin-token",
			Data: map[string]any{
				"username": "github-admin",
				"token":    "ghp_CANARY1234567890abcdefghijklmnopqrstuv",
				"scope":    "repo,admin:org,admin:repo_hooks",
			},
		},
		{
			Path: ".canary/production-database",
			Data: map[string]any{
				"username": "db_admin",
				"password": "C4n4ry!Str0ng!P455w0rd!2024",
				"host":     "prod-db.internal.example.com",
				"port":     "5432",
				"database": "production",
			},
		},
	}
}
