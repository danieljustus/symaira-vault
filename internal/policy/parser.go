package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadPolicy loads a policy from a YAML file.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is provided by the caller
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parse policy file: %w", err)
	}

	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("validate policy: %w", err)
	}

	return &policy, nil
}

// LoadPoliciesFromDir loads all policy files from a directory.
// Files must have .yaml or .yml extension.
func LoadPoliciesFromDir(dir string) ([]*Policy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policy directory: %w", err)
	}

	var policies []*Policy
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(dir, name)
		policy, err := LoadPolicy(path)
		if err != nil {
			return nil, fmt.Errorf("load policy %q: %w", name, err)
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

// DefaultPolicyDir returns the default directory for policy files.
func DefaultPolicyDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "openpass", "policies")
}
