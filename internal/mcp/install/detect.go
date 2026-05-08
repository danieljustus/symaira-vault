package install

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// DetectResult holds the outcome of an agent detection attempt.
type DetectResult struct {
	Detected   bool
	ConfigPath string
	BinaryPath string
}

// DetectAgent checks whether the given agent is installed by looking for
// its binary in PATH and its config file in known locations.
func DetectAgent(agentType AgentType) (*DetectResult, error) {
	def, err := GetAgentDefinition(agentType)
	if err != nil {
		return nil, err
	}

	result := &DetectResult{}

	// Check for binary in PATH.
	for _, bin := range def.BinaryNames {
		if path, ok := findBinary(bin); ok {
			result.Detected = true
			result.BinaryPath = path
			break
		}
	}

	// Check for existing config file.
	for _, cfgPath := range def.ConfigPaths {
		expanded, err := ExpandHome(cfgPath)
		if err != nil {
			continue
		}
		if _, err := osStat(expanded); err == nil {
			result.Detected = true
			if result.ConfigPath == "" {
				result.ConfigPath = expanded
			}
			break
		}
	}

	return result, nil
}

// DetectAllAgents returns detection results for all supported agents.
func DetectAllAgents() map[AgentType]*DetectResult {
	results := make(map[AgentType]*DetectResult)
	for _, agentType := range SupportedAgents() {
		result, _ := DetectAgent(agentType)
		if result != nil {
			results[agentType] = result
		}
	}
	return results
}

// findBinary searches for an executable name in PATH.
func findBinary(name string) (string, bool) {
	pathEnv, _ := osLookupEnv("PATH")
	sep := string(filepath.ListSeparator)
	for _, dir := range strings.Split(pathEnv, sep) {
		if dir == "" {
			continue
		}
		fullPath := filepath.Join(dir, name)
		if runtime.GOOS == "windows" {
			for _, ext := range []string{".exe", ".cmd", ".bat"} {
				withExt := fullPath + ext
				if info, err := osStat(withExt); err == nil && !info.IsDir() {
					return withExt, true
				}
			}
		} else {
			if info, err := osStat(fullPath); err == nil && !info.IsDir() {
				return fullPath, true
			}
		}
	}
	return "", false
}

// ResolveConfigPath returns the preferred config path for an agent.
// It expands ~ and creates the parent directory if needed.
func ResolveConfigPath(agentType AgentType) (string, error) {
	def, err := GetAgentDefinition(agentType)
	if err != nil {
		return "", err
	}

	for _, cfgPath := range def.ConfigPaths {
		expanded, err := ExpandHome(cfgPath)
		if err != nil {
			continue
		}
		return expanded, nil
	}

	return "", fmt.Errorf("no config path available for agent %q", agentType)
}

// EnsureConfigDir creates the parent directory for the given config path.
func EnsureConfigDir(configPath string) error {
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory %q: %w", dir, err)
	}
	return nil
}
