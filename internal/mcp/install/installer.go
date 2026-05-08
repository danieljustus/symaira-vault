package install

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Result holds the outcome of an install operation.
type Result struct {
	AgentType   AgentType
	ConfigPath  string
	WasCreated  bool
	WasUpdated  bool
	WasUnchanged bool
	TokenID     string
}

// InstallOptions configures the install operation.
type InstallOptions struct {
	AgentType   AgentType
	ServerKey   string
	RootKey     string
	ServerConfig map[string]any
	Format      ConfigFormat
	ConfigPath  string // optional override
	DryRun      bool
}

// Install injects the OpenPass MCP server configuration into an agent's config
// file. It is idempotent: running twice with the same config produces no change
// on the second run.
func Install(opts InstallOptions) (*Result, error) {
	def, err := GetAgentDefinition(opts.AgentType)
	if err != nil {
		return nil, err
	}

	configPath := opts.ConfigPath
	if configPath == "" {
		configPath, err = ResolveConfigPath(opts.AgentType)
		if err != nil {
			return nil, err
		}
	}

	rw, err := GetReaderWriter(opts.Format)
	if err != nil {
		return nil, err
	}

	existingConfig, err := rw.Read(configPath)
	if err != nil {
		return nil, err
	}

	rootKey := opts.RootKey
	if rootKey == "" {
		rootKey = def.RootKey
	}
	serverKey := opts.ServerKey
	if serverKey == "" {
		serverKey = def.ServerKey
	}

	updatedConfig, changed := InjectServerConfig(existingConfig, rootKey, serverKey, opts.ServerConfig)

	result := &Result{
		AgentType:  opts.AgentType,
		ConfigPath: configPath,
	}

	fileExists := false
	if _, statErr := os.Stat(configPath); statErr == nil {
		fileExists = true
	}

	if !changed {
		result.WasUnchanged = true
		return result, nil
	}

	if fileExists {
		result.WasUpdated = true
	} else {
		result.WasCreated = true
	}

	if opts.DryRun {
		return result, nil
	}

	if err := EnsureConfigDir(configPath); err != nil {
		return nil, err
	}

	if err := rw.Write(configPath, updatedConfig); err != nil {
		return nil, err
	}

	return result, nil
}

// BackupConfig creates a backup of the existing config file before modification.
func BackupConfig(configPath string) (string, error) {
	if _, err := os.Stat(configPath); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("stat config %q: %w", configPath, err)
	}

	backupPath := configPath + ".backup"
	data, err := os.ReadFile(configPath) // #nosec G304 -- path comes from caller which validates it
	if err != nil {
		return "", fmt.Errorf("read config for backup %q: %w", configPath, err)
	}
	if err := os.WriteFile(backupPath, data, 0o600); err != nil {
		return "", fmt.Errorf("write backup %q: %w", backupPath, err)
	}
	return backupPath, nil
}

// PreviewConfig returns a string representation of what the config would look like.
func PreviewConfig(data map[string]any, format ConfigFormat) (string, error) {
	switch format {
	case FormatJSON:
		out, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return "", err
		}
		return string(out) + "\n", nil
	case FormatYAML:
		out, err := yaml.Marshal(data)
		if err != nil {
			return "", err
		}
		return string(out), nil
	default:
		return "", fmt.Errorf("unsupported format %q", format)
	}
}
