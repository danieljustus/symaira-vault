package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/danieljustus/OpenPass/internal/fileutil"
)

// KnownConfigKeys returns all known config key paths for tab completion.
// Wildcard entries (for example agents.*.canWrite) are used as schema hints
// and are not returned directly by shell completion.
func KnownConfigKeys() []string {
	return []string{
		// Top-level keys
		"vaultDir",
		"defaultAgent",
		"sessionTimeout",
		"authMethod",
		"useTouchID",
		"defaultProfile",
		"envWhitelist",
		"scan_patterns",

		// Agents
		"agents",
		"agents.*.tier",
		"agents.*.approvalMode",
		"agents.*.allowedPaths",
		"agents.*.redactFields",
		"agents.*.canWrite",
		"agents.*.canRunCommands",
		"agents.*.canManageConfig",
		"agents.*.canUseClipboard",
		"agents.*.canUseAutotype",
		"agents.*.canReadValues",
		"agents.*.exposeValueTools",
		"agents.*.autoUnseal",
		"agents.*.requireApproval",
		"agents.*.approvalTimeout",
		"agents.*.allowed_tools",
		"agents.*.max_reads_per_hour",
		"agents.*.max_reads_per_day",
		"agents.*.max_secrets_in_session",
		"agents.*.dynamicProviders",
		"agents.*.allowedEnvVars",
		"agents.*.allowedExecutables",
		"agents.*.promptInjectionMode",
		"agents.*.pre_call_hooks",
		"agents.*.post_call_hooks",
		"agents.*.skillPath",
		"agents.*.skillVersion",

		// Vault
		"vault",
		"vault.path",
		"vault.default_recipients",
		"vault.confirm_remove",
		"vault.authMethod",
		"vault.useTouchID",
		"vault.search_workers",
		"vault.pseudonymize_paths",
		"vault.scrypt_work_factor",
		"vault.last_rotated",
		"vault.format_version",
		"vault.legacy_mode",
		"vault.argon2id_time",
		"vault.argon2id_memory",
		"vault.argon2id_threads",

		// Git
		"git",
		"git.commit_template",
		"git.auto_push",
		"git.auto_pull",
		"git.auto_pull_interval",

		// MCP
		"mcp",
		"mcp.bind",
		"mcp.port",
		"mcp.stdio",
		"mcp.httpTokenFile",
		"mcp.otlp_endpoint",
		"mcp.read_header_timeout",
		"mcp.read_timeout",
		"mcp.write_timeout",
		"mcp.shutdown_timeout",
		"mcp.approval_timeout",
		"mcp.rate_limit",
		"mcp.trusted_proxy_ips",
		"mcp.metrics_auth_required",
		"mcp.tls_cert_file",
		"mcp.tls_key_file",
		"mcp.allow_insecure_bind",

		// Update
		"update",
		"update.cache_ttl",

		// Clipboard
		"clipboard",
		"clipboard.auto_clear_duration",

		// Audit
		"audit",
		"audit.maxSizeMb",
		"audit.maxBackups",
		"audit.maxAgeDays",

		// Logging
		"logging",
		"logging.level",
		"logging.format",

		// Profiles
		"profiles",
		"profiles.*.vault",
	}
}

// DefaultConfigFilePath returns the default config file path (~/.openpass/config.yaml).
func DefaultConfigFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	if home == "" {
		return "", fmt.Errorf("cannot determine home directory: empty path")
	}
	return filepath.Join(home, defaultConfigDir, defaultConfigFile), nil
}

// LoadConfigNode loads a YAML config file and returns its root *yaml.Node.
func LoadConfigNode(path string) (*yaml.Node, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("cannot read config file: %w", err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("cannot parse config file: %w", err)
	}
	return &root, nil
}

// SaveConfigNode saves a *yaml.Node tree to a file using atomic writes.
func SaveConfigNode(path string, root *yaml.Node) error {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(root); err != nil {
		return fmt.Errorf("cannot encode config: %w", err)
	}
	_ = encoder.Close()

	return fileutil.AtomicWriteFile(path, buf.Bytes(), 0o600)
}

// NodeToString returns the YAML string representation of a yaml.Node.
// For scalars this returns the value directly; for complex nodes it returns
// the indented YAML block.
func NodeToString(node *yaml.Node) string {
	switch node.Kind {
	case yaml.ScalarNode, yaml.AliasNode:
		return node.Value
	default:
		var buf bytes.Buffer
		encoder := yaml.NewEncoder(&buf)
		encoder.SetIndent(2)
		if err := encoder.Encode(node); err != nil {
			return node.Value
		}
		_ = encoder.Close()
		return strings.TrimSpace(buf.String())
	}
}

// GetConfigValue navigates the YAML node tree by dotted path and returns the
// target *yaml.Node. Returns an error if the path does not exist.
func GetConfigValue(root *yaml.Node, path string) (*yaml.Node, error) {
	parts := strings.Split(path, ".")
	return navigateToNode(root, parts)
}

// SetConfigValue sets a value at the given dotted path in the YAML node tree.
// Intermediate mapping nodes are created as needed. The value string is parsed
// as YAML to infer types (bool, int, float, string, list, map).
func SetConfigValue(root *yaml.Node, path string, value string) error {
	parts := strings.Split(path, ".")
	return setNodeAtPath(root, parts, value)
}

// ConfigTreeKeys recursively walks the YAML node tree and returns all leaf
// paths as dotted strings.
func ConfigTreeKeys(root *yaml.Node) []string {
	var keys []string
	if root == nil {
		return keys
	}
	walkConfigTree(root, "", &keys)
	return keys
}

// walkConfigTree recursively walks a yaml.Node tree collecting leaf paths.
func walkConfigTree(node *yaml.Node, prefix string, keys *[]string) {
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			walkConfigTree(child, prefix, keys)
		}
	case yaml.MappingNode:
		for i := 0; i < len(node.Content)-1; i += 2 {
			key := node.Content[i].Value
			val := node.Content[i+1]
			fullPath := prefix
			if fullPath != "" {
				fullPath += "."
			}
			fullPath += key
			walkConfigTree(val, fullPath, keys)
		}
	case yaml.ScalarNode, yaml.SequenceNode, yaml.AliasNode:
		*keys = append(*keys, prefix)
	}
}

// parseConfigValue parses a CLI value string into an interface{} using YAML
// type inference. This lets users write "true" → bool, "42" → int, etc.
func parseConfigValue(value string) interface{} {
	if value == "" {
		return ""
	}
	var result interface{}
	if err := yaml.Unmarshal([]byte(value), &result); err == nil {
		return result
	}
	return value
}

// navigateToNode walks the YAML node tree following the path parts.
// It returns the node at the final path segment.
func navigateToNode(root *yaml.Node, parts []string) (*yaml.Node, error) {
	current := root

	if current.Kind == yaml.DocumentNode && len(current.Content) > 0 {
		current = current.Content[0]
	}

	for i, part := range parts {
		if current.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("cannot access key %q: parent is a %s node, not a mapping",
				part, nodeKindName(current.Kind))
		}
		var found bool
		for j := 0; j < len(current.Content)-1; j += 2 {
			if current.Content[j].Value == part {
				current = current.Content[j+1]
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("key %q not found", strings.Join(parts[:i+1], "."))
		}
	}
	return current, nil
}

func setNodeAtPath(root *yaml.Node, parts []string, value string) error {
	if len(parts) == 0 {
		return fmt.Errorf("empty path")
	}

	current := root
	if current.Kind == yaml.DocumentNode && len(current.Content) > 0 {
		current = current.Content[0]
	}
	if current.Kind != yaml.MappingNode {
		return fmt.Errorf("root node is a %s, not a mapping", nodeKindName(current.Kind))
	}

	for i, part := range parts {
		if current.Kind != yaml.MappingNode {
			return fmt.Errorf("cannot set key %q: parent is a %s node", part, nodeKindName(current.Kind))
		}

		foundIdx := -1
		for j := 0; j < len(current.Content)-1; j += 2 {
			if current.Content[j].Value == part {
				foundIdx = j
				break
			}
		}

		if i == len(parts)-1 {
			parsed := parseConfigValue(value)
			valueNode := &yaml.Node{}
			if err := valueNode.Encode(parsed); err != nil {
				return fmt.Errorf("cannot encode value: %w", err)
			}
			if foundIdx >= 0 {
				current.Content[foundIdx+1] = valueNode
			} else {
				keyNode := &yaml.Node{
					Kind:  yaml.ScalarNode,
					Value: part,
					Tag:   "!!str",
				}
				current.Content = append(current.Content, keyNode, valueNode)
			}
			return nil
		}

		if foundIdx >= 0 {
			child := current.Content[foundIdx+1]
			if child.Kind != yaml.MappingNode {
				newMap := &yaml.Node{
					Kind: yaml.MappingNode,
					Tag:  "!!map",
				}
				current.Content[foundIdx+1] = newMap
				current = newMap
			} else {
				current = child
			}
		} else {
			newMap := &yaml.Node{
				Kind: yaml.MappingNode,
				Tag:  "!!map",
			}
			keyNode := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: part,
				Tag:   "!!str",
			}
			current.Content = append(current.Content, keyNode, newMap)
			current = newMap
		}
	}

	return nil
}

// nodeKindName returns a human-readable name for a yaml.Kind.
func nodeKindName(kind yaml.Kind) string {
	switch kind {
	case yaml.DocumentNode:
		return "document"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	default:
		return fmt.Sprintf("unknown(%d)", kind)
	}
}
