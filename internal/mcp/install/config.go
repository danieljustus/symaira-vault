package install

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ConfigReaderWriter handles serialization and deserialization of agent configs.
type ConfigReaderWriter interface {
	Read(path string) (map[string]any, error)
	Write(path string, data map[string]any) error
}

// JSONConfigRW reads and writes JSON config files.
type JSONConfigRW struct{}

// Read reads a JSON config file. If the file does not exist, it returns an empty map.
func (j JSONConfigRW) Read(path string) (map[string]any, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is validated by caller
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]any), nil
		}
		return nil, fmt.Errorf("read JSON config %q: %w", path, err)
	}

	var result map[string]any
	if len(data) == 0 {
		return make(map[string]any), nil
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse JSON config %q: %w", path, err)
	}
	if result == nil {
		return make(map[string]any), nil
	}
	return result, nil
}

// Write writes data to a JSON config file with 0o600 permissions.
func (j JSONConfigRW) Write(path string, data map[string]any) error {
	out, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON config: %w", err)
	}
	out = append(out, '\n')
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("write JSON config %q: %w", path, err)
	}
	return nil
}

// YAMLConfigRW reads and writes YAML config files.
type YAMLConfigRW struct{}

// Read reads a YAML config file. If the file does not exist, it returns an empty map.
func (y YAMLConfigRW) Read(path string) (map[string]any, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is validated by caller
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]any), nil
		}
		return nil, fmt.Errorf("read YAML config %q: %w", path, err)
	}

	var result map[string]any
	if len(data) == 0 {
		return make(map[string]any), nil
	}
	if err := yaml.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse YAML config %q: %w", path, err)
	}
	if result == nil {
		return make(map[string]any), nil
	}
	return result, nil
}

// Write writes data to a YAML config file with 0o600 permissions.
func (y YAMLConfigRW) Write(path string, data map[string]any) error {
	out, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal YAML config: %w", err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("write YAML config %q: %w", path, err)
	}
	return nil
}

// TOMLConfigRW reads and writes TOML config files using a simple line-based
// parser that handles the section structure needed for MCP server configuration
// (e.g. [mcp_servers.symvault]).
type TOMLConfigRW struct{}

// Read reads a TOML config file. Only top-level string key-value pairs and
// section blocks are parsed; inline tables and arrays are returned as raw strings.
func (t TOMLConfigRW) Read(path string) (map[string]any, error) {
	data, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]any), nil
		}
		return nil, fmt.Errorf("read TOML config %q: %w", path, err)
	}
	return parseTOML(string(data)), nil
}

// Write writes data to a TOML config file with 0o600 permissions.
// The data map is expected to contain nested maps representing sections.
func (t TOMLConfigRW) Write(path string, data map[string]any) error {
	out := renderTOML(data, 0)
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		return fmt.Errorf("write TOML config %q: %w", path, err)
	}
	return nil
}

// parseTOML parses a TOML string into a nested map. It handles top-level keys
// and [section] / [section.subsection] headers.
func parseTOML(input string) map[string]any {
	result := make(map[string]any)
	current := result
	var sectionPath []string

	for _, line := range strings.Split(input, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Section header: [section] or [section.sub]
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			sectionPath = strings.Split(trimmed[1:len(trimmed)-1], ".")
			current = result
			for _, part := range sectionPath {
				part = strings.TrimSpace(part)
				if m, ok := current[part].(map[string]any); ok {
					current = m
				} else {
					m := make(map[string]any)
					current[part] = m
					current = m
				}
			}
			continue
		}

		// Key = value
		if idx := strings.Index(trimmed, "="); idx > 0 {
			key := strings.TrimSpace(trimmed[:idx])
			value := strings.TrimSpace(trimmed[idx+1:])
			current[key] = parseTOMLValue(value)
		}
	}

	return result
}

// parseTOMLValue parses a TOML value string into a Go value.
func parseTOMLValue(value string) any {
	if value == "" {
		return ""
	}
	switch {
	case value == "true":
		return true
	case value == "false":
		return false
	case strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`):
		return value[1 : len(value)-1]
	case strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'"):
		return value[1 : len(value)-1]
	case strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]"):
		// Inline array - return as raw string for simplicity
		return value
	default:
		// Try number
		return value
	}
}

// renderTOML renders a nested Go map as TOML. depth controls indentation (0 for top-level).
func renderTOML(data map[string]any, depth int) string {
	var sb strings.Builder
	prefix := strings.Repeat("  ", depth)

	for k, v := range data {
		switch val := v.(type) {
		case map[string]any:
			if depth == 0 {
				fmt.Fprintf(&sb, "\n[%s]\n", k)
			} else {
				fmt.Fprintf(&sb, "%s[%s]\n", prefix, k)
			}
			sb.WriteString(renderTOML(val, depth+1))
		case string:
			fmt.Fprintf(&sb, "%s%s = %q\n", prefix, k, val)
		case bool:
			fmt.Fprintf(&sb, "%s%s = %v\n", prefix, k, val)
		case int, int64, float64:
			fmt.Fprintf(&sb, "%s%s = %v\n", prefix, k, val)
		default:
			fmt.Fprintf(&sb, "%s%s = %q\n", prefix, k, fmt.Sprintf("%v", val))
		}
	}
	return sb.String()
}

// GetReaderWriter returns the appropriate reader/writer for the given format.
func GetReaderWriter(format ConfigFormat) (ConfigReaderWriter, error) {
	switch format {
	case FormatJSON:
		return JSONConfigRW{}, nil
	case FormatYAML:
		return YAMLConfigRW{}, nil
	case FormatTOML:
		return TOMLConfigRW{}, nil
	default:
		return nil, fmt.Errorf("unsupported config format %q", format)
	}
}

// InjectServerConfig injects or updates the Symaira Vault server configuration
// into an agent's config map. It returns the updated map and a bool indicating
// whether a change was made.
func InjectServerConfig(config map[string]any, rootKey, serverKey string, serverConfig map[string]any) (map[string]any, bool) {
	if config == nil {
		config = make(map[string]any)
	}

	root, ok := config[rootKey].(map[string]any)
	if !ok || root == nil {
		root = make(map[string]any)
		config[rootKey] = root
	}

	existing, ok := root[serverKey].(map[string]any)
	if ok && existing != nil {
		if configEqual(existing, serverConfig) {
			return config, false
		}
	}

	root[serverKey] = serverConfig
	return config, true
}

func configEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok {
			return false
		}
		switch avTyped := av.(type) {
		case map[string]any:
			bvTyped, ok := bv.(map[string]any)
			if !ok || !configEqual(avTyped, bvTyped) {
				return false
			}
		case []any, []string:
			if !slicesEqual(av, bv) {
				return false
			}
		default:
			if !valuesEqual(av, bv) {
				return false
			}
		}
	}
	return true
}

func slicesEqual(a, b any) bool {
	aStrs, aOk := asStringSlice(a)
	bStrs, bOk := asStringSlice(b)
	if !aOk || !bOk {
		return false
	}
	if len(aStrs) != len(bStrs) {
		return false
	}
	for i := range aStrs {
		if aStrs[i] != bStrs[i] {
			return false
		}
	}
	return true
}

func valuesEqual(a, b any) bool {
	if a == b {
		return true
	}
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case float64:
		return numEqual(av, b)
	case int:
		return numEqual(float64(av), b)
	case int64:
		return numEqual(float64(av), b)
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	default:
		return false
	}
}

func numEqual(a float64, b any) bool {
	switch bv := b.(type) {
	case float64:
		return a == bv
	case int:
		return a == float64(bv)
	case int64:
		return a == float64(bv)
	default:
		return false
	}
}

func asStringSlice(v any) ([]string, bool) {
	switch s := v.(type) {
	case []string:
		return s, true
	case []any:
		result := make([]string, len(s))
		for i, item := range s {
			str, ok := item.(string)
			if !ok {
				return nil, false
			}
			result[i] = str
		}
		return result, true
	default:
		return nil, false
	}
}
