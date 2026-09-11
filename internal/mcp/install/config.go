package install

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"

	"github.com/danieljustus/symaira-vault/internal/fsutil"
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

// TOMLConfigRW reads and writes TOML config files while retaining the original
// document for preservation-safe managed-entry updates.
type TOMLConfigRW struct {
	original  []byte
	rootKey   string
	serverKey string
}

// SetManagedEntry identifies the table that the installer owns.
func (t *TOMLConfigRW) SetManagedEntry(rootKey, serverKey string) {
	t.rootKey, t.serverKey = rootKey, serverKey
}

// Read reads and validates a TOML config file. If the file does not exist, it
// returns an empty map and Write will create a valid TOML document.
func (t *TOMLConfigRW) Read(path string) (map[string]any, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is validated by caller
	if err != nil {
		if os.IsNotExist(err) {
			t.original = nil
			return make(map[string]any), nil
		}
		return nil, fmt.Errorf("read TOML config %q: %w", path, err)
	}
	var result map[string]any
	if err := toml.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse TOML config %q: %w", path, err)
	}
	t.original = append(t.original[:0], data...)
	if result == nil {
		result = make(map[string]any)
	}
	return result, nil
}

// Write writes data to a TOML config file with 0600 permissions. Existing
// documents are updated by replacing only the managed table, retaining all
// unrelated bytes (including comments and formatting).
func (t *TOMLConfigRW) Write(path string, data map[string]any) error {
	var out []byte
	var err error
	if len(t.original) > 0 && t.rootKey != "" && t.serverKey != "" {
		out, err = replaceManagedTOML(t.original, t.rootKey, t.serverKey, data)
	} else {
		out, err = toml.Marshal(data)
	}
	if err != nil {
		return fmt.Errorf("marshal TOML config: %w", err)
	}
	if err := fsutil.AtomicWriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("write TOML config %q: %w", path, err)
	}
	return nil
}

func replaceManagedTOML(original []byte, rootKey, serverKey string, data map[string]any) ([]byte, error) {
	root, ok := data[rootKey].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("TOML root %q is not a table", rootKey)
	}
	server, ok := root[serverKey].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("TOML server %q is not a table", serverKey)
	}
	encoded, err := toml.Marshal(server)
	if err != nil {
		return nil, err
	}
	header := "[" + rootKey + "." + serverKey + "]\n"
	replacement := append([]byte(header), encoded...)
	lines := strings.SplitAfter(string(original), "\n")
	start, end := -1, -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\n"))
		if trimmed == header[:len(header)-1] {
			start = i
			break
		}
	}
	if start < 0 {
		separator := []byte("\n")
		if len(original) == 0 || original[len(original)-1] == '\n' {
			separator = nil
		}
		return append(append(append([]byte{}, original...), separator...), replacement...), nil
	}
	managedPrefix := "[" + rootKey + "." + serverKey + "."
	for i := start + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(strings.TrimSuffix(lines[i], "\n"))
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") && !strings.HasPrefix(trimmed, managedPrefix) {
			end = i
			break
		}
	}
	if end < 0 {
		end = len(lines)
	}
	var sb strings.Builder
	for _, line := range lines[:start] {
		sb.WriteString(line)
	}
	sb.Write(replacement)
	for _, line := range lines[end:] {
		sb.WriteString(line)
	}
	return []byte(sb.String()), nil
}

// parseTOML parses a TOML string into a nested map for compatibility with
// existing package users. Invalid input is represented as an empty map; file
// reads use toml.Unmarshal and return the parse error.
func parseTOML(input string) map[string]any {
	var result map[string]any
	if err := toml.Unmarshal([]byte(input), &result); err != nil || result == nil {
		return make(map[string]any)
	}
	return result
}

// renderTOML renders a nested Go map as TOML.
func renderTOML(data map[string]any, _ int) string {
	out, err := toml.Marshal(data)
	if err != nil {
		return ""
	}
	return string(out)
}

// GetReaderWriter returns the appropriate reader/writer for the given format.
func GetReaderWriter(format ConfigFormat) (ConfigReaderWriter, error) {
	switch format {
	case FormatJSON:
		return JSONConfigRW{}, nil
	case FormatYAML:
		return YAMLConfigRW{}, nil
	case FormatTOML:
		return &TOMLConfigRW{}, nil
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
