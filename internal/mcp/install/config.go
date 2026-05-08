package install

import (
	"encoding/json"
	"fmt"
	"os"

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

// GetReaderWriter returns the appropriate reader/writer for the given format.
func GetReaderWriter(format ConfigFormat) (ConfigReaderWriter, error) {
	switch format {
	case FormatJSON:
		return JSONConfigRW{}, nil
	case FormatYAML:
		return YAMLConfigRW{}, nil
	default:
		return nil, fmt.Errorf("unsupported config format %q", format)
	}
}

// InjectServerConfig injects or updates the OpenPass server configuration
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
