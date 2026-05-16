// Package apitemplates provides API request templates with credential isolation.
// Templates define how to authenticate and communicate with external APIs
// without agents ever seeing the raw credential values.
package apitemplates

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// AuthType defines the authentication mechanism for an API template.
type AuthType string

const (
	// AuthBearer sends credentials via Authorization: Bearer <token> header.
	AuthBearer AuthType = "bearer"
	// AuthBasic sends credentials via HTTP Basic Auth (base64(username:password)).
	AuthBasic AuthType = "basic"
	// AuthHeader sends credentials via a custom header defined in the vault entry.
	AuthHeader AuthType = "header"
	// AuthQueryParam sends credentials as a URL query parameter.
	AuthQueryParam AuthType = "query_param"
)

// APITemplate defines how to authenticate and communicate with an external API.
type APITemplate struct {
	// Name is the template identifier (e.g., "github", "openai").
	Name string `yaml:"-" json:"name"`
	// BaseURL is the base URL for the API (e.g., "https://api.github.com").
	BaseURL string `yaml:"base_url" json:"base_url"`
	// AuthType specifies the authentication mechanism.
	AuthType AuthType `yaml:"auth_type" json:"auth_type"`
	// EntryRef is the 1Password op:// vault reference for credential storage.
	EntryRef string `yaml:"entry_ref" json:"entry_ref"`
	// AllowedEndpoints is a list of glob patterns for allowed endpoint paths.
	AllowedEndpoints []string `yaml:"allowed_endpoints" json:"allowed_endpoints"`
	// AllowedMethods is a list of allowed HTTP methods.
	AllowedMethods []string `yaml:"allowed_methods" json:"allowed_methods"`
	// DefaultHeaders are headers to include in every request.
	DefaultHeaders map[string]string `yaml:"default_headers" json:"default_headers,omitempty"`
}

// templateFile is the on-disk representation of an APITemplate.
type templateFile struct {
	BaseURL          string            `yaml:"base_url"`
	AuthType         AuthType          `yaml:"auth_type"`
	EntryRef         string            `yaml:"entry_ref"`
	AllowedEndpoints []string          `yaml:"allowed_endpoints"`
	AllowedMethods   []string          `yaml:"allowed_methods"`
	DefaultHeaders   map[string]string `yaml:"default_headers"`
}

// Load loads a template by name. It checks the user's template directory
// (<vault>/templates/) first, then falls back to embedded built-ins.
func Load(name string, vaultDir string) (*APITemplate, error) {
	if name == "" {
		return nil, fmt.Errorf("template name is required")
	}

	// Check user override directory first
	if vaultDir != "" {
		userPath := filepath.Join(vaultDir, "templates", name+".yaml")
		if _, err := os.Stat(userPath); err == nil {
			return loadFromFile(name, userPath)
		}
	}

	// Fall back to built-in templates
	return loadBuiltin(name)
}

// LoadAll loads all embedded built-in templates.
func LoadAll() ([]*APITemplate, error) {
	var templates []*APITemplate

	// Load built-in templates
	entries, err := builtinFS.ReadDir("builtin")
	if err != nil {
		return nil, fmt.Errorf("read builtin templates: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		name := entry.Name()[:len(entry.Name())-len(".yaml")]
		tmpl, err := loadBuiltin(name)
		if err != nil {
			return nil, fmt.Errorf("load builtin %q: %w", name, err)
		}
		templates = append(templates, tmpl)
	}

	if len(templates) == 0 {
		return nil, fmt.Errorf("no templates found")
	}

	return templates, nil
}

// loadBuiltin loads a built-in template by name.
func loadBuiltin(name string) (*APITemplate, error) {
	data, err := builtinFS.ReadFile(filepath.Join("builtin", name+".yaml"))
	if err != nil {
		return nil, fmt.Errorf("template %q not found", name)
	}
	return parseTemplate(name, data)
}

// loadFromFile loads a template from a file path.
func loadFromFile(name, path string) (*APITemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read template file %q: %w", path, err)
	}
	return parseTemplate(name, data)
}

// parseTemplate parses YAML data into an APITemplate.
func parseTemplate(name string, data []byte) (*APITemplate, error) {
	var tf templateFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("parse template %q: %w", name, err)
	}

	if tf.BaseURL == "" {
		return nil, fmt.Errorf("template %q: base_url is required", name)
	}
	if tf.AuthType == "" {
		return nil, fmt.Errorf("template %q: auth_type is required", name)
	}
	if tf.EntryRef == "" {
		return nil, fmt.Errorf("template %q: entry_ref is required", name)
	}

	return &APITemplate{
		Name:             name,
		BaseURL:          tf.BaseURL,
		AuthType:         tf.AuthType,
		EntryRef:         tf.EntryRef,
		AllowedEndpoints: tf.AllowedEndpoints,
		AllowedMethods:   tf.AllowedMethods,
		DefaultHeaders:   tf.DefaultHeaders,
	}, nil
}
