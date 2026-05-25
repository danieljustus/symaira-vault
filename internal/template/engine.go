// Package template provides template-based secret generation for Symaira Vault.
// It supports built-in templates (env, docker-compose, k8s-secret, github-actions, terraform)
// and custom templates loaded from a directory.
package template

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	vaultsvc "github.com/danieljustus/symaira-vault/internal/vaultsvc"
)

// ErrTemplateNotFound is returned when a requested template does not exist.
var ErrTemplateNotFound = errors.New("template not found")

// ErrInvalidRef is returned when a secret reference cannot be parsed.
var ErrInvalidRef = errors.New("invalid secret reference")

// ErrValidationFailed is returned when template validation fails.
var ErrValidationFailed = errors.New("template validation failed")

// RenderData is the data structure passed to all templates during execution.
type RenderData struct {
	// Name is the name of the resource being generated (e.g., secret name, env file name).
	Name string
	// Refs maps template variable names to secret references.
	Refs map[string]string
	// Values maps template variable names to resolved (or masked) secret values.
	Values map[string]string
}

// Engine provides template rendering and validation for secret generation.
type Engine struct {
	vault    vaultsvc.Service
	funcs    template.FuncMap
	builtins map[string]string
	custom   map[string]string
}

// NewEngine creates a new template engine backed by the given vault service.
func NewEngine(vault vaultsvc.Service) *Engine {
	return &Engine{
		vault:    vault,
		funcs:    DefaultFuncMap(),
		builtins: builtinTemplates(),
		custom:   make(map[string]string),
	}
}

// Render executes the named template with the given secret references.
// In dry-run mode, all secret values are replaced with "***".
func (e *Engine) Render(ctx context.Context, templateName string, name string, refs map[string]string, dryRun bool) (string, error) {
	src, err := e.getTemplateSource(templateName)
	if err != nil {
		return "", err
	}

	values, err := e.resolveRefs(ctx, refs, dryRun)
	if err != nil {
		return "", err
	}

	tmpl, err := template.New(templateName).Funcs(e.funcs).Parse(src)
	if err != nil {
		return "", fmt.Errorf("parse template %q: %w", templateName, err)
	}

	data := RenderData{
		Name:   name,
		Refs:   refs,
		Values: values,
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template %q: %w", templateName, err)
	}

	return buf.String(), nil
}

// Validate checks that all secret references in refs can be resolved from the vault.
func (e *Engine) Validate(ctx context.Context, templateName string, refs map[string]string) error {
	_, err := e.resolveRefs(ctx, refs, false)
	return err
}

// LoadCustomTemplates loads all .tmpl files from the given directory as custom templates.
// The template name is the filename without the extension.
func (e *Engine) LoadCustomTemplates(dir string) error {
	templates, err := loadTemplatesFromDir(dir)
	if err != nil {
		return err
	}
	e.custom = templates
	return nil
}

// ListBuiltins returns the names of all available built-in templates, sorted alphabetically.
func (e *Engine) ListBuiltins() []string {
	names := make([]string, 0, len(e.builtins))
	for name := range e.builtins {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// getTemplateSource returns the raw template string for the given template name.
// It checks custom templates first, then built-ins.
func (e *Engine) getTemplateSource(name string) (string, error) {
	if src, ok := e.custom[name]; ok {
		return src, nil
	}
	if src, ok := e.builtins[name]; ok {
		return src, nil
	}
	return "", fmt.Errorf("%w: %s", ErrTemplateNotFound, name)
}

// resolveRefs resolves all secret references in refs.
// In dry-run mode, returns masked values instead of actual secrets.
func (e *Engine) resolveRefs(ctx context.Context, refs map[string]string, dryRun bool) (map[string]string, error) {
	values := make(map[string]string, len(refs))
	if dryRun {
		for alias := range refs {
			values[alias] = "***"
		}
		return values, nil
	}

	aliases := make([]string, 0, len(refs))
	for alias := range refs {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)

	for _, alias := range aliases {
		ref := refs[alias]
		value, err := ResolveRef(ctx, e.vault, ref)
		if err != nil {
			return nil, fmt.Errorf("resolve ref %q: %w", alias, err)
		}
		values[alias] = value
	}
	return values, nil
}

// loadTemplatesFromDir reads all .tmpl files from a directory.
func loadTemplatesFromDir(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read template directory: %w", err)
	}

	templates := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tmpl") {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), ".tmpl")
		path := filepath.Join(dir, entry.Name())
		content, err := os.ReadFile(path) //#nosec G304 -- path is constructed from dir (validated above) and .tmpl file entries
		if err != nil {
			return nil, fmt.Errorf("read template %s: %w", path, err)
		}
		templates[name] = string(content)
	}

	return templates, nil
}
