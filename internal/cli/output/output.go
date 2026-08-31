// Package output provides output formatting and printing utilities for the CLI,
// supporting text, JSON, and YAML output formats.
package output

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
)

// Deps holds the external dependencies required by output handlers.
type Deps struct {
	Quiet  func() bool
	Format func() string
}

// Handler formats and prints output using explicit dependencies.
type Handler struct {
	deps Deps
}

// New creates a Handler bound to the provided dependencies.
func New(deps Deps) *Handler {
	return &Handler{deps: deps}
}

// Printer is the interface for format-specific output.
type Printer interface {
	Print(v interface{}) error
}

type textPrinter struct {
	deps Deps
}

func (p textPrinter) Print(v interface{}) error {
	if p.deps.Quiet() {
		return nil
	}
	// This is explicit user-facing CLI output, not application logging.
	// CodeQL: exclude
	fmt.Println(v)
	return nil
}

type jsonPrinter struct {
	deps Deps
}

func (p jsonPrinter) Print(v interface{}) error {
	if p.deps.Quiet() {
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

type yamlPrinter struct {
	deps Deps
}

func (p yamlPrinter) Print(v interface{}) error {
	if p.deps.Quiet() {
		return nil
	}
	out, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}

const formatText = "text"

// NewPrinter returns a Printer for the requested format.
func (h *Handler) NewPrinter(format string) (Printer, error) {
	switch format {
	case formatText, "":
		return textPrinter{deps: h.deps}, nil
	case "json":
		return jsonPrinter{deps: h.deps}, nil
	case "yaml":
		return yamlPrinter{deps: h.deps}, nil
	default:
		return nil, fmt.Errorf("unknown output format: %q (valid: text, json, yaml)", format)
	}
}

// PrintResult formats and prints v using the configured output format.
func (h *Handler) PrintResult(v interface{}) error {
	format := formatText
	if h.deps.Format != nil {
		format = h.deps.Format()
	}
	printer, err := h.NewPrinter(format)
	if err != nil {
		return err
	}
	return printer.Print(v)
}

// PrintJSON encodes v as JSON to stdout, respecting quiet mode.
func (h *Handler) PrintJSON(v interface{}) {
	if h.deps.Quiet != nil && h.deps.Quiet() {
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		cliout.Errorf("JSON encoding error: %v", err)
	}
}

// WantJSONOutput reports whether JSON output is requested.
func (h *Handler) WantJSONOutput(flagJSON bool) bool {
	format := formatText
	if h.deps.Format != nil {
		format = h.deps.Format()
	}
	if format == "json" {
		return true
	}
	if flagJSON {
		return true
	}
	return false
}
