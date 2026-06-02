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

var QuietModeFn func() bool
var OutputFormatFn func() string

type Printer interface {
	Print(v interface{}) error
}

type TextPrinter struct{}

func (p TextPrinter) Print(v interface{}) error {
	if QuietModeFn != nil && QuietModeFn() {
		return nil
	}
	fmt.Println(v)
	return nil
}

type JSONPrinter struct{}

func (p JSONPrinter) Print(v interface{}) error {
	if QuietModeFn != nil && QuietModeFn() {
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

type YAMLPrinter struct{}

func (p YAMLPrinter) Print(v interface{}) error {
	if QuietModeFn != nil && QuietModeFn() {
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

func NewPrinter(format string) (Printer, error) {
	switch format {
	case formatText, "":
		return TextPrinter{}, nil
	case "json":
		return JSONPrinter{}, nil
	case "yaml":
		return YAMLPrinter{}, nil
	default:
		return nil, fmt.Errorf("unknown output format: %q (valid: text, json, yaml)", format)
	}
}

func PrintResult(v interface{}) error {
	format := formatText
	if OutputFormatFn != nil {
		format = OutputFormatFn()
	}
	printer, err := NewPrinter(format)
	if err != nil {
		return err
	}
	return printer.Print(v)
}

func PrintJSON(v interface{}) {
	if QuietModeFn != nil && QuietModeFn() {
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		cliout.Errorf("JSON encoding error: %v", err)
	}
}

var jsonDeprecationWarned = false

func WantJSONOutput(legacyJSON bool) bool {
	format := formatText
	if OutputFormatFn != nil {
		format = OutputFormatFn()
	}
	if format == "json" {
		return true
	}
	if legacyJSON {
		if !jsonDeprecationWarned {
			jsonDeprecationWarned = true
			cliout.Warnf("Note: --json is deprecated; prefer --output=json (works on all commands).")
		}
		return true
	}
	return false
}
