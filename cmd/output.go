package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	cli "github.com/danieljustus/OpenPass/internal/cli"
)

// Printer defines the interface for output formatting.
type Printer interface {
	Print(v interface{}) error
}

// TextPrinter outputs values as plain text.
type TextPrinter struct{}

func (p TextPrinter) Print(v interface{}) error {
	if quietMode {
		return nil
	}
	fmt.Println(v)
	return nil
}

// JSONPrinter outputs values as JSON.
type JSONPrinter struct{}

func (p JSONPrinter) Print(v interface{}) error {
	if quietMode {
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// YAMLPrinter outputs values as YAML.
type YAMLPrinter struct{}

func (p YAMLPrinter) Print(v interface{}) error {
	if quietMode {
		return nil
	}
	out, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}

// NewPrinter creates a Printer for the given format.
// Valid formats: "text", "json", "yaml".
func NewPrinter(format string) (Printer, error) {
	switch format {
	case "text", "":
		return TextPrinter{}, nil
	case "json":
		return JSONPrinter{}, nil
	case "yaml":
		return YAMLPrinter{}, nil
	default:
		return nil, fmt.Errorf("unknown output format: %q (valid: text, json, yaml)", format)
	}
}

// PrintResult prints the value using the current output format.
func PrintResult(v interface{}) error {
	printer, err := NewPrinter(cli.OutputFormat)
	if err != nil {
		return err
	}
	return printer.Print(v)
}

// PrintJSON outputs the given value as JSON to stdout.
//
// Deprecated: use PrintResult with json format instead.
func PrintJSON(v interface{}) {
	if quietMode {
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "JSON encoding error: %v\n", err)
	}
}
