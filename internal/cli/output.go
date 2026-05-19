package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Printer interface {
	Print(v interface{}) error
}

type TextPrinter struct{}

func (p TextPrinter) Print(v interface{}) error {
	if QuietMode {
		return nil
	}
	fmt.Println(v)
	return nil
}

type JSONPrinter struct{}

func (p JSONPrinter) Print(v interface{}) error {
	if QuietMode {
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

type YAMLPrinter struct{}

func (p YAMLPrinter) Print(v interface{}) error {
	if QuietMode {
		return nil
	}
	out, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}

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

func PrintResult(v interface{}) error {
	printer, err := NewPrinter(OutputFormat)
	if err != nil {
		return err
	}
	return printer.Print(v)
}

func PrintJSON(v interface{}) {
	if QuietMode {
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "JSON encoding error: %v\n", err)
	}
}

var jsonDeprecationWarned = false

func WantJSONOutput(legacyJSON bool) bool {
	if OutputFormat == "json" {
		return true
	}
	if legacyJSON {
		if !jsonDeprecationWarned {
			jsonDeprecationWarned = true
			fmt.Fprintln(os.Stderr, "Note: --json is deprecated; prefer --output=json (works on all commands).")
		}
		return true
	}
	return false
}
