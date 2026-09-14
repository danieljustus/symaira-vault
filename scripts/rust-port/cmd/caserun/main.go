// caserun exposes the existing native process-tree harness to CLI drivers.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/diff"
)

type request struct {
	Binary string    `json:"binary"`
	Case   diff.Case `json:"case"`
}

func execute(input io.Reader, output io.Writer) error {
	var req request
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("expected one request, got trailing input: %v", err)
	}
	if req.Binary == "" {
		return fmt.Errorf("binary is required")
	}
	result, err := diff.Run(req.Binary, req.Case)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}

func main() {
	if err := execute(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
