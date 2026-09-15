package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/scripts/rust-port/internal/diff"
)

func TestHelper(t *testing.T) {
	if os.Getenv("CASERUN_HELPER") != "1" {
		t.Skip("runs only as the re-executed helper subprocess")
	}
	switch os.Args[len(os.Args)-1] {
	case "write":
		if err := os.Mkdir(filepath.Join(os.Getenv("HOME"), "unexpected"), 0o700); err != nil {
			os.Exit(2)
		}
	case "timeout":
		time.Sleep(time.Minute)
	case "streams":
		fmt.Fprint(os.Stdout, "out\x00")
		fmt.Fprint(os.Stderr, "err\xff")
		os.Exit(7)
	}
	os.Exit(0)
}

func TestExecuteNativeObservations(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"clean", "write", "timeout", "streams"} {
		t.Run(mode, func(t *testing.T) {
			req := request{Binary: binary, Case: diff.Case{
				ID: mode, Args: []string{"-test.run=^TestHelper$", "--", mode},
				// This test re-executes its own binary. Under -cover that
				// binary's coverage runtime writes "warning: GOCOVERDIR not
				// set" to stderr on exit, which corrupts the raw-stream
				// assertion below. Giving it a directory silences the warning
				// at its source instead of relaxing the byte comparison.
				Env:       map[string]string{"CASERUN_HELPER": "1", "GOCOVERDIR": t.TempDir()},
				TimeoutMS: 10000,
				Setup:     []diff.SetupFile{{Path: "fixture", Content: "untouched"}},
			}}
			if mode == "timeout" {
				req.Case.TimeoutMS = 250
			}
			input, marshalErr := json.Marshal(req)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			var output bytes.Buffer
			if runErr := execute(bytes.NewReader(input), &output); runErr != nil {
				t.Fatal(runErr)
			}
			var result diff.Result
			if decodeErr := json.Unmarshal(output.Bytes(), &result); decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if result.TimedOut != (mode == "timeout") {
				t.Fatalf("unexpected timeout: %v", result.TimedOut)
			}
			if reflect.DeepEqual(result.FilesBefore, result.Files) != (mode != "write") {
				t.Fatal("before/after manifests did not detect mutation correctly")
			}
			if mode == "streams" && (result.ExitCode != 7 || string(result.Stdout) != "out\x00" || string(result.Stderr) != "err\xff") {
				t.Fatal("lost raw output or exit status")
			}
			if _, statErr := os.Stat(result.SandboxRoot); !os.IsNotExist(statErr) {
				t.Fatalf("sandbox not cleaned: %v", statErr)
			}
		})
	}
}

func TestExecuteRejectsInvalidRequests(t *testing.T) {
	for _, input := range []string{`{}`, `{"unknown":1}`, `{} {}`, `{} trailing`} {
		var output bytes.Buffer
		if err := execute(strings.NewReader(input), &output); err == nil || output.Len() != 0 {
			t.Fatalf("accepted invalid request %q", input)
		}
	}
}
