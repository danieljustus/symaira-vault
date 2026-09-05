// Command diffharness compares two binaries as isolated black boxes.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	portdiff "github.com/danieljustus/symaira-vault/scripts/rust-port/internal/diff"
)

func main() {
	left := flag.String("left", "", "path to the reference binary")
	right := flag.String("right", "", "path to the candidate binary")
	casesPath := flag.String("cases", "testdata/port/cli/cases.json", "path to the case suite")
	stage := flag.String("stage", "", "run only cases assigned to this migration stage")
	flag.Parse()
	if *left == "" || *right == "" {
		fatal("--left and --right are required")
	}

	content, err := os.ReadFile(*casesPath)
	if err != nil {
		fatal("read cases: %v", err)
	}
	var suite portdiff.Suite
	if err := json.Unmarshal(content, &suite); err != nil {
		fatal("decode cases: %v", err)
	}
	if suite.SchemaVersion != 1 {
		fatal("unsupported case schema_version %d", suite.SchemaVersion)
	}
	if len(suite.Cases) == 0 {
		fatal("case suite is empty")
	}

	seen := make(map[string]bool, len(suite.Cases))
	passed := 0
	for _, testCase := range suite.Cases {
		if testCase.ID == "" || seen[testCase.ID] {
			fatal("case IDs must be non-empty and unique: %q", testCase.ID)
		}
		seen[testCase.ID] = true
		if *stage != "" && testCase.Stage != *stage {
			continue
		}
		leftResult, err := portdiff.Run(*left, testCase)
		if err != nil {
			fatal("%s left run: %v", testCase.ID, err)
		}
		rightResult, err := portdiff.Run(*right, testCase)
		if err != nil {
			fatal("%s right run: %v", testCase.ID, err)
		}
		if err := portdiff.Compare(testCase, leftResult, rightResult); err != nil {
			fatal("%s: %v", testCase.ID, err)
		}
		fmt.Printf("PASS %s\n", testCase.ID)
		passed++
	}
	if passed == 0 {
		fatal("no cases selected for stage %q", *stage)
	}
	fmt.Printf("PASS all %d selected differential cases\n", passed)
}

func fatal(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "FAIL "+format+"\n", args...)
	os.Exit(1)
}
