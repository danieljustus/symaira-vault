package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestMainWritesSourceBoundFixture(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../.."))
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(oldDir); err != nil {
			t.Error(err)
		}
	}()
	oldArgs, oldCommandLine := os.Args, flag.CommandLine
	defer func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	}()
	output := filepath.Join(t.TempDir(), "http-initialize.json")
	flag.CommandLine = flag.NewFlagSet("http001initgen", flag.ExitOnError)
	os.Args = []string{"http001initgen", "--output", output}
	main()
	contents, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var got fixture
	if err := json.Unmarshal(contents, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Cases) < 25 {
		t.Fatalf("generated %d oracle cases, want at least 25", len(got.Cases))
	}
	for _, name := range []string{"initialize", "authenticated_prompts_list_after_initialize"} {
		found := false
		for _, testCase := range got.Cases {
			if testCase.Name == name {
				found = true
				if name == "authenticated_prompts_list_after_initialize" && !testCase.Response.ConnectionReused {
					t.Fatalf("%s did not record HTTP keep-alive reuse", name)
				}
				break
			}
		}
		if !found {
			t.Fatalf("generated fixture omits %q", name)
		}
	}
}
