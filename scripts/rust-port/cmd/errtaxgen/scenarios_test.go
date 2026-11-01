package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyNormalizers(t *testing.T) {
	got, err := applyNormalizers([]string{normalizePassword20}, observation{Stdout: "abcdefghij0123456789\n"})
	if err != nil || got.Stdout != passwordPlaceholder {
		t.Fatalf("password20 = %q, %v", got.Stdout, err)
	}
	for _, stdout := range []string{"short\n", "abcdefghij0123456789", "abcdefghij0123456789\nextra\n", "abcdefghij012345678!\n"} {
		got, err := applyNormalizers([]string{normalizePassword20}, observation{Stdout: stdout})
		if err != nil || got.Stdout != stdout {
			t.Errorf("password20 must leave %q alone, got %q, %v", stdout, got.Stdout, err)
		}
	}
	got, err = applyNormalizers([]string{normalizeKeyBytes}, observation{Stderr: "New key: b9e4f8cc (first 4 bytes)\nNew key: zz (first 4 bytes)\n"})
	if err != nil || got.Stderr != keyBytesLine+"\nNew key: zz (first 4 bytes)\n" {
		t.Fatalf("key_bytes = %q, %v", got.Stderr, err)
	}
	if _, err := applyNormalizers([]string{"bogus"}, observation{}); err == nil {
		t.Fatal("an unknown normalizer must be an error")
	}
}

// withBookkeeping swaps the exclusion and normalizer tables for one test.
func withBookkeeping(t *testing.T, exclusions []exclusion, normalizers map[string][]string) {
	t.Helper()
	origExclusions, origNormalizers := scenarioExclusions, scenarioNormalizers
	t.Cleanup(func() { scenarioExclusions, scenarioNormalizers = origExclusions, origNormalizers })
	scenarioExclusions, scenarioNormalizers = exclusions, normalizers
}

func TestExtraPositionalInputsMatrix(t *testing.T) {
	withBookkeeping(t,
		[]exclusion{{Path: "symvault doctor", States: bothStates, Reason: "host report"}},
		map[string][]string{"symvault generate": {normalizePassword20}})
	inventory := []nilArgsEntry{
		{Path: "symvault lock", Runnable: true},
		{Path: "symvault share", HasSubcommands: true},
		{Path: "symvault generate", Runnable: true, HasSubcommands: true},
		{Path: "symvault doctor", Runnable: true},
	}
	inputs, err := extraPositionalInputs(inventory)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]scenarioInput{}
	for _, in := range inputs {
		if _, dup := names[in.name]; dup {
			t.Errorf("duplicate scenario %s", in.name)
		}
		names[in.name] = in
	}
	// lock: 3 uninitialized + 2 initialized; generate likewise; doctor is excluded
	// in both states and the non-runnable group has no scenario.
	if len(inputs) != 10 {
		t.Fatalf("%d inputs, want 10: %v", len(inputs), names)
	}
	if got := names["extra_initialized_lock_x2"].args; strings.Join(got, " ") != "lock x y" {
		t.Errorf("lock x2 args = %v", got)
	}
	if got := names["extra_uninitialized_lock_dd1"].args; strings.Join(got, " ") != "lock -- x" {
		t.Errorf("lock dd1 args = %v", got)
	}
	if _, ok := names["extra_initialized_lock_dd1"]; ok {
		t.Error("the -- variant is recorded in the empty sandbox only")
	}
	if got := names["extra_uninitialized_generate_x1"].normalize; len(got) != 1 || got[0] != normalizePassword20 {
		t.Errorf("generate normalize = %v", got)
	}
	for name := range names {
		if strings.Contains(name, "doctor") || strings.Contains(name, "share") {
			t.Errorf("unexpected scenario %s", name)
		}
	}
}

func TestExtraPositionalInputsRejectsStaleBookkeeping(t *testing.T) {
	lock := []nilArgsEntry{{Path: "symvault lock", Runnable: true}}
	withBookkeeping(t, []exclusion{{Path: "symvault gone", States: bothStates, Reason: "r"}}, nil)
	if _, err := extraPositionalInputs(lock); err == nil || !strings.Contains(err.Error(), "scenarioExclusions") {
		t.Fatalf("err = %v, want a stale-exclusion error", err)
	}
	withBookkeeping(t, nil, map[string][]string{"symvault gone": {normalizePassword20}})
	if _, err := extraPositionalInputs(lock); err == nil || !strings.Contains(err.Error(), "scenarioNormalizers") {
		t.Fatalf("err = %v, want a stale-normalizer error", err)
	}
}

// The production tables name commands of the compiled tree only.
func TestProductionBookkeepingMatchesTheInventory(t *testing.T) {
	inventory, err := compiledNilArgsInventory()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := extraPositionalInputs(inventory); err != nil {
		t.Fatal(err)
	}
}

func TestExclusionsCarryReasons(t *testing.T) {
	for _, item := range scenarioExclusions {
		if item.Reason == "" || len(item.States) == 0 {
			t.Errorf("exclusion %+v needs a reason and a state", item)
		}
	}
}

func TestRunFileUseInputs(t *testing.T) {
	inputs := runFileUseInputs()
	seen := map[string]bool{}
	states := map[string]int{}
	for _, in := range inputs {
		if seen[in.name] {
			t.Errorf("duplicate %s", in.name)
		}
		seen[in.name] = true
		states[in.state]++
		if in.args[0] != "run" && !(in.args[0] == "file" && in.args[1] == "use") {
			t.Errorf("%s covers %v", in.name, in.args)
		}
	}
	if states[stateUninitialized] != states[stateInitialized] || states[stateInitialized] == 0 {
		t.Fatalf("states = %v", states)
	}
}

func TestSeedRoundTrip(t *testing.T) {
	src, err := newSandbox()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(src.root) }()
	vault := filepath.Join(src.root, "xdg-data", "vault")
	if err := os.MkdirAll(filepath.Join(vault, "entries"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vault, "config.yaml"), []byte("vaultDir: "+vault+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vault, "identity.age"), []byte{0x00, 0xff, 0x10}, 0o600); err != nil {
		t.Fatal(err)
	}
	seed, err := src.collectSeed()
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, item := range seed {
		kinds = append(kinds, item.Kind+":"+item.Path)
		if item.Path == "xdg-data/vault/config.yaml" && item.Data != "vaultDir: "+rootMarker+"/xdg-data/vault\n" {
			t.Errorf("config text = %q: the sandbox root must be recorded as %s", item.Data, rootMarker)
		}
		if item.Path == "xdg-data/vault/identity.age" && (item.Base64 == "" || item.Data != "") {
			t.Errorf("binary file must be base64: %+v", item)
		}
	}
	if len(seed) != 5 || kinds[0] != "dir:xdg-data" {
		t.Fatalf("seed = %v", kinds)
	}

	dst, err := newSandbox()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dst.root) }()
	if err := dst.writeSeed(seed); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dst.root, "xdg-data", "vault", "config.yaml")) // #nosec G304 -- test temp path
	if err != nil || string(raw) != "vaultDir: "+filepath.Join(dst.root, "xdg-data", "vault")+"\n" {
		t.Fatalf("config = %q, %v", raw, err)
	}
	if info, err := os.Stat(filepath.Join(dst.root, "xdg-data", "vault", "identity.age")); err != nil || info.Mode().Perm() != 0o600 || info.Size() != 3 {
		t.Fatalf("identity = %v, %v", info, err)
	}
	if err := dst.writeSeed([]seedFile{{Path: "x", Kind: "socket"}}); err == nil {
		t.Fatal("an unknown seed kind must be rejected")
	}
}

func TestExistingSeed(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"vault_seed":[{"path":"a","kind":"dir","mode":448}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if seed := existingSeed(good); len(seed) != 1 || seed[0].Path != "a" {
		t.Fatalf("seed = %v", seed)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if existingSeed(bad) != nil || existingSeed(filepath.Join(dir, "missing.json")) != nil {
		t.Fatal("an unreadable fixture has no seed")
	}
}

func TestRecordScenariosFlagsVolatileOutput(t *testing.T) {
	skipWithoutPOSIXShell(t)
	steady := fakeOracle(t, `echo steady; exit 0`)
	inputs := []scenarioInput{{name: "steady", state: stateUninitialized, args: []string{"x"}}}
	cases, err := recordScenarios(steady, nil, inputs)
	if err != nil || len(cases) != 1 || cases[0].Observation.Stdout != "steady\n" {
		t.Fatalf("cases = %+v, %v", cases, err)
	}

	counter := filepath.Join(t.TempDir(), "n")
	volatile := fakeOracle(t, `n=$(cat `+counter+` 2>/dev/null || echo 0); n=$((n+1)); echo $n > `+counter+`; echo "run $n"`)
	_, err = recordScenarios(volatile, nil, inputs)
	if err == nil || !strings.Contains(err.Error(), "is not deterministic") || !strings.Contains(err.Error(), "run 1") {
		t.Fatalf("err = %v, want a determinism failure naming the differing line", err)
	}
}

func TestRecordScenariosAppliesNormalizersBeforeComparing(t *testing.T) {
	skipWithoutPOSIXShell(t)
	counter := filepath.Join(t.TempDir(), "n")
	script := `n=$(cat ` + counter + ` 2>/dev/null || echo 0); n=$((n+1)); echo $n > ` + counter + `; printf 'abcdefghij01234567%02d\n' $n`
	oracle := fakeOracle(t, script)
	inputs := []scenarioInput{{name: "generate", state: stateUninitialized, args: []string{"generate", "x"}, normalize: []string{normalizePassword20}}}
	cases, err := recordScenarios(oracle, nil, inputs)
	if err != nil || cases[0].Observation.Stdout != passwordPlaceholder {
		t.Fatalf("cases = %+v, %v", cases, err)
	}
	inputs[0].normalize = []string{"bogus"}
	if _, err := recordScenarios(oracle, nil, inputs); err == nil {
		t.Fatal("an unknown normalizer must fail the recording")
	}
}

func TestFirstDifference(t *testing.T) {
	a := observation{Stdout: "one\ntwo\n", Stderr: "e\n"}
	if got := firstDifference(a, observation{Stdout: "one\n2\n", Stderr: "e\n"}); !strings.Contains(got, "stdout line 2") {
		t.Errorf("got %s", got)
	}
	if got := firstDifference(a, observation{ExitCode: 2, Stdout: a.Stdout, Stderr: a.Stderr}); !strings.Contains(got, "exit 0 vs 2") {
		t.Errorf("got %s", got)
	}
	if got := firstDifference(a, a); got != "identical" {
		t.Errorf("got %s", got)
	}
}

// The compiled command tree is the source of the nil-Args list. These are the
// facts the Rust port relies on; the digest-bound sources make them the pinned
// oracle's.
func TestCompiledNilArgsInventory(t *testing.T) {
	inventory, err := compiledNilArgsInventory()
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]nilArgsEntry{}
	for i, entry := range inventory {
		byPath[entry.Path] = entry
		if i > 0 && inventory[i-1].Path >= entry.Path {
			t.Errorf("inventory is not sorted at %s", entry.Path)
		}
		if entry.Path == "symvault" {
			t.Error("the root is not part of the inventory")
		}
	}
	for _, want := range []string{"symvault lock", "symvault verify", "symvault unlock", "symvault generate", "symvault share list", "symvault policy list"} {
		if entry, ok := byPath[want]; !ok || !entry.Runnable {
			t.Errorf("%s must be a runnable nil-Args command, got %+v", want, entry)
		}
	}
	if byPath["symvault help"].Origin != "cobra" {
		t.Errorf("help must be recorded as a cobra default command: %+v", byPath["symvault help"])
	}
	// Commands with a validator are not nil-Args.
	for _, not := range []string{"symvault get", "symvault run", "symvault file use", "symvault delete"} {
		if _, ok := byPath[not]; ok {
			t.Errorf("%s has an Args validator", not)
		}
	}
	if group := byPath["symvault config"]; group.Runnable || !group.HasSubcommands {
		t.Errorf("config is a non-runnable group: %+v", group)
	}
}
