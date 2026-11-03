package main

import (
	"strings"
	"testing"
)

func testSeed() []seedFile {
	return []seedFile{
		{Path: "xdg-data/symaira-vault", Kind: "dir"},
		{Path: "xdg-data/symaira-vault/config.yaml", Kind: "file", Data: "vaultDir: x\n"},
		{Path: "xdg-data/symaira-vault/identity.age", Kind: "file", Data: "id"},
		{Path: "xdg-data/symaira-vault/entries/config.yaml", Kind: "dir"},
	}
}

func TestSpecForStateShapesEachUnlockState(t *testing.T) {
	seed := testSeed()
	type want struct {
		seeded, passphraseEnv, tz bool
		omit                      string
		suffix                    bool
	}
	cases := map[string]want{
		stateUninitialized:         {},
		stateInitialized:           {seeded: true, passphraseEnv: true},
		stateLocked:                {seeded: true, tz: true},
		stateIdentityOnly:          {seeded: true, passphraseEnv: true, omit: vaultConfigFile},
		stateConfigOnly:            {seeded: true, passphraseEnv: true, omit: vaultIdentityFile},
		stateIdentityOnlyLocked:    {seeded: true, tz: true, omit: vaultConfigFile},
		stateConfigOnlyLocked:      {seeded: true, tz: true, omit: vaultIdentityFile},
		stateConfigOnlyEnvDisabled: {seeded: true, passphraseEnv: true, omit: vaultIdentityFile, suffix: true},
		stateEnvDisabled:           {seeded: true, passphraseEnv: true, suffix: true},

		stateConfigClipboardInvalid: {seeded: true, passphraseEnv: true, suffix: true},
		stateConfigSyntaxInvalid:    {seeded: true, passphraseEnv: true, suffix: true},
	}
	for state, w := range cases {
		spec, err := specForState(state, seed)
		if err != nil {
			t.Fatalf("%s: %v", state, err)
		}
		if (len(spec.seed) > 0) != w.seeded || spec.initialized != w.passphraseEnv || spec.tzOnly != w.tz {
			t.Errorf("%s: spec = %+v", state, spec)
		}
		if w.omit == "" && len(spec.omit) != 0 || w.omit != "" && (len(spec.omit) != 1 || spec.omit[0] != w.omit) {
			t.Errorf("%s: omit = %v, want %q", state, spec.omit, w.omit)
		}
		if (spec.configSuffix != "") != w.suffix {
			t.Errorf("%s: configSuffix = %q", state, spec.configSuffix)
		}
	}
	if _, err := specForState("typo", seed); err == nil {
		t.Fatal("an unknown state must be an error")
	}
}

// Only regular files of the omitted base name are dropped: a directory that
// happens to carry the name stays.
func TestWithoutFilesDropsOnlyTheNamedRegularFile(t *testing.T) {
	seed := testSeed()
	kept := withoutFiles(seed, []string{vaultConfigFile})
	if len(kept) != len(seed)-1 {
		t.Fatalf("kept %d of %d entries", len(kept), len(seed))
	}
	for _, entry := range kept {
		if entry.Path == "xdg-data/symaira-vault/config.yaml" {
			t.Fatal("config.yaml was kept")
		}
	}
	if got := withoutFiles(seed, nil); len(got) != len(seed) {
		t.Fatalf("no omit changed the seed: %d entries", len(got))
	}
	if got := withoutFiles(seed, []string{"absent.txt"}); len(got) != len(seed) {
		t.Fatalf("an absent name changed the seed: %d entries", len(got))
	}
}

func TestWithConfigSuffixAppendsToTheConfigOnlyAndLeavesTheSeedAlone(t *testing.T) {
	seed := testSeed()
	out := withConfigSuffix(seed, envDisabledConfigSuffix)
	for i, entry := range out {
		switch {
		case entry.Path == "xdg-data/symaira-vault/config.yaml":
			if !strings.HasSuffix(entry.Data, envDisabledConfigSuffix) || !strings.HasPrefix(entry.Data, "vaultDir: x\n") {
				t.Errorf("config = %q", entry.Data)
			}
		case entry.Data != seed[i].Data:
			t.Errorf("%s changed", entry.Path)
		}
	}
	if seed[1].Data != "vaultDir: x\n" {
		t.Fatalf("the input seed was modified: %q", seed[1].Data)
	}
	if got := withConfigSuffix(seed, ""); &got[0] != &seed[0] {
		t.Fatal("an empty suffix must return the seed unchanged")
	}
}

func TestUnlockStateInputsCoverEveryStateOnce(t *testing.T) {
	inputs := unlockStateInputs()
	seen := map[string]bool{}
	perState := map[string]int{}
	for _, in := range inputs {
		if seen[in.name] {
			t.Errorf("duplicate %s", in.name)
		}
		seen[in.name] = true
		perState[in.state]++
		if !strings.HasPrefix(in.name, "unlock_"+in.state+"_") {
			t.Errorf("%s does not carry its state %s", in.name, in.state)
		}
		if _, err := specForState(in.state, testSeed()); err != nil {
			t.Errorf("%s: %v", in.name, err)
		}
	}
	partial, configOnly, alsoLocked := 0, 0, 0
	for _, cmd := range unlockCommands {
		if cmd.configOnly && cmd.alsoLocked {
			alsoLocked++
		}
		if cmd.partial {
			partial++
		}
		if cmd.configOnly {
			configOnly++
		}
	}
	for _, state := range unlockStates {
		want := partial
		switch {
		case state == stateLocked:
			want = len(unlockCommands) - configOnly + alsoLocked
		case isConfigInvalidState(state):
			want = partial + configOnly
		}
		if perState[state] != want {
			t.Errorf("%s: %d scenarios, want %d", state, perState[state], want)
		}
	}
}

// The config-invalid states append a section Go refuses: a negative
// clipboard.auto_clear_duration fails Config.Validate, an unterminated flow
// sequence fails the load. Both start from the complete settled vault.
func TestConfigInvalidStatesAppendTheirSectionToTheSeededConfig(t *testing.T) {
	for state, suffix := range map[string]string{
		stateConfigClipboardInvalid: clipboardInvalidConfigSuffix,
		stateConfigSyntaxInvalid:    syntaxInvalidConfigSuffix,
	} {
		if !isConfigInvalidState(state) {
			t.Errorf("%s is not a config-invalid state", state)
		}
		spec, err := specForState(state, testSeed())
		if err != nil {
			t.Fatal(err)
		}
		if spec.configSuffix != suffix || len(spec.omit) != 0 || !spec.initialized {
			t.Errorf("%s: spec = %+v", state, spec)
		}
	}
	if !strings.Contains(clipboardInvalidConfigSuffix, "auto_clear_duration: -") {
		t.Errorf("clipboard suffix = %q", clipboardInvalidConfigSuffix)
	}
	if isConfigInvalidState(stateEnvDisabled) || isConfigInvalidState(stateLocked) {
		t.Fatal("only the config-invalid states are config-invalid")
	}
	// get runs only where the configuration is refused and in the locked vault.
	for _, in := range unlockStateInputs() {
		if strings.HasSuffix(in.name, "_get") && !isConfigInvalidState(in.state) && in.state != stateLocked {
			t.Errorf("%s: get runs outside the config-invalid and locked states", in.name)
		}
	}
}

// `import <file>` is refused when it opens the vault, after it parsed a valid
// source: the scenarios carry that CSV source and run in the config-invalid
// states and in the locked vault (an EOF at the passphrase prompt), never in the
// partial shapes.
func TestImportScenariosCarryAValidCSVSourceInTheConfigInvalidAndLockedStatesOnly(t *testing.T) {
	seen := map[string]bool{}
	for _, in := range unlockStateInputs() {
		if len(in.args) == 0 || in.args[0] != "import" || len(in.args) < 2 || in.args[1] != importSourceFile {
			continue
		}
		seen[in.name] = true
		if !isConfigInvalidState(in.state) && in.state != stateLocked {
			t.Errorf("%s runs outside the config-invalid and locked states", in.name)
		}
		if !strings.HasSuffix(importSourceFile, ".csv") || in.files[importSourceFile] != importSourceFiles[importSourceFile] {
			t.Errorf("%s: files = %v", in.name, in.files)
		}
	}
	for _, state := range []string{stateConfigClipboardInvalid, stateConfigSyntaxInvalid, stateLocked} {
		for _, name := range []string{"import_csv", "import_csv_dry_run"} {
			if !seen["unlock_"+state+"_"+name] {
				t.Errorf("unlock_%s_%s is not recorded", state, name)
			}
		}
	}
	if !strings.HasPrefix(importSourceFiles[importSourceFile], "title,") {
		t.Errorf("source = %q", importSourceFiles[importSourceFile])
	}
}

// The locked-vault sweep: every vault-opening command Go reaches through
// cli.WithVault/WithVaultRaw/UnlockVault is recorded with an EOF passphrase prompt.
func TestLockedSweepRecordsEveryVaultOpeningCommand(t *testing.T) {
	want := []string{"import_csv", "import_csv_dry_run", "export_csv_yes", "broker", "generate_store",
		"git_log", "template_generate", "ui", "set_value", "file_get", "file_add", "device_revoke", "mcp_serve_http"}
	seen := map[string]bool{}
	for _, in := range unlockStateInputs() {
		if in.state == stateLocked {
			seen[in.name] = true
		}
	}
	for _, name := range want {
		if !seen["unlock_locked_"+name] {
			t.Errorf("unlock_locked_%s is not recorded", name)
		}
	}
}
