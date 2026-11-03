package main

import (
	"fmt"
	"path"
)

// The vault shapes and passphrase environments of the unlock-state section. The
// other scenarios start from an empty sandbox or from the settled vault with the
// environment passphrase, so they never see a prompt that reaches EOF or a vault
// whose files are only partly present.
const (
	// stateLocked is the settled vault without SYMVAULT_PASSPHRASE: the
	// passphrase prompt reads EOF from the empty stdin.
	stateLocked = "locked"
	// stateIdentityOnly and stateConfigOnly drop config.yaml or identity.age from
	// the settled vault; the environment passphrase is available.
	stateIdentityOnly = "identity_only"
	stateConfigOnly   = "config_only"
	// The *Locked variants drop the same file and the environment passphrase.
	stateIdentityOnlyLocked = "identity_only_locked"
	stateConfigOnlyLocked   = "config_only_locked"
	// stateConfigOnlyEnvDisabled is config_only with security.disable_env_passphrase
	// in the config: the environment passphrase is available but the policy of
	// the configuration forbids it, so the prompt (EOF) decides. A command that
	// ignores the actual configuration uses the environment passphrase instead.
	stateConfigOnlyEnvDisabled = "config_only_env_disabled"
	// stateEnvDisabled is the same policy in the complete vault.
	stateEnvDisabled        = "env_disabled"
	envDisabledConfigSuffix = "security:\n    disable_env_passphrase: true\n"

	// The config-invalid states append a section to the settled vault's config.yaml
	// that Go refuses when it resolves the configuration (PLATFORM-001), before the
	// passphrase policy and before the vault is opened. A negative
	// clipboard.auto_clear_duration is a validation error (Config.Validate); an
	// unterminated flow sequence is a load error. The environment passphrase is
	// available in both, so only the configuration decides.
	stateConfigClipboardInvalid  = "config_clipboard_invalid"
	stateConfigSyntaxInvalid     = "config_syntax_invalid"
	clipboardInvalidConfigSuffix = "clipboard:\n    auto_clear_duration: -5\n"
	syntaxInvalidConfigSuffix    = "clipboard: [\n"

	vaultConfigFile   = "config.yaml"
	vaultIdentityFile = "identity.age"
)

var unlockStates = []string{stateLocked, stateIdentityOnly, stateConfigOnly, stateIdentityOnlyLocked, stateConfigOnlyLocked, stateConfigOnlyEnvDisabled, stateEnvDisabled, stateConfigClipboardInvalid, stateConfigSyntaxInvalid}

// isConfigInvalidState reports the states whose config.yaml Go refuses.
func isConfigInvalidState(state string) bool {
	return state == stateConfigClipboardInvalid || state == stateConfigSyntaxInvalid
}

// specForState maps a scenario state to the sandbox it starts from.
func specForState(state string, seed []seedFile) (runSpec, error) {
	switch state {
	case stateUninitialized:
		return runSpec{}, nil
	case stateInitialized:
		return runSpec{initialized: true, seed: seed}, nil
	case stateLocked:
		return runSpec{seed: seed, tzOnly: true}, nil
	case stateIdentityOnly:
		return runSpec{initialized: true, seed: seed, omit: []string{vaultConfigFile}}, nil
	case stateConfigOnly:
		return runSpec{initialized: true, seed: seed, omit: []string{vaultIdentityFile}}, nil
	case stateIdentityOnlyLocked:
		return runSpec{seed: seed, tzOnly: true, omit: []string{vaultConfigFile}}, nil
	case stateConfigOnlyLocked:
		return runSpec{seed: seed, tzOnly: true, omit: []string{vaultIdentityFile}}, nil
	case stateEnvDisabled:
		return runSpec{initialized: true, seed: seed, configSuffix: envDisabledConfigSuffix}, nil
	case stateConfigOnlyEnvDisabled:
		return runSpec{initialized: true, seed: seed, omit: []string{vaultIdentityFile}, configSuffix: envDisabledConfigSuffix}, nil
	case stateConfigClipboardInvalid:
		return runSpec{initialized: true, seed: seed, configSuffix: clipboardInvalidConfigSuffix}, nil
	case stateConfigSyntaxInvalid:
		return runSpec{initialized: true, seed: seed, configSuffix: syntaxInvalidConfigSuffix}, nil
	}
	return runSpec{}, fmt.Errorf("unknown scenario state %q", state)
}

// withoutFiles drops the seed entries of regular files whose base name is in
// omit. The tests pin that every omitted name exists in the seed.
func withoutFiles(seed []seedFile, omit []string) []seedFile {
	if len(omit) == 0 {
		return seed
	}
	var kept []seedFile
	for _, entry := range seed {
		dropped := false
		for _, name := range omit {
			if entry.Kind == "file" && path.Base(entry.Path) == name {
				dropped = true
			}
		}
		if !dropped {
			kept = append(kept, entry)
		}
	}
	return kept
}

// withConfigSuffix appends suffix to the seeded config.yaml.
func withConfigSuffix(seed []seedFile, suffix string) []seedFile {
	if suffix == "" {
		return seed
	}
	out := make([]seedFile, len(seed))
	copy(out, seed)
	for i, entry := range out {
		if entry.Kind == "file" && path.Base(entry.Path) == vaultConfigFile {
			out[i].Data += suffix
		}
	}
	return out
}

// unlockCommand is one command of the unlock-state section. partial marks the
// commands that are also run on the partial vault shapes.
type unlockCommand struct {
	name    string
	args    []string
	partial bool
	// configOnly marks a command that runs in the config-invalid states only:
	// `get` unlocks without prompting once stdin is not a terminal
	// (WithVaultForScripting), so the configuration is resolved non-interactively
	// and a refusal is not offered a repair. `dynamic generate` and `mcp serve`
	// are recorded here for the same refusal (exit 6 and the doctor hint).
	configOnly bool
}

// unlockCommands are the commands that unlock the vault through the prompting
// path of Go's UnlockVault. Go resolves config.yaml first (a missing file is the
// default configuration), obtains the passphrase under that policy and only
// then opens the vault: it reads identity.age, then loads config.yaml. A prompt
// that reads EOF is an ExitLocked error (exit 4 and the locked hint), not a
// plain exit 1.
//
// `get`, `set` and `file get|add` are left out on purpose: they do not take the
// prompting path in Go (get is non-interactive, set asks for the username first)
// and differ for reasons of their own.
var unlockCommands = []unlockCommand{
	{"device_pair", []string{"device", "pair"}, true, false},
	{"device_pair_x", []string{"device", "pair", "x"}, true, false},
	{"list", []string{"list"}, true, false},
	{"find", []string{"find", "x"}, false, false},
	{"add", []string{"add", "x"}, false, false},
	{"delete", []string{"delete", "x"}, false, false},
	{"edit", []string{"edit", "x"}, false, false},
	{"verify", []string{"verify"}, true, false},
	{"unlock", []string{"unlock"}, true, false},
	{"migrate_pseudonymize", []string{"migrate", "pseudonymize"}, true, false},
	{"migrate_pseudonymize_yes", []string{"migrate", "pseudonymize", "--yes"}, true, false},
	{"recipients_add", []string{"recipients", "add", "x"}, false, false},
	{"recipients_remove", []string{"recipients", "remove", "x"}, false, false},
	{"run", []string{"run", "--", "x"}, false, false},
	{"file_use", []string{"file", "use", seedFileEntry, "x"}, false, false},
	{"import_review_list", []string{"import", "review", "list"}, false, false},
	{"import_review_promote", []string{"import", "review", "promote", "x"}, false, false},
	{"intake_x", []string{"intake", "x"}, false, false},
	{"get", []string{"get", seedFileEntry}, false, true},
	// `dynamic generate` opens the vault through cli.WithVault and `mcp serve
	// --stdio` through ServeUnlockVault (whose wrapVaultError passes an
	// ExitConfigError unchanged); both refuse a configuration Go does not load.
	{"dynamic_generate", []string{"dynamic", "generate", "--engine", "x", "--role", "x"}, false, true},
	{"mcp_serve_stdio", []string{"mcp", "serve", "--stdio", "--agent", "a"}, false, true},
}

// unlockStateInputs runs unlockCommands in every unlock state: all of them in
// the locked vault, the partial ones in the partial shapes, and the partial and
// config-only ones in the config-invalid states.
func unlockStateInputs() []scenarioInput {
	var out []scenarioInput
	for _, state := range unlockStates {
		for _, cmd := range unlockCommands {
			if cmd.configOnly && !isConfigInvalidState(state) {
				continue
			}
			if state != stateLocked && !cmd.partial && !cmd.configOnly {
				continue
			}
			out = append(out, scenarioInput{
				name:        fmt.Sprintf("unlock_%s_%s", state, cmd.name),
				description: fmt.Sprintf("%v in the %s vault shape", cmd.args, state),
				state:       state,
				args:        cmd.args,
			})
		}
	}
	return out
}
