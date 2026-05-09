package wizard

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/git"
	"github.com/danieljustus/OpenPass/internal/mcp"
	"github.com/danieljustus/OpenPass/internal/mcp/install"
	"github.com/danieljustus/OpenPass/internal/session"
	"github.com/danieljustus/OpenPass/internal/vault"
)

// Apply executes all side-effects collected in WizardState in the prescribed
// order. Errors are accumulated in state.ApplyErrors; apply continues best-effort
// so the user can run `openpass doctor` afterwards.
func Apply(state *WizardState) error {
	var errs []string

	if err := applyVaultInit(state, &errs); err != nil {
		// vault init failure is fatal — nothing else can proceed.
		return err
	}

	// Wipe passphrase from memory immediately after vault init.
	for i := range state.Passphrase {
		state.Passphrase[i] = 0
	}
	state.Passphrase = nil

	applyGit(state, &errs)
	applyRecipients(state, &errs)
	applyProfile(state, &errs)
	applyAgents(state, &errs)

	state.ApplyErrors = errs
	if len(errs) > 0 {
		return fmt.Errorf("apply completed with errors — run `openpass doctor` for details")
	}
	return nil
}

func applyVaultInit(state *WizardState, errs *[]string) error {
	if state.ExistingVault {
		return nil
	}
	cfg := configpkg.Default()
	cfg.VaultDir = state.VaultDir
	cfg.AuthMethod = state.AuthMethod

	if _, err := vault.InitWithPassphrase(state.VaultDir, state.Passphrase, cfg); err != nil {
		return fmt.Errorf("vault init: %w", err)
	}

	if state.AuthMethod == configpkg.AuthMethodTouchID && session.BiometricAvailable() {
		if err := session.SaveBiometricPassphrase(context.Background(), state.VaultDir, state.Passphrase); err != nil {
			*errs = append(*errs, fmt.Sprintf("Touch ID setup: %v", err))
		}
	}
	return nil
}

func applyGit(state *WizardState, errs *[]string) {
	if state.SyncMode != syncGit {
		return
	}
	if err := git.Init(state.VaultDir); err != nil {
		*errs = append(*errs, fmt.Sprintf("git init: %v", err))
		return
	}
	if err := git.CreateGitignore(state.VaultDir); err != nil {
		*errs = append(*errs, fmt.Sprintf("gitignore: %v", err))
	}
	if state.GitRemoteURL != "" {
		has, _ := git.HasRemote(state.VaultDir, "origin")
		if !has {
			if err := git.AddRemote(state.VaultDir, "origin", state.GitRemoteURL); err != nil {
				*errs = append(*errs, fmt.Sprintf("git remote: %v", err))
			}
		}
	}
	cfgPath := filepath.Join(state.VaultDir, "config.yaml")
	if cfg, err := configpkg.Load(cfgPath); err == nil {
		cfg.Git.AutoPush = state.AutoPush
		_ = cfg.Save()
	}
}

func applyRecipients(state *WizardState, errs *[]string) {
	if len(state.Recipients) == 0 {
		return
	}
	rm := vault.NewRecipientsManager(state.VaultDir)
	for _, r := range state.Recipients {
		if err := rm.AddRecipient(r); err != nil {
			prefix := r
			if len(r) > 8 {
				prefix = r[:8]
			}
			*errs = append(*errs, fmt.Sprintf("add recipient %s: %v", prefix, err))
		}
	}
}

func applyProfile(state *WizardState, errs *[]string) {
	if state.ProfileName == "" || state.ProfileName == defaultProfile {
		return
	}
	home, _ := os.UserHomeDir()
	globalCfgPath := filepath.Join(home, ".openpass", "config.yaml")
	cfg, err := configpkg.Load(globalCfgPath)
	if err != nil {
		cfg = configpkg.Default()
	}
	if cfg.Profiles == nil {
		cfg.Profiles = make(map[string]*configpkg.Profile)
	}
	if _, exists := cfg.Profiles[state.ProfileName]; !exists {
		cfg.Profiles[state.ProfileName] = &configpkg.Profile{VaultPath: state.VaultDir}
		if saveErr := cfg.Save(); saveErr != nil {
			*errs = append(*errs, fmt.Sprintf("save profile: %v", saveErr))
		}
	}
}

func applyAgents(state *WizardState, errs *[]string) {
	for _, sel := range state.SelectedAgents {
		if err := installAgent(state.VaultDir, sel); err != nil {
			*errs = append(*errs, fmt.Sprintf("install agent %s: %v", sel.AgentType, err))
		}
	}
}

func installAgent(vaultDir string, sel AgentSelection) error {
	reg, _, err := mcp.LoadTokenSystem(vaultDir)
	if err != nil {
		return fmt.Errorf("load token system: %w", err)
	}

	serverConfig := map[string]any{}

	if sel.Transport == "http" {
		allowedTools := []string{"*"}
		if sel.ReadOnly {
			allowedTools = []string{"get", "list", "find"}
		}
		_, rawToken, tokenErr := reg.Create(sel.AgentType, allowedTools, sel.AgentType, 0)
		if tokenErr != nil {
			return fmt.Errorf("create token: %w", tokenErr)
		}
		serverConfig["transport"] = "http"
		serverConfig["token"] = rawToken
	}

	if sel.Scope != "" && sel.Scope != "*" {
		serverConfig["pathScope"] = sel.Scope
	}

	opts := install.InstallOptions{
		AgentType:    install.AgentType(sel.AgentType),
		ServerConfig: serverConfig,
	}
	_, err = install.Install(opts)
	return err
}
