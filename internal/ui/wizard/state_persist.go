package wizard

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/danieljustus/symaira-vault/internal/fileutil"
)

const resumeFileName = ".wizard-resume.yaml"
const resumeMaxAge = 24 * time.Hour

type resumeState struct {
	VaultDir       string           `yaml:"vault_dir"`
	ExistingVault  bool             `yaml:"existing_vault"`
	AuthMethod     string           `yaml:"auth_method"`
	SyncMode       string           `yaml:"sync_mode"`
	GitRemoteURL   string           `yaml:"git_remote_url"`
	AutoPush       bool             `yaml:"auto_push"`
	MultiDevice    bool             `yaml:"multi_device"`
	Recipients     []string         `yaml:"recipients,omitempty"`
	SelectedAgents []AgentSelection `yaml:"selected_agents,omitempty"`
	BackupDir      string           `yaml:"backup_dir"`
	ProfileName    string           `yaml:"profile_name"`
	KeepOnError    bool             `yaml:"keep_on_error"`
	LastStep       string           `yaml:"last_step"`
}

func resumeFilePath(vaultDir string) string {
	if dir, err := os.UserCacheDir(); err == nil {
		hash := sha256.Sum256([]byte(vaultDir))
		suffix := fmt.Sprintf("%x", hash[:8])
		return filepath.Join(dir, "symaira", "wizard", suffix+".yaml")
	}
	return filepath.Join(vaultDir, resumeFileName)
}

func ensureResumeDir(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o700)
}

func SaveResumeState(vaultDir string, state *WizardState, lastStep string) error {
	rs := resumeState{
		VaultDir:       state.VaultDir,
		ExistingVault:  state.ExistingVault,
		AuthMethod:     state.AuthMethod,
		SyncMode:       state.SyncMode,
		GitRemoteURL:   state.GitRemoteURL,
		AutoPush:       state.AutoPush,
		MultiDevice:    state.MultiDevice,
		Recipients:     state.Recipients,
		SelectedAgents: state.SelectedAgents,
		BackupDir:      state.BackupDir,
		ProfileName:    state.ProfileName,
		KeepOnError:    state.KeepOnError,
		LastStep:       lastStep,
	}

	data, err := yaml.Marshal(&rs)
	if err != nil {
		return fmt.Errorf("marshal resume state: %w", err)
	}

	path := resumeFilePath(vaultDir)
	if err := ensureResumeDir(path); err != nil {
		return fmt.Errorf("create resume dir: %w", err)
	}

	return fileutil.AtomicWriteFile(path, data, 0o600)
}

func LoadResumeState(vaultDir string) (*WizardState, string, error) {
	path := resumeFilePath(vaultDir)
	data, err := os.ReadFile(path) // #nosec G304 — path is a SHA-256 hash of vaultDir under cache dir, not user-controlled traversal
	if err != nil {
		return nil, "", fmt.Errorf("read resume state: %w", err)
	}

	var rs resumeState
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, "", fmt.Errorf("unmarshal resume state: %w", err)
	}

	state := &WizardState{
		VaultDir:       rs.VaultDir,
		ExistingVault:  rs.ExistingVault,
		AuthMethod:     rs.AuthMethod,
		SyncMode:       rs.SyncMode,
		GitRemoteURL:   rs.GitRemoteURL,
		AutoPush:       rs.AutoPush,
		MultiDevice:    rs.MultiDevice,
		Recipients:     rs.Recipients,
		SelectedAgents: rs.SelectedAgents,
		BackupDir:      rs.BackupDir,
		ProfileName:    rs.ProfileName,
		KeepOnError:    rs.KeepOnError,
	}

	return state, rs.LastStep, nil
}

func ResumeFileAge(vaultDir string) (time.Duration, error) {
	fi, err := os.Stat(resumeFilePath(vaultDir))
	if err != nil {
		return 0, err
	}
	return time.Since(fi.ModTime()), nil
}

func DeleteResumeFile(vaultDir string) error {
	path := resumeFilePath(vaultDir)
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func resumeFileExists(vaultDir string) bool {
	_, err := os.Stat(resumeFilePath(vaultDir))
	return !os.IsNotExist(err)
}

func legacyResumePath(vaultDir string) string {
	return filepath.Join(vaultDir, resumeFileName)
}

func MigrateLegacyResumeFile(vaultDir string) {
	legacy := legacyResumePath(vaultDir)
	current := resumeFilePath(vaultDir)
	if legacy == current {
		return
	}
	if _, err := os.Stat(legacy); os.IsNotExist(err) {
		return
	}
	if resumeFileExists(vaultDir) {
		_ = os.Remove(legacy)
		return
	}
	if err := ensureResumeDir(current); err != nil {
		return
	}
	data, err := os.ReadFile(legacy) // #nosec G304 — legacy path is vaultDir + ".wizard-resume.yaml" inside the vault, same security domain
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(current), 0o700); err != nil {
		return
	}
	if err := fileutil.AtomicWriteFile(current, data, 0o600); err != nil {
		return
	}
	_ = os.Remove(legacy)
}
