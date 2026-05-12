package wizard

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/danieljustus/OpenPass/internal/fileutil"
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
	return filepath.Join(vaultDir, resumeFileName)
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

	return fileutil.AtomicWriteFile(resumeFilePath(vaultDir), data, 0o600)
}

func LoadResumeState(vaultDir string) (*WizardState, string, error) {
	data, err := os.ReadFile(resumeFilePath(vaultDir))
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
	err := os.Remove(resumeFilePath(vaultDir))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
