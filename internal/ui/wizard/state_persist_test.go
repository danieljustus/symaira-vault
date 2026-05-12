package wizard

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStatePersist_SaveAndLoadRoundTrip(t *testing.T) {
	vaultDir := t.TempDir()
	state := &WizardState{
		VaultDir:      vaultDir,
		ExistingVault: false,
		AuthMethod:    "passphrase",
		SyncMode:      "local",
		AutoPush:      false,
		MultiDevice:   false,
		BackupDir:     "",
		ProfileName:   "default",
		KeepOnError:   false,
	}
	lastStep := "profile"

	if err := SaveResumeState(vaultDir, state, lastStep); err != nil {
		t.Fatalf("SaveResumeState() error = %v", err)
	}

	loaded, gotLastStep, err := LoadResumeState(vaultDir)
	if err != nil {
		t.Fatalf("LoadResumeState() error = %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadResumeState() returned nil")
	}

	if loaded.VaultDir != state.VaultDir {
		t.Errorf("VaultDir = %q, want %q", loaded.VaultDir, state.VaultDir)
	}
	if loaded.ExistingVault != state.ExistingVault {
		t.Errorf("ExistingVault = %v, want %v", loaded.ExistingVault, state.ExistingVault)
	}
	if loaded.AuthMethod != state.AuthMethod {
		t.Errorf("AuthMethod = %q, want %q", loaded.AuthMethod, state.AuthMethod)
	}
	if loaded.SyncMode != state.SyncMode {
		t.Errorf("SyncMode = %q, want %q", loaded.SyncMode, state.SyncMode)
	}
	if loaded.AutoPush != state.AutoPush {
		t.Errorf("AutoPush = %v, want %v", loaded.AutoPush, state.AutoPush)
	}
	if loaded.MultiDevice != state.MultiDevice {
		t.Errorf("MultiDevice = %v, want %v", loaded.MultiDevice, state.MultiDevice)
	}
	if loaded.BackupDir != state.BackupDir {
		t.Errorf("BackupDir = %q, want %q", loaded.BackupDir, state.BackupDir)
	}
	if loaded.ProfileName != state.ProfileName {
		t.Errorf("ProfileName = %q, want %q", loaded.ProfileName, state.ProfileName)
	}
	if loaded.KeepOnError != state.KeepOnError {
		t.Errorf("KeepOnError = %v, want %v", loaded.KeepOnError, state.KeepOnError)
	}
	if loaded.Passphrase != nil {
		t.Errorf("Passphrase should be nil after load, got %v", loaded.Passphrase)
	}
	if gotLastStep != lastStep {
		t.Errorf("LastStep = %q, want %q", gotLastStep, lastStep)
	}
}

func TestStatePersist_SaveExcludesPassphrase(t *testing.T) {
	vaultDir := t.TempDir()
	state := &WizardState{
		VaultDir:      vaultDir,
		Passphrase:    []byte("secret"),
		AuthMethod:    "passphrase",
		SyncMode:      "local",
		ProfileName:   "test",
	}

	if err := SaveResumeState(vaultDir, state, "test"); err != nil {
		t.Fatalf("SaveResumeState() error = %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(vaultDir, resumeFileName))
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}

	if bytes.Contains(raw, []byte("\npassphrase:")) || bytes.HasPrefix(raw, []byte("passphrase:")) {
		t.Error("raw YAML contains 'passphrase:' as a field key; it should be excluded")
	}
}

func TestStatePersist_LoadReturnsNilPassphrase(t *testing.T) {
	vaultDir := t.TempDir()
	state := &WizardState{
		VaultDir:      vaultDir,
		Passphrase:    []byte("secret"),
		AuthMethod:    "passphrase",
		ProfileName:   "test",
	}

	if err := SaveResumeState(vaultDir, state, "test"); err != nil {
		t.Fatalf("SaveResumeState() error = %v", err)
	}

	loaded, _, err := LoadResumeState(vaultDir)
	if err != nil {
		t.Fatalf("LoadResumeState() error = %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadResumeState() returned nil")
	}
	if loaded.Passphrase != nil {
		t.Errorf("Passphrase should be nil, got %v", loaded.Passphrase)
	}
}

func TestStatePersist_ResumeFileAge_Fresh(t *testing.T) {
	vaultDir := t.TempDir()
	state := &WizardState{
		VaultDir:    vaultDir,
		ProfileName: "test",
	}

	if err := SaveResumeState(vaultDir, state, "test"); err != nil {
		t.Fatalf("SaveResumeState() error = %v", err)
	}

	age, err := ResumeFileAge(vaultDir)
	if err != nil {
		t.Fatalf("ResumeFileAge() error = %v", err)
	}
	if age < 0 {
		t.Errorf("age should be >= 0, got %v", age)
	}
	if age > 5*time.Second {
		t.Errorf("age = %v, want <= 5s (freshly saved)", age)
	}
}

func TestStatePersist_ResumeFileAge_NotExist(t *testing.T) {
	vaultDir := t.TempDir()

	_, err := ResumeFileAge(vaultDir)
	if err == nil {
		t.Error("expected error for non-existent resume file, got nil")
	}
}

func TestStatePersist_DeleteResumeFile(t *testing.T) {
	vaultDir := t.TempDir()
	state := &WizardState{
		VaultDir:    vaultDir,
		ProfileName: "test",
	}

	if err := SaveResumeState(vaultDir, state, "test"); err != nil {
		t.Fatalf("SaveResumeState() error = %v", err)
	}

	path := resumeFilePath(vaultDir)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("resume file should exist after SaveResumeState")
	}

	if err := DeleteResumeFile(vaultDir); err != nil {
		t.Fatalf("DeleteResumeFile() error = %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("resume file should be deleted after DeleteResumeFile")
	}

	if err := DeleteResumeFile(vaultDir); err != nil {
		t.Errorf("DeleteResumeFile() on non-existent should return nil, got %v", err)
	}
}

func TestStatePersist_SaveWithAllFields(t *testing.T) {
	vaultDir := t.TempDir()
	state := &WizardState{
		VaultDir:      vaultDir,
		ExistingVault: true,
		Passphrase:    []byte("should-not-persist"),
		AuthMethod:    "touchid",
		SyncMode:      "git",
		GitRemoteURL:  "git@github.com:user/repo.git",
		AutoPush:      true,
		MultiDevice:   true,
		Recipients:    []string{"age1abc123", "age1def456"},
		SelectedAgents: []AgentSelection{
			{AgentType: "claude-code", Transport: "stdio", Scope: "*", ReadOnly: false},
			{AgentType: "hermes", Transport: "http", Scope: "/path", ReadOnly: true},
		},
		BackupDir:   "/tmp/backups",
		ProfileName: "my-profile",
		KeepOnError: true,
	}
	lastStep := "confirm"

	if err := SaveResumeState(vaultDir, state, lastStep); err != nil {
		t.Fatalf("SaveResumeState() error = %v", err)
	}

	loaded, gotLastStep, err := LoadResumeState(vaultDir)
	if err != nil {
		t.Fatalf("LoadResumeState() error = %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadResumeState() returned nil")
	}

	if loaded.VaultDir != state.VaultDir {
		t.Errorf("VaultDir = %q, want %q", loaded.VaultDir, state.VaultDir)
	}
	if loaded.ExistingVault != state.ExistingVault {
		t.Errorf("ExistingVault = %v, want %v", loaded.ExistingVault, state.ExistingVault)
	}
	if loaded.AuthMethod != state.AuthMethod {
		t.Errorf("AuthMethod = %q, want %q", loaded.AuthMethod, state.AuthMethod)
	}
	if loaded.SyncMode != state.SyncMode {
		t.Errorf("SyncMode = %q, want %q", loaded.SyncMode, state.SyncMode)
	}
	if loaded.GitRemoteURL != state.GitRemoteURL {
		t.Errorf("GitRemoteURL = %q, want %q", loaded.GitRemoteURL, state.GitRemoteURL)
	}
	if loaded.AutoPush != state.AutoPush {
		t.Errorf("AutoPush = %v, want %v", loaded.AutoPush, state.AutoPush)
	}
	if loaded.MultiDevice != state.MultiDevice {
		t.Errorf("MultiDevice = %v, want %v", loaded.MultiDevice, state.MultiDevice)
	}
	if loaded.BackupDir != state.BackupDir {
		t.Errorf("BackupDir = %q, want %q", loaded.BackupDir, state.BackupDir)
	}
	if loaded.ProfileName != state.ProfileName {
		t.Errorf("ProfileName = %q, want %q", loaded.ProfileName, state.ProfileName)
	}
	if loaded.KeepOnError != state.KeepOnError {
		t.Errorf("KeepOnError = %v, want %v", loaded.KeepOnError, state.KeepOnError)
	}

	if len(loaded.Recipients) != len(state.Recipients) {
		t.Errorf("len(Recipients) = %d, want %d", len(loaded.Recipients), len(state.Recipients))
	} else {
		for i := range state.Recipients {
			if loaded.Recipients[i] != state.Recipients[i] {
				t.Errorf("Recipients[%d] = %q, want %q", i, loaded.Recipients[i], state.Recipients[i])
			}
		}
	}

	if len(loaded.SelectedAgents) != len(state.SelectedAgents) {
		t.Errorf("len(SelectedAgents) = %d, want %d", len(loaded.SelectedAgents), len(state.SelectedAgents))
	} else {
		for i := range state.SelectedAgents {
			if loaded.SelectedAgents[i].AgentType != state.SelectedAgents[i].AgentType {
				t.Errorf("SelectedAgents[%d].AgentType = %q, want %q", i, loaded.SelectedAgents[i].AgentType, state.SelectedAgents[i].AgentType)
			}
			if loaded.SelectedAgents[i].Transport != state.SelectedAgents[i].Transport {
				t.Errorf("SelectedAgents[%d].Transport = %q, want %q", i, loaded.SelectedAgents[i].Transport, state.SelectedAgents[i].Transport)
			}
			if loaded.SelectedAgents[i].Scope != state.SelectedAgents[i].Scope {
				t.Errorf("SelectedAgents[%d].Scope = %q, want %q", i, loaded.SelectedAgents[i].Scope, state.SelectedAgents[i].Scope)
			}
			if loaded.SelectedAgents[i].ReadOnly != state.SelectedAgents[i].ReadOnly {
				t.Errorf("SelectedAgents[%d].ReadOnly = %v, want %v", i, loaded.SelectedAgents[i].ReadOnly, state.SelectedAgents[i].ReadOnly)
			}
		}
	}

	// Passphrase must never be restored.
	if loaded.Passphrase != nil {
		t.Errorf("Passphrase should be nil, got %v", loaded.Passphrase)
	}

	// ApplyErrors is not persisted, so it should be nil/empty after load.
	if loaded.ApplyErrors != nil {
		t.Errorf("ApplyErrors should be nil after load, got %v", loaded.ApplyErrors)
	}

	if gotLastStep != lastStep {
		t.Errorf("LastStep = %q, want %q", gotLastStep, lastStep)
	}
}
