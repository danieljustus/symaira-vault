package config

import "testing"

func TestSyncConfigEffectiveMethodAndFilesystemSync(t *testing.T) {
	tests := []struct {
		name       string
		config     *SyncConfig
		method     string
		filesystem bool
	}{
		{name: "nil config", config: nil, method: SyncMethodGit},
		{name: "empty method", config: &SyncConfig{}, method: SyncMethodGit},
		{name: "git method", config: &SyncConfig{Method: SyncMethodGit}, method: SyncMethodGit},
		{name: "icloud method", config: &SyncConfig{Method: SyncMethodICloudDrive}, method: SyncMethodICloudDrive, filesystem: true},
		{name: "unknown method", config: &SyncConfig{Method: "unknown"}, method: SyncMethodGit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.EffectiveMethod(); got != tt.method {
				t.Fatalf("EffectiveMethod() = %q, want %q", got, tt.method)
			}
			if got := tt.config.IsFilesystemSync(); got != tt.filesystem {
				t.Fatalf("IsFilesystemSync() = %t, want %t", got, tt.filesystem)
			}
		})
	}
}

func TestMergeSecurityConfigAndDefaults(t *testing.T) {
	defaults := defaultSecurityConfig()
	if defaults.DisableEnvPassphrase || defaults.AllowEnvPassphrase {
		t.Fatalf("default security config must deny environment passphrases: %+v", defaults)
	}

	tests := []struct {
		name  string
		raw   SecurityConfig
		field map[string]bool
		want  SecurityConfig
	}{
		{name: "no fields", raw: SecurityConfig{}, field: map[string]bool{}, want: defaults},
		{
			name:  "disable field",
			raw:   SecurityConfig{DisableEnvPassphrase: true},
			field: map[string]bool{"disable_env_passphrase": true},
			want:  SecurityConfig{DisableEnvPassphrase: true},
		},
		{
			name:  "allow field",
			raw:   SecurityConfig{AllowEnvPassphrase: true},
			field: map[string]bool{"allow_env_passphrase": true},
			want:  SecurityConfig{AllowEnvPassphrase: true},
		},
		{
			name:  "both fields",
			raw:   SecurityConfig{DisableEnvPassphrase: true, AllowEnvPassphrase: true},
			field: map[string]bool{"disable_env_passphrase": true, "allow_env_passphrase": true},
			want:  SecurityConfig{DisableEnvPassphrase: true, AllowEnvPassphrase: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeSecurityConfig(&tt.raw, tt.field)
			if *got != tt.want {
				t.Fatalf("mergeSecurityConfig() = %+v, want %+v", *got, tt.want)
			}
		})
	}
}

func TestInt64Ptr(t *testing.T) {
	const want int64 = 922337203685
	got := Int64Ptr(want)
	if got == nil || *got != want {
		t.Fatalf("Int64Ptr(%d) = %v, want pointer to %d", want, got, want)
	}
}
