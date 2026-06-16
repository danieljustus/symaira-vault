package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestCommandRequiresVault_RootCommand(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	if !commandRequiresVault(cmd) {
		t.Error("commandRequiresVault() = false for command without annotations, want true")
	}
}

func TestCommandRequiresVault_AnnotationTrue(t *testing.T) {
	cmd := &cobra.Command{
		Use:         "test",
		Annotations: map[string]string{RequiresVaultAnnotation: "true"},
	}
	if !commandRequiresVault(cmd) {
		t.Error("commandRequiresVault() = false for annotation 'true', want true")
	}
}

func TestCommandRequiresVault_AnnotationFalse(t *testing.T) {
	cmd := &cobra.Command{
		Use:         "test",
		Annotations: map[string]string{RequiresVaultAnnotation: "false"},
	}
	if commandRequiresVault(cmd) {
		t.Error("commandRequiresVault() = true for annotation 'false', want false")
	}
}

func TestCommandRequiresVault_ParentAnnotation(t *testing.T) {
	parent := &cobra.Command{
		Use:         "parent",
		Annotations: map[string]string{RequiresVaultAnnotation: "false"},
	}
	child := &cobra.Command{Use: "child"}
	parent.AddCommand(child)

	if commandRequiresVault(child) {
		t.Error("commandRequiresVault() = true when parent has 'false' annotation, want false")
	}
}

func TestCommandRequiresVault_NilAnnotations(t *testing.T) {
	cmd := &cobra.Command{Use: "test", Annotations: nil}
	if !commandRequiresVault(cmd) {
		t.Error("commandRequiresVault() = false for nil annotations, want true")
	}
}

func TestCommandRequiresVault_EmptyAnnotations(t *testing.T) {
	cmd := &cobra.Command{Use: "test", Annotations: map[string]string{}}
	if !commandRequiresVault(cmd) {
		t.Error("commandRequiresVault() = false for empty annotations, want true")
	}
}

func TestCommandRequiresVault_UnrelatedAnnotation(t *testing.T) {
	cmd := &cobra.Command{
		Use:         "test",
		Annotations: map[string]string{"other-key": "value"},
	}
	if !commandRequiresVault(cmd) {
		t.Error("commandRequiresVault() = false for unrelated annotation, want true")
	}
}

func TestRequiresVaultAnnotation(t *testing.T) {
	if RequiresVaultAnnotation != "symvault/requires-vault" {
		t.Errorf("RequiresVaultAnnotation = %q, want symvault/requires-vault", RequiresVaultAnnotation)
	}
}

func TestNewCLIContext_VaultPath(t *testing.T) {
	ctx := NewCLIContext()
	if ctx.Vault == "" {
		t.Error("NewCLIContext().Vault is empty")
	}
}

func TestNewCLIContext_ThemePreset(t *testing.T) {
	ctx := NewCLIContext()
	if ctx.ThemePreset != "" {
		t.Errorf("NewCLIContext().ThemePreset = %q, want empty", ctx.ThemePreset)
	}
}

func TestNewCLIContext_Profile(t *testing.T) {
	ctx := NewCLIContext()
	if ctx.Profile != "" {
		t.Errorf("NewCLIContext().Profile = %q, want empty", ctx.Profile)
	}
}

func TestCLIContext_VaultFlag(t *testing.T) {
	ctx := NewCLIContext()
	if ctx.vaultFlag != nil {
		t.Error("NewCLIContext().vaultFlag should be nil initially")
	}
}

func TestCLIContext_ProfileFlag(t *testing.T) {
	ctx := NewCLIContext()
	if ctx.profileFlag != nil {
		t.Error("NewCLIContext().profileFlag should be nil initially")
	}
}

func TestSyncFromContext_NilContext(t *testing.T) {
	// Should not panic
	syncFromContext(nil)
}

func TestSyncToContext_NilContext(t *testing.T) {
	// Should not panic
	syncToContext(nil)
}

func TestPrintQuietAware_WhenQuiet(t *testing.T) {
	orig := QuietMode
	QuietMode = true
	defer func() { QuietMode = orig }()

	// This should not panic and should not print
	PrintQuietAware("test %s", "message")
}

func TestPrintQuietAware_WhenNotQuiet(t *testing.T) {
	orig := QuietMode
	QuietMode = false
	defer func() { QuietMode = orig }()

	// This should not panic
	PrintQuietAware("test %s", "message")
}

func TestPrintlnQuietAware_WhenQuiet(t *testing.T) {
	orig := QuietMode
	QuietMode = true
	defer func() { QuietMode = orig }()

	// This should not panic
	PrintlnQuietAware("test")
}

func TestPrintlnQuietAware_WhenNotQuiet(t *testing.T) {
	orig := QuietMode
	QuietMode = false
	defer func() { QuietMode = orig }()

	// This should not panic
	PrintlnQuietAware("test")
}
