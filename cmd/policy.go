package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/policy"
)

var policyValidateCmd = &cobra.Command{
	Use:   "validate <file>",
	Short: "Validate a policy file",
	Long: `Validate a policy file for syntax and semantic errors.

Checks that the policy file has valid YAML structure, correct version,
valid rule names, known actions, and well-formed conditions.

Example:
  openpass policy validate ~/.config/openpass/policies/dev.yaml`,
	Args: cobra.ExactArgs(1),
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]

		// Expand ~ to home directory
		if len(path) > 0 && path[0] == '~' {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("cannot determine home directory: %w", err)
			}
			path = filepath.Join(home, path[1:])
		}

		p, err := policy.LoadPolicy(path)
		if err != nil {
			cmd.Printf("❌ Policy validation failed for %s\n", path)
			return err
		}

		cmd.Printf("✅ Policy %q is valid\n", p.Version)
		if p.Description != "" {
			cmd.Printf("   Description: %s\n", p.Description)
		}
		cmd.Printf("   Rules: %d\n", len(p.Rules))
		for _, rule := range p.Rules {
			cmd.Printf("   - %s (priority: %d, action: %s)\n", rule.Name, rule.Priority, rule.Action)
		}
		return nil
	},
}

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage declarative policies",
	Long: `Manage context-aware auto-approval policies for MCP tool calls.

Policies are YAML files stored in ~/.config/openpass/policies/.
They define rules for when tool calls should be allowed, denied,
prompted, or require biometric authentication.`,
	Example: `  # Validate a policy file before activating it
  openpass policy validate ./my-policy.yaml

  # Apply a policy
  openpass policy apply ./my-policy.yaml

  # List active policies
  openpass policy list

  # Remove a named policy
  openpass policy remove dev-readonly`,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
}

var policyApplyCmd = &cobra.Command{
	Use:   "apply <file>",
	Short: "Apply a policy file to the vault",
	Long: `Load and validate a policy file, then copy it to the vault's policies directory.

Example:
  openpass policy apply ~/policies/dev.yaml`,
	Args: cobra.ExactArgs(1),
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		sourcePath := args[0]
		if len(sourcePath) > 0 && sourcePath[0] == '~' {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("cannot determine home directory: %w", err)
			}
			sourcePath = filepath.Join(home, sourcePath[1:])
		}

		p, err := policy.LoadPolicy(sourcePath)
		if err != nil {
			cmd.Printf("❌ Policy validation failed for %s\n", sourcePath)
			return err
		}

		vaultDir, _ := vaultPath()
		policiesDir := filepath.Join(vaultDir, "policies")
		_ = os.MkdirAll(policiesDir, 0750)

		destPath := filepath.Join(policiesDir, filepath.Base(sourcePath))
		data, err := os.ReadFile(sourcePath) //#nosec G304 -- sourcePath is validated by caller
		if err != nil {
			return fmt.Errorf("read policy file: %w", err)
		}

		// #nosec G306 -- 0640 is intentional for policy files within vault
		if err := os.WriteFile(destPath, data, 0640); err != nil {
			return fmt.Errorf("write policy file: %w", err)
		}

		cmd.Printf("✅ Policy %q applied (%d rules)\n", p.Version, len(p.Rules))
		return nil
	},
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all applied policies",
	Long:  `List all policy files in the vault's policies directory.`,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir, _ := vaultPath()
		policiesDir := filepath.Join(vaultDir, "policies")

		entries, err := os.ReadDir(policiesDir)
		if err != nil {
			if os.IsNotExist(err) {
				cmd.Println("No policies directory found.")
				return nil
			}
			return fmt.Errorf("read policies directory: %w", err)
		}

		if len(entries) == 0 {
			cmd.Println("No policies applied.")
			return nil
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			cmd.Printf("  - %s\n", entry.Name())
		}
		return nil
	},
}

var policyRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove an applied policy",
	Long:  `Remove a policy file from the vault's policies directory.`,
	Args:  cobra.ExactArgs(1),
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir, _ := vaultPath()
		policiesDir := filepath.Join(vaultDir, "policies")
		policyPath := filepath.Join(policiesDir, args[0])

		if _, err := os.Stat(policyPath); os.IsNotExist(err) {
			return fmt.Errorf("policy %q not found", args[0])
		}

		if err := os.Remove(policyPath); err != nil {
			return fmt.Errorf("remove policy: %w", err)
		}

		cmd.Printf("✅ Policy %q removed\n", args[0])
		return nil
	},
}

func init() {
	policyCmd.AddCommand(policyValidateCmd)
	policyCmd.AddCommand(policyApplyCmd)
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyRemoveCmd)
	rootCmd.AddCommand(policyCmd)
}
