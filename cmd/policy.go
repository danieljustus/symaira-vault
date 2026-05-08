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
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
}

func init() {
	policyCmd.AddCommand(policyValidateCmd)
	rootCmd.AddCommand(policyCmd)
}
