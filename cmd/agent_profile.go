package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
)

var agentProfileCmd = &cobra.Command{
	Use:   "profile <name>",
	Short: "Manage agent profiles",
	Long:  `Show, edit, and export agent profiles.`,
	Args:  cobra.ExactArgs(1),
	Example: `  # Show agent profile
  openpass agent profile my-agent show

  # Show profile as JSON
  openpass agent profile my-agent show --output json

  # Edit agent profile in $EDITOR
  openpass agent profile my-agent edit

  # Export profile as YAML to stdout
  openpass agent profile my-agent export`,
}

var agentProfileShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display agent profile",
	Long:  `Display the agent profile in YAML or JSON format.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := mustGetProfileAgentName(cmd)
		output, _ := cmd.Flags().GetString("output")

		profile, err := loadAgentProfile(agentName)
		if err != nil {
			return err
		}

		switch output {
		case "json":
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(profile)
		default:
			enc := yaml.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent(2)
			defer func() { _ = enc.Close() }()
			return enc.Encode(profile)
		}
	},
}

var agentProfileEditCmd = &cobra.Command{
	Use:   "edit",
	Short: "Edit agent profile in $EDITOR",
	Long: `Open the agent profile in your configured editor ($EDITOR or $VISUAL).
After saving, the profile is validated and you are prompted to apply changes.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := mustGetProfileAgentName(cmd)

		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = os.Getenv("VISUAL")
		}
		if editor == "" {
			return fmt.Errorf("neither $EDITOR nor $VISUAL is set")
		}

		vaultDir := getVaultDir()
		configPath := filepath.Join(vaultDir, "config.yaml")

		data, err := os.ReadFile(configPath) //nolint:gosec G304 — path is filepath.Join(vaultDir, "config.yaml")
		if err != nil {
			return fmt.Errorf("read config: %w", err)
		}

		tmpFile, err := os.CreateTemp("", fmt.Sprintf("openpass-agent-%s-*.yaml", agentName))
		if err != nil {
			return fmt.Errorf("create temp file: %w", err)
		}
		tmpPath := tmpFile.Name()
		defer func() { _ = os.Remove(tmpPath) }()

		section, err := extractAgentSection(data, agentName)
		if err != nil {
			_ = tmpFile.Close()
			return fmt.Errorf("extract agent section: %w", err)
		}

		if _, writeErr := tmpFile.Write(section); writeErr != nil {
			_ = tmpFile.Close()
			return fmt.Errorf("write temp file: %w", writeErr)
		}
		_ = tmpFile.Close()

		editorCmd := exec.Command(editor, tmpPath) //nolint:gosec G204 — editor is user-configured via $EDITOR, tmpPath is from os.CreateTemp
		editorCmd.Stdin = os.Stdin
		editorCmd.Stdout = os.Stdout
		editorCmd.Stderr = os.Stderr
		if runErr := editorCmd.Run(); runErr != nil {
			return fmt.Errorf("editor exited with error: %w", runErr)
		}

		editedData, err := os.ReadFile(tmpPath) //nolint:gosec G304 — tmpPath is from os.CreateTemp, safe
		if err != nil {
			return fmt.Errorf("read edited file: %w", err)
		}

		var editedProfile configpkg.AgentProfile
		if unmarshalErr := yaml.Unmarshal(editedData, &editedProfile); unmarshalErr != nil {
			return fmt.Errorf("invalid YAML in edited profile: %w", unmarshalErr)
		}

		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Edited profile for %q:\n", agentName)
		showProfilePreview(cmd, &editedProfile)

		_, _ = fmt.Fprint(cmd.ErrOrStderr(), "\nApply changes? [y/N] ")
		var response string
		_, _ = fmt.Scanln(&response)
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Changes discarded.")
			return nil
		}

		cfg, err := configpkg.Load(configPath)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		editedProfile.Name = agentName
		if cfg.Agents == nil {
			cfg.Agents = make(map[string]configpkg.AgentProfile)
		}
		cfg.Agents[agentName] = editedProfile

		if err := cfg.SaveTo(configPath); err != nil {
			return fmt.Errorf("save config: %w", err)
		}

		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Profile for %q updated.\n", agentName)
		return nil
	},
}

var agentProfileExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export agent profile as YAML",
	Long: `Export the agent profile to stdout or to a file.
Output is in YAML format by default.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		agentName := mustGetProfileAgentName(cmd)
		outputPath, _ := cmd.Flags().GetString("output")

		profile, err := loadAgentProfile(agentName)
		if err != nil {
			return err
		}

		var out *os.File
		if outputPath != "" {
			f, err := os.Create(outputPath) //nolint:gosec G304 — outputPath is user-provided export destination
			if err != nil {
				return fmt.Errorf("create output file: %w", err)
			}
			defer func() { _ = f.Close() }()
			out = f
		} else {
			out = os.Stdout
		}

		enc := yaml.NewEncoder(out)
		enc.SetIndent(2)
		defer func() { _ = enc.Close() }()
		return enc.Encode(profile)
	},
}

func loadAgentProfile(agentName string) (*configpkg.AgentProfile, error) {
	configPath := filepath.Join(getVaultDir(), "config.yaml")
	cfg, err := configpkg.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	profile, ok := cfg.Agents[agentName]
	if !ok {
		return nil, fmt.Errorf("agent %q not found in config", agentName)
	}
	profile.Name = agentName
	return &profile, nil
}

func mustGetProfileAgentName(cmd *cobra.Command) string {
	parent := cmd.Parent()
	if parent != nil {
		parentArgs := parent.Flags().Args()
		if len(parentArgs) > 0 {
			return parentArgs[0]
		}
	}
	return "unknown"
}

func extractAgentSection(data []byte, agentName string) ([]byte, error) {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	agents, ok := raw["agents"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("no agents section found in config")
	}

	agentData, ok := agents[agentName]
	if !ok {
		return nil, fmt.Errorf("agent %q not found in config", agentName)
	}

	return yaml.Marshal(agentData)
}

func showProfilePreview(cmd *cobra.Command, profile *configpkg.AgentProfile) {
	enc := yaml.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent(2)
	defer func() { _ = enc.Close() }()
	_ = enc.Encode(profile)
}

func init() {
	agentProfileCmd.AddCommand(agentProfileShowCmd)
	agentProfileCmd.AddCommand(agentProfileEditCmd)
	agentProfileCmd.AddCommand(agentProfileExportCmd)
	agentCmd.AddCommand(agentProfileCmd)

	agentProfileShowCmd.Flags().StringP("output", "o", "yaml", "Output format (yaml, json)")
	agentProfileExportCmd.Flags().StringP("output", "o", "", "Output file path (default: stdout)")
}
