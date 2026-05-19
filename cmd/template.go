package cmd

import (
	"context"
	"fmt"
	"os"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/template"
	vaultsvc "github.com/danieljustus/OpenPass/internal/vaultsvc"
)

var (
	templateType   string
	templateOutput string
	templateDryRun bool
	templateName   string
)

var templateCmd = &cobra.Command{
	Use:   "template",
	Short: "Generate configuration files from templates",
	Long: `Generate configuration files from built-in or custom templates.

Supported template types:
  env             - Environment variable file
  docker-compose  - Docker Compose environment section
  k8s-secret      - Kubernetes Secret manifest
  github-actions  - GitHub Actions workflow secrets
  terraform       - Terraform variable definitions`,
	Example: `  # Generate a .env file from the work/* entries
  openpass template generate env --prefix work/ > .env

  # K8s Secret manifest
  openpass template generate k8s-secret --name prod-secrets prod/*`,
}

var templateGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a configuration file from a template",
	Example: `  # Generate .env file from vault secrets
  openpass template generate --type env --name myapp

  # Generate Kubernetes secret manifest
  openpass template generate --type k8s-secret --name myapp --output k8s/secret.yaml

  # Dry-run to preview without real values
  openpass template generate --type env --name myapp --dry-run`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return withVault(func(svc vaultsvc.Service) error {
			ctx := context.Background()
			engine := template.NewEngine(svc)

			refs := make(map[string]string)
			customDir := os.ExpandEnv("$HOME/.config/openpass/templates")
			_ = engine.LoadCustomTemplates(customDir)

			output, err := engine.Render(ctx, templateType, templateName, refs, templateDryRun)
			if err != nil {
				return fmt.Errorf("render template: %w", err)
			}

			if templateOutput != "" {
				if err := os.WriteFile(templateOutput, []byte(output), 0600); err != nil {
					return fmt.Errorf("write output file: %w", err)
				}
				if cli.OutputFormat == "text" {
					fmt.Printf("Template written to: %s\n", templateOutput)
				} else {
					return PrintResult(map[string]interface{}{
						"output_path": templateOutput,
						"dry_run":     templateDryRun,
					})
				}
				return nil
			}

			fmt.Println(output)
			return nil
		})
	},
}

func init() {
	templateGenerateCmd.Flags().StringVar(&templateType, "type", "", "Template type (env, docker-compose, k8s-secret, github-actions, terraform)")
	templateGenerateCmd.Flags().StringVar(&templateOutput, "output", "", "Output file path (optional)")
	templateGenerateCmd.Flags().BoolVar(&templateDryRun, "dry-run", false, "Show template with masked values")
	templateGenerateCmd.Flags().StringVar(&templateName, "name", "app", "Name of the resource being generated")
	_ = templateGenerateCmd.MarkFlagRequired("type")

	templateCmd.AddCommand(templateGenerateCmd)
	rootCmd.AddCommand(templateCmd)
}
