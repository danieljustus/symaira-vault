package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-vault/internal/template"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var (
	templateType   string
	templateOutput string
	templateDryRun bool
	templateName   string
	templatePrefix string
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
  symvault template generate env --prefix work/ > .env

  # K8s Secret manifest
  symvault template generate k8s-secret --name prod-secrets prod/*`,
}

var templateGenerateCmd = &cobra.Command{
	Use:   "generate [KEY=ref ...]",
	Short: "Generate a configuration file from a template",
	Long: `Generate a configuration file from a template.

Refs can be specified as positional KEY=ref arguments or via --prefix to
automatically select entries matching a vault path prefix. Each ref is a
vault entry path with an optional dot-separated field (e.g. db.password).
When --prefix is used without positional args, all matching entries are
included with the entry basename as the key.`,
	Example: `  # Generate .env file from specific vault secrets
  symvault template generate --type env DB_PASS=prod/db.password API_KEY=stripe.token

  # Generate .env from all entries under work/
  symvault template generate --type env --prefix work/

  # Generate Kubernetes secret manifest with mixed refs
  symvault template generate --type k8s-secret --name prod-secrets --prefix work/ DB_HOST=infra.db.host

  # Dry-run to preview without real values
  symvault template generate --type env --prefix work/ --dry-run`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cli.WithVault(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
			ctx := context.Background()
			engine := template.NewEngine(v)

			refs := make(map[string]string)

			if templatePrefix != "" {
				entries, listErr := vaultpkg.List(v.Dir, templatePrefix, v.Identity)
				if listErr != nil {
					return fmt.Errorf("list entries with prefix %q: %w", templatePrefix, listErr)
				}
				for _, entryPath := range entries {
					entry, readErr := vaultpkg.ReadEntry(v.Dir, entryPath, v.Identity)
					if readErr != nil {
						return fmt.Errorf("read entry %q: %w", entryPath, readErr)
					}
					for field := range entry.Data {
						basename := entryPath
						if idx := strings.LastIndex(entryPath, "/"); idx >= 0 {
							basename = entryPath[idx+1:]
						}
						key := basename + "." + field
						refs[key] = entryPath + "." + field
					}
				}
			}

			for _, arg := range args {
				parts := strings.SplitN(arg, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid ref format: %q (expected KEY=path[.field])", arg)
				}
				key := parts[0]
				ref := parts[1]
				if key == "" || ref == "" {
					return fmt.Errorf("empty key or ref in: %q", arg)
				}
				refs[key] = ref
			}

			if len(refs) == 0 {
				return fmt.Errorf("no secret references provided: use positional KEY=ref arguments or --prefix")
			}

			customDir := os.ExpandEnv("$HOME/.config/symvault/templates")
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
					return cli.PrintResult(map[string]interface{}{
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
	templateGenerateCmd.Flags().StringVar(&templatePrefix, "prefix", "", "Vault path prefix to auto-select entries (e.g. work/)")
	_ = templateGenerateCmd.MarkFlagRequired("type")

	templateCmd.AddCommand(templateGenerateCmd)
	rootCmd.AddCommand(templateCmd)
}
