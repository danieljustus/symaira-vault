package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

var (
	MigrateYes      bool
	MigrateV4DryRun bool
)

var MigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Vault migration commands",
	Example: `  # Pseudonymise on-disk paths (one-way)
  openpass migrate pseudonymize --dry-run
  openpass migrate pseudonymize`,
}

var migratePseudonymizeCmd = &cobra.Command{
	Use:   "pseudonymize",
	Short: "Migrate vault entries to pseudonymized storage paths",
	Long: `Migrate vault entries to pseudonymized storage paths.

WARNING: This rewrites every entry in the vault. Make a backup first.
Each entry is read, re-encrypted with its plaintext path stored inside
the encrypted data, and written to an HMAC-SHA256 derived path under
entries/. The old plaintext-named files are removed.

After migration, enable pseudonymize_paths in your vault config.yaml
to write new entries to pseudonymized paths.`,
	Example: `  openpass migrate pseudonymize`,
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir, err := cli.VaultPath()
		if err != nil {
			return err
		}

		if !vaultpkg.IsInitialized(vaultDir) {
			return errorspkg.NewCLIError(errorspkg.ExitNotInitialized,
				"vault not initialized. Run 'openpass init' first",
				errorspkg.ErrVaultNotInitialized)
		}

		v, err := cli.UnlockVault(vaultDir, true)
		if err != nil {
			return err
		}

		confirmed, err := cli.ConfirmInteractive(
			"Migrate all entries to pseudonymized paths. Make a backup first",
			MigrateYes,
		)
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Fprintln(os.Stderr, "Canceled")
			return nil
		}

		return runPseudonymizeMigration(v)
	},
}

func runPseudonymizeMigration(v *vaultpkg.Vault) error {
	vaultDir := v.Dir

	var ageFiles []string
	err := filepath.WalkDir(filepath.Join(vaultDir, "entries"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".age" {
			ageFiles = append(ageFiles, path)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("walk entries: %w", err)
	}

	if len(ageFiles) == 0 {
		cli.PrintlnQuietAware("No entries to migrate. Enabling pseudonymize_paths in config.")
		return enablePseudonymizeConfig(vaultDir)
	}

	cli.PrintlnQuietAware(fmt.Sprintf("Migrating %d entries to pseudonymized paths...", len(ageFiles)))

	migrated := 0
	for _, filePath := range ageFiles {
		rel, relErr := filepath.Rel(filepath.Join(vaultDir, "entries"), filePath)
		if relErr != nil {
			return fmt.Errorf("compute relative path for %s: %w", filePath, relErr)
		}
		plainPath := strings.TrimSuffix(filepath.ToSlash(rel), ".age")

		entry, readErr := vaultpkg.ReadEntry(vaultDir, plainPath, v.Identity)
		if readErr != nil {
			return fmt.Errorf("read entry %s: %w", plainPath, readErr)
		}

		if err := vaultpkg.WriteEntry(vaultDir, plainPath, entry, v.Identity); err != nil {
			return fmt.Errorf("rewrite entry %s: %w", plainPath, err)
		}

		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove old entry %s: %w", filePath, err)
		}

		migrated++
		fmt.Fprintf(os.Stderr, "\rMigrated %d/%d entries", migrated, len(ageFiles))
	}
	fmt.Fprintln(os.Stderr)

	if err := enablePseudonymizeConfig(vaultDir); err != nil {
		return err
	}

	cli.PrintlnQuietAware("Migration complete. All entries now use pseudonymized paths.")
	return nil
}

var migrateV4Cmd = &cobra.Command{
	Use:   "v4",
	Short: "Migrate agent profiles and config to v4.0 format",
	Long: `Migrate agent profiles to the v4.0 format by assigning tier fields.

Agent profiles without a tier field are automatically assigned a tier based
on their existing capabilities:

  - Profiles with CanRunCommands=true  → admin tier
  - Profiles with CanWrite=true        → standard tier
  - All other profiles                 → safe tier

The original config is backed up as config.yaml.v3-backup-<timestamp>
before any changes are written.

This migration is idempotent — running it multiple times is safe for
profiles that already have a tier field.`,
	Example: `  openpass migrate v4
  openpass migrate v4 --dry-run
  openpass migrate v4 --yes`,
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir, err := cli.VaultPath()
		if err != nil {
			return err
		}

		cfg, err := configpkg.Load(filepath.Join(vaultDir, "config.yaml"))
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		type pendingTier struct {
			name string
			tier string
		}
		var pending []pendingTier

		for name, profile := range cfg.Agents {
			if profile.Tier != nil && *profile.Tier != "" {
				continue
			}
			var tier string
			switch {
			case profile.CanRunCommands != nil && *profile.CanRunCommands:
				tier = "admin"
			case profile.CanWrite != nil && *profile.CanWrite:
				tier = "standard"
			default:
				tier = "safe"
			}
			pending = append(pending, pendingTier{name: name, tier: tier})
		}

		if len(pending) == 0 {
			cli.PrintlnQuietAware("All profiles already have tier fields.")
			return nil
		}

		cli.PrintlnQuietAware(fmt.Sprintf("Found %d agent profile(s) without tier fields:", len(pending)))
		for _, p := range pending {
			cli.PrintlnQuietAware(fmt.Sprintf("  %s → %s", p.name, p.tier))
		}

		if MigrateV4DryRun {
			cli.PrintlnQuietAware("Dry-run: no changes written.")
			return nil
		}

		confirmed, err := cli.ConfirmInteractive(
			"Migrate agent profiles to v4.0 format",
			MigrateYes,
		)
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Fprintln(os.Stderr, "Canceled")
			return nil
		}

		// Backup original config
		configPath := filepath.Join(vaultDir, "config.yaml")
		backupPath := filepath.Join(vaultDir, fmt.Sprintf("config.yaml.v3-backup-%d", time.Now().Unix()))
		input, err := os.ReadFile(filepath.Clean(configPath))
		if err != nil {
			return fmt.Errorf("read config for backup: %w", err)
		}
		if err := os.WriteFile(backupPath, input, 0o600); err != nil {
			return fmt.Errorf("write backup: %w", err)
		}
		cli.PrintlnQuietAware(fmt.Sprintf("Backup created: %s", backupPath))

		for _, p := range pending {
			profile := cfg.Agents[p.name]
			profile.Tier = configpkg.StrPtr(p.tier)
			cfg.Agents[p.name] = profile
		}

		if err := cfg.SaveTo(configPath); err != nil {
			return fmt.Errorf("save migrated config: %w", err)
		}

		cli.PrintlnQuietAware(fmt.Sprintf("Migrated %d agent profile(s) to v4.0 format.", len(pending)))
		return nil
	},
}

var migrateKDFCmd = &cobra.Command{
	Use:   "kdf",
	Short: "Migrate vault KDF from scrypt to argon2id",
	Long: `Migrate the vault's key derivation function from scrypt to argon2id.

⚠️  This command is a STUB and not yet implemented.
A future release will provide the full migration workflow.

Argon2id is the industry standard for password hashing (2025+) and provides
stronger resistance against GPU-based attacks compared to scrypt.

In the meantime:
  1. Back up your vault: cp -r ~/.openpass ~/.openpass.backup
  2. Wait for a future release with full migration support
  3. Run 'openpass doctor' to track the migration recommendation`,
	Example: `  openpass migrate kdf`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("⚠️  Migration from scrypt to argon2id is not yet implemented.")
		fmt.Println()
		fmt.Println("Argon2id will provide stronger GPU resistance for your master passphrase.")
		fmt.Println("This feature is planned for a future release.")
		fmt.Println()
		fmt.Println("In the meantime, your vault is secure with scrypt (work factor 18).")
		fmt.Println("To track the recommendation, run: openpass doctor")
		return nil
	},
}

func enablePseudonymizeConfig(vaultDir string) error {
	cfg, err := configpkg.Load(filepath.Join(vaultDir, "config.yaml"))
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if cfg.Vault == nil {
		cfg.Vault = &configpkg.VaultConfig{}
	}
	cfg.Vault.PseudonymizePaths = true

	if err := cfg.SaveTo(filepath.Join(vaultDir, "config.yaml")); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	return nil
}

func init() {
	MigrateCmd.AddCommand(migratePseudonymizeCmd)
	migratePseudonymizeCmd.Flags().BoolVarP(&MigrateYes, "yes", "y", false, "Skip confirmation prompt")
	MigrateCmd.AddCommand(migrateKDFCmd)
	MigrateCmd.AddCommand(migrateV4Cmd)
	migrateV4Cmd.Flags().BoolVarP(&MigrateYes, "yes", "y", false, "Skip confirmation prompt")
	migrateV4Cmd.Flags().BoolVar(&MigrateV4DryRun, "dry-run", false, "Preview changes without writing")
	cli.RootCmd.AddCommand(MigrateCmd)
}
