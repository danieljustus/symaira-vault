package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cli "github.com/danieljustus/symaira-vault/internal/cli"

	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var (
	MigrateYes      bool
	MigrateV4DryRun bool
)

var MigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Vault migration commands",
	Example: `  # Pseudonymise on-disk paths (one-way)
  symvault migrate pseudonymize --dry-run
  symvault migrate pseudonymize`,
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
	Example: `  symvault migrate pseudonymize`,
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir, err := cli.VaultPath()
		if err != nil {
			return err
		}

		if !vaultpkg.IsInitialized(vaultDir) {
			return errorspkg.NewVaultNotInitialized()
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
	Example: `  symvault migrate v4
  symvault migrate v4 --dry-run
  symvault migrate v4 --yes`,
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
	Short: "Migrate the vault identity from scrypt to argon2id",
	Long: `Migrate the vault identity's key derivation function from the legacy
scrypt KDF to argon2id.

Argon2id is the industry standard for password hashing and provides stronger
resistance against GPU-based attacks than scrypt. New vaults already use
argon2id.

This command performs the migration itself — it does not just report status.
Automatic migration on every unlock additionally happens when
vault.auto_migrate_kdf: true is set in config.yaml, but by default that is
off, so this command is the way to upgrade an existing scrypt vault.

identity.age is backed up to identity.age.bak before any change, and the new
file is decrypt-verified before the migration is considered done. On any
failure the original identity.age is restored automatically. Changing
config.yaml's scrypt_work_factor alone does not perform this migration —
only this command (or auto_migrate_kdf) re-encrypts identity.age.`,
	Example: `  symvault migrate kdf
  symvault migrate kdf --yes`,
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir := cli.GetVaultDir()
		identityPath := filepath.Join(vaultDir, "identity.age")
		raw, err := os.ReadFile(identityPath) // #nosec G304 -- fixed filename under the resolved vault dir
		if err != nil {
			return fmt.Errorf("read vault identity (%s): %w", identityPath, err)
		}

		switch cryptopkg.DetectEncryptedIdentityFormat(raw) {
		case "argon2id":
			fmt.Println("✓ Your vault identity is already protected with argon2id.")
			fmt.Println("No migration is needed.")
			return nil
		case "scrypt":
			// handled below
		default:
			fmt.Println("Could not determine the vault identity's key derivation function.")
			fmt.Println("Run 'symvault doctor' for a full diagnosis.")
			return nil
		}

		fmt.Println("Your vault identity is currently protected with scrypt.")

		// Unlock (which needs the passphrase) before the confirmation prompt,
		// not after: ConfirmInteractive reads through a buffered os.Stdin
		// reader that is free to consume more than the "y\n" line, which
		// would silently steal bytes a later raw passphrase read expects.
		// This also fails fast on a wrong passphrase before asking the user
		// to confirm a migration that couldn't proceed anyway.
		passphrase, err := cli.ReadHiddenInput("Passphrase: ", nil)
		if err != nil {
			return fmt.Errorf("read passphrase: %w", err)
		}
		defer cryptopkg.Wipe(passphrase)

		v, err := vaultpkg.OpenWithPassphrase(vaultDir, passphrase)
		if err != nil {
			return fmt.Errorf("unlock vault: %w", err)
		}

		// OpenWithPassphrase already migrates when vault.auto_migrate_kdf is
		// set — v.NeedsMigration is only true when it left the file as scrypt
		// (auto-migrate off, or a prior attempt failed). When auto-migrate
		// already did the work, report that instead of asking for a
		// confirmation the open call has already acted on.
		if !v.NeedsMigration {
			fmt.Println("✓ Migrated automatically on unlock (vault.auto_migrate_kdf is enabled).")
			fmt.Println("The previous identity.age was backed up to identity.age.bak.")
			return nil
		}

		confirmed, err := cli.ConfirmInteractive(
			"Migrate the vault identity to argon2id now (identity.age is backed up to identity.age.bak first)",
			MigrateYes,
		)
		if err != nil {
			return err
		}
		if !confirmed {
			fmt.Fprintln(os.Stderr, "Canceled")
			return nil
		}

		if err := vaultpkg.MigrateKDF(vaultDir, v.Identity, passphrase, v); err != nil {
			return fmt.Errorf("migrate kdf: %w", err)
		}

		raw2, readErr := os.ReadFile(identityPath) // #nosec G304 -- fixed filename under the resolved vault dir
		if readErr != nil || cryptopkg.DetectEncryptedIdentityFormat(raw2) != "argon2id" {
			return fmt.Errorf("migration did not complete — identity.age was restored to its original form; run `symvault doctor` for details")
		}

		fmt.Println("✓ Migrated vault identity to argon2id.")
		fmt.Println("The previous identity.age was backed up to identity.age.bak.")
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
	migrateKDFCmd.Flags().BoolVarP(&MigrateYes, "yes", "y", false, "Skip confirmation prompt")
	MigrateCmd.AddCommand(migrateV4Cmd)
	migrateV4Cmd.Flags().BoolVarP(&MigrateYes, "yes", "y", false, "Skip confirmation prompt")
	migrateV4Cmd.Flags().BoolVar(&MigrateV4DryRun, "dry-run", false, "Preview changes without writing")
	cli.RootCmd.AddCommand(MigrateCmd)
}
