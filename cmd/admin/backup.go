package admin

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

var BackupExcludeGit bool

var backupCmd = &cobra.Command{
	Use:   "backup <archive-path>",
	Short: "Create a backup archive of the vault",
	Long: `Create a compressed archive (.tar.gz) of the current vault.

The backup includes all vault files: identity.age, config.yaml, entries/, and mcp-token.
Use --exclude-git to omit the .git/ directory from the backup.`,
	Example: `  # Full backup to a tarball
  openpass backup ~/openpass-2026-05-17.tar.gz

  # Skip the Git history (smaller archive)
  openpass backup --exclude-git ~/openpass.tar.gz`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir, err := cli.VaultPath()
		if err != nil {
			return err
		}

		if !vaultpkg.IsInitialized(vaultDir) {
			return errorspkg.NewCLIError(errorspkg.ExitNotInitialized, "vault not initialized. Run 'openpass init' first", errorspkg.ErrVaultNotInitialized)
		}

		archivePath := args[0]
		if !strings.HasSuffix(archivePath, ".tar.gz") {
			archivePath += ".tar.gz"
		}

		if err := CreateBackup(vaultDir, archivePath, BackupExcludeGit); err != nil {
			return fmt.Errorf("backup failed: %w", err)
		}

		cli.PrintQuietAware("Backup created: %s\n", archivePath)
		return nil
	},
}

func CreateBackup(vaultDir, archivePath string, excludeGit bool) error {
	if err := os.MkdirAll(filepath.Dir(archivePath), 0o700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}

	f, err := os.Create(archivePath) // #nosec // archivePath is user-provided output path
	if err != nil {
		return fmt.Errorf("create archive: %w", err)
	}
	defer func() { _ = f.Close() }()

	gw := gzip.NewWriter(f)
	defer func() { _ = gw.Close() }()

	tw := tar.NewWriter(gw)
	defer func() { _ = tw.Close() }()

	return filepath.Walk(vaultDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip symlinks — do not follow them
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		relPath, err := filepath.Rel(vaultDir, path)
		if err != nil {
			return err
		}

		if excludeGit && strings.HasPrefix(relPath, ".git") {
			return nil
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relPath

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if !info.IsDir() {
			file, err := os.Open(path) // #nosec // path comes from trusted vault directory
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(tw, file)
			_ = file.Close()
			if copyErr != nil {
				return copyErr
			}
		}

		return nil
	})
}

var restoreCmd = &cobra.Command{
	Use:   "restore <archive-path>",
	Short: "Restore vault from a backup archive",
	Long: `Restore a vault from a previously created backup archive (.tar.gz).

The archive is extracted into the current vault directory. If the vault directory
does not exist, it will be created. After extraction, the vault is verified
to ensure all expected files are present.`,
	Example: `  # Restore into the default vault directory
  openpass restore ~/openpass-2026-05-17.tar.gz

  # Restore into a custom location
  openpass --vault ~/restored restore archive.tar.gz`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir, err := cli.VaultPath()
		if err != nil {
			return err
		}

		archivePath := args[0]
		if _, err := os.Stat(archivePath); err != nil {
			return fmt.Errorf("archive not found: %w", err)
		}

		if err := RestoreBackup(archivePath, vaultDir); err != nil {
			return fmt.Errorf("restore failed: %w", err)
		}

		if !vaultpkg.IsInitialized(vaultDir) {
			return errorspkg.NewCLIError(errorspkg.ExitNotInitialized, "vault not initialized. Run 'openpass init' first", errorspkg.ErrVaultNotInitialized)
		}

		cli.PrintQuietAware("Vault restored to: %s\n", vaultDir)
		return nil
	},
}

func RestoreBackup(archivePath, vaultDir string) error {
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}

	f, err := os.Open(archivePath) // #nosec // archivePath is user-provided input, validated by caller
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer func() { _ = f.Close() }()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("read gzip: %w", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read archive: %w", err)
		}

		targetPath := filepath.Join(vaultDir, header.Name) // #nosec // path traversal checked below
		cleanTarget := filepath.Clean(targetPath)
		cleanVaultDir := filepath.Clean(vaultDir)
		if !strings.HasPrefix(cleanTarget, cleanVaultDir+string(filepath.Separator)) && cleanTarget != cleanVaultDir {
			return fmt.Errorf("archive contains path traversal: %s", header.Name)
		}

		// Reject restore if target already exists as a symlink
		if existingInfo, err := os.Lstat(targetPath); err == nil {
			if existingInfo.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("target path is a symlink: %s", targetPath)
			}
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if header.Mode < 0 {
				return fmt.Errorf("invalid negative mode in archive: %s", header.Name)
			}
			mode := os.FileMode(header.Mode) & 0o700 // #nosec G115 // header.Mode validated as non-negative above
			if err := os.MkdirAll(targetPath, mode); err != nil {
				return fmt.Errorf("create directory: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
				return fmt.Errorf("create parent directory: %w", err)
			}
			if header.Mode < 0 {
				return fmt.Errorf("invalid negative mode in archive: %s", header.Name)
			}
			mode := os.FileMode(header.Mode) & 0o600                                          // #nosec G115 // header.Mode validated as non-negative above
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode) // #nosec // path validated above
			if err != nil {
				return fmt.Errorf("create file: %w", err)
			}
			_, copyErr := io.CopyN(outFile, tr, header.Size) // #nosec // size from trusted backup archive
			_ = outFile.Close()
			if copyErr != nil {
				return fmt.Errorf("write file: %w", copyErr)
			}
		default:
			return fmt.Errorf("unsupported archive entry type: %s", header.Name)
		}
	}

	return VerifyBackup(vaultDir)
}

func VerifyBackup(vaultDir string) error {
	required := []string{"identity.age", "config.yaml"}
	for _, file := range required {
		path := filepath.Join(vaultDir, file)
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("missing required file: %s", file)
		}
	}

	entriesDir := filepath.Join(vaultDir, "entries")
	if _, err := os.Stat(entriesDir); err != nil {
		return fmt.Errorf("missing entries directory")
	}

	return nil
}

func ComputeSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec // path is user-provided backup file
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func init() {
	backupCmd.Flags().BoolVar(&BackupExcludeGit, "exclude-git", false, "Exclude .git/ directory from backup")
	cli.RootCmd.AddCommand(backupCmd)
	cli.RootCmd.AddCommand(restoreCmd)
}
