package cmd

import (
	"fmt"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	cli "github.com/danieljustus/OpenPass/internal/cli"
	configpkg "github.com/danieljustus/OpenPass/internal/config"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/git"
	"github.com/danieljustus/OpenPass/internal/ui/cliout"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

var (
	remoteName     string
	remotePath     string
	remotePushFlag bool
)

var remoteCmd = &cobra.Command{
	Use:   "remote",
	Short: "Manage git remote for vault sync",
	Long: `Manage the git remote used for synchronizing the vault.

Use 'openpass remote init <ssh-target>' to configure a remote git repository
for vault synchronization. The vault must be initialized first.`,
	Example: `  openpass remote init hermes@macmini
  openpass remote init user@host:/custom/path.git
  openpass remote init hermes@macmini --push
  openpass remote status`,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
}

var remoteInitCmd = &cobra.Command{
	Use:   "init <ssh-target>",
	Short: "Initialize git remote for the vault",
	Long: `Configure a remote git repository for vault synchronization.

The ssh-target can be in these formats:
  user@host           - bare repo at ~/openpass-remote.git on remote
  user@host:path      - bare repo at path on remote
  host                - bare repo at ~/openpass-remote.git using current user
  host:path           - bare repo at path using current user

Flags:
  --name   - Remote name (default: "origin")
  --path   - Custom bare repo path on remote (default: ~/openpass-remote.git)
  --push   - Push the vault to the remote after setup

This command also enables git.auto_push in your OpenPass config.`,
	Example: `  openpass remote init hermes@macmini
  openpass remote init dev@server:/srv/git/openpass.git --name upstream
  openpass remote init hermes@macmini --push`,
	Args: cobra.ExactArgs(1),
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: runRemoteInit,
}

var remoteStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show remote sync configuration",
	Long:  `Display the current git remote configuration and sync status for the vault.`,
	Annotations: map[string]string{
		requiresVaultAnnotation: "false",
	},
	RunE: runRemoteStatus,
}

func init() {
	rootCmd.AddCommand(remoteCmd)
	remoteCmd.AddCommand(remoteInitCmd)
	remoteCmd.AddCommand(remoteStatusCmd)

	remoteInitCmd.Flags().StringVarP(&remoteName, "name", "n", "origin", "Remote name")
	remoteInitCmd.Flags().StringVarP(&remotePath, "path", "p", "", "Custom bare repo path on remote (default: ~/openpass-remote.git)")
	remoteInitCmd.Flags().BoolVar(&remotePushFlag, "push", false, "Push vault to remote after setup")
}

func runRemoteInit(cmd *cobra.Command, args []string) error {
	sshTarget := strings.TrimSpace(args[0])
	if sshTarget == "" {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "ssh-target must not be empty", nil)
	}

	vaultDir, err := vaultPath()
	if err != nil {
		return err
	}

	if !vaultpkg.IsInitialized(vaultDir) {
		return errorspkg.NewCLIError(errorspkg.ExitNotInitialized,
			"vault not initialized. Run 'openpass init' first",
			errorspkg.ErrVaultNotInitialized)
	}

	hasRemote, err := git.HasRemote(vaultDir, remoteName)
	if err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "cannot check existing remotes", err)
	}
	if hasRemote {
		existingURL, _ := git.GetRemoteURL(vaultDir, remoteName)
		if existingURL != "" {
			return errorspkg.NewCLIError(errorspkg.ExitGeneralError,
				fmt.Sprintf("remote %q already exists with URL %s. Remove it first to reconfigure.",
					remoteName, existingURL), nil)
		}
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError,
			fmt.Sprintf("remote %q already exists. Remove it first to reconfigure.", remoteName), nil)
	}

	sshUser, sshHost, repoPath, err := parseSSHTarget(sshTarget, remotePath)
	if err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "invalid ssh-target", err)
	}

	remoteURL := buildSSHURL(sshUser, sshHost, repoPath)

	if err := git.AddRemote(vaultDir, remoteName, remoteURL); err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "cannot add remote", err)
	}

	if err := enableAutoPush(); err != nil {
		cliout.Warnf("Warning: remote added but could not enable auto_push in config: %v", err)
	}

	printlnQuietAware(fmt.Sprintf("Remote %q added successfully.", remoteName))
	cliout.Hintf("SSH target: %s", sshTarget)
	cliout.Hintf("Remote URL: %s", remoteURL)
	cliout.Hintf("Bare repo path: %s", repoPath)

	if remotePushFlag {
		printlnQuietAware("Pushing vault to remote...")
		if err := git.Push(vaultDir); err != nil {
			cliout.Warnf("Warning: initial push failed: %v", err)
			cliout.Hintf("Make sure a bare git repository exists at %s on %s", repoPath, sshHost)
			cliout.Hintf("Create it with: ssh %s 'git init --bare %s'", sshHost, repoPath)
		} else {
			printlnQuietAware("Vault pushed successfully.")
		}
	} else {
		cliout.Hintf("Create the bare repo on the remote with:")
		cliout.Hintf("  ssh %s 'git init --bare %s'", sshHost, repoPath)
		cliout.Hintf("Then push with: openpass git push")
	}

	return nil
}

func runRemoteStatus(cmd *cobra.Command, args []string) error {
	vaultDir, err := vaultPath()
	if err != nil {
		return err
	}

	if !vaultpkg.IsInitialized(vaultDir) {
		return errorspkg.NewCLIError(errorspkg.ExitNotInitialized,
			"vault not initialized. Run 'openpass init' first",
			errorspkg.ErrVaultNotInitialized)
	}

	url, err := git.GetRemoteURL(vaultDir, "origin")
	if err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError, "cannot get remote info", err)
	}

	if url == "" {
		if cli.OutputFormat == "text" {
			printlnQuietAware("No remote configured.")
			cliout.Hintf("Use 'openpass remote init <ssh-target>' to configure a remote.")
		} else {
			_ = PrintResult(map[string]interface{}{
				"configured": false,
				"message":    "No remote configured",
			})
		}
		return nil
	}

	autoPush := loadAutoPushConfig()

	if cli.OutputFormat == "text" {
		printQuietAware("Remote configuration for %q:\n", remoteName)
		printlnQuietAware("  URL:      " + url)
		printQuietAware("  AutoPush: ")
		if autoPush {
			printlnQuietAware("enabled")
		} else {
			printlnQuietAware("disabled")
		}
	} else {
		_ = PrintResult(map[string]interface{}{
			"configured": true,
			"remote": map[string]interface{}{
				"name":     remoteName,
				"url":      url,
				"autoPush": autoPush,
			},
		})
	}

	return nil
}

func parseSSHTarget(target, customPath string) (user, host, path string, err error) {
	if target == "" {
		return "", "", "", fmt.Errorf("empty ssh target")
	}

	remainder := target

	if atIdx := strings.LastIndex(remainder, "@"); atIdx >= 0 {
		user = remainder[:atIdx]
		remainder = remainder[atIdx+1:]
	}

	if colonIdx := strings.LastIndex(remainder, ":"); colonIdx >= 0 {
		host = remainder[:colonIdx]
		path = remainder[colonIdx+1:]
	} else {
		host = remainder
	}

	if host == "" {
		return "", "", "", fmt.Errorf("host must not be empty in ssh target %q", target)
	}

	if user == "" {
		currentUser, uerr := osuser.Current()
		if uerr == nil {
			user = currentUser.Username
		}
	}

	if customPath != "" {
		path = customPath
	}
	if path == "" {
		path = "~/openpass-remote.git"
	}

	return user, host, path, nil
}

func buildSSHURL(user, host, path string) string {
	cleanPath := path
	cleanPath = strings.TrimPrefix(cleanPath, "~")
	cleanPath = strings.TrimPrefix(cleanPath, "/")

	if user != "" {
		return fmt.Sprintf("ssh://%s@%s/~%s", user, host, cleanPath)
	}
	return fmt.Sprintf("ssh://%s/~%s", host, cleanPath)
}

func enableAutoPush() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	configPath := filepath.Join(home, ".openpass", "config.yaml")
	cfg, err := configpkg.Load(configPath)
	if err != nil {
		cfg = configpkg.Default()
	}

	if cfg.Git == nil {
		defaults := configpkg.Default()
		cfg.Git = defaults.Git
	}
	if !cfg.Git.AutoPush {
		cfg.Git.AutoPush = true
		if err := cfg.Save(); err != nil {
			return fmt.Errorf("cannot save config: %w", err)
		}
	}

	return nil
}

func loadAutoPushConfig() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}

	cfg, err := configpkg.Load(filepath.Join(home, ".openpass", "config.yaml"))
	if err != nil {
		return false
	}

	if cfg.Git != nil {
		return cfg.Git.AutoPush
	}

	return configpkg.Default().Git.AutoPush
}
