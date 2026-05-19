package mcp

import (
	"fmt"
	"os"
	"path/filepath"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"github.com/spf13/cobra"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/daemon"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/ui/cliout"
)

var serveInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install MCP server as a background service",
	Long: `Install the OpenPass MCP server as a system background service.

On macOS, this creates a LaunchAgent plist in ~/Library/LaunchAgents/
and loads it with launchctl. The service starts automatically on login
and stays running.

On Linux, this creates a systemd user service in ~/.config/systemd/user/
and enables it to start automatically.`,
	Example: `  # Install as autostart service
  openpass serve install

  # Check status
  openpass serve status

  # Remove again
  openpass serve uninstall`,
	RunE: runServeInstall,
}

var serveUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove the MCP server background service",
	Long: `Stop and remove the OpenPass MCP server background service.

On macOS, this unloads the LaunchAgent and removes the plist file.

On Linux, this stops and disables the systemd user service and removes
the service file.`,
	RunE: runServeUninstall,
}

var serveStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show MCP server service status",
	Long: `Display the current status of the OpenPass MCP server background service.

Reports whether the service is running, stopped, or not installed,
along with the service file path, port, and vault directory.`,
	RunE: runServeStatus,
}

func init() {
	ServeCmd.AddCommand(serveInstallCmd)
	ServeCmd.AddCommand(serveUninstallCmd)
	ServeCmd.AddCommand(serveStatusCmd)
}

func runServeInstall(cmd *cobra.Command, args []string) error {
	vaultDir, err := cli.VaultPath()
	if err != nil {
		return err
	}

	cfg, cfgErr := loadServeConfig()
	if cfgErr != nil {
		cliout.Warnf("Could not load config, using defaults: %v", cfgErr)
	}

	installer, err := daemon.NewInstaller(cfg, vaultDir)
	if err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError,
			"create installer", err)
	}

	if err := installer.Install(); err != nil {
		return err
	}

	svcPath, _ := installer.ServiceFilePath()
	cli.PrintlnQuietAware("Service installed successfully.")
	if svcPath != "" {
		fmt.Printf("  Service file: %s\n", svcPath)
	}
	fmt.Printf("  Port:         %d\n", installer.Port())
	fmt.Printf("  Bind:         %s\n", installer.Bind())
	fmt.Printf("  Vault:        %s\n", installer.VaultDir())

	return nil
}

func runServeUninstall(cmd *cobra.Command, args []string) error {
	vaultDir, err := cli.VaultPath()
	if err != nil {
		return err
	}

	cfg, _ := loadServeConfig()

	installer, err := daemon.NewInstaller(cfg, vaultDir)
	if err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError,
			"create installer", err)
	}

	if err := installer.Uninstall(); err != nil {
		return err
	}

	cli.PrintlnQuietAware("Service uninstalled successfully.")
	return nil
}

func runServeStatus(cmd *cobra.Command, args []string) error {
	vaultDir, err := cli.VaultPath()
	if err != nil {
		return err
	}

	cfg, _ := loadServeConfig()

	installer, err := daemon.NewInstaller(cfg, vaultDir)
	if err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError,
			"create installer", err)
	}

	status, err := installer.Status()
	if err != nil {
		return err
	}

	fmt.Printf("Status: %s\n", status)
	svcPath, _ := installer.ServiceFilePath()
	if svcPath != "" {
		fmt.Printf("  Service file: %s\n", svcPath)
	}
	fmt.Printf("  Port:         %d\n", installer.Port())
	fmt.Printf("  Bind:         %s\n", installer.Bind())
	fmt.Printf("  Vault:        %s\n", installer.VaultDir())

	return nil
}

func loadServeConfig() (*configpkg.Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(home, ".openpass", "config.yaml")
	return configpkg.Load(configPath)
}
