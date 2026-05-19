package mcp

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"

	cli "github.com/danieljustus/OpenPass/internal/cli"

	"net"
	"strings"

	"github.com/spf13/cobra"

	"github.com/danieljustus/OpenPass/internal/config"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/mcp"
	"github.com/danieljustus/OpenPass/internal/mcp/serverbootstrap"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

var RunStdioServerFunc = func(ctx context.Context, vault *vaultpkg.Vault, agentName string) error {
	return serverbootstrap.RunStdioServer(ctx, vault, agentName, mcp.New)
}
var RunHTTPServerFunc = func(ctx context.Context, bind string, port int, vault *vaultpkg.Vault) error {
	vaultDir, _ := cli.VaultPath()
	return serverbootstrap.RunHTTPServer(ctx, bind, port, vault, vaultDir, Version, mcp.New)
}
var FindAvailablePortFunc = cli.FindAvailablePort

// IsLocalhostBind returns true if bind refers to the loopback interface
// (127.0.0.1, localhost, ::1, or similar).
func IsLocalhostBind(bind string) bool {
	bind = strings.TrimSpace(bind)
	if bind == "127.0.0.1" || bind == "localhost" || bind == "::1" {
		return true
	}
	ip := net.ParseIP(bind)
	return ip != nil && ip.IsLoopback()
}

var ServeUnlockVault = cli.UnlockVault

//nolint:gocyclo // Complex CLI orchestration: vault unlock + server bootstrap + signal handling
func runServe(cmd *cobra.Command, args []string) error {
	agentName, err := cmd.Flags().GetString("agent")
	if err != nil {
		return fmt.Errorf("read agent flag: %w", err)
	}
	port, err := cmd.Flags().GetInt("port")
	if err != nil {
		return fmt.Errorf("read port flag: %w", err)
	}
	stdioFlag, err := cmd.Flags().GetBool("stdio")
	if err != nil {
		return fmt.Errorf("read stdio flag: %w", err)
	}
	bind, err := cmd.Flags().GetString("bind")
	if err != nil {
		return fmt.Errorf("read bind flag: %w", err)
	}
	tlsCertFlag, err := cmd.Flags().GetString("tls-cert")
	if err != nil {
		return fmt.Errorf("read tls-cert flag: %w", err)
	}
	tlsKeyFlag, err := cmd.Flags().GetString("tls-key")
	if err != nil {
		return fmt.Errorf("read tls-key flag: %w", err)
	}
	if bind == "" {
		return fmt.Errorf("--bind must not be empty; use '127.0.0.1' for localhost-only")
	}
	if !IsLocalhostBind(bind) {
		fmt.Fprintf(os.Stderr, "Warning: binding to %s without TLS — traffic will be unencrypted. Use --tls-cert/--tls-key for secure connections.\n", bind)
	}
	if stdioFlag && agentName == "" {
		return fmt.Errorf("--agent is required in --stdio mode")
	}
	vaultDir, err := cli.VaultPath()
	if err != nil {
		return err
	}
	if !vaultpkg.IsInitialized(vaultDir) {
		return errorspkg.NewCLIError(errorspkg.ExitNotInitialized, "vault not initialized. Run 'openpass init' first", errorspkg.ErrVaultNotInitialized)
	}
	var vault *vaultpkg.Vault
	if agentName != "" || !stdioFlag {
		if !cli.SessionIsExpired(vaultDir) {
			vault, err = ServeUnlockVault(vaultDir, false)
		}
		if vault == nil {
			vault, err = ServeUnlockVault(vaultDir, !stdioFlag)
		}
		if err != nil {
			return err
		}
	}
	// Apply CLI TLS flag overrides to the vault config so they take
	// precedence over config file values before the HTTP server starts.
	if vault != nil && vault.Config != nil {
		if vault.Config.MCP == nil {
			vault.Config.MCP = &config.MCPConfig{}
		}
		if tlsCertFlag != "" {
			vault.Config.MCP.TLSCertFile = tlsCertFlag
		}
		if tlsKeyFlag != "" {
			vault.Config.MCP.TLSKeyFile = tlsKeyFlag
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	ServeSignalNotify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig := <-sigCh
		if sig == syscall.SIGQUIT {
			fmt.Fprintln(os.Stderr, "Received SIGQUIT, shutting down gracefully...")
		}
		cancel()
	}()
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	if stdioFlag {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := RunStdioServerFunc(ctx, vault, agentName); err != nil {
				errCh <- fmt.Errorf("stdio server: %w", err)
			}
		}()
	}
	if !stdioFlag {
		actualPort, isPreferred, err := FindAvailablePortFunc(bind, port)
		if err != nil {
			return fmt.Errorf("port allocation failed: %w", err)
		}
		if !isPreferred {
			fmt.Fprintf(os.Stderr, "Port %d is in use, using port %d instead\n", port, actualPort)
		}
		if err := cli.SaveRuntimePort(vaultDir, actualPort); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not save runtime port: %v\n", err)
		}
		fmt.Fprintf(os.Stderr, "MCP server listening on %s:%d\n", bind, actualPort)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := RunHTTPServerFunc(ctx, bind, actualPort, vault); err != nil {
				errCh <- fmt.Errorf("http server: %w", err)
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		select {
		case err := <-errCh:
			return err
		default:
			return nil
		}
	case err := <-errCh:
		cancel()
		return err
	case <-ctx.Done():
		if vDir, err := cli.VaultPath(); err == nil {
			_ = cli.ClearRuntimePort(vDir)
		}
		return nil
	}
}
