package serverbootstrap

import (
	"context"
	"fmt"
	"time"

	server "github.com/danieljustus/OpenPass/internal/mcp/server"
	trans "github.com/danieljustus/OpenPass/internal/mcp/transport"
	"github.com/danieljustus/OpenPass/internal/metrics"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

// RunStdioServer starts the stdio MCP server.
func RunStdioServer(ctx context.Context, vault *vaultpkg.Vault, agentName string, factory func(*vaultpkg.Vault, string, string) (*server.Server, error)) error {
	var mcpServer *server.Server
	if vault != nil && agentName != "" {
		var err error
		mcpServer, err = factory(vault, agentName, "stdio")
		if err != nil {
			return fmt.Errorf("failed to create MCP server: %w", err)
		}
		defer func() { _ = mcpServer.Close() }()
	}

	otlpEndpoint := ""
	if vault != nil && vault.Config != nil && vault.Config.MCP != nil {
		otlpEndpoint = vault.Config.MCP.OTLPEndpoint
	}
	shutdownTracing, err := metrics.InitTracing(otlpEndpoint, "")
	if err != nil {
		return fmt.Errorf("init tracing: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = shutdownTracing(shutdownCtx)
		cancel()
	}()

	st := trans.NewStdioTransport()
	handler := server.NewProtocolHandler("openpass", "1.0.0", mcpServer)

	errCh := make(chan error, 1)
	go func() {
		errCh <- st.Start(ctx, handler.HandleMessage)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		select {
		case err := <-errCh:
			return err
		case <-time.After(2 * time.Second):
			return fmt.Errorf("stdio server shutdown timeout")
		}
	}
}
