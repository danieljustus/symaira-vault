package cmd

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	brokerpkg "github.com/danieljustus/symaira-vault/internal/broker"
	cli "github.com/danieljustus/symaira-vault/internal/cli"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var (
	brokerAddr        string
	brokerStrict      bool
	brokerPassthrough []string
)

// BrokerSignalNotify is a seam for tests; production uses signal.Notify.
var BrokerSignalNotify = signal.Notify

func newBrokerCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "broker",
		Short: "Run the egress credential broker (loopback MITM proxy)",
		Long: `Run an opt-in loopback MITM forward proxy that attaches vault
credentials to the agent's outbound HTTPS/HTTP requests server-side.

A brokered secret never enters the agent's process environment, argv or
process listing: the child process only receives HTTPS_PROXY/HTTP_PROXY and
the path to the broker's CA certificate. Hosts covered by an API template
get credential injection; unmatched hosts are forwarded untouched (or
rejected with 403 in --strict mode). Hosts in --passthrough are tunneled
without TLS interception (escape hatch for certificate-pinning clients).

Same-machine limitation: on one host this removes the plaintext from the
child environment, but an agent with the user's own filesystem access can
still reach the vault. Deploy the broker on a separate host (or the agent
in a container) for the strong guarantee.

The broker exits on SIGINT/SIGTERM. The generated CA certificate is written
to <vault>/broker-ca.pem.`,
		Example: `  # Start the broker on an ephemeral loopback port
  symvault broker

  # Fixed port, strict mode (unmatched hosts get 403)
  symvault broker --addr 127.0.0.1:8080 --strict

  # Pass through hosts whose clients pin certificates
  symvault broker --passthrough corporate.internal,legacy.example.com

  # Use with a child process (env exports are printed at startup)
  symvault run --broker -- gh pr create`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.WithVault(func(v *vaultpkg.Vault, vs *cli.VaultService) error {
				proxy, err := brokerpkg.New(brokerpkg.Config{
					VaultDir:    v.Dir,
					Identity:    v.Identity,
					AgentName:   "broker",
					Strict:      brokerStrict,
					Passthrough: brokerPassthrough,
				})
				if err != nil {
					return fmt.Errorf("start broker: %w", err)
				}

				caPath := filepath.Join(v.Dir, "broker-ca.pem")
				if writeErr := os.WriteFile(caPath, proxy.CA().CertPEM(), 0o600); writeErr != nil {
					return fmt.Errorf("write CA certificate: %w", writeErr)
				}

				ln, err := net.Listen("tcp", brokerAddr)
				if err != nil {
					return fmt.Errorf("listen on %s: %w", brokerAddr, err)
				}
				proxyURL := "http://" + ln.Addr().String()

				fmt.Printf("Symaira Vault egress broker listening on %s\n", proxyURL)
				fmt.Printf("CA certificate written to %s\n", caPath)
				fmt.Println("Export the following in the agent's environment:")
				fmt.Printf("  HTTPS_PROXY=%s\n", proxyURL)
				fmt.Printf("  HTTP_PROXY=%s\n", proxyURL)
				fmt.Printf("  SSL_CERT_FILE=%s\n", caPath)
				fmt.Printf("  NODE_EXTRA_CA_CERTS=%s\n", caPath)
				fmt.Printf("  REQUESTS_CA_BUNDLE=%s\n", caPath)
				fmt.Println("  NO_PROXY=127.0.0.1,localhost")
				if brokerStrict {
					fmt.Println("Strict mode: requests to hosts without a template are rejected with 403.")
				}
				if len(brokerPassthrough) > 0 {
					fmt.Printf("Passthrough hosts (no TLS interception): %v\n", brokerPassthrough)
				}

				srv := &http.Server{
					Handler:           proxy.Handler(),
					ReadHeaderTimeout: 30 * time.Second,
					ReadTimeout:       60 * time.Second,
					WriteTimeout:      60 * time.Second,
					IdleTimeout:       30 * time.Second,
				}
				errCh := make(chan error, 1)
				go func() { errCh <- srv.Serve(ln) }()

				sigCh := make(chan os.Signal, 1)
				BrokerSignalNotify(sigCh, os.Interrupt, syscall.SIGTERM)
				select {
				case <-sigCh:
					_ = srv.Close()
					return nil
				case err := <-errCh:
					return err
				}
			})
		},
	}
	c.Flags().StringVar(&brokerAddr, "addr", "127.0.0.1:0", "Loopback listen address (0 selects an ephemeral port)")
	c.Flags().BoolVar(&brokerStrict, "strict", false, "Reject requests to hosts without a matching template with 403")
	c.Flags().StringSliceVar(&brokerPassthrough, "passthrough", nil, "Hosts tunneled without TLS interception (comma-separated, domain suffixes match)")
	c.GroupID = cli.GroupIDVault
	return c
}

// brokerEnvForRun starts an ephemeral broker for `run --broker` and returns
// the environment variables the child process needs plus a cleanup function.
// strict and passthrough mirror the standalone broker command's --strict and
// --passthrough flags (run exposes them as --broker-strict and
// --broker-passthrough because --passthrough already means parent-env
// passthrough there).
func brokerEnvForRun(v *vaultpkg.Vault, strict bool, passthrough []string) (map[string]string, func(), error) {
	proxy, err := brokerpkg.New(brokerpkg.Config{
		VaultDir:    v.Dir,
		Identity:    v.Identity,
		AgentName:   "broker",
		Strict:      strict,
		Passthrough: passthrough,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("start broker: %w", err)
	}
	caPath := filepath.Join(v.Dir, "broker-ca.pem")
	if writeErr := os.WriteFile(caPath, proxy.CA().CertPEM(), 0o600); writeErr != nil {
		return nil, nil, fmt.Errorf("write CA certificate: %w", writeErr)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("listen: %w", err)
	}
	proxyURL := "http://" + ln.Addr().String()
	srv := &http.Server{
		Handler:           proxy.Handler(),
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()

	env := map[string]string{
		"HTTPS_PROXY":         proxyURL,
		"HTTP_PROXY":          proxyURL,
		"SSL_CERT_FILE":       caPath,
		"NODE_EXTRA_CA_CERTS": caPath,
		"REQUESTS_CA_BUNDLE":  caPath,
		"NO_PROXY":            "127.0.0.1,localhost",
	}
	return env, func() {
		_ = srv.Close()
		// srv.Close only closes the listener once the Serve goroutine hands it
		// back; closing it explicitly removes the window where a connection
		// that completed its TCP handshake in the accept backlog is still
		// delivered to a listener that tests expect to be gone.
		_ = ln.Close()
	}, nil
}
