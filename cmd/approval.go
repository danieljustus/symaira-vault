package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	mcpcmd "github.com/danieljustus/symaira-vault/cmd/mcp"
	"github.com/danieljustus/symaira-vault/internal/approval"
	cli "github.com/danieljustus/symaira-vault/internal/cli"
	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/mcp/serverbootstrap"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

type approvalListOutput struct {
	Requests []approval.Entry `json:"requests"`
}

type approvalOutcomeOutput struct {
	Outcome approval.Outcome `json:"outcome"`
}

func newApprovalCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "approval",
		Short: "List and decide pending agent approval requests",
		Long: `Inspect the pending approval queue owned by the running local server.

Decisions are sent to the server over its loopback-only, vault-directory
ownership-authenticated API. This command does not act as or create an
approval device and never displays secret values.`,
		Annotations: map[string]string{cli.JSONOutputAnnotation: "true"},
		GroupID:     cli.GroupIDAgentsMCP,
		Example: `  symvault approval list
  symvault approval list --json
  symvault approval decide apr-0123456789ab --approve`,
	}
	c.AddCommand(newApprovalListCmd(), newApprovalDecideCmd())
	return c
}

func newApprovalListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List pending approval requests",
		Example: "  symvault approval list --output json",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out approvalListOutput
			if err := approvalAPIRequest(http.MethodGet, approval.PathLocalApprovals, &out); err != nil {
				return err
			}
			if cli.OutputFormat == "json" || cli.OutputFormat == "yaml" {
				return cli.PrintResult(out)
			}
			if len(out.Requests) == 0 {
				printlnQuietAware("No pending approval requests.")
				return nil
			}
			printQuietAware("%-18s %-20s %-32s %-6s %-10s %s\n", "REQUEST ID", "AGENT", "PATH", "WRITE", "STATUS", "EXPIRES")
			for _, r := range out.Requests {
				printQuietAware("%-18s %-20s %-32s %-6t %-10s %s\n", r.ID, r.AgentName, r.Path, r.Write, r.Status, r.ExpiresAt.Format(time.RFC3339))
			}
			return nil
		},
	}
}

func newApprovalDecideCmd() *cobra.Command {
	var approve, deny bool
	c := &cobra.Command{
		Use:     "decide <request-id>",
		Short:   "Approve or deny a pending approval request",
		Example: "  symvault approval decide apr-0123456789ab --approve",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if approve == deny {
				return fmt.Errorf("exactly one of --approve or --deny is required")
			}
			action := "deny"
			if approve {
				action = "approve"
			}
			var out approvalOutcomeOutput
			if err := approvalAPIRequest(http.MethodPost, approval.PathLocalApprovalAction+args[0]+"/"+action, &out); err != nil {
				return err
			}
			if cli.OutputFormat == "json" || cli.OutputFormat == "yaml" {
				return cli.PrintResult(out)
			}
			printQuietAware("Approval request %q %s.\n", out.Outcome.ID, out.Outcome.Status)
			return nil
		},
	}
	c.Flags().BoolVar(&approve, "approve", false, "Approve the request")
	c.Flags().BoolVar(&deny, "deny", false, "Deny the request")
	return c
}

func approvalAPIRequest(method, path string, result any) error {
	vaultDir, err := cli.VaultPath()
	if err != nil {
		return err
	}
	if !vaultpkg.IsInitialized(vaultDir) {
		return errorspkg.NewVaultNotInitialized()
	}
	port, bind, ok := cli.LoadRuntimeServer(vaultDir)
	if !ok {
		return fmt.Errorf("could not find the running server — is 'symvault serve' running?")
	}
	if bind == "" {
		bind = "127.0.0.1"
	}
	if !mcpcmd.IsLocalhostBind(bind) {
		return fmt.Errorf("approval CLI requires a server bound to loopback; running server is bound to %q", bind)
	}
	runtimeTLS, runtimeOK := cli.LoadRuntimeTLSConfig(vaultDir)
	certFile, clientCAFile, clientCertFile, clientKeyFile := "", "", "", ""
	clientAuthRequired := false
	if runtimeOK {
		certFile = runtimeTLS.Certificate
		clientCAFile = runtimeTLS.ClientCAFile
		clientCertFile = runtimeTLS.ClientCertificate
		clientKeyFile = runtimeTLS.ClientKey
		clientAuthRequired = runtimeTLS.ClientAuthRequired
	} else if cfg, loadErr := configpkg.Load(filepath.Join(vaultDir, "config.yaml")); loadErr == nil && cfg != nil && cfg.MCP != nil {
		certFile = strings.TrimSpace(cfg.MCP.TLSCertFile)
		clientCAFile = strings.TrimSpace(cfg.MCP.TLSClientCAFile)
		clientCertFile = strings.TrimSpace(cfg.MCP.ApprovalTLSCertFile)
		clientKeyFile = strings.TrimSpace(cfg.MCP.ApprovalTLSKeyFile)
		clientAuthRequired = cfg.MCP.MTLSEnabled
	}
	if certFile == "" {
		certFile, _, err = serverbootstrap.EnsureTLSCert(vaultDir)
		if err != nil {
			return fmt.Errorf("load server TLS certificate: %w", err)
		}
	}
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("read server TLS certificate")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return fmt.Errorf("parse server TLS certificate")
	}
	secret, err := serverbootstrap.EnsureEnrollSecret(vaultDir)
	if err != nil {
		return fmt.Errorf("load vault-ownership proof secret: %w", err)
	}
	now := time.Now().UTC()
	req, err := http.NewRequest(method, fmt.Sprintf("https://%s%s", net.JoinHostPort(bind, fmt.Sprint(port)), path), nil)
	if err != nil {
		return fmt.Errorf("build approval request: %w", err)
	}
	req.Header.Set(approval.HeaderEnrollTimestamp, now.Format(time.RFC3339))
	req.Header.Set(approval.HeaderEnrollProof, approval.EnrollProof(secret, now))
	tlsConfig := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if clientAuthRequired {
		if clientCertFile == "" || clientKeyFile == "" || clientCAFile == "" {
			return fmt.Errorf("approval CLI cannot connect while the running MCP server requires mTLS because the dedicated local approval client certificate, key, and CA must both be configured")
		}
		if identityErr := validateApprovalClientIdentity(pemBytes, clientCertFile, clientCAFile); identityErr != nil {
			return identityErr
		}
		clientCert, loadErr := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if loadErr != nil {
			return fmt.Errorf("load local approval client identity failed")
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connect to local approval server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if strings.TrimSpace(apiErr.Error) != "" {
			return fmt.Errorf("approval server: %s", apiErr.Error)
		}
		return fmt.Errorf("approval server returned HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
		return fmt.Errorf("decode approval response: %w", err)
	}
	return nil
}

// approvalTLSCertFile returns the certificate used by the running HTTP server.
func approvalTLSCertFile(vaultDir string) (string, error) {
	if cert, ok := cli.LoadRuntimeTLSCert(vaultDir); ok {
		return cert, nil
	}
	cfg, err := configpkg.Load(filepath.Join(vaultDir, "config.yaml"))
	if err == nil && cfg != nil && cfg.MCP != nil && strings.TrimSpace(cfg.MCP.TLSCertFile) != "" && strings.TrimSpace(cfg.MCP.TLSKeyFile) != "" {
		return strings.TrimSpace(cfg.MCP.TLSCertFile), nil
	}
	cert, _, ensureErr := serverbootstrap.EnsureTLSCert(vaultDir)
	if ensureErr != nil {
		return "", ensureErr
	}
	return cert, nil
}

// validateApprovalClientIdentity checks the certificate identity without ever reading the server private key.
func validateApprovalClientIdentity(serverPEM []byte, clientCertFile, caFile string) error {
	serverBlock, _ := pem.Decode(serverPEM)
	if serverBlock == nil {
		return fmt.Errorf("parse server TLS certificate")
	}
	serverCert, err := x509.ParseCertificate(serverBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse server TLS certificate")
	}
	clientPEM, err := os.ReadFile(clientCertFile) // #nosec G304 -- path is the locally configured approval client certificate.
	if err != nil {
		return fmt.Errorf("read local approval client identity")
	}
	clientBlock, _ := pem.Decode(clientPEM)
	if clientBlock == nil {
		return fmt.Errorf("parse local approval client identity")
	}
	clientLeaf, err := x509.ParseCertificate(clientBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse local approval client identity")
	}
	serverKey, err := x509.MarshalPKIXPublicKey(serverCert.PublicKey)
	if err != nil {
		return fmt.Errorf("inspect server TLS certificate")
	}
	clientKey, err := x509.MarshalPKIXPublicKey(clientLeaf.PublicKey)
	if err != nil {
		return fmt.Errorf("inspect local approval client identity")
	}
	if string(serverKey) == string(clientKey) {
		return fmt.Errorf("approval CLI refuses to reuse the MCP server certificate identity as the approval client identity")
	}
	caPEM, err := os.ReadFile(caFile) // #nosec G304 -- path is the locally configured approval client CA.
	if err != nil {
		return fmt.Errorf("read approval client CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("parse approval client CA")
	}
	intermediates := x509.NewCertPool()
	for rest := clientPEM; ; {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		cert, e := x509.ParseCertificate(block.Bytes)
		if e == nil && cert.SerialNumber.Cmp(clientLeaf.SerialNumber) != 0 {
			intermediates.AddCert(cert)
		}
	}
	if _, err := clientLeaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("verify local approval client identity")
	}
	return nil
}
