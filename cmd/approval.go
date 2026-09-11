package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	mcpcmd "github.com/danieljustus/symaira-vault/cmd/mcp"
	"github.com/danieljustus/symaira-vault/internal/approval"
	cli "github.com/danieljustus/symaira-vault/internal/cli"
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
	certFile, _, err := serverbootstrap.EnsureTLSCert(vaultDir)
	if err != nil {
		return fmt.Errorf("load server TLS certificate: %w", err)
	}
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("read server TLS certificate: %w", err)
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
	req, err := http.NewRequest(method, fmt.Sprintf("https://%s:%d%s", bind, port, path), nil)
	if err != nil {
		return fmt.Errorf("build approval request: %w", err)
	}
	req.Header.Set(approval.HeaderEnrollTimestamp, now.Format(time.RFC3339))
	req.Header.Set(approval.HeaderEnrollProof, approval.EnrollProof(secret, now))
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connect to local approval server: %w", err)
	}
	defer resp.Body.Close()
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
