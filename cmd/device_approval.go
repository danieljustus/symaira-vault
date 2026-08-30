package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/danieljustus/symaira-vault/internal/approval"
	cli "github.com/danieljustus/symaira-vault/internal/cli"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	mcputil "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/mcp/serverbootstrap"
	"github.com/danieljustus/symaira-vault/internal/pairing"
	"github.com/danieljustus/symaira-vault/internal/ui"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var approvalPairHost string

// approvalPairingPayload is the JSON scanned/pasted by the iOS app to pair
// as an approval device. It carries the entire trust story for the
// connection: host/port to reach the server, the one-time code to redeem,
// and the SHA-256 fingerprint the phone pins its TLS connection to.
type approvalPairingPayload struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Code        string `json:"code"`
	Fingerprint string `json:"fingerprint"`
}

func newDeviceApprovalPairCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "approval-pair",
		Short: "Pair a phone as an approval device for agent credential requests",
		Long: `Generate a QR code a phone can scan to become an approval device: a
device that can approve or deny agent write requests when approval mode is
"prompt". This is unrelated to 'symvault device pair', which pairs a
second computer for vault-content sync and re-encrypts every entry —
approval-pair only grants the ability to approve/deny agent requests and
never touches vault encryption or entry content.

Requires 'symvault serve' to already be running with TLS (the default),
since the phone pins its connection to the server's certificate
fingerprint rather than trusting a certificate authority.`,
		Example: `  symvault device approval-pair
  symvault device approval-pair --host 192.168.1.42`,
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultDir, err := cli.VaultPath()
			if err != nil {
				return err
			}
			if !vaultpkg.IsInitialized(vaultDir) {
				return errorspkg.NewVaultNotInitialized()
			}

			port, ok := cli.LoadRuntimePort(vaultDir)
			if !ok {
				return fmt.Errorf("could not find the running server's port — is 'symvault serve' running?")
			}

			host := strings.TrimSpace(approvalPairHost)
			if host == "" {
				candidates, detectErr := mcputil.DetectLANIPv4()
				if detectErr != nil || len(candidates) == 0 {
					return fmt.Errorf("could not auto-detect a LAN address; pass --host <ip> explicitly")
				}
				if len(candidates) > 1 {
					var b strings.Builder
					b.WriteString("multiple network addresses found; pass --host to pick one:\n")
					for _, ip := range candidates {
						fmt.Fprintf(&b, "  %s\n", ip)
					}
					return fmt.Errorf("%s", b.String())
				}
				host = candidates[0].String()
			}

			code, expiresAt, fingerprint, err := mintApprovalEnrollCode(vaultDir, port)
			if err != nil {
				return fmt.Errorf("mint pairing code: %w", err)
			}

			payload := approvalPairingPayload{Host: host, Port: port, Code: code, Fingerprint: fingerprint}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				return fmt.Errorf("marshal pairing payload: %w", err)
			}

			qrArt, qrErr := ui.RenderQRCodeForWidth(string(payloadJSON), cliout.TermWidth())

			printQuietAware("\n=== Approval Device Pairing ===\n\n")
			if qrErr != nil {
				printQuietAware("(QR code not shown: %v)\n\n", qrErr)
			} else {
				printQuietAware("%s\n", qrArt)
			}
			printQuietAware("Scan this with the Symaira Vault iOS app, or enter it manually:\n\n")
			printQuietAware("  Host:        %s\n", host)
			printQuietAware("  Port:        %d\n", port)
			printQuietAware("  Code:        %s\n", code)
			printQuietAware("  Fingerprint: %s\n", fingerprint)
			printQuietAware("\nExpires: %s\n", expiresAt.Format(time.RFC3339))
			return nil
		},
	}
	c.Flags().StringVar(&approvalPairHost, "host", "", "LAN address the phone should connect to (auto-detected when omitted)")
	return c
}

// mintApprovalEnrollCode asks the already-running "symvault serve" process,
// over its localhost-only enroll-code endpoint, to mint a short-lived
// pairing code. It trusts exactly the certificate cached in vaultDir (the
// same one the server presents), not the system trust store — this is a
// same-machine call to the server's own loopback address, not the LAN path
// a phone would take.
func mintApprovalEnrollCode(vaultDir string, port int) (code string, expiresAt time.Time, fingerprint string, err error) {
	certFile, _, err := serverbootstrap.EnsureTLSCert(vaultDir)
	if err != nil {
		return "", time.Time{}, "", fmt.Errorf("ensure TLS certificate: %w", err)
	}
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		return "", time.Time{}, "", fmt.Errorf("read TLS certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return "", time.Time{}, "", fmt.Errorf("parse TLS certificate")
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}

	url := fmt.Sprintf("https://127.0.0.1:%d%s", port, approval.PathDeviceEnrollCode)
	resp, err := client.Post(url, "application/json", bytes.NewReader(nil))
	if err != nil {
		return "", time.Time{}, "", fmt.Errorf("call %s (is 'symvault serve' running with TLS?): %w", approval.PathDeviceEnrollCode, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if apiErr.Error != "" {
			return "", time.Time{}, "", fmt.Errorf("%s", apiErr.Error)
		}
		return "", time.Time{}, "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var out struct {
		Code        string    `json:"code"`
		ExpiresAt   time.Time `json:"expires_at"`
		Fingerprint string    `json:"fingerprint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", time.Time{}, "", fmt.Errorf("decode response: %w", err)
	}
	return out.Code, out.ExpiresAt, out.Fingerprint, nil
}

func newDeviceApprovalListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "approval-list",
		Short: "List devices enrolled as approval devices",
		Long: `List devices that can approve or deny agent credential requests
(enrolled via 'symvault device approval-pair'). This is a different device
registry from 'symvault device list', which shows vault-content sync
devices — an approval device cannot decrypt vault entries, it can only
approve or deny agent requests.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultDir, err := cli.VaultPath()
			if err != nil {
				return err
			}
			store, err := pairing.NewDeviceSessionStore(vaultDir)
			if err != nil {
				return fmt.Errorf("load approval device store: %w", err)
			}
			sessions := store.List()
			if len(sessions) == 0 {
				printQuietAware("No approval devices enrolled.\n")
				return nil
			}
			printQuietAware("%-24s %-24s %-20s %-20s %s\n", "DEVICE ID", "NAME", "ENROLLED", "EXPIRES", "STATUS")
			for _, s := range sessions {
				status := "active"
				switch {
				case s.Revoked:
					status = "revoked"
				case time.Now().After(s.ExpiresAt):
					status = "expired"
				}
				name := s.Name
				if name == "" {
					name = "(unnamed)"
				}
				printQuietAware("%-24s %-24s %-20s %-20s %s\n",
					s.DeviceID, name, s.CreatedAt.Format("2006-01-02 15:04"), s.ExpiresAt.Format("2006-01-02 15:04"), status)
			}
			return nil
		},
	}
}

func newDeviceApprovalRevokeCmd() *cobra.Command {
	var yes bool
	c := &cobra.Command{
		Use:   "approval-revoke <device-id>",
		Short: "Revoke an approval device's ability to approve/deny requests",
		Long: `Revoke a device enrolled via 'symvault device approval-pair', so it can
no longer approve or deny agent credential requests. This does NOT
re-encrypt or otherwise affect vault entries — it only invalidates that
device's approval-decision bearer token. For revoking a vault-content sync
device instead, use 'symvault device revoke <name>' (a different, more
destructive command that re-encrypts every entry).`,
		Example: `  symvault device approval-list
  symvault device approval-revoke dev-abc123`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceID := args[0]
			vaultDir, err := cli.VaultPath()
			if err != nil {
				return err
			}
			store, err := pairing.NewDeviceSessionStore(vaultDir)
			if err != nil {
				return fmt.Errorf("load approval device store: %w", err)
			}

			found := false
			for _, s := range store.List() {
				if s.DeviceID == deviceID {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("approval device %q not found", deviceID)
			}

			if !yes {
				fmt.Fprintf(os.Stderr, "This will revoke approval device %q. Continue? [y/N]: ", deviceID)
				var answer string
				_, _ = fmt.Fscanln(os.Stdin, &answer)
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					fmt.Fprintln(os.Stderr, "Canceled")
					return nil
				}
			}

			store.Revoke(deviceID)
			if err := store.Save(); err != nil {
				return fmt.Errorf("save approval device store: %w", err)
			}
			printQuietAware("Approval device %q revoked.\n", deviceID)
			return nil
		},
	}
	c.Flags().BoolVarP(&yes, "yes", "y", false, "Skip confirmation prompt")
	return c
}
