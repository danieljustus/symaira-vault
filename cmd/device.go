package cmd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	configpkg "github.com/danieljustus/OpenPass/internal/config"
	cryptopkg "github.com/danieljustus/OpenPass/internal/crypto"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
	"github.com/danieljustus/OpenPass/internal/git"
	"github.com/danieljustus/OpenPass/internal/pairing"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

var (
	defaultDeviceName string
	deviceRevokeYes   bool
)

var deviceCmd = &cobra.Command{
	Use:   "device",
	Short: "Manage paired devices for multi-device vault access",
	Long: `Manage paired devices that can access this vault.

Use 'openpass device pair' to generate a pairing token for a new device,
and 'openpass device join' on the new device to join the vault.`,
	Example: `  openpass device pair
  openpass device join ssh://user@host/path/to/vault.git <token>
  openpass device accept <token>`,
}

var devicePairCmd = &cobra.Command{
	Use:   "pair",
	Short: "Generate a pairing token for a new device",
	Long: `Generate a pairing token that another device can use to join this vault.

This saves the pairing token and this device's public key to the vault,
commits and pushes the token file. The joining device reads this file
to obtain this device's public key for encryption.

IMPORTANT: After the joining device submits its public key (via 'openpass device join'),
you must run 'openpass device accept <token>' to re-encrypt all entries
for the new device.`,
	Example: `  openpass device pair`,
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir, err := vaultPath()
		if err != nil {
			return err
		}

		v, err := unlockVault(vaultDir, true)
		if err != nil {
			return err
		}

		token, err := pairing.GenerateToken()
		if err != nil {
			return fmt.Errorf("generate token: %w", err)
		}

		publicKey := v.Identity.Recipient().String()

		pairingData := pairingFile{
			Token:     string(token),
			PublicKey: publicKey,
			CreatedAt: time.Now().UTC(),
		}

		if err := savePairingFile(vaultDir, string(token)+".json", pairingData); err != nil {
			return fmt.Errorf("save pairing file: %w", err)
		}

		if err := git.AutoCommitAndPush(vaultDir, fmt.Sprintf("Pairing token %s", token), v.Config.Git.AutoPush); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not auto-commit/push: %v\n", err)
		}

		printQuietAware("\n=== Pairing Token ===\n")
		printQuietAware("Token: %s\n\n", token)
		printQuietAware("This device's public key: %s\n", publicKey)
		printQuietAware("\nOn the joining device, run:\n")
		printQuietAware("  openpass device join <remote-url> %s\n\n", token)
		printQuietAware("After the joining device has submitted its key, run:\n")
		printQuietAware("  openpass device accept %s\n\n", token)

		return nil
	},
}

var deviceJoinCmd = &cobra.Command{
	Use:   "join <remote-url> <token>",
	Short: "Join an existing vault as a new device",
	Long: `Join an existing vault from a remote git repository.

Clones the vault repository, reads the pairing token file to obtain
the existing device's public key, generates a new identity for this device,
and submits this device's public key back to the vault.

After completion, the existing device must run 'openpass device accept <token>'
to re-encrypt all entries for this new device.`,
	Example: `  openpass device join ssh://user@host/path/to/vault.git 123456`,
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		remoteURL := args[0]
		token := strings.TrimSpace(args[1])

		vaultDir, err := vaultPath()
		if err != nil {
			return err
		}

		if vaultpkg.IsInitialized(vaultDir) {
			return fmt.Errorf("vault already initialized at %s. Use a different --vault or remove the existing vault first", vaultDir)
		}

		fmt.Fprintf(os.Stderr, "Cloning vault from %s ...\n", remoteURL)
		if _, err = gogit.PlainClone(vaultDir, false, &gogit.CloneOptions{
			URL:      remoteURL,
			Progress: os.Stderr,
		}); err != nil {
			return fmt.Errorf("clone vault: %w", err)
		}

		pairingPath := filepath.Join(vaultDir, ".openpass", "pairing", token+".json")
		var pf pairingFile
		// #nosec G304 -- pairingPath is constructed within the vault directory
		pfData, err := os.ReadFile(pairingPath)
		if err != nil {
			return fmt.Errorf("invalid or expired pairing token: could not read pairing file. Ensure the token is correct and the pairing device has pushed the token file: %w", err)
		}
		if err = json.Unmarshal(pfData, &pf); err != nil {
			return fmt.Errorf("invalid pairing file: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Pairing with device (public key: %s)\n", truncatePubkey(pf.PublicKey))

		passphrase, err := readHiddenInput("Enter passphrase for this device: ", nil)
		if err != nil {
			return fmt.Errorf("read passphrase: %w", err)
		}
		defer cryptopkg.Wipe(passphrase)
		if len(passphrase) < 12 {
			return fmt.Errorf("passphrase must be at least 12 characters")
		}

		identity, err := cryptopkg.GenerateIdentity()
		if err != nil {
			return fmt.Errorf("generate identity: %w", err)
		}
		myPubkey := identity.Recipient().String()

		cfg := configpkg.Default()
		cfg.VaultDir = vaultDir
		cfg.Git = &configpkg.GitConfig{
			AutoPush:         true,
			AutoPull:         true,
			AutoPullInterval: 10 * time.Second,
			CommitTemplate:   "Update from OpenPass",
		}

		cfgPath := filepath.Join(vaultDir, "config.yaml")
		cfgData, err := yaml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("marshal config: %w", err)
		}
		if err := os.WriteFile(cfgPath, cfgData, 0o600); err != nil {
			return fmt.Errorf("write config: %w", err)
		}

		identityPath := filepath.Join(vaultDir, "identity.age")
		if err := cryptopkg.SaveIdentity(identity, identityPath, passphrase, 0); err != nil {
			return fmt.Errorf("save identity: %w", err)
		}

		recipientsPath := filepath.Join(vaultDir, "recipients.txt")
		recipientsContent := fmt.Sprintf("# OpenPass vault recipients\n# Added by device join\n%s\n", pf.PublicKey)
		if err := os.WriteFile(recipientsPath, []byte(recipientsContent), 0o600); err != nil {
			return fmt.Errorf("write recipients: %w", err)
		}

		joinedData := joinedFile{
			Token:     token,
			Name:      defaultDeviceName,
			PublicKey: myPubkey,
			CreatedAt: time.Now().UTC(),
		}
		if defaultDeviceName == "" {
			hostname, _ := os.Hostname()
			if hostname != "" {
				joinedData.Name = hostname
			} else {
				joinedData.Name = "device-" + token
			}
		}

		if err := savePairingFile(vaultDir, token+"-joined.json", joinedData); err != nil {
			return fmt.Errorf("save joined file: %w", err)
		}

		cleanupPairingFile := filepath.Join(vaultDir, ".openpass", "pairing", token+".json")
		_ = os.Remove(cleanupPairingFile)

		if err := git.AutoCommitWithOptions(vaultDir, git.CommitOptions{
			Message: fmt.Sprintf("Device join: %s (token %s)", joinedData.Name, token),
		}); err != nil {
			return fmt.Errorf("commit: %w", err)
		}

		fmt.Fprintf(os.Stderr, "\n=== Join Successful ===\n")
		printQuietAware("\nYour public key: %s\n", myPubkey)
		printQuietAware("Device name: %s\n\n", joinedData.Name)
		printQuietAware("IMPORTANT: Entries cannot be decrypted yet.\n")
		printQuietAware("On the existing device, run:\n")
		printQuietAware("  openpass device accept %s\n\n", token)

		if err := git.Push(vaultDir); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not push joined file: %v\n", err)
			fmt.Fprintf(os.Stderr, "Push manually with: openpass git push\n")
		}

		return nil
	},
}

var deviceAcceptCmd = &cobra.Command{
	Use:   "accept <token>",
	Short: "Accept a join request and re-encrypt entries for the new device",
	Long: `Accept a device join request by adding the new device's public key
as a recipient and re-encrypting all vault entries so the new device
can decrypt them.`,
	Example: `  openpass device accept 123456`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		token := strings.TrimSpace(args[0])

		vaultDir, err := vaultPath()
		if err != nil {
			return err
		}

		v, err := unlockVault(vaultDir, true)
		if err != nil {
			return err
		}

		joinedPath := filepath.Join(vaultDir, ".openpass", "pairing", token+"-joined.json")
		var jf joinedFile
		// #nosec G304 -- joinedPath is constructed within the vault directory
		jfData, err := os.ReadFile(joinedPath)
		if err != nil {
			return fmt.Errorf("no join request found for token %s. Ensure the joining device has completed 'openpass device join' and pushed: %w", token, err)
		}
		if err = json.Unmarshal(jfData, &jf); err != nil {
			return fmt.Errorf("parse joined file: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Accepting join from device: %s (public key: %s)\n", jf.Name, truncatePubkey(jf.PublicKey))

		rm := vaultpkg.NewRecipientsManager(vaultDir)
		if err = rm.AddRecipient(jf.PublicKey); err != nil {
			return fmt.Errorf("add recipient: %w", err)
		}

		allRecipients, err := v.GetAllRecipientsForEncryption()
		if err != nil {
			return fmt.Errorf("get recipients: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Re-encrypting all entries for %d recipient(s)...\n", len(allRecipients))
		if err := vaultpkg.ReencryptAll(vaultDir, v.Identity, allRecipients); err != nil {
			return fmt.Errorf("re-encrypt: %w", err)
		}

		_ = os.Remove(joinedPath)

		if err := git.AutoCommitAndPush(vaultDir, fmt.Sprintf("Accept device join: %s", jf.Name), v.Config.Git.AutoPush); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not auto-commit/push: %v\n", err)
		}

		printQuietAware("\n=== Pairing Complete ===\n")
		printQuietAware("Device %q can now access all vault entries.\n\n", jf.Name)
		printQuietAware("On the joining device, run 'openpass git pull' to fetch the re-encrypted entries.\n")

		return nil
	},
}

var deviceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all devices",
	Long: `List all devices registered in the vault's device registry.

Shows device name, public key (truncated), added date, and last seen time.
Also shows recipients from recipients.txt that are not associated with
any registered device (unmanaged recipients).`,
	Example: `  openpass device list
  openpass device list --output json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultDir, err := vaultPath()
		if err != nil {
			return err
		}

		dm := vaultpkg.NewDeviceManager(vaultDir)
		devices, err := dm.ListDevices()
		if err != nil {
			return fmt.Errorf("list devices: %w", err)
		}

		rm := vaultpkg.NewRecipientsManager(vaultDir)
		recipientStrs, err := rm.LoadRecipientStrings()
		if err != nil {
			recipientStrs = nil
		}

		deviceKeys := make(map[string]bool, len(devices))
		for _, d := range devices {
			deviceKeys[d.PublicKey] = true
		}

		var unmanaged []string
		for _, r := range recipientStrs {
			if !deviceKeys[r] {
				unmanaged = append(unmanaged, r)
			}
		}

		if outputFormat == "json" || outputFormat == "yaml" {
			type deviceOutput struct {
				Name      string `json:"name" yaml:"name"`
				PublicKey string `json:"public_key" yaml:"public_key"`
				AddedAt   string `json:"added_at" yaml:"added_at"`
				LastSeen  string `json:"last_seen,omitempty" yaml:"last_seen,omitempty"`
			}
			devOutput := make([]deviceOutput, 0, len(devices))
			for _, d := range devices {
				do := deviceOutput{
					Name:      d.Name,
					PublicKey: d.PublicKey,
					AddedAt:   d.AddedAt.Format(time.RFC3339),
				}
				if d.LastSeen != nil {
					do.LastSeen = d.LastSeen.Format(time.RFC3339)
				}
				devOutput = append(devOutput, do)
			}
			output := map[string]interface{}{
				"devices": devOutput,
				"count":   len(devices),
			}
			if len(unmanaged) > 0 {
				output["unmanaged_recipients"] = unmanaged
			}
			return PrintResult(output)
		}

		// Text output
		if len(devices) == 0 {
			printlnQuietAware("No devices registered.")
			if len(unmanaged) > 0 {
				printlnQuietAware("\nUnmanaged recipients in recipients.txt:")
				for _, r := range unmanaged {
					printlnQuietAware("  " + truncatePubkey(r))
				}
			}
			return nil
		}

		printQuietAware("Devices (%d):\n\n", len(devices))
		for _, d := range devices {
			lastSeenStr := "never"
			if d.LastSeen != nil {
				lastSeenStr = d.LastSeen.Format(time.RFC3339)
			}
			printQuietAware("  %s\n", d.Name)
			printQuietAware("    Public Key: %s\n", truncatePubkey(d.PublicKey))
			printQuietAware("    Added:      %s\n", d.AddedAt.Format(time.RFC3339))
			printQuietAware("    Last Seen:  %s\n\n", lastSeenStr)
		}

		if len(unmanaged) > 0 {
			printlnQuietAware("Unmanaged recipients in recipients.txt:")
			for _, r := range unmanaged {
				printlnQuietAware("  " + truncatePubkey(r))
			}
			printlnQuietAware("")
		}

		return nil
	},
}

var (
	deviceAddPair bool
	deviceAddName string
)

var deviceAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add this device to an existing multi-device vault",
	Long: `Add this device to an existing multi-device vault using a pairing
token and public key obtained via QR code from the original device.

This command is used on the second device after the initial setup wizard
shows a QR code. It creates a new local vault with its own identity,
adds the first device's public key as a recipient, and saves a pairing
request so the first device can accept it.`,
	Example: `  openpass device add --pair "123456:age1..."`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !deviceAddPair {
			return fmt.Errorf("use 'openpass device add --pair <token:publickey>' to pair a device")
		}
		if len(args) < 1 {
			return fmt.Errorf("missing pairing data. Usage: openpass device add --pair <token> or <token:publickey>")
		}

		raw := strings.TrimSpace(args[0])

		vaultDir, err := vaultPath()
		if err != nil {
			return err
		}

		if vaultpkg.IsInitialized(vaultDir) {
			return fmt.Errorf("vault already initialized at %s. Use a different --vault or remove the existing vault first", vaultDir)
		}

		// Parse QR data: token or token:publicKey
		var token, existingPubkey string
		if idx := strings.Index(raw, ":"); idx > 0 {
			token = raw[:idx]
			existingPubkey = raw[idx+1:]
		} else {
			token = raw
		}

		if !strings.HasPrefix(existingPubkey, "age1") || len(existingPubkey) < 50 {
			return fmt.Errorf("invalid public key in pairing data: expected age1... format")
		}

		passphrase, err := readHiddenInput("Enter passphrase for this device: ", nil)
		if err != nil {
			return fmt.Errorf("read passphrase: %w", err)
		}
		defer cryptopkg.Wipe(passphrase)
		if len(passphrase) < 12 {
			return fmt.Errorf("passphrase must be at least 12 characters")
		}

		// Generate identity for this device
		identity, err := cryptopkg.GenerateIdentity()
		if err != nil {
			return fmt.Errorf("generate identity: %w", err)
		}

		// Create vault directory structure
		if mkdirErr := os.MkdirAll(filepath.Join(vaultDir, "entries"), 0o700); mkdirErr != nil {
			return fmt.Errorf("create entries dir: %w", mkdirErr)
		}

		// Write config
		cfg := configpkg.Default()
		cfg.VaultDir = vaultDir
		cfg.Git = &configpkg.GitConfig{
			AutoPush:         true,
			AutoPull:         true,
			AutoPullInterval: 10 * time.Second,
			CommitTemplate:   "Update from OpenPass",
		}
		cfgPath := filepath.Join(vaultDir, "config.yaml")
		cfgData, err := yaml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("marshal config: %w", err)
		}
		if err := os.WriteFile(cfgPath, cfgData, 0o600); err != nil {
			return fmt.Errorf("write config: %w", err)
		}

		// Save identity encrypted with passphrase
		identityPath := filepath.Join(vaultDir, "identity.age")
		if err := cryptopkg.SaveIdentity(identity, identityPath, passphrase, 0); err != nil {
			return fmt.Errorf("save identity: %w", err)
		}

		// Write recipients.txt with existing device's public key
		recipientsPath := filepath.Join(vaultDir, "recipients.txt")
		recipientsContent := fmt.Sprintf("# OpenPass vault recipients\n# Added by device add --pair\n%s\n", existingPubkey)
		if err := os.WriteFile(recipientsPath, []byte(recipientsContent), 0o600); err != nil {
			return fmt.Errorf("write recipients: %w", err)
		}

		// Save joined file
		joinedData := joinedFile{
			Token:     token,
			Name:      deviceAddName,
			PublicKey: identity.Recipient().String(),
			CreatedAt: time.Now().UTC(),
		}
		if deviceAddName == "" {
			hostname, _ := os.Hostname()
			if hostname != "" {
				joinedData.Name = hostname
			} else {
				joinedData.Name = "device-" + token
			}
		}

		if err := savePairingFile(vaultDir, token+"-joined.json", joinedData); err != nil {
			return fmt.Errorf("save joined file: %w", err)
		}

		fmt.Fprintf(os.Stderr, "\n=== Pairing Setup Complete ===\n")
		fmt.Fprintf(os.Stderr, "Your public key: %s\n", identity.Recipient().String())
		fmt.Fprintf(os.Stderr, "Device name: %s\n\n", joinedData.Name)
		fmt.Fprintf(os.Stderr, "IMPORTANT: Entries cannot be decrypted yet.\n")
		fmt.Fprintf(os.Stderr, "On the original device, run:\n")
		fmt.Fprintf(os.Stderr, "  openpass device accept %s\n\n", token)
		fmt.Fprintf(os.Stderr, "After accepting, pull the re-encrypted entries:\n")
		fmt.Fprintf(os.Stderr, "  openpass git pull\n")

		return nil
	},
}

var deviceRevokeCmd = &cobra.Command{
	Use:   "revoke <name>",
	Short: "Revoke a device and re-encrypt all entries",
	Long: `Revoke a device's access to the vault by removing its public key
from the device registry and recipients list, then re-encrypting all
entries so the revoked device can no longer decrypt them.

WARNING: This is irreversible. The revoked device will permanently lose
access to all vault entries.`,
	Example: `  openpass device revoke macbook
  openpass device revoke macbook --yes`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		deviceName := args[0]

		vaultDir, err := vaultPath()
		if err != nil {
			return err
		}

		if !vaultpkg.IsInitialized(vaultDir) {
			return errorspkg.NewCLIError(errorspkg.ExitNotInitialized,
				"vault not initialized. Run 'openpass init' first",
				errorspkg.ErrVaultNotInitialized)
		}

		v, err := unlockVault(vaultDir, true)
		if err != nil {
			return err
		}

		// Find the device in the registry
		dm := vaultpkg.NewDeviceManager(vaultDir)
		device, err := dm.GetDevice(deviceName)
		if err != nil {
			return fmt.Errorf("cannot look up device: %w", err)
		}
		if device == nil {
			return fmt.Errorf("device %q not found in device registry", deviceName)
		}

		// Prevent revoking the current device
		currentPubkey := v.Identity.Recipient().String()
		if device.PublicKey == currentPubkey {
			return fmt.Errorf("cannot revoke the current device %q (this device's identity would be lost)", deviceName)
		}

		// Confirmation prompt unless --yes is passed
		if !deviceRevokeYes {
			fmt.Fprintf(os.Stderr, "This will revoke device %q and re-encrypt all entries.\nContinue? [y/N]: ", deviceName)
			answer, readErr := bufio.NewReader(os.Stdin).ReadString('\n')
			if readErr != nil && answer == "" {
				return fmt.Errorf("read confirmation: %w", readErr)
			}
			if strings.ToLower(strings.TrimSpace(answer)) != "y" {
				fmt.Fprintln(os.Stderr, "Canceled")
				return nil
			}
		}

		// Remove device from registry
		if err = dm.RemoveDevice(deviceName); err != nil {
			return fmt.Errorf("remove device from registry: %w", err)
		}

		// Remove device's public key from recipients
		rm := vaultpkg.NewRecipientsManager(vaultDir)
		if err = rm.RemoveRecipient(device.PublicKey); err != nil {
			// Not found in recipients is acceptable — may have been manually removed
			if !errors.Is(err, vaultpkg.ErrRecipientNotFound) {
				return fmt.Errorf("remove recipient: %w", err)
			}
		}

		// Get remaining recipients for re-encryption
		allRecipients, err := v.GetAllRecipientsForEncryption()
		if err != nil {
			return fmt.Errorf("get recipients: %w", err)
		}

		// Re-encrypt all entries without the revoked device
		fmt.Fprintf(os.Stderr, "Re-encrypting all entries for %d recipient(s)...\n", len(allRecipients))
		if err := vaultpkg.ReencryptAll(vaultDir, v.Identity, allRecipients); err != nil {
			return fmt.Errorf("re-encrypt: %w", err)
		}

		// Auto-commit and push
		if err := git.AutoCommitAndPush(vaultDir, fmt.Sprintf("Revoke device: %s", deviceName), v.Config.Git.AutoPush); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not auto-commit/push: %v\n", err)
		}

		printQuietAware("\nDevice %q has been revoked and all entries re-encrypted.\n", deviceName)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(deviceCmd)
	deviceCmd.AddCommand(devicePairCmd)
	deviceCmd.AddCommand(deviceJoinCmd)
	deviceCmd.AddCommand(deviceAcceptCmd)
	deviceCmd.AddCommand(deviceListCmd)
	deviceCmd.AddCommand(deviceRevokeCmd)
	deviceCmd.AddCommand(deviceAddCmd)
	deviceAddCmd.Flags().BoolVar(&deviceAddPair, "pair", false, "Pair with an existing device using QR data")
	deviceAddCmd.Flags().StringVar(&deviceAddName, "name", "", "Name for this device (defaults to hostname)")
	deviceJoinCmd.Flags().StringVar(&defaultDeviceName, "name", "", "Name for this device (defaults to hostname)")
	deviceRevokeCmd.Flags().BoolVarP(&deviceRevokeYes, "yes", "y", false, "Skip confirmation prompt")
}

type pairingFile struct {
	Token     string    `json:"token"`
	PublicKey string    `json:"public_key"`
	CreatedAt time.Time `json:"created_at"`
}

type joinedFile struct {
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key"`
	CreatedAt time.Time `json:"created_at"`
}

func savePairingFile(vaultDir, filename string, data any) error {
	pairingDir := filepath.Join(vaultDir, ".openpass", "pairing")
	if err := os.MkdirAll(pairingDir, 0o700); err != nil {
		return fmt.Errorf("create pairing dir: %w", err)
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	filePath := filepath.Join(pairingDir, filename)
	if err := os.WriteFile(filePath, jsonData, 0o600); err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}

func truncatePubkey(pubkey string) string {
	if len(pubkey) > 16 {
		return pubkey[:16] + "..."
	}
	return pubkey
}
