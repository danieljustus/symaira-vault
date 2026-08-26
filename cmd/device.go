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

	cli "github.com/danieljustus/symaira-vault/internal/cli"
	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
	errorspkg "github.com/danieljustus/symaira-vault/internal/errors"
	"github.com/danieljustus/symaira-vault/internal/git"
	"github.com/danieljustus/symaira-vault/internal/pairing"
	"github.com/danieljustus/symaira-vault/internal/ui/cliout"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

var (
	defaultDeviceName string
	deviceRevokeYes   bool
	joinPairingFile   string
)

// deviceCmd is retained for API compatibility; NewCommands() uses
// newDeviceCmd() so every call gets a fresh command.
var deviceCmd = newDeviceCmd()

func newDeviceCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "device",
		Short: "Manage paired devices for multi-device vault access",
		Long: `Manage paired devices that can access this vault.

Use 'symvault device pair' to generate a pairing token for a new device,
and 'symvault device join' on the new device to join the vault.`,
		Example: `  symvault device pair
  symvault device join ssh://user@host/path/to/vault.git <token>
  symvault device accept <token>`,
		Annotations: map[string]string{
			cli.JSONOutputAnnotation: "true",
		},
	}
	c.GroupID = cli.GroupIDSharingSync
	c.AddCommand(newDevicePairCmd())
	c.AddCommand(newDeviceJoinCmd())
	c.AddCommand(newDeviceAcceptCmd())
	c.AddCommand(newDeviceListCmd())
	c.AddCommand(newDeviceRevokeCmd())
	c.AddCommand(newDeviceAddCmd())
	return c
}

func newDevicePairCmd() *cobra.Command {
	devicePairCmd := &cobra.Command{
		Use:   "pair",
		Short: "Generate a pairing token for a new device",
		Long: `Generate a pairing token that another device can use to join this vault.

This saves the pairing token and this device's public key to the vault,
commits and pushes the token file. The joining device reads this file
to obtain this device's public key for encryption.

IMPORTANT: After the joining device submits its public key (via 'symvault device join'),
you must run 'symvault device accept <token>' to re-encrypt all entries
for the new device.`,
		Example: `  symvault device pair`,
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultDir, err := cli.VaultPath()
			if err != nil {
				return err
			}

			v, err := cli.UnlockVault(vaultDir, true)
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

			if err := git.AutoCommitAndPush(vaultDir, fmt.Sprintf("Pairing token %s", token), gitAutoPush(v)); err != nil {
				cliout.Warnf("Warning: could not auto-commit/push: %v", err)
			}

			printQuietAware("\n=== Pairing Token ===\n")
			printQuietAware("Token: %s\n\n", token)
			printQuietAware("This device's public key: %s\n", publicKey)
			printQuietAware("Key fingerprint:          %s (SHA-256)\n", cryptopkg.PublicKeyFingerprint(publicKey))
			printQuietAware("\nOn the joining device, run:\n")
			printQuietAware("  symvault device join <remote-url> %s\n\n", token)
			printQuietAware("Without a git remote, share %s by any channel and run:\n",
				filepath.Join(configpkg.DefaultVaultSubdir, "pairing", string(token)+".json"))
			printQuietAware("  symvault device join --pairing-file <path-to-token.json> %s\n\n", token)
			printQuietAware("After the joining device has submitted its key, run:\n")
			printQuietAware("  symvault device accept %s\n\n", token)

			return nil
		},
	}
	return devicePairCmd
}

// resolveJoinPairing validates command-line arguments and returns the pairing
// token plus, for the --pairing-file transport, the parsed invitation.
func resolveJoinPairing(pairingFilePath string, args []string) (string, pairing.PairingFile, error) {
	if pairingFilePath != "" {
		if len(args) != 1 {
			return "", pairing.PairingFile{}, fmt.Errorf("with --pairing-file, pass only the pairing token: 'device join --pairing-file <path> <token>'")
		}
		token := strings.TrimSpace(args[0])
		if valErr := pairing.ValidatePairingToken(token); valErr != nil {
			return "", pairing.PairingFile{}, fmt.Errorf("invalid pairing token: %w", valErr)
		}
		// #nosec G304 -- path comes from the operator's own command line
		pfData, readErr := os.ReadFile(pairingFilePath)
		if readErr != nil {
			return "", pairing.PairingFile{}, fmt.Errorf("read pairing file: %w", readErr)
		}
		pf, parseErr := pairing.ParsePairingFile(pfData)
		if parseErr != nil {
			return "", pairing.PairingFile{}, parseErr
		}
		if pf.Token != "" && pf.Token != token {
			return "", pairing.PairingFile{}, fmt.Errorf("pairing file token %q does not match the given token %q", pf.Token, token)
		}
		if pf.PublicKey == "" || !strings.HasPrefix(pf.PublicKey, "age1") {
			return "", pairing.PairingFile{}, fmt.Errorf("invalid pairing file: missing or malformed public_key")
		}
		return token, pf, nil
	}

	if len(args) != 2 {
		return "", pairing.PairingFile{}, fmt.Errorf("accepts between 1 and 2 arg(s), received %d — either '<remote-url> <token>' or '--pairing-file <path> <token>'", len(args))
	}
	token := strings.TrimSpace(args[1])
	if valErr := pairing.ValidatePairingToken(token); valErr != nil {
		return "", pairing.PairingFile{}, fmt.Errorf("invalid pairing token: %w", valErr)
	}
	return token, pairing.PairingFile{}, nil
}

// loadGitPairingFile reads the invitation written by 'device pair' from the
// cloned vault on the git transport.
func loadGitPairingFile(vaultDir, token string) (pairing.PairingFile, error) {
	pairingPath := filepath.Join(vaultDir, configpkg.DefaultVaultSubdir, "pairing", token+".json")
	// #nosec G304 -- pairingPath is constructed within the vault directory
	pfData, err := vaultpkg.SafeReadFile(pairingPath)
	if err != nil {
		return pairing.PairingFile{}, fmt.Errorf("invalid or expired pairing token: could not read pairing file. Ensure the token is correct and the pairing device has pushed the token file: %w", err)
	}
	var pf pairingFile
	if err := json.Unmarshal(pfData, &pf); err != nil {
		return pairing.PairingFile{}, fmt.Errorf("invalid pairing file: %w", err)
	}
	return pairing.PairingFile{
		Token:     pf.Token,
		PublicKey: pf.PublicKey,
		CreatedAt: pf.CreatedAt,
	}, nil
}

// setupJoinedDevice writes the joining device's local vault files — config,
// encrypted identity, and the recipients list — and returns its public key.
func setupJoinedDevice(vaultDir, existingPubkey string, passphrase []byte) (string, error) {
	identity, err := cryptopkg.GenerateIdentity()
	if err != nil {
		return "", fmt.Errorf("generate identity: %w", err)
	}
	myPubkey := identity.Recipient().String()

	cfg := configpkg.Default()
	cfg.VaultDir = vaultDir
	cfg.Git = &configpkg.GitConfig{
		AutoPush:         true,
		AutoPull:         true,
		AutoPullInterval: 10 * time.Second,
		CommitTemplate:   "Update from Symaira Vault",
	}

	cfgPath := filepath.Join(vaultDir, "config.yaml")
	cfgData, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(cfgPath, cfgData, 0o600); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}

	identityPath := filepath.Join(vaultDir, "identity.age")
	if err := cryptopkg.SaveIdentity(identity, identityPath, passphrase, 0); err != nil {
		return "", fmt.Errorf("save identity: %w", err)
	}

	recipientsPath := filepath.Join(vaultDir, "recipients.txt")
	recipientsContent := fmt.Sprintf("# Symaira Vault vault recipients\n# Added by device join\n%s\n", existingPubkey)
	if err := os.WriteFile(recipientsPath, []byte(recipientsContent), 0o600); err != nil {
		return "", fmt.Errorf("write recipients: %w", err)
	}

	return myPubkey, nil
}

func newDeviceJoinCmd() *cobra.Command {
	deviceJoinCmd := &cobra.Command{
		Use:   "join <remote-url> <token>",
		Short: "Join an existing vault as a new device",
		Long: `Join an existing vault from a remote git repository.

Clones the vault repository, reads the pairing token file to obtain
the existing device's public key, generates a new identity for this device,
and submits this device's public key back to the vault.

After completion, the existing device must run 'symvault device accept <token>'
to re-encrypt all entries for this new device.

To join without a git remote, pass the invitation artifact directly with
--pairing-file. The file is the <token>.json written by 'symvault device pair'
on the existing device; it can travel over any channel (synced folder, AirDrop,
manual copy). The response artifact is then left in the local vault directory
as <token>-response.json for delivery back to the existing device by any
means; 'symvault device accept' accepts both <token>-joined.json (git flow)
and <token>-response.json (file flow).`,
		Example: `  symvault device join ssh://user@host/path/to/vault.git 123456
  symvault device join --pairing-file ~/Downloads/ABCD1234.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			token, pairingPF, err := resolveJoinPairing(joinPairingFile, args)
			if err != nil {
				return err
			}

			vaultDir, err := cli.VaultPath()
			if err != nil {
				return err
			}

			if vaultpkg.IsInitialized(vaultDir) {
				return fmt.Errorf("vault already initialized at %s. Use a different --vault or remove the existing vault first", vaultDir)
			}

			if joinPairingFile != "" {
				cliout.Hintf("Pairing without git transport using %s", joinPairingFile)
			} else {
				cliout.Hintf("Cloning vault from %s ...", args[0])
				if _, err = gogit.PlainClone(vaultDir, false, &gogit.CloneOptions{
					URL:      args[0],
					Progress: os.Stderr,
				}); err != nil {
					return fmt.Errorf("clone vault: %w", err)
				}
				pairingPF, err = loadGitPairingFile(vaultDir, token)
				if err != nil {
					return err
				}
			}

			cliout.Hintf("Pairing with device (public key: %s)", truncatePubkey(pairingPF.PublicKey))

			passphrase, err := cli.ReadHiddenInput("Enter passphrase for this device (minimum 12 characters): ", nil)
			if err != nil {
				return fmt.Errorf("read passphrase: %w", err)
			}
			defer cryptopkg.Wipe(passphrase)
			if len(passphrase) < 12 {
				return fmt.Errorf("passphrase must be at least 12 characters")
			}

			myPubkey, err := setupJoinedDevice(vaultDir, pairingPF.PublicKey, passphrase)
			if err != nil {
				return err
			}

			joinedData := joinedFile{
				Token:     token,
				Name:      defaultDeviceName,
				PublicKey: myPubkey,
				CreatedAt: time.Now().UTC(),
			}
			if defaultDeviceName == "" {
				joinedData.Name = git.DeviceIdentity(vaultDir)
				if joinedData.Name == git.UnknownDeviceName {
					joinedData.Name = "device-" + token
				}
			}

			responseFilename := token + "-joined.json"
			if joinPairingFile != "" {
				// File-transport flow: leave a self-describing response artifact
				// in the local vault directory. It is not committed to git; the
				// operator delivers it back to the existing device out of band.
				responseFilename = token + "-response.json"
			}
			if err := savePairingFile(vaultDir, responseFilename, joinedData); err != nil {
				return fmt.Errorf("save joined file: %w", err)
			}
			if joinPairingFile != "" {
				printQuietAware("\nResponse artifact written to: %s\n",
					filepath.Join(vaultDir, configpkg.DefaultVaultSubdir, "pairing", responseFilename))
			}

			cleanupPairingFile := filepath.Join(vaultDir, configpkg.DefaultVaultSubdir, "pairing", token+".json")
			_ = os.Remove(cleanupPairingFile)

			if err := git.AutoCommitWithOptions(vaultDir, git.CommitOptions{
				Message: fmt.Sprintf("Device join: %s (token %s)", joinedData.Name, token),
			}); err != nil {
				return fmt.Errorf("commit: %w", err)
			}

			cliout.Hintf("=== Join Successful ===")
			printQuietAware("\nDevice name:     %s\n", joinedData.Name)
			printQuietAware("Key type:        age X25519\n")
			printQuietAware("Your public key: %s\n", myPubkey)
			printQuietAware("Key fingerprint: %s (SHA-256)\n\n", cryptopkg.PublicKeyFingerprint(myPubkey))
			printQuietAware("IMPORTANT: Entries cannot be decrypted yet.\n")
			printQuietAware("On the existing device, run:\n")
			printQuietAware("  symvault device accept %s\n\n", token)

			if joinPairingFile == "" {
				if err := git.Push(vaultDir); err != nil {
					cliout.Warnf("Warning: Could not push joined file: %v", err)
					cliout.Hintf("Push manually with: symvault git push")
				}
			}

			return nil
		},
	}
	deviceJoinCmd.Flags().StringVar(&defaultDeviceName, "name", "", "Name for this device (defaults to hostname)")
	deviceJoinCmd.Flags().StringVar(&joinPairingFile, "pairing-file", "", "Join without a git remote: path to the <token>.json invitation artifact produced by 'device pair'")
	return deviceJoinCmd
}

func newDeviceAcceptCmd() *cobra.Command {
	deviceAcceptCmd := &cobra.Command{
		Use:   "accept <token>",
		Short: "Accept a join request and re-encrypt entries for the new device",
		Long: `Accept a device join request by adding the new device's public key
as a recipient and re-encrypting all vault entries so the new device
can decrypt them.`,
		Example: `  symvault device accept 123456`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			token := strings.TrimSpace(args[0])

			if err := pairing.ValidatePairingToken(token); err != nil {
				return fmt.Errorf("invalid pairing token: %w", err)
			}

			vaultDir, err := cli.VaultPath()
			if err != nil {
				return err
			}

			v, err := cli.UnlockVault(vaultDir, true)
			if err != nil {
				return err
			}

			// The join response may arrive under either canonical name:
			// <token>-joined.json (git transport) or <token>-response.json
			// (transport-independent flow). Both carry the same format.
			var (
				jf        joinedFile
				jfData    []byte
				foundName string
			)
			for _, name := range pairing.ResponseFilenames(token) {
				candidatePath := filepath.Join(vaultDir, configpkg.DefaultVaultSubdir, "pairing", name)
				// #nosec G304 -- candidatePath is constructed within the vault directory
				data, readErr := vaultpkg.SafeReadFile(candidatePath)
				if readErr == nil {
					jfData = data
					foundName = name
					break
				}
			}
			if jfData == nil {
				return fmt.Errorf("no join request found for token %s. Ensure the joining device has completed 'symvault device join' and the response artifact (%s-joined.json or %s-response.json) is present in the vault", token, token, token)
			}
			if err = json.Unmarshal(jfData, &jf); err != nil {
				return fmt.Errorf("parse joined file %s: %w", foundName, err)
			}

			fp := cryptopkg.PublicKeyFingerprint(jf.PublicKey)

			printQuietAware("\n=== Joining Device Request ===\n")
			printQuietAware("Device name:     %s\n", jf.Name)
			printQuietAware("Key type:        age X25519\n")
			printQuietAware("Public key:      %s\n", jf.PublicKey)
			printQuietAware("Key fingerprint: %s (SHA-256)\n\n", fp)

			cliout.Hintf("Accepting join from device: %s (public key: %s)", jf.Name, truncatePubkey(jf.PublicKey))

			rm := vaultpkg.NewRecipientsManager(vaultDir)
			if err = rm.AddRecipient(jf.PublicKey); err != nil {
				return fmt.Errorf("add recipient: %w", err)
			}

			allRecipients, err := v.GetAllRecipientsForEncryption()
			if err != nil {
				return fmt.Errorf("get recipients: %w", err)
			}

			cliout.Hintf("Re-encrypting all entries for %d recipient(s)...", len(allRecipients))
			if err := vaultpkg.ReencryptAll(vaultDir, v.Identity, allRecipients); err != nil {
				return fmt.Errorf("re-encrypt: %w", err)
			}

			// Remove the response artifact under whichever name it was found.
			_ = os.Remove(filepath.Join(vaultDir, configpkg.DefaultVaultSubdir, "pairing", foundName))

			if err := git.AutoCommitAndPush(vaultDir, fmt.Sprintf("Accept device join: %s", jf.Name), gitAutoPush(v)); err != nil {
				cliout.Warnf("Warning: could not auto-commit/push: %v", err)
			}

			printQuietAware("\n=== Pairing Complete ===\n")
			printQuietAware("Device %q can now access all vault entries.\n\n", jf.Name)
			printQuietAware("On the joining device, run 'symvault git pull' to fetch the re-encrypted entries.\n")

			return nil
		},
	}
	return deviceAcceptCmd
}

func newDeviceListCmd() *cobra.Command {
	deviceListCmd := &cobra.Command{
		Use:   "list",
		Short: "List all devices",
		Long: `List all devices registered in the vault's device registry.

Shows device name, public key (truncated), added date, and last seen time.
Also shows recipients from recipients.txt that are not associated with
any registered device (unmanaged recipients).`,
		Example: `  symvault device list
  symvault device list --output json`,
		Annotations: map[string]string{
			cli.JSONOutputAnnotation: "true",
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			vaultDir, err := cli.VaultPath()
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

			if cli.OutputFormat == "json" || cli.OutputFormat == "yaml" {
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
				return cli.PrintResult(output)
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
	return deviceListCmd
}

var (
	deviceAddPair bool
	deviceAddName string
)

func newDeviceAddCmd() *cobra.Command {
	deviceAddCmd := &cobra.Command{
		Use:   "add",
		Short: "Add this device to an existing multi-device vault",
		Long: `Add this device to an existing multi-device vault using a pairing
token and public key obtained via QR code from the original device.

This command is used on the second device after the initial setup wizard
shows a QR code. It creates a new local vault with its own identity,
adds the first device's public key as a recipient, and saves a pairing
request so the first device can accept it.`,
		Example: `  symvault device add --pair "123456:age1..."`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !deviceAddPair {
				return fmt.Errorf("use 'symvault device add --pair <token:publickey>' to pair a device")
			}
			if len(args) < 1 {
				return fmt.Errorf("missing pairing data. Usage: symvault device add --pair <token> or <token:publickey>")
			}

			raw := strings.TrimSpace(args[0])

			vaultDir, err := cli.VaultPath()
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

			if valErr := pairing.ValidatePairingToken(token); valErr != nil {
				return fmt.Errorf("invalid pairing token: %w", valErr)
			}

			if !strings.HasPrefix(existingPubkey, "age1") || len(existingPubkey) < 50 {
				return fmt.Errorf("invalid public key in pairing data: expected age1... format")
			}

			passphrase, err := cli.ReadHiddenInput("Enter passphrase for this device (minimum 12 characters): ", nil)
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
				CommitTemplate:   "Update from Symaira Vault",
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
			recipientsContent := fmt.Sprintf("# Symaira Vault vault recipients\n# Added by device add --pair\n%s\n", existingPubkey)
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
				joinedData.Name = git.DeviceIdentity(vaultDir)
				if joinedData.Name == git.UnknownDeviceName {
					joinedData.Name = "device-" + token
				}
			}

			if err := savePairingFile(vaultDir, token+"-joined.json", joinedData); err != nil {
				return fmt.Errorf("save joined file: %w", err)
			}

			cliout.Hintf("=== Pairing Setup Complete ===")
			fmt.Fprintf(os.Stderr, "Device name:     %s\n", joinedData.Name)
			fmt.Fprintf(os.Stderr, "Key type:        age X25519\n")
			fmt.Fprintf(os.Stderr, "Your public key: %s\n", identity.Recipient().String())
			fmt.Fprintf(os.Stderr, "Key fingerprint: %s (SHA-256)\n\n", cryptopkg.PublicKeyFingerprint(identity.Recipient().String()))
			fmt.Fprintf(os.Stderr, "IMPORTANT: Entries cannot be decrypted yet.\n")
			fmt.Fprintf(os.Stderr, "On the original device, run:\n")
			fmt.Fprintf(os.Stderr, "  symvault device accept %s\n\n", token)
			fmt.Fprintf(os.Stderr, "After accepting, pull the re-encrypted entries:\n")
			fmt.Fprintf(os.Stderr, "  symvault git pull\n")

			return nil
		},
	}
	deviceAddCmd.Flags().BoolVar(&deviceAddPair, "pair", false, "Pair with an existing device using QR data")
	deviceAddCmd.Flags().StringVar(&deviceAddName, "name", "", "Name for this device (defaults to hostname)")
	return deviceAddCmd
}

func newDeviceRevokeCmd() *cobra.Command {
	deviceRevokeCmd := &cobra.Command{
		Use:   "revoke <name>",
		Short: "Revoke a device and re-encrypt all entries",
		Long: `Revoke a device's access to the vault by removing its public key
from the device registry and recipients list, then re-encrypting all
entries so the revoked device can no longer decrypt them.

WARNING: This is irreversible. The revoked device will permanently lose
access to all vault entries.`,
		Example: `  symvault device revoke macbook
  symvault device revoke macbook --yes`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceName := args[0]

			vaultDir, err := cli.VaultPath()
			if err != nil {
				return err
			}

			if !vaultpkg.IsInitialized(vaultDir) {
				return errorspkg.NewVaultNotInitialized()
			}

			v, err := cli.UnlockVault(vaultDir, true)
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
			cliout.Hintf("Re-encrypting all entries for %d recipient(s)...", len(allRecipients))
			if err := vaultpkg.ReencryptAll(vaultDir, v.Identity, allRecipients); err != nil {
				return fmt.Errorf("re-encrypt: %w", err)
			}

			// Auto-commit and push
			if err := git.AutoCommitAndPush(vaultDir, fmt.Sprintf("Revoke device: %s", deviceName), gitAutoPush(v)); err != nil {
				cliout.Warnf("Warning: could not auto-commit/push: %v", err)
			}

			printQuietAware("\nDevice %q has been revoked and all entries re-encrypted.\n", deviceName)
			return nil
		},
	}
	deviceRevokeCmd.Flags().BoolVarP(&deviceRevokeYes, "yes", "y", false, "Skip confirmation prompt")
	return deviceRevokeCmd
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
	pairingDir := filepath.Join(vaultDir, configpkg.DefaultVaultSubdir, "pairing")
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

func gitAutoPush(v *vaultpkg.Vault) bool {
	if v != nil && v.Config != nil && v.Config.Git != nil {
		return v.Config.Git.AutoPush
	}
	return false
}
