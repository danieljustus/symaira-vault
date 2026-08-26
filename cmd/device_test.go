package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	configpkg "github.com/danieljustus/symaira-vault/internal/config"
	cryptopkg "github.com/danieljustus/symaira-vault/internal/crypto"
	"github.com/danieljustus/symaira-vault/internal/pairing"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func TestDeviceAccept_DisplaysFingerprintAndAccepts(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	vaultFlagReset(t)

	// Generate joining device identity
	joiningIdentity, err := cryptopkg.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate joining identity: %v", err)
	}
	joiningPubkey := joiningIdentity.Recipient().String()
	expectedFingerprint := cryptopkg.PublicKeyFingerprint(joiningPubkey)
	if expectedFingerprint == "" {
		t.Fatal("expected fingerprint to not be empty")
	}

	token, err := pairing.GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// Write joined file
	jf := joinedFile{
		Token:     string(token),
		Name:      "test-phone",
		PublicKey: joiningPubkey,
		CreatedAt: time.Now().UTC(),
	}
	pairingDir := filepath.Join(vaultDir, configpkg.DefaultVaultSubdir, "pairing")
	if err := os.MkdirAll(pairingDir, 0o700); err != nil {
		t.Fatalf("mkdir pairing dir: %v", err)
	}
	jfBytes, err := json.MarshalIndent(jf, "", "  ")
	if err != nil {
		t.Fatalf("marshal joined file: %v", err)
	}
	jfPath := filepath.Join(pairingDir, string(token)+"-joined.json")
	if err := os.WriteFile(jfPath, jfBytes, 0o600); err != nil {
		t.Fatalf("write joined file: %v", err)
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "device", "accept", string(token)})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	output := captureStdout(func() {
		execErr = rootCmd.Execute()
	})

	if execErr != nil {
		t.Fatalf("device accept execute failed: %v", execErr)
	}

	// Verify stdout output contains all expected fingerprint and device metadata
	if !strings.Contains(output, "=== Joining Device Request ===") {
		t.Errorf("output missing header: %q", output)
	}
	if !strings.Contains(output, "Device name:     test-phone") {
		t.Errorf("output missing device name: %q", output)
	}
	if !strings.Contains(output, "Key type:        age X25519") {
		t.Errorf("output missing key type: %q", output)
	}
	if !strings.Contains(output, "Public key:      "+joiningPubkey) {
		t.Errorf("output missing public key: %q", output)
	}
	if !strings.Contains(output, "Key fingerprint: "+expectedFingerprint) {
		t.Errorf("output missing fingerprint %q: %q", expectedFingerprint, output)
	}
	if !strings.Contains(output, "=== Pairing Complete ===") {
		t.Errorf("output missing pairing complete: %q", output)
	}
	if !strings.Contains(output, "Device \"test-phone\" can now access all vault entries.") {
		t.Errorf("output missing device grant confirmation: %q", output)
	}

	// Verify joining public key was added to recipients
	rm := vaultpkg.NewRecipientsManager(vaultDir)
	recipients, err := rm.LoadRecipientStrings()
	if err != nil {
		t.Fatalf("load recipients: %v", err)
	}
	found := false
	for _, r := range recipients {
		if r == joiningPubkey {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("joining public key %s not found in recipients list %v", joiningPubkey, recipients)
	}

	// Verify joined file was removed
	if _, err := os.Stat(jfPath); !os.IsNotExist(err) {
		t.Errorf("joined file still exists at %s", jfPath)
	}
}

// ===== Transport-independent pairing handshake (#867) =====

func TestDeviceJoin_PairingFile_FullFlow(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	_ = vaultDir
	setPassEnv(t, string(passphrase)) // not used by join; join reads the passphrase from stdin
	vaultFlagReset(t)

	token, err := pairing.GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	existingIdentity, err := cryptopkg.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate existing identity: %v", err)
	}
	pf := pairing.PairingFile{
		Token:     string(token),
		PublicKey: existingIdentity.Recipient().String(),
		CreatedAt: time.Now().UTC(),
	}
	pfBytes, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		t.Fatalf("marshal pairing file: %v", err)
	}
	pairingFilePath := filepath.Join(t.TempDir(), "pairing-invite.json")
	if err := os.WriteFile(pairingFilePath, pfBytes, 0o600); err != nil {
		t.Fatalf("write pairing file: %v", err)
	}

	joinDir := t.TempDir()

	restore := pipeStdin(t, "test-passphrase-for-joined-device\n")
	t.Cleanup(restore)

	rootCmd.SetArgs([]string{"--vault", joinDir, "device", "join", "--name", "file-phone",
		"--pairing-file", pairingFilePath, string(token)})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	output := captureStdout(func() {
		execErr = rootCmd.Execute()
	})

	if execErr != nil {
		t.Fatalf("device join --pairing-file execute failed: %v", execErr)
	}

	// Response artifact must exist under the -response.json name and carry
	// the joining device's public key.
	respPath := filepath.Join(joinDir, configpkg.DefaultVaultSubdir, "pairing", string(token)+"-response.json")
	respData, err := os.ReadFile(respPath)
	if err != nil {
		t.Fatalf("response artifact missing at %s: %v", respPath, err)
	}
	var resp pairing.JoinResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("parse response artifact: %v", err)
	}
	if !strings.HasPrefix(resp.PublicKey, "age1") {
		t.Errorf("unexpected public key in response: %q", resp.PublicKey)
	}
	if resp.Name != "file-phone" {
		t.Errorf("expected device name file-phone, got %q", resp.Name)
	}
	if !strings.Contains(output, "Response artifact written to:") {
		t.Errorf("output missing response artifact path hint: %q", output)
	}
	if strings.Contains(output, "Cloning vault from") {
		t.Errorf("file flow must not clone a git remote: %q", output)
	}

	// recipients.txt must contain the existing device's public key.
	recipData, err := os.ReadFile(filepath.Join(joinDir, "recipients.txt"))
	if err != nil {
		t.Fatalf("read recipients.txt: %v", err)
	}
	if !strings.Contains(string(recipData), pf.PublicKey) {
		t.Errorf("recipients.txt missing existing public key %s", pf.PublicKey)
	}
}

func TestDeviceJoin_PairingFile_TokenMismatchRejected(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	_ = vaultDir
	setPassEnv(t, string(passphrase))
	vaultFlagReset(t)

	token, err := pairing.GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	otherToken, err := pairing.GenerateToken()
	if err != nil {
		t.Fatalf("generate other token: %v", err)
	}

	existingIdentity, err := cryptopkg.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate existing identity: %v", err)
	}
	pf := pairing.PairingFile{
		Token:     string(otherToken),
		PublicKey: existingIdentity.Recipient().String(),
		CreatedAt: time.Now().UTC(),
	}
	pfBytes, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		t.Fatalf("marshal pairing file: %v", err)
	}
	pairingFilePath := filepath.Join(t.TempDir(), "pairing-invite.json")
	if err := os.WriteFile(pairingFilePath, pfBytes, 0o600); err != nil {
		t.Fatalf("write pairing file: %v", err)
	}

	joinDir := t.TempDir()

	rootCmd.SetArgs([]string{"--vault", joinDir, "device", "join",
		"--pairing-file", pairingFilePath, string(token)})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Fatal("expected error for mismatched tokens")
	}
	if !strings.Contains(execErr.Error(), "does not match") {
		t.Errorf("unexpected error message: %v", execErr)
	}
}

func TestDeviceAccept_AcceptsResponseArtefact(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	vaultFlagReset(t)

	joiningIdentity, err := cryptopkg.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate joining identity: %v", err)
	}
	joiningPubkey := joiningIdentity.Recipient().String()

	token, err := pairing.GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	jr := joinedFile{
		Token:     string(token),
		Name:      "response-phone",
		PublicKey: joiningPubkey,
		CreatedAt: time.Now().UTC(),
	}
	pairingDir := filepath.Join(vaultDir, configpkg.DefaultVaultSubdir, "pairing")
	if err := os.MkdirAll(pairingDir, 0o700); err != nil {
		t.Fatalf("mkdir pairing dir: %v", err)
	}
	jrBytes, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		t.Fatalf("marshal join response: %v", err)
	}
	respPath := filepath.Join(pairingDir, string(token)+"-response.json")
	if err := os.WriteFile(respPath, jrBytes, 0o600); err != nil {
		t.Fatalf("write join response: %v", err)
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "device", "accept", string(token)})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	output := captureStdout(func() {
		execErr = rootCmd.Execute()
	})

	if execErr != nil {
		t.Fatalf("device accept (response artifact) failed: %v", execErr)
	}
	if !strings.Contains(output, `Device "response-phone" can now access all vault entries.`) {
		t.Errorf("output missing device grant confirmation: %q", output)
	}

	rm := vaultpkg.NewRecipientsManager(vaultDir)
	recipients, err := rm.LoadRecipientStrings()
	if err != nil {
		t.Fatalf("load recipients: %v", err)
	}
	found := false
	for _, r := range recipients {
		if r == joiningPubkey {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("joining public key %s not found in recipients list %v", joiningPubkey, recipients)
	}
	if _, err := os.Stat(respPath); !os.IsNotExist(err) {
		t.Errorf("response artifact still exists at %s", respPath)
	}
}

func TestDevicePair_DisplaysFingerprint(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	vaultFlagReset(t)

	rootCmd.SetArgs([]string{"--vault", vaultDir, "device", "pair"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	output := captureStdout(func() {
		execErr = rootCmd.Execute()
	})

	if execErr != nil {
		t.Fatalf("device pair execute failed: %v", execErr)
	}

	if !strings.Contains(output, "=== Pairing Token ===") {
		t.Errorf("output missing header: %q", output)
	}
	if !strings.Contains(output, "Token:") {
		t.Errorf("output missing token: %q", output)
	}
	if !strings.Contains(output, "This device's public key:") {
		t.Errorf("output missing public key: %q", output)
	}
	if !strings.Contains(output, "Key fingerprint:") {
		t.Errorf("output missing key fingerprint: %q", output)
	}
	if !strings.Contains(output, "(SHA-256)") {
		t.Errorf("output missing (SHA-256): %q", output)
	}
}

func TestDeviceAccept_InvalidToken(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	vaultFlagReset(t)

	rootCmd.SetArgs([]string{"--vault", vaultDir, "device", "accept", "invalid/token"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Fatal("expected error for invalid token")
	}
	if !strings.Contains(execErr.Error(), "invalid pairing token") {
		t.Errorf("unexpected error message: %v", execErr)
	}
}

func TestDeviceAccept_NoJoinRequest(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	vaultFlagReset(t)

	token, err := pairing.GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "device", "accept", string(token)})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Fatal("expected error when no join request exists")
	}
	if !strings.Contains(execErr.Error(), "no join request found") {
		t.Errorf("unexpected error message: %v", execErr)
	}
}

func TestDeviceAccept_CorruptJoinedFile(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	vaultFlagReset(t)

	token, err := pairing.GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	pairingDir := filepath.Join(vaultDir, configpkg.DefaultVaultSubdir, "pairing")
	if err := os.MkdirAll(pairingDir, 0o700); err != nil {
		t.Fatalf("mkdir pairing dir: %v", err)
	}
	jfPath := filepath.Join(pairingDir, string(token)+"-joined.json")
	if err := os.WriteFile(jfPath, []byte("not-valid-json"), 0o600); err != nil {
		t.Fatalf("write joined file: %v", err)
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "device", "accept", string(token)})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr == nil {
		t.Fatal("expected error for corrupt joined file")
	}
	if !strings.Contains(execErr.Error(), "parse joined file") {
		t.Errorf("unexpected error message: %v", execErr)
	}
}

func TestDeviceAccept_DefaultDeviceName(t *testing.T) {
	vaultDir, passphrase := initVault(t)
	setPassEnv(t, string(passphrase))
	vaultFlagReset(t)

	joiningIdentity, err := cryptopkg.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate joining identity: %v", err)
	}
	joiningPubkey := joiningIdentity.Recipient().String()
	expectedFingerprint := cryptopkg.PublicKeyFingerprint(joiningPubkey)

	token, err := pairing.GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	// Write joined file with empty name
	jf := joinedFile{
		Token:     string(token),
		Name:      "",
		PublicKey: joiningPubkey,
		CreatedAt: time.Now().UTC(),
	}
	pairingDir := filepath.Join(vaultDir, configpkg.DefaultVaultSubdir, "pairing")
	if err := os.MkdirAll(pairingDir, 0o700); err != nil {
		t.Fatalf("mkdir pairing dir: %v", err)
	}
	jfBytes, err := json.MarshalIndent(jf, "", "  ")
	if err != nil {
		t.Fatalf("marshal joined file: %v", err)
	}
	jfPath := filepath.Join(pairingDir, string(token)+"-joined.json")
	if err := os.WriteFile(jfPath, jfBytes, 0o600); err != nil {
		t.Fatalf("write joined file: %v", err)
	}

	rootCmd.SetArgs([]string{"--vault", vaultDir, "device", "accept", string(token)})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	output := captureStdout(func() {
		execErr = rootCmd.Execute()
	})

	if execErr != nil {
		t.Fatalf("device accept execute failed: %v", execErr)
	}

	if !strings.Contains(output, "Key fingerprint: "+expectedFingerprint) {
		t.Errorf("output missing expected fingerprint %s: %q", expectedFingerprint, output)
	}
	if !strings.Contains(output, "Key type:        age X25519") {
		t.Errorf("output missing key type: %q", output)
	}
}

func TestDeviceAdd_DisplaysFingerprint(t *testing.T) {
	vaultDir := t.TempDir()
	vaultFlagReset(t)

	existingIdentity, err := cryptopkg.GenerateIdentity()
	if err != nil {
		t.Fatalf("generate existing identity: %v", err)
	}
	existingPubkey := existingIdentity.Recipient().String()

	token, err := pairing.GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	cleanupStdin := pipeStdin(t, "test-device-passphrase-123\n")
	t.Cleanup(cleanupStdin)

	rootCmd.SetArgs([]string{"--vault", vaultDir, "device", "add", "--pair", string(token) + ":" + existingPubkey, "--name", "added-device"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	var execErr error
	output := captureStderr(func() {
		execErr = rootCmd.Execute()
	})

	if execErr != nil {
		t.Fatalf("device add execute failed: %v, output: %s", execErr, output)
	}

	if !strings.Contains(output, "Device name:     added-device") {
		t.Errorf("output missing device name: %q", output)
	}
	if !strings.Contains(output, "Key type:        age X25519") {
		t.Errorf("output missing key type: %q", output)
	}
	if !strings.Contains(output, "Your public key: age1") {
		t.Errorf("output missing public key: %q", output)
	}
	if !strings.Contains(output, "Key fingerprint:") {
		t.Errorf("output missing key fingerprint: %q", output)
	}
	if !strings.Contains(output, "(SHA-256)") {
		t.Errorf("output missing (SHA-256): %q", output)
	}
}
