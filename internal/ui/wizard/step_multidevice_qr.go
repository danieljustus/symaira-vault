package wizard

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/danieljustus/OpenPass/internal/pairing"
	"github.com/danieljustus/OpenPass/internal/ui"
)

// PairingQRStep shows a QR code with pairing token after vault init
// when multi-device + git sync is enabled.
type PairingQRStep struct {
	state  *WizardState
	token  pairing.Token
	done   bool
	saved  bool
	errMsg string
}

func NewPairingQRStep(state *WizardState) *PairingQRStep {
	return &PairingQRStep{state: state}
}

func (s *PairingQRStep) Title() string { return "Device Pairing QR" }

func (s *PairingQRStep) ShouldShow(st WizardState) bool {
	return st.MultiDevice && st.SyncMode == syncGit && !st.ExistingVault
}

func (s *PairingQRStep) Init() tea.Cmd {
	if s.saved {
		return nil
	}

	var err error
	s.token, err = pairing.GenerateToken()
	if err != nil {
		s.errMsg = fmt.Sprintf("generate token: %v", err)
		return nil
	}

	publicKey := s.state.VaultPublicKey
	if publicKey == "" {
		s.errMsg = "vault public key not available"
		return nil
	}

	// Save pairing JSON file so device accept --pair can use it
	type pairingFile struct {
		Token     string    `json:"token"`
		PublicKey string    `json:"public_key"`
		CreatedAt time.Time `json:"created_at"`
	}
	enc, err := json.MarshalIndent(pairingFile{
		Token:     string(s.token),
		PublicKey: publicKey,
		CreatedAt: time.Now().UTC(),
	}, "", "  ")
	if err != nil {
		s.errMsg = fmt.Sprintf("marshal pairing data: %v", err)
		return nil
	}

	pairingDir := s.state.VaultDir + "/.openpass/pairing"
	if err := os.MkdirAll(pairingDir, 0o700); err != nil {
		s.errMsg = fmt.Sprintf("create pairing dir: %v", err)
		return nil
	}
	if err := os.WriteFile(pairingDir+"/"+string(s.token)+".json", enc, 0o600); err != nil {
		s.errMsg = fmt.Sprintf("write pairing file: %v", err)
		return nil
	}

	s.saved = true
	return nil
}

func (s *PairingQRStep) Update(msg tea.Msg) (Step, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		if km.String() == keyEnter || km.String() == "q" {
			s.done = true
			return s, stepDoneCmd()
		}
	}
	return s, nil
}

func (s *PairingQRStep) View() string {
	if s.errMsg != "" {
		return fmt.Sprintf("%s\n\n%s\n\n%s",
			titleStyle.Render("Device Pairing QR"),
			errorStyle.Render("Error: "+s.errMsg),
			helpStyle.Render("Enter to continue"),
		)
	}

	publicKey := s.state.VaultPublicKey
	qrData := string(s.token) + ":" + publicKey
	qrArt := ui.RenderQRCode(qrData)

	truncated := publicKey
	if len(truncated) > 16 {
		truncated = truncated[:16] + "..."
	}

	lines := []string{
		titleStyle.Render("Device Pairing QR"),
		"",
		"Scan this QR code on your second device, or use the token below:",
		"",
		qrArt,
		"",
		fmt.Sprintf("  %-18s %s", focusedStyle.Render("Token:"), s.token),
		fmt.Sprintf("  %-18s %s", dimStyle.Render("Public Key:"), truncated),
		"",
		"On the second device, run:",
		"",
		fmt.Sprintf("  %s", focusedStyle.Render("openpass device add --pair \""+qrData+"\"")),
		"",
		dimStyle.Render("After the second device has joined, run on this device:"),
		fmt.Sprintf("  %s", focusedStyle.Render("openpass device accept "+string(s.token))),
		"",
		helpStyle.Render("Enter or Q to continue"),
	}

	return strings.Join(lines, "\n")
}
