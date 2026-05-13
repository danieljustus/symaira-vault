// Package forms provides interactive Bubble Tea forms for OpenPass CLI operations.
package forms

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	cryptopkg "github.com/danieljustus/OpenPass/internal/crypto"
	vaultpkg "github.com/danieljustus/OpenPass/internal/vault"
)

const placeholderOptional = "optional"

const (
	fieldUsername = iota
	fieldPassword
	fieldType
	fieldUsageHint
	fieldAutoRotate
	fieldURL
	fieldNotes
	fieldTOTPSecret
	fieldTOTPIssuer
	fieldTOTPAccount
	fieldCount
)

var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	labelStyle   = lipgloss.NewStyle().Width(14).Align(lipgloss.Right)
	focusedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	helpStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	typeStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
)

// AddEntryForm is a Bubble Tea model for interactively adding a password entry.
type AddEntryForm struct {
	username    textinput.Model
	password    textinput.Model
	secretType  textinput.Model
	usageHint   textarea.Model
	autoRotate  textinput.Model
	url         textinput.Model
	notes       textarea.Model
	totpSecret  textinput.Model
	totpIssuer  textinput.Model
	totpAccount textinput.Model

	focused     int
	force       bool
	submitted   bool
	canceled    bool
	passwordErr error
	width       int
}

// NewAddEntryForm creates a new add entry form with optional default values.
func NewAddEntryForm(force bool) *AddEntryForm {
	f := &AddEntryForm{
		force: force,
	}

	f.username = textinput.New()
	f.username.Placeholder = placeholderOptional
	f.username.CharLimit = 256

	f.password = textinput.New()
	f.password.Placeholder = "required"
	f.password.EchoMode = textinput.EchoPassword
	f.password.CharLimit = 1024

	f.secretType = textinput.New()
	f.secretType.Placeholder = "auto-detect"
	f.secretType.CharLimit = 32

	f.usageHint = textarea.New()
	f.usageHint.Placeholder = "auto-generated from type"
	f.usageHint.ShowLineNumbers = false
	f.usageHint.SetHeight(2)
	f.usageHint.SetWidth(40)
	f.usageHint.CharLimit = 512

	f.autoRotate = textinput.New()
	f.autoRotate.Placeholder = "no"
	f.autoRotate.CharLimit = 3
	f.autoRotate.SetValue("no")

	f.url = textinput.New()
	f.url.Placeholder = placeholderOptional
	f.url.CharLimit = 2048

	f.notes = textarea.New()
	f.notes.Placeholder = placeholderOptional
	f.notes.ShowLineNumbers = false
	f.notes.SetHeight(3)
	f.notes.SetWidth(40)
	f.notes.CharLimit = 4096

	f.totpSecret = textinput.New()
	f.totpSecret.Placeholder = placeholderOptional
	f.totpSecret.CharLimit = 256

	f.totpIssuer = textinput.New()
	f.totpIssuer.Placeholder = placeholderOptional
	f.totpIssuer.CharLimit = 256

	f.totpAccount = textinput.New()
	f.totpAccount.Placeholder = placeholderOptional
	f.totpAccount.CharLimit = 256

	f.focusField(0)

	return f
}

// SetDefaults pre-fills form fields from a data map.
func (f *AddEntryForm) SetDefaults(data map[string]any) {
	if v, ok := data["username"].(string); ok && v != "" {
		f.username.SetValue(v)
	}
	if v, ok := data["password"].(string); ok && v != "" {
		f.password.SetValue(v)
		f.validatePassword()
		f.autoDetectType(v)
	}
	if v, ok := data["_secret_type"].(string); ok && v != "" {
		f.secretType.SetValue(v)
		f.updateUsageHintFromType()
	}
	if v, ok := data["_usage_hint"].(string); ok && v != "" {
		f.usageHint.SetValue(v)
	}
	if v, ok := data["_auto_rotate"].(bool); ok && v {
		f.autoRotate.SetValue("yes")
	}
	if v, ok := data["url"].(string); ok && v != "" {
		f.url.SetValue(v)
	}
	if v, ok := data["notes"].(string); ok && v != "" {
		f.notes.SetValue(v)
	}
	if totp, ok := data["totp"].(map[string]any); ok {
		if v, ok := totp["secret"].(string); ok {
			f.totpSecret.SetValue(v)
		}
		if v, ok := totp["issuer"].(string); ok {
			f.totpIssuer.SetValue(v)
		}
		if v, ok := totp["account_name"].(string); ok {
			f.totpAccount.SetValue(v)
		}
	}
}

func (f *AddEntryForm) autoDetectType(password string) {
	if f.secretType.Value() != "" {
		return
	}
	detected := vaultpkg.DetectSecretType(password)
	f.secretType.SetValue(string(detected))
	f.updateUsageHintFromType()
}

func (f *AddEntryForm) updateUsageHintFromType() {
	if f.usageHint.Value() != "" {
		return
	}
	t := vaultpkg.SecretTypeFromString(f.secretType.Value())
	hint := vaultpkg.UsageHintForType(t)
	if hint != "" {
		f.usageHint.SetValue(hint)
	}
}

func (f *AddEntryForm) focusField(idx int) {
	f.focused = idx

	f.username.Blur()
	f.password.Blur()
	f.secretType.Blur()
	f.usageHint.Blur()
	f.autoRotate.Blur()
	f.url.Blur()
	f.notes.Blur()
	f.totpSecret.Blur()
	f.totpIssuer.Blur()
	f.totpAccount.Blur()

	switch idx {
	case fieldUsername:
		f.username.Focus()
	case fieldPassword:
		f.password.Focus()
	case fieldType:
		f.secretType.Focus()
	case fieldUsageHint:
		f.usageHint.Focus()
	case fieldAutoRotate:
		f.autoRotate.Focus()
	case fieldURL:
		f.url.Focus()
	case fieldNotes:
		f.notes.Focus()
	case fieldTOTPSecret:
		f.totpSecret.Focus()
	case fieldTOTPIssuer:
		f.totpIssuer.Focus()
	case fieldTOTPAccount:
		f.totpAccount.Focus()
	}
}

func (f *AddEntryForm) nextField() {
	if f.focused < fieldCount-1 {
		f.focusField(f.focused + 1)
	}
}

func (f *AddEntryForm) prevField() {
	if f.focused > 0 {
		f.focusField(f.focused - 1)
	}
}

func (f *AddEntryForm) submit() {
	f.submitted = true
}

func (f *AddEntryForm) handleEnter() {
	if f.focused == fieldCount-1 {
		f.submit()
	} else {
		f.nextField()
	}
}

func (f *AddEntryForm) validatePassword() {
	password := f.password.Value()
	if password == "" {
		f.passwordErr = nil
		return
	}
	if f.force {
		f.passwordErr = nil
		return
	}
	s := cryptopkg.AssessPasswordStrength(password)
	if s.Weak {
		f.passwordErr = fmt.Errorf("%s (weak — press Enter to continue)", s.Message)
	} else {
		f.passwordErr = nil
	}
}

func (f *AddEntryForm) Init() tea.Cmd {
	return textinput.Blink
}

//nolint:gocyclo // complexity inherent to TUI state machine handling many input modes
func (f *AddEntryForm) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		f.width = msg.Width
		f.usageHint.SetWidth(min(60, msg.Width-20))
		f.notes.SetWidth(min(60, msg.Width-20))
		return f, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			f.canceled = true
			return f, tea.Quit
		case "tab":
			f.nextField()
			return f, nil
		case "shift+tab":
			f.prevField()
			return f, nil
		case "enter":
			if f.focused == fieldUsageHint || f.focused == fieldNotes {
				var cmd tea.Cmd
				if f.focused == fieldUsageHint {
					f.usageHint, cmd = f.usageHint.Update(msg)
				} else {
					f.notes, cmd = f.notes.Update(msg)
				}
				return f, cmd
			}
			f.handleEnter()
			return f, nil
		case "backspace", "ctrl+h":
			if f.isFieldEmpty() {
				f.prevField()
				return f, nil
			}
		}
	}

	var cmd tea.Cmd
	switch f.focused {
	case fieldUsername:
		f.username, cmd = f.username.Update(msg)
	case fieldPassword:
		f.password, cmd = f.password.Update(msg)
		f.validatePassword()
		if f.password.Value() != "" {
			f.autoDetectType(f.password.Value())
		}
	case fieldType:
		f.secretType, cmd = f.secretType.Update(msg)
		f.updateUsageHintFromType()
	case fieldUsageHint:
		f.usageHint, cmd = f.usageHint.Update(msg)
	case fieldAutoRotate:
		f.autoRotate, cmd = f.autoRotate.Update(msg)
	case fieldURL:
		f.url, cmd = f.url.Update(msg)
	case fieldNotes:
		f.notes, cmd = f.notes.Update(msg)
	case fieldTOTPSecret:
		f.totpSecret, cmd = f.totpSecret.Update(msg)
	case fieldTOTPIssuer:
		f.totpIssuer, cmd = f.totpIssuer.Update(msg)
	case fieldTOTPAccount:
		f.totpAccount, cmd = f.totpAccount.Update(msg)
	}

	if f.submitted {
		return f, tea.Quit
	}

	return f, cmd
}

func (f *AddEntryForm) isFieldEmpty() bool {
	switch f.focused {
	case fieldUsername:
		return f.username.Value() == "" && f.username.Position() == 0
	case fieldPassword:
		return f.password.Value() == "" && f.password.Position() == 0
	case fieldType:
		return f.secretType.Value() == "" && f.secretType.Position() == 0
	case fieldUsageHint:
		return f.usageHint.Value() == ""
	case fieldAutoRotate:
		return f.autoRotate.Value() == "" && f.autoRotate.Position() == 0
	case fieldURL:
		return f.url.Value() == "" && f.url.Position() == 0
	case fieldNotes:
		return f.notes.Value() == ""
	case fieldTOTPSecret:
		return f.totpSecret.Value() == "" && f.totpSecret.Position() == 0
	case fieldTOTPIssuer:
		return f.totpIssuer.Value() == "" && f.totpIssuer.Position() == 0
	case fieldTOTPAccount:
		return f.totpAccount.Value() == "" && f.totpAccount.Position() == 0
	}
	return false
}

func (f *AddEntryForm) typeDisplay() string {
	t := vaultpkg.SecretTypeFromString(f.secretType.Value())
	icon := vaultpkg.SecretTypeIcon(t)
	return fmt.Sprintf("%s %s", icon, t)
}

func (f *AddEntryForm) View() string {
	if f.width == 0 {
		f.width = 80
	}

	var b strings.Builder

	b.WriteString(titleStyle.Render("Add New Entry"))
	b.WriteString("\n\n")

	fields := []struct {
		label string
		view  string
	}{
		{"Username", f.username.View()},
		{"Password", f.password.View()},
		{"Type", f.secretType.View() + " " + typeStyle.Render(f.typeDisplay())},
		{"Usage Hint", f.usageHint.View()},
		{"Auto Rotate", f.autoRotate.View()},
		{"URL", f.url.View()},
		{"Notes", f.notes.View()},
		{"TOTP Secret", f.totpSecret.View()},
		{"TOTP Issuer", f.totpIssuer.View()},
		{"TOTP Account", f.totpAccount.View()},
	}

	for i, field := range fields {
		label := labelStyle.Render(field.label + ":")
		if i == f.focused {
			label = focusedStyle.Render(field.label + ":")
		}
		b.WriteString(label)
		b.WriteString(" ")
		b.WriteString(field.view)
		b.WriteString("\n")

		if i == fieldPassword && f.password.Value() != "" {
			b.WriteString(strings.Repeat(" ", 16))
			if f.passwordErr != nil {
				b.WriteString(errorStyle.Render("Strength: " + f.passwordErr.Error()))
			} else {
				b.WriteString(successStyle.Render("Strength: OK"))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render("Tab/Shift+Tab: navigate · Enter: next/submit · Ctrl+C: cancel"))
	if f.focused == fieldUsageHint || f.focused == fieldNotes {
		b.WriteString(helpStyle.Render(" · Enter: new line"))
	}
	b.WriteString("\n")

	return b.String()
}

// Data returns the collected form data as a map.
func (f *AddEntryForm) Data() map[string]any {
	data := make(map[string]any)

	username := strings.TrimSpace(f.username.Value())
	if username != "" {
		data["username"] = username
	}

	password := f.password.Value()
	if password != "" {
		data["password"] = password
	}

	url := strings.TrimSpace(f.url.Value())
	if url != "" {
		data["url"] = url
	}

	notes := strings.TrimSpace(f.notes.Value())
	if notes != "" {
		data["notes"] = notes
	}

	totpSecret := strings.TrimSpace(f.totpSecret.Value())
	if totpSecret != "" {
		totpData := map[string]any{
			"secret": totpSecret,
		}
		if issuer := strings.TrimSpace(f.totpIssuer.Value()); issuer != "" {
			totpData["issuer"] = issuer
		}
		if account := strings.TrimSpace(f.totpAccount.Value()); account != "" {
			totpData["account_name"] = account
		}
		data["totp"] = totpData
	}

	return data
}

// SecretMetadata returns the collected secret metadata from the form.
func (f *AddEntryForm) SecretMetadata() vaultpkg.SecretMetadata {
	meta := vaultpkg.SecretMetadata{}

	if t := f.secretType.Value(); t != "" {
		meta.Type = vaultpkg.SecretTypeFromString(t)
	}

	if hint := f.usageHint.Value(); hint != "" {
		meta.UsageHint = hint
	}

	if f.autoRotate.Value() == "yes" {
		meta.AutoRotate = true
	}

	return meta
}

// RunAddEntryForm runs the interactive add entry form and returns the collected data and metadata.
// When force is true, password strength validation is skipped.
// Defaults can be used to pre-fill form fields.
func RunAddEntryForm(force bool, defaults map[string]any) (map[string]any, vaultpkg.SecretMetadata, error) {
	form := NewAddEntryForm(force)
	if defaults != nil {
		form.SetDefaults(defaults)
	}

	p := tea.NewProgram(form)
	m, err := p.Run()
	if err != nil {
		return nil, vaultpkg.SecretMetadata{}, fmt.Errorf("form error: %w", err)
	}

	f, ok := m.(*AddEntryForm)
	if !ok {
		return nil, vaultpkg.SecretMetadata{}, fmt.Errorf("unexpected model type")
	}

	if f.canceled {
		return nil, vaultpkg.SecretMetadata{}, fmt.Errorf("canceled")
	}

	return f.Data(), f.SecretMetadata(), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
