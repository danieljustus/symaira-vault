// Package daemon provides cross-platform service management for
// installing, uninstalling, and checking the status of the OpenPass
// MCP server as a background service (launchd on macOS, systemd on Linux).
package daemon

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/template"

	"github.com/danieljustus/OpenPass/internal/config"
	errorspkg "github.com/danieljustus/OpenPass/internal/errors"
)

const (
	// macOS launchd paths
	launchAgentDir      = "LaunchAgents"
	launchAgentLabel    = "com.openpass.mcp"
	launchAgentFileName = "com.openpass.mcp.plist"
	logDir              = "Logs"
	logFileName         = "openpass-mcp.log"
	errorLogFileName    = "openpass-mcp.error.log"

	// Linux systemd paths
	systemdUserDir  = ".config/systemd/user"
	systemdUnitName = "openpass-mcp.service"
)

// Linux systemd service template — values are pre-escaped before rendering
const systemdTmpl = `[Unit]
Description=OpenPass MCP Server

[Service]
Type=simple
ExecStart="{{.BinaryPath}}" serve --port {{.PortStr}} --bind "{{.Bind}}"
Environment="OPENPASS_VAULT={{.VaultDir}}"
Restart=on-failure

[Install]
WantedBy=default.target
`

// tmplData holds the values substituted into the systemd service file template.
type tmplData struct {
	BinaryPath string
	VaultDir   string
	PortStr    string
	Bind       string
}

// InstallOpts contains the user-supplied installation values to validate.
type InstallOpts struct {
	BinaryPath string
	VaultDir   string
	Bind       string
	Port       int
}

// hasDisallowedChars returns true if s contains characters that would allow
// template injection in plist XML or systemd unit files.
func hasDisallowedChars(s string) bool {
	return strings.ContainsAny(s, "\n\r<>\"'")
}

// validateInstallOptions validates that all user-supplied options are safe
// for template rendering. It must be called before any template execution.
func validateInstallOptions(opts InstallOpts) error {
	var errs []string

	if !filepath.IsAbs(opts.BinaryPath) {
		errs = append(errs, "binary path must be an absolute path")
	} else if hasDisallowedChars(opts.BinaryPath) {
		errs = append(errs, "binary path contains disallowed characters (newlines or <>\"')")
	}

	if !filepath.IsAbs(opts.VaultDir) {
		errs = append(errs, "vault directory must be an absolute path")
	} else if hasDisallowedChars(opts.VaultDir) {
		errs = append(errs, "vault directory contains disallowed characters (newlines or <>\"')")
	}

	if opts.Bind == "" {
		errs = append(errs, "bind address must not be empty")
	} else if hasDisallowedChars(opts.Bind) {
		errs = append(errs, "bind address contains disallowed characters (newlines or <>\"')")
	}

	if opts.Port < 1 || opts.Port > 65535 {
		errs = append(errs, "port must be between 1 and 65535")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid installation options: %s", strings.Join(errs, "; "))
	}
	return nil
}

// systemdEscape escapes a value for safe inclusion in a systemd unit file.
// Backslashes and double-quotes are escaped per systemd.syntax rules.
func systemdEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// ---------------------------------------------------------------------------
// Plist XML types — constructed via encoding/xml for automatic XML escaping
// ---------------------------------------------------------------------------

// plistKey is an XML <key> element.
type plistKey struct {
	XMLName xml.Name `xml:"key"`
	Value   string   `xml:",chardata"`
}

// plistString is an XML <string> element.
type plistString struct {
	XMLName xml.Name `xml:"string"`
	Value   string   `xml:",chardata"`
}

// plistArray is an <array> containing <string> elements.
type plistArray struct {
	XMLName xml.Name      `xml:"array"`
	Items   []plistString `xml:"string"`
}

// plistTrue is a self-closing <true/> element.
type plistTrue struct {
	XMLName xml.Name `xml:"true"`
}

// plistEntry is a single <key><value> pair within a <dict>.
// Exactly one of Str, Arr, Tru, or Dict must be set.
type plistEntry struct {
	Key  string
	Str  *plistString
	Arr  *plistArray
	Tru  *plistTrue
	Dict *plistDict
}

// plistDict is an XML <dict> with alternating <key> / <value> entries.
type plistDict struct {
	XMLName xml.Name `xml:"dict"`
	Entries []plistEntry
}

// MarshalXML implements xml.Marshaler for plistDict, emitting alternating
// <key>K</key><V>V</V> pairs to match the plist DTD requirements.
func (d plistDict) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	for _, entry := range d.Entries {
		if err := e.EncodeElement(plistKey{Value: entry.Key},
			xml.StartElement{Name: xml.Name{Local: "key"}}); err != nil {
			return err
		}
		var err error
		switch {
		case entry.Str != nil:
			err = e.EncodeElement(entry.Str,
				xml.StartElement{Name: xml.Name{Local: "string"}})
		case entry.Arr != nil:
			err = e.EncodeElement(entry.Arr,
				xml.StartElement{Name: xml.Name{Local: "array"}})
		case entry.Tru != nil:
			err = e.EncodeElement(entry.Tru,
				xml.StartElement{Name: xml.Name{Local: "true"}})
		case entry.Dict != nil:
			err = e.EncodeElement(entry.Dict,
				xml.StartElement{Name: xml.Name{Local: "dict"}})
		default:
			return fmt.Errorf("plist entry %q has no value", entry.Key)
		}
		if err != nil {
			return err
		}
	}
	return e.EncodeToken(start.End())
}

// plistRoot is the top-level <plist> element wrapping a single <dict>.
type plistRoot struct {
	XMLName xml.Name  `xml:"plist"`
	Version string    `xml:"version,attr"`
	Dict    plistDict `xml:"dict"`
}

// Installer manages the OpenPass MCP background service on the current platform.
type Installer struct {
	binaryPath string
	vaultDir   string
	port       int
	bind       string
	logPath    string
	errLogPath string
}

// NewInstaller creates an Installer for the given configuration and vault directory.
// If cfg or cfg.MCP is nil, default port (8080) and bind (127.0.0.1) are used.
func NewInstaller(cfg *config.Config, vaultDir string) (*Installer, error) {
	binaryPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("get executable path: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home directory: %w", err)
	}

	port := 8080
	bind := "127.0.0.1"
	if cfg != nil && cfg.MCP != nil {
		if cfg.MCP.Port > 0 {
			port = cfg.MCP.Port
		}
		if cfg.MCP.Bind != "" {
			bind = cfg.MCP.Bind
		}
	}

	return &Installer{
		binaryPath: binaryPath,
		vaultDir:   vaultDir,
		port:       port,
		bind:       bind,
		logPath:    filepath.Join(home, logDir, logFileName),
		errLogPath: filepath.Join(home, logDir, errorLogFileName),
	}, nil
}

// Install installs the MCP server as a background service on the current platform.
func (i *Installer) Install() error {
	opts := InstallOpts{
		BinaryPath: i.binaryPath,
		VaultDir:   i.vaultDir,
		Bind:       i.bind,
		Port:       i.port,
	}
	if err := validateInstallOptions(opts); err != nil {
		return err
	}

	switch runtime.GOOS {
	case "darwin":
		return i.installDarwin()
	case "linux":
		return i.installLinux()
	default:
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError,
			fmt.Sprintf("unsupported platform: %s; service templates are available for macOS (launchd) and Linux (systemd)", runtime.GOOS),
			nil)
	}
}

// Uninstall removes the MCP server background service from the current platform.
func (i *Installer) Uninstall() error {
	switch runtime.GOOS {
	case "darwin":
		return i.uninstallDarwin()
	case "linux":
		return i.uninstallLinux()
	default:
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError,
			fmt.Sprintf("unsupported platform: %s", runtime.GOOS),
			nil)
	}
}

// Status returns the service status: "running", "stopped", or "not installed".
func (i *Installer) Status() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return i.statusDarwin()
	case "linux":
		return i.statusLinux()
	default:
		return "", errorspkg.NewCLIError(errorspkg.ExitGeneralError,
			fmt.Sprintf("unsupported platform: %s", runtime.GOOS),
			nil)
	}
}

// VaultDir returns the vault directory configured for the service.
func (i *Installer) VaultDir() string {
	return i.vaultDir
}

// Port returns the port configured for the service.
func (i *Installer) Port() int {
	return i.port
}

// Bind returns the bind address configured for the service.
func (i *Installer) Bind() string {
	return i.bind
}

// BinaryPath returns the path to the openpass binary.
func (i *Installer) BinaryPath() string {
	return i.binaryPath
}

// ServiceFilePath returns the path to the service definition file for the current platform.
func (i *Installer) ServiceFilePath() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return i.darwinPlistPath()
	case "linux":
		return i.linuxServicePath()
	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// ---------------------------------------------------------------------------
// Darwin (macOS launchd)
// ---------------------------------------------------------------------------

func (i *Installer) darwinPlistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home directory: %w", err)
	}
	return filepath.Join(home, launchAgentDir, launchAgentFileName), nil
}

func (i *Installer) installDarwin() error {
	plistPath, err := i.darwinPlistPath()
	if err != nil {
		return err
	}

	if err := i.writePlist(plistPath); err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitPermissionDenied,
			"failed to write launchd plist", err)
	}

	// Unload any existing instance first (ignore errors)
	// #nosec G204 -- plistPath is generated internally by darwinPlistPath()
	_ = exec.Command("launchctl", "unload", plistPath).Run()

	// #nosec G204 -- plistPath is generated internally by darwinPlistPath()
	if out, err := exec.Command("launchctl", "load", plistPath).CombinedOutput(); err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError,
			fmt.Sprintf("failed to load launchd service: %s", strings.TrimSpace(string(out))),
			err)
	}

	return nil
}

func (i *Installer) uninstallDarwin() error {
	plistPath, err := i.darwinPlistPath()
	if err != nil {
		return err
	}

	// Try to unload (best-effort)
	// #nosec G204 -- plistPath is generated internally by darwinPlistPath()
	_ = exec.Command("launchctl", "unload", plistPath).Run()

	if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
		return errorspkg.NewCLIError(errorspkg.ExitPermissionDenied,
			"failed to remove launchd plist", err)
	}

	return nil
}

func (i *Installer) statusDarwin() (string, error) {
	plistPath, err := i.darwinPlistPath()
	if err != nil {
		return "", err
	}

	if _, statErr := os.Stat(plistPath); os.IsNotExist(statErr) {
		return "not installed", nil
	}

	out, err := exec.Command("launchctl", "list", launchAgentLabel).CombinedOutput()
	if err != nil {
		return "stopped", nil
	}

	// launchctl list outputs status, PID, name on lines
	output := strings.TrimSpace(string(out))
	if strings.Contains(output, launchAgentLabel) {
		fields := strings.Fields(output)
		if len(fields) >= 2 && fields[0] != "-" {
			return "running", nil
		}
	}

	return "stopped", nil
}

func (i *Installer) writePlist(path string) error {
	opts := InstallOpts{
		BinaryPath: i.binaryPath,
		VaultDir:   i.vaultDir,
		Bind:       i.bind,
		Port:       i.port,
	}
	if err := validateInstallOptions(opts); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(i.logPath), 0o700); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	buf.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")

	root := plistRoot{
		Version: "1.0",
		Dict: plistDict{
			Entries: []plistEntry{
				{Key: "Label", Str: &plistString{Value: "com.openpass.mcp"}},
				{Key: "ProgramArguments", Arr: &plistArray{
					Items: []plistString{
						{Value: i.binaryPath},
						{Value: "serve"},
						{Value: "--port"},
						{Value: strconv.Itoa(i.port)},
						{Value: "--bind"},
						{Value: i.bind},
					},
				}},
				{Key: "EnvironmentVariables", Dict: &plistDict{
					Entries: []plistEntry{
						{Key: "OPENPASS_VAULT", Str: &plistString{Value: i.vaultDir}},
					},
				}},
				{Key: "RunAtLoad", Tru: &plistTrue{}},
				{Key: "KeepAlive", Tru: &plistTrue{}},
				{Key: "StandardOutPath", Str: &plistString{Value: i.logPath}},
				{Key: "StandardErrorPath", Str: &plistString{Value: i.errLogPath}},
			},
		},
	}

	encoder := xml.NewEncoder(&buf)
	encoder.Indent("", "    ")
	if err := encoder.Encode(root); err != nil {
		return fmt.Errorf("encode plist XML: %w", err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Linux (systemd user)
// ---------------------------------------------------------------------------

func (i *Installer) linuxServicePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home directory: %w", err)
	}
	return filepath.Join(home, systemdUserDir, systemdUnitName), nil
}

func (i *Installer) installLinux() error {
	svcPath, err := i.linuxServicePath()
	if err != nil {
		return err
	}

	if err := i.writeService(svcPath); err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitPermissionDenied,
			"failed to write systemd service file", err)
	}

	if out, err := exec.Command("systemctl", "--user", "daemon-reload").CombinedOutput(); err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError,
			fmt.Sprintf("systemctl daemon-reload failed: %s", strings.TrimSpace(string(out))),
			err)
	}

	if out, err := exec.Command("systemctl", "--user", "enable", "openpass-mcp").CombinedOutput(); err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError,
			fmt.Sprintf("systemctl enable failed: %s", strings.TrimSpace(string(out))),
			err)
	}

	if out, err := exec.Command("systemctl", "--user", "start", "openpass-mcp").CombinedOutput(); err != nil {
		return errorspkg.NewCLIError(errorspkg.ExitGeneralError,
			fmt.Sprintf("systemctl start failed: %s", strings.TrimSpace(string(out))),
			err)
	}

	return nil
}

func (i *Installer) uninstallLinux() error {
	// Best-effort stop and disable
	_ = exec.Command("systemctl", "--user", "stop", "openpass-mcp").Run()
	_ = exec.Command("systemctl", "--user", "disable", "openpass-mcp").Run()

	svcPath, err := i.linuxServicePath()
	if err != nil {
		return err
	}

	if err := os.Remove(svcPath); err != nil && !os.IsNotExist(err) {
		return errorspkg.NewCLIError(errorspkg.ExitPermissionDenied,
			"failed to remove systemd service file", err)
	}

	// Reload to pick up the removal
	_ = exec.Command("systemctl", "--user", "daemon-reload").Run()

	return nil
}

func (i *Installer) statusLinux() (string, error) {
	svcPath, err := i.linuxServicePath()
	if err != nil {
		return "", err
	}

	if _, statErr := os.Stat(svcPath); os.IsNotExist(statErr) {
		return "not installed", nil
	}

	out, err := exec.Command("systemctl", "--user", "is-active", "openpass-mcp").CombinedOutput()
	if err != nil {
		output := strings.TrimSpace(string(out))
		if output == "inactive" || output == "failed" {
			return "stopped", nil
		}
		return "stopped", nil
	}

	output := strings.TrimSpace(string(out))
	if output == "active" {
		return "running", nil
	}

	return "stopped", nil
}

func (i *Installer) writeService(path string) error {
	opts := InstallOpts{
		BinaryPath: i.binaryPath,
		VaultDir:   i.vaultDir,
		Bind:       i.bind,
		Port:       i.port,
	}
	if err := validateInstallOptions(opts); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	data := tmplData{
		BinaryPath: systemdEscape(i.binaryPath),
		VaultDir:   systemdEscape(i.vaultDir),
		PortStr:    strconv.Itoa(i.port),
		Bind:       systemdEscape(i.bind),
	}

	tmpl, err := template.New("service").Parse(systemdTmpl)
	if err != nil {
		return fmt.Errorf("parse service template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("render service template: %w", err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write service file: %w", err)
	}

	return nil
}
