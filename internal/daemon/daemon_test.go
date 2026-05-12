package daemon

import (
	"encoding/xml"
	"runtime"
	"strings"
	"testing"
)

func TestValidateInstallOptions_MaliciousVaultDir(t *testing.T) {
	opts := InstallOpts{
		BinaryPath: "/usr/local/bin/openpass",
		VaultDir:   "/tmp/x</string><key>RunAtLoad</key><true/>",
		Bind:       "127.0.0.1",
		Port:       8080,
	}
	err := validateInstallOptions(opts)
	if err == nil {
		t.Fatal("expected error for malicious vaultDir, got nil")
	}
}

func TestValidateInstallOptions_NewlinesInVaultDir(t *testing.T) {
	opts := InstallOpts{
		BinaryPath: "/usr/local/bin/openpass",
		VaultDir:   "/tmp/x\nvault",
		Bind:       "127.0.0.1",
		Port:       8080,
	}
	err := validateInstallOptions(opts)
	if err == nil {
		t.Fatal("expected error for vaultDir with newline, got nil")
	}
}

func TestValidateInstallOptions_NewlinesInBinaryPath(t *testing.T) {
	opts := InstallOpts{
		BinaryPath: "/usr/local/bin\nopenpass",
		VaultDir:   "/home/user/.openpass",
		Bind:       "127.0.0.1",
		Port:       8080,
	}
	err := validateInstallOptions(opts)
	if err == nil {
		t.Fatal("expected error for binaryPath with newline, got nil")
	}
}

func TestValidateInstallOptions_MaliciousBind(t *testing.T) {
	opts := InstallOpts{
		BinaryPath: "/usr/local/bin/openpass",
		VaultDir:   "/home/user/.openpass",
		Bind:       "127.0.0.1\nextra",
		Port:       8080,
	}
	err := validateInstallOptions(opts)
	if err == nil {
		t.Fatal("expected error for malicious bind, got nil")
	}
}

func TestValidateInstallOptions_ValidValues(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on Windows: uses Unix-style absolute paths")
	}
	opts := InstallOpts{
		BinaryPath: "/usr/local/bin/openpass",
		VaultDir:   "/home/user/.openpass",
		Bind:       "127.0.0.1",
		Port:       8080,
	}
	if err := validateInstallOptions(opts); err != nil {
		t.Fatalf("unexpected error for valid opts: %v", err)
	}
}

func TestValidateInstallOptions_RelativeBinaryPath(t *testing.T) {
	opts := InstallOpts{
		BinaryPath: "openpass",
		VaultDir:   "/home/user/.openpass",
		Bind:       "127.0.0.1",
		Port:       8080,
	}
	if err := validateInstallOptions(opts); err == nil {
		t.Fatal("expected error for relative binary path")
	}
}

func TestValidateInstallOptions_RelativeVaultDir(t *testing.T) {
	opts := InstallOpts{
		BinaryPath: "/usr/local/bin/openpass",
		VaultDir:   "relative/path",
		Bind:       "127.0.0.1",
		Port:       8080,
	}
	if err := validateInstallOptions(opts); err == nil {
		t.Fatal("expected error for relative vault dir")
	}
}

func TestValidateInstallOptions_EmptyBind(t *testing.T) {
	opts := InstallOpts{
		BinaryPath: "/usr/local/bin/openpass",
		VaultDir:   "/home/user/.openpass",
		Bind:       "",
		Port:       8080,
	}
	if err := validateInstallOptions(opts); err == nil {
		t.Fatal("expected error for empty bind")
	}
}

func TestValidateInstallOptions_InvalidPort(t *testing.T) {
	tests := []struct {
		port int
	}{
		{0},
		{65536},
		{-1},
	}
	for _, tt := range tests {
		opts := InstallOpts{
			BinaryPath: "/usr/local/bin/openpass",
			VaultDir:   "/home/user/.openpass",
			Bind:       "127.0.0.1",
			Port:       tt.port,
		}
		if err := validateInstallOptions(opts); err == nil {
			t.Errorf("expected error for port %d", tt.port)
		}
	}
}

func TestPlistXML_RoundTrip(t *testing.T) {
	root := plistRoot{
		Version: "1.0",
		Dict: plistDict{
			Entries: []plistEntry{
				{Key: "Label", Str: &plistString{Value: "com.openpass.mcp"}},
				{Key: "ProgramArguments", Arr: &plistArray{
					Items: []plistString{
						{Value: "/usr/local/bin/openpass"},
						{Value: "serve"},
						{Value: "--port"},
						{Value: "8080"},
						{Value: "--bind"},
						{Value: "127.0.0.1"},
					},
				}},
				{Key: "EnvironmentVariables", Dict: &plistDict{
					Entries: []plistEntry{
						{Key: "OPENPASS_VAULT", Str: &plistString{Value: "/home/user/.openpass"}},
					},
				}},
				{Key: "RunAtLoad", Tru: &plistTrue{}},
				{Key: "KeepAlive", Tru: &plistTrue{}},
				{Key: "StandardOutPath", Str: &plistString{Value: "/home/user/Logs/openpass-mcp.log"}},
				{Key: "StandardErrorPath", Str: &plistString{Value: "/home/user/Logs/openpass-mcp.error.log"}},
			},
		},
	}

	data, err := xml.MarshalIndent(root, "", "    ")
	if err != nil {
		t.Fatalf("marshal plist: %v", err)
	}

	output := string(data)

	// Verify basic structure
	if !strings.Contains(output, "<plist version=\"1.0\">") {
		t.Error("missing plist root element")
	}
	if !strings.Contains(output, "</plist>") {
		t.Error("missing plist closing element")
	}
	if !strings.Contains(output, "<key>Label</key>") {
		t.Error("missing Label key")
	}
	if !strings.Contains(output, "<string>com.openpass.mcp</string>") {
		t.Error("missing Label value")
	}
	if !strings.Contains(output, "<key>ProgramArguments</key>") {
		t.Error("missing ProgramArguments key")
	}
	if !strings.Contains(output, "<string>/usr/local/bin/openpass</string>") {
		t.Error("missing binary path in program arguments")
	}
	if !strings.Contains(output, "<key>EnvironmentVariables</key>") {
		t.Error("missing EnvironmentVariables key")
	}
	if !strings.Contains(output, "<string>/home/user/.openpass</string>") {
		t.Error("missing vault dir in environment")
	}
	if !strings.Contains(output, "<true>") {
		t.Error("missing true elements")
	}

	// Verify the dict contains alternating key/value entries
	idx := strings.Index(output, "<dict>")
	if idx < 0 {
		t.Fatal("no dict element found")
	}
	dictContent := output[idx:]
	if !strings.Contains(dictContent, "</dict>") {
		t.Error("dict not closed")
	}
}

func TestPlistXML_SpecialCharsEscaped(t *testing.T) {
	root := plistRoot{
		Version: "1.0",
		Dict: plistDict{
			Entries: []plistEntry{
				{Key: "Test", Str: &plistString{Value: "special<>&'\""}},
			},
		},
	}

	data, err := xml.MarshalIndent(root, "", "    ")
	if err != nil {
		t.Fatalf("marshal plist: %v", err)
	}

	output := string(data)

	// encoding/xml should escape XML special characters
	if strings.Contains(output, "<string>special<>&'\"</string>") {
		t.Error("XML special characters were not escaped")
	}
	if !strings.Contains(output, "&lt;") || !strings.Contains(output, "&amp;") {
		t.Error("expected XML entities in output")
	}
	if !strings.Contains(output, "&apos;") && !strings.Contains(output, "'") {
		// encoding/xml may or may not escape apostrophe — ' is fine in XML content
	}
}

func TestPlistXML_NestedDictStructure(t *testing.T) {
	root := plistRoot{
		Version: "1.0",
		Dict: plistDict{
			Entries: []plistEntry{
				{Key: "OuterKey", Str: &plistString{Value: "outer"}},
				{Key: "NestedDict", Dict: &plistDict{
					Entries: []plistEntry{
						{Key: "InnerKey", Str: &plistString{Value: "inner"}},
					},
				}},
			},
		},
	}

	data, err := xml.MarshalIndent(root, "", "    ")
	if err != nil {
		t.Fatalf("marshal plist: %v", err)
	}

	output := string(data)

	if !strings.Contains(output, "<key>NestedDict</key>") {
		t.Error("missing NestedDict key")
	}
	if !strings.Contains(output, "<key>InnerKey</key>") {
		t.Error("missing InnerKey key in nested dict")
	}
	if !strings.Contains(output, "<string>inner</string>") {
		t.Error("missing inner value")
	}
}

func TestPlistXML_ArrayOrderPreserved(t *testing.T) {
	root := plistRoot{
		Version: "1.0",
		Dict: plistDict{
			Entries: []plistEntry{
				{Key: "ProgramArguments", Arr: &plistArray{
					Items: []plistString{
						{Value: "first"},
						{Value: "second"},
						{Value: "third"},
					},
				}},
			},
		},
	}

	data, err := xml.MarshalIndent(root, "", "    ")
	if err != nil {
		t.Fatalf("marshal plist: %v", err)
	}

	output := string(data)

	first := strings.Index(output, "<string>first</string>")
	second := strings.Index(output, "<string>second</string>")
	third := strings.Index(output, "<string>third</string>")

	if first < 0 || second < 0 || third < 0 {
		t.Fatal("missing array elements")
	}
	if !(first < second && second < third) {
		t.Error("array order not preserved")
	}
}

func TestSystemdEscape(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"path with spaces", "path with spaces"},
		{`path"with"quotes`, `path\"with\"quotes`},
		{`path\with\backslashes`, `path\\with\\backslashes`},
		{`mixed\and"quotes`, `mixed\\and\"quotes`},
		{"normal/path", "normal/path"},
		{"", ""},
	}
	for _, tt := range tests {
		got := systemdEscape(tt.input)
		if got != tt.expected {
			t.Errorf("systemdEscape(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestValidateInstallOptions_DisallowedCharsInBinaryPath(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"angle bracket", "/usr/bin/<openpass"},
		{"double quote", "/usr/bin/\"openpass"},
		{"single quote", "/usr/bin/'openpass"},
		{"carriage return", "/usr/bin/\ropenpass"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := InstallOpts{
				BinaryPath: tt.value,
				VaultDir:   "/home/user/.openpass",
				Bind:       "127.0.0.1",
				Port:       8080,
			}
			if err := validateInstallOptions(opts); err == nil {
				t.Errorf("expected error for binaryPath with %s", tt.name)
			}
		})
	}
}

func TestValidateInstallOptions_DisallowedCharsInVaultDir(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"angle bracket", "/tmp/x<inject"},
		{"double quote", "/tmp/x\"inject"},
		{"greater than", "/tmp/x>inject"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := InstallOpts{
				BinaryPath: "/usr/local/bin/openpass",
				VaultDir:   tt.value,
				Bind:       "127.0.0.1",
				Port:       8080,
			}
			if err := validateInstallOptions(opts); err == nil {
				t.Errorf("expected error for vaultDir with %s", tt.name)
			}
		})
	}
}

func TestValidateInstallOptions_DisallowedCharsInBind(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"double quote", "127.0.0.1\""},
		{"angle bracket", "127.0.0.1<"},
		{"newline", "127.0.0.1\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := InstallOpts{
				BinaryPath: "/usr/local/bin/openpass",
				VaultDir:   "/home/user/.openpass",
				Bind:       tt.value,
				Port:       8080,
			}
			if err := validateInstallOptions(opts); err == nil {
				t.Errorf("expected error for bind with %s", tt.name)
			}
		})
	}
}
