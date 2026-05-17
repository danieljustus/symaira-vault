package agentskill

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixedTime is a deterministic timestamp used in tests that check output.
var fixedTime = time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)

// normalizeEOL converts CRLF to LF for cross-platform test consistency.
func normalizeEOL(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
}

func testVars(overrides TemplateVars) TemplateVars {
	v := TemplateVars{
		AgentName:          "hermes",
		ToolPrefix:         "mcp_openpass_",
		SlashPrefix:        "/openpass:",
		OpenPassVersion:    "4.0.0-test",
		ProfileTier:        "safe",
		VaultPath:          "~/.openpass",
		InstalledAt:        fixedTime.Format(time.RFC3339),
		SkillSchemaVersion: DefaultSkillSchemaVersion,
	}
	if overrides.AgentName != "" {
		v.AgentName = overrides.AgentName
	}
	if overrides.ToolPrefix != "" {
		v.ToolPrefix = overrides.ToolPrefix
	}
	if overrides.SlashPrefix != "" || overrides.SlashPrefix == "" && overrides.AgentName != "" {
		v.SlashPrefix = overrides.SlashPrefix
	}
	if overrides.OpenPassVersion != "" {
		v.OpenPassVersion = overrides.OpenPassVersion
	}
	if overrides.ProfileTier != "" {
		v.ProfileTier = overrides.ProfileTier
	}
	if overrides.VaultPath != "" {
		v.VaultPath = overrides.VaultPath
	}
	if overrides.InstalledAt != "" {
		v.InstalledAt = overrides.InstalledAt
	}
	return v
}

// TestRenderGolden tests that Render produces deterministic output that
// matches golden files for each supported agent.
func TestRenderGolden(t *testing.T) {
	tests := []struct {
		name      string
		agentName string
		vars      TemplateVars
	}{
		{
			name:      "hermes",
			agentName: "hermes",
			vars: testVars(TemplateVars{
				AgentName:   "hermes",
				ToolPrefix:  "mcp_openpass_",
				SlashPrefix: "/openpass:",
				ProfileTier: "safe",
			}),
		},
		{
			name:      "claude-code",
			agentName: "claude-code",
			vars: testVars(TemplateVars{
				AgentName:   "claude-code",
				ToolPrefix:  "mcp__openpass__",
				SlashPrefix: "/mcp__openpass__",
				ProfileTier: "standard",
			}),
		},
		{
			name:      "codex",
			agentName: "codex",
			vars: testVars(TemplateVars{
				AgentName:   "codex",
				ToolPrefix:  "mcp0_openpass_",
				SlashPrefix: "",
				ProfileTier: "admin",
			}),
		},
		{
			name:      "opencode",
			agentName: "opencode",
			vars: testVars(TemplateVars{
				AgentName:   "opencode",
				ToolPrefix:  "mcp0_op_",
				SlashPrefix: "/openpass:",
				ProfileTier: "standard",
			}),
		},
		{
			name:      "openclaw",
			agentName: "openclaw",
			vars: testVars(TemplateVars{
				AgentName:   "openclaw",
				ToolPrefix:  "mcp__openclaw_openpass__",
				SlashPrefix: "",
				ProfileTier: "custom",
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Render(tt.agentName, tt.vars)
			if err != nil {
				t.Fatalf("Render(%q) = %v", tt.agentName, err)
			}

			goldenPath := filepath.Join("testdata", t.Name()+".golden")

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				if os.IsNotExist(err) {
					t.Logf("golden file %s does not exist; creating from current output", goldenPath)
					if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
						t.Fatalf("create testdata dir: %v", err)
					}
					if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
						t.Fatalf("write golden file: %v", err)
					}
					return
				}
				t.Fatalf("read golden file: %v", err)
			}

			got = normalizeEOL(got)
			want = normalizeEOL(want)

			if !bytes.Equal(got, want) {
				// Show a useful diff by logging key differences.
				gotLines := strings.Split(string(got), "\n")
				wantLines := strings.Split(string(want), "\n")
				for i := 0; i < len(gotLines) && i < len(wantLines); i++ {
					if gotLines[i] != wantLines[i] {
						t.Logf("first diff at line %d:\n  got:  %q\n  want: %q", i+1, gotLines[i], wantLines[i])
						break
					}
				}
				if len(gotLines) != len(wantLines) {
					t.Logf("line count: got %d, want %d", len(gotLines), len(wantLines))
				}
				t.Errorf("rendered output for %q does not match golden file %s", tt.agentName, goldenPath)
			}
		})
	}
}

// TestRender_HashStable verifies that rendering the same input twice
// produces identical output (deterministic hashing when InstalledAt is set).
func TestRender_HashStable(t *testing.T) {
	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	first, err := Render("hermes", vars)
	if err != nil {
		t.Fatalf("first Render: %v", err)
	}

	second, err := Render("hermes", vars)
	if err != nil {
		t.Fatalf("second Render: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Error("rendered output differs between calls with same input")
	}
}

// TestRender_UnknownAgent verifies that an error is returned for unknown agents.
func TestRender_UnknownAgent(t *testing.T) {
	_, err := Render("nonexistent", TemplateVars{})
	if err == nil {
		t.Fatal("expected error for unknown agent")
	}
	if !strings.Contains(err.Error(), "unknown agent") {
		t.Errorf("error = %v, want 'unknown agent'", err)
	}
}

// TestOutputFileName verifies the output filename mapping.
func TestOutputFileName(t *testing.T) {
	tests := []struct {
		agent string
		want  string
	}{
		{"hermes", "SKILL.md"},
		{"claude-code", "SKILL.md"},
		{"codex", "AGENTS.md"},
		{"opencode", "SKILL.md"},
		{"openclaw", "SKILL.md"},
	}

	for _, tt := range tests {
		t.Run(tt.agent, func(t *testing.T) {
			got, err := OutputFileName(tt.agent)
			if err != nil {
				t.Fatalf("OutputFileName(%q) = %v", tt.agent, err)
			}
			if got != tt.want {
				t.Errorf("OutputFileName(%q) = %q, want %q", tt.agent, got, tt.want)
			}
		})
	}
}

// TestOutputFileName_Unknown verifies error for unknown agents.
func TestOutputFileName_Unknown(t *testing.T) {
	_, err := OutputFileName("unknown")
	if err == nil {
		t.Fatal("expected error for unknown agent")
	}
}

// TestSupportedAgents verifies the list is non-empty and contains expected names.
func TestSupportedAgents(t *testing.T) {
	agents := SupportedAgents()
	if len(agents) == 0 {
		t.Fatal("SupportedAgents() returned empty list")
	}

	found := make(map[string]bool)
	for _, a := range agents {
		found[a] = true
	}

	expected := []string{"hermes", "claude-code", "codex", "opencode", "openclaw"}
	for _, e := range expected {
		if !found[e] {
			t.Errorf("missing agent %q in SupportedAgents()", e)
		}
	}
}

// TestManifestParseGolden verifies that ParseManifest successfully extracts
// frontmatter from a rendered skill file.
func TestManifestParseGolden(t *testing.T) {
	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})
	rendered, err := Render("hermes", vars)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	manifest, err := ParseManifest(rendered)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}

	if manifest.Name != "openpass" {
		t.Errorf("manifest.Name = %q, want %q", manifest.Name, "openpass")
	}
	if manifest.ManagedBy != SentinelValue {
		t.Errorf("manifest.ManagedBy = %q, want %q", manifest.ManagedBy, SentinelValue)
	}
	if manifest.ManagedVersion != "4.0.0-test" {
		t.Errorf("manifest.ManagedVersion = %q, want %q", manifest.ManagedVersion, "4.0.0-test")
	}
	if manifest.ManagedProfileTier != "safe" {
		t.Errorf("manifest.ManagedProfileTier = %q, want %q", manifest.ManagedProfileTier, "safe")
	}
	if !strings.HasPrefix(manifest.ManagedHash, "sha256:") {
		t.Errorf("manifest.ManagedHash = %q, want sha256: prefix", manifest.ManagedHash)
	}
	if manifest.ManagedInstalledAt == "" {
		t.Error("manifest.ManagedInstalledAt is empty")
	}
}

// TestFindSentinel verifies sentinel detection.
func TestFindSentinel(t *testing.T) {
	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	rendered, err := Render("hermes", vars)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	if !FindSentinel(rendered) {
		t.Error("FindSentinel returned false for managed content")
	}

	unmanaged := []byte("---\nname: test\n---\n\nbody")
	if FindSentinel(unmanaged) {
		t.Error("FindSentinel returned true for unmanaged content")
	}

	if FindSentinel([]byte("no frontmatter")) {
		t.Error("FindSentinel returned true for content without frontmatter")
	}
}

// TestExtractBody verifies body extraction from rendered content.
func TestExtractBody(t *testing.T) {
	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	rendered, err := Render("hermes", vars)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	body, err := ExtractBody(rendered)
	if err != nil {
		t.Fatalf("ExtractBody: %v", err)
	}

	if len(body) == 0 {
		t.Fatal("ExtractBody returned empty body")
	}

	// Verify body starts with the expected content (the template body).
	if !bytes.HasPrefix(body, []byte("\n")) && !bytes.HasPrefix(body, []byte("#")) {
		t.Errorf("body does not start with expected content; first 20 bytes: %q", body[:min(20, len(body))])
	}
}

// TestExtractBody_NoFrontmatter verifies error for content without frontmatter.
func TestExtractBody_NoFrontmatter(t *testing.T) {
	_, err := ExtractBody([]byte("plain content without frontmatter"))
	if err == nil {
		t.Error("expected error for content without frontmatter")
	}
}

// TestHashBytes verifies the hash format.
func TestHashBytes(t *testing.T) {
	h := HashBytes([]byte("hello"))
	if !strings.HasPrefix(h, "sha256:") {
		t.Errorf("HashBytes prefix = %q, want %q", h[:7], "sha256:")
	}
	if len(h) != 7+64 { // sha256: + 64 hex chars
		t.Errorf("HashBytes length = %d, want %d", len(h), 7+64)
	}

	// Same input must produce same output.
	h2 := HashBytes([]byte("hello"))
	if h != h2 {
		t.Errorf("HashBytes not deterministic: %q != %q", h, h2)
	}
}

// TestVerifyHash verifies hash integrity checking.
func TestVerifyHash(t *testing.T) {
	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	rendered, err := Render("hermes", vars)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	if err := VerifyHash(normalizeEOL(rendered)); err != nil {
		t.Errorf("VerifyHash failed for valid content: %v", err)
	}

	// Tamper with the body.
	tampered := bytes.Replace(rendered, []byte("OpenPass is"), []byte("OpenPass was"), 1)
	if err := VerifyHash(tampered); err == nil {
		t.Error("VerifyHash should fail for tampered content")
	}
}

// TestInstall_FreshWrite verifies that Install writes a new file.
func TestInstall_FreshWrite(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")

	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	if err := Install("hermes", target, vars, false); err != nil {
		t.Fatalf("Install: %v", err)
	}

	if _, err := os.Stat(target); err != nil {
		t.Errorf("target file not created: %v", err)
	}

	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read installed file: %v", err)
	}

	if !FindSentinel(content) {
		t.Error("installed file missing sentinel")
	}
}

// TestInstall_Idempotent verifies that installing twice is a no-op.
func TestInstall_Idempotent(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")

	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	if err := Install("hermes", target, vars, false); err != nil {
		t.Fatalf("first Install: %v", err)
	}

	firstHash, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read first install: %v", err)
	}

	if err := Install("hermes", target, vars, false); err != nil {
		t.Fatalf("second Install: %v", err)
	}

	secondHash, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read second install: %v", err)
	}

	if !bytes.Equal(firstHash, secondHash) {
		t.Error("second install changed the file (not idempotent)")
	}

	// Verify no .bak file was created.
	if _, err := os.Stat(target + ".bak"); err == nil {
		t.Error("unexpected .bak file from idempotent install")
	}
}

// TestInstall_ReplacesManaged verifies that Install overwrites a managed file
// when content changes and creates a backup.
func TestInstall_ReplacesManaged(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")

	firstVars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
		ProfileTier: "safe",
	})

	if err := Install("hermes", target, firstVars, false); err != nil {
		t.Fatalf("first Install: %v", err)
	}

	secondVars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
		ProfileTier: "admin", // changed tier
	})

	if err := Install("hermes", target, secondVars, false); err != nil {
		t.Fatalf("second Install: %v", err)
	}

	// Verify backup was created.
	if _, err := os.Stat(target + ".bak"); err != nil {
		t.Errorf("backup file not created: %v", err)
	}
}

// TestInstall_UnmanagedFile verifies that Install refuses to overwrite
// unmanaged files without force.
func TestInstall_UnmanagedFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")

	if err := os.WriteFile(target, []byte("---\nname: custom\n---\n\nbody"), 0o644); err != nil {
		t.Fatalf("write unmanaged file: %v", err)
	}

	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	err := Install("hermes", target, vars, false)
	if err == nil {
		t.Fatal("expected error for unmanaged file")
	}
	if !strings.Contains(err.Error(), ErrUnmanagedFile.Error()) {
		t.Errorf("error = %v, want %v", err, ErrUnmanagedFile)
	}

	// With force=true it should succeed.
	if err := Install("hermes", target, vars, true); err != nil {
		t.Fatalf("Install with force: %v", err)
	}
}

// TestRefresh verifies Refresh updates an existing managed file.
func TestRefresh(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")

	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	if err := Install("hermes", target, vars, false); err != nil {
		t.Fatalf("Install: %v", err)
	}

	if err := Refresh("hermes", target, vars); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
}

// TestRefresh_NotInstalled verifies Refresh returns an error when the file
// does not exist.
func TestRefresh_NotInstalled(t *testing.T) {
	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	err := Refresh("hermes", "/nonexistent/path/SKILL.md", vars)
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

// TestRefresh_Unmanaged verifies Refresh returns an error for unmanaged files.
func TestRefresh_Unmanaged(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")

	if err := os.WriteFile(target, []byte("---\nname: custom\n---\n\nbody"), 0o644); err != nil {
		t.Fatalf("write unmanaged file: %v", err)
	}

	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	err := Refresh("hermes", target, vars)
	if err == nil {
		t.Fatal("expected error for unmanaged file")
	}
}

// TestUninstall verifies Uninstall removes a managed file.
func TestUninstall(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")

	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	if err := Install("hermes", target, vars, false); err != nil {
		t.Fatalf("Install: %v", err)
	}

	if err := Uninstall(target); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	if _, err := os.Stat(target); err == nil {
		t.Error("file still exists after Uninstall")
	}
}

// TestUninstall_NotExists verifies Uninstall is idempotent when the file
// does not exist.
func TestUninstall_NotExists(t *testing.T) {
	if err := Uninstall("/nonexistent/path/SKILL.md"); err != nil {
		t.Errorf("Uninstall on non-existent file: %v", err)
	}
}

// TestUninstall_Unmanaged verifies Uninstall refuses to delete unmanaged files.
func TestUninstall_Unmanaged(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")

	if err := os.WriteFile(target, []byte("---\nname: custom\n---\n\nbody"), 0o644); err != nil {
		t.Fatalf("write unmanaged file: %v", err)
	}

	err := Uninstall(target)
	if err == nil {
		t.Fatal("expected error for unmanaged file")
	}

	// File should still exist.
	if _, err := os.Stat(target); err != nil {
		t.Errorf("file was deleted despite being unmanaged")
	}
}

// TestExport verifies that Export produces a valid tar.gz with expected files.
func TestExport(t *testing.T) {
	var buf bytes.Buffer

	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	if err := Export("hermes", vars, &buf); err != nil {
		t.Fatalf("Export: %v", err)
	}

	if buf.Len() == 0 {
		t.Fatal("Export produced empty output")
	}

	// Read back the tar.gz archive.
	gr, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	var foundFiles []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next: %v", err)
		}

		foundFiles = append(foundFiles, hdr.Name)

		// Verify content is non-empty.
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read tar entry %s: %v", hdr.Name, err)
		}
		if len(content) == 0 {
			t.Errorf("tar entry %s is empty", hdr.Name)
		}
	}

	if len(foundFiles) == 0 {
		t.Fatal("tar archive contains no files")
	}

	hasSkill := false
	hasInstall := false
	for _, f := range foundFiles {
		switch f {
		case "SKILL.md":
			hasSkill = true
		case "INSTALL.md":
			hasInstall = true
		}
	}

	if !hasSkill {
		t.Errorf("tar archive missing SKILL.md; found: %v", foundFiles)
	}
	if !hasInstall {
		t.Errorf("tar archive missing INSTALL.md; found: %v", foundFiles)
	}
}

// TestExportToFile verifies that ExportToFile writes a valid tar.gz to disk.
func TestExportToFile(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "skill.tar.gz")

	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	if err := ExportToFile("hermes", vars, output); err != nil {
		t.Fatalf("ExportToFile: %v", err)
	}

	if _, err := os.Stat(output); err != nil {
		t.Errorf("export file not created: %v", err)
	}

	// Verify it's valid gzip.
	f, err := os.Open(output)
	if err != nil {
		t.Fatalf("open export: %v", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gr.Close()
}

// TestVerifyRender verifies the VerifyRender function.
func TestVerifyRender(t *testing.T) {
	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	rendered, err := Render("hermes", vars)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	match, err := VerifyRender("hermes", vars, rendered)
	if err != nil {
		t.Fatalf("VerifyRender: %v", err)
	}
	if !match {
		t.Error("VerifyRender returned false for valid content")
	}
}

// TestPrefixConfig carries different prefix configurations.
// This test ensures that agent-specific templates render correctly
// with their expected tool prefixes and slash prefixes.
func TestPrefixConfig(t *testing.T) {
	tests := []struct {
		name        string
		agent       string
		toolPrefix  string
		slashPrefix string
	}{
		{
			name:        "hermes",
			agent:       "hermes",
			toolPrefix:  "mcp_openpass_",
			slashPrefix: "/openpass:",
		},
		{
			name:        "claude-code",
			agent:       "claude-code",
			toolPrefix:  "mcp__openpass__",
			slashPrefix: "/mcp__openpass__",
		},
		{
			name:        "codex",
			agent:       "codex",
			toolPrefix:  "mcp0_op_",
			slashPrefix: "",
		},
		{
			name:        "opencode",
			agent:       "opencode",
			toolPrefix:  "mcp_op_",
			slashPrefix: "/op:",
		},
		{
			name:        "openclaw",
			agent:       "openclaw",
			toolPrefix:  "mcp__oc_op__",
			slashPrefix: "/openclaw_op:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vars := testVars(TemplateVars{
				AgentName:   tt.agent,
				ToolPrefix:  tt.toolPrefix,
				SlashPrefix: tt.slashPrefix,
			})

			rendered, err := Render(tt.agent, vars)
			if err != nil {
				t.Fatalf("Render(%q): %v", tt.agent, err)
			}

			// Verify the tool prefix appears in the rendered content.
			if !bytes.Contains(rendered, []byte(tt.toolPrefix)) {
				t.Errorf("rendered content missing tool prefix %q", tt.toolPrefix)
			}

			// Verify the manifest parses correctly.
			manifest, err := ParseManifest(rendered)
			if err != nil {
				t.Fatalf("ParseManifest: %v", err)
			}
			if !strings.HasPrefix(manifest.ManagedHash, "sha256:") {
				t.Errorf("bad hash prefix: %q", manifest.ManagedHash)
			}
		})
	}
}

// TestInstall_RoundTrip verifies a full install → read → uninstall cycle.
func TestInstall_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")

	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	if err := Install("hermes", target, vars, false); err != nil {
		t.Fatalf("Install: %v", err)
	}

	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Verify hash integrity.
	if err := VerifyHash(normalizeEOL(content)); err != nil {
		t.Errorf("VerifyHash after install: %v", err)
	}

	// Uninstall.
	if err := Uninstall(target); err != nil {
		t.Fatalf("Uninstall: %v", err)
	}

	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("file still exists after uninstall")
	}
}

// TestManifest_BodyHashConsistency verifies that the hash in the manifest
// matches the body hash of the rendered content.
func TestManifest_BodyHashConsistency(t *testing.T) {
	vars := testVars(TemplateVars{
		AgentName:   "hermes",
		ToolPrefix:  "mcp_openpass_",
		SlashPrefix: "/openpass:",
	})

	rendered, err := Render("hermes", vars)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	rendered = normalizeEOL(rendered)
	body, err := ExtractBody(rendered)
	if err != nil {
		t.Fatalf("ExtractBody: %v", err)
	}
	body = normalizeEOL(body)

	expectedHash := HashBytes(body)

	manifest, err := ParseManifest(rendered)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}

	if manifest.ManagedHash != expectedHash {
		t.Errorf("hash mismatch:\n  manifest: %s\n  computed: %s", manifest.ManagedHash, expectedHash)
	}
}

// TestProfileTiers renders with each profile tier and verifies the content
// contains the expected tier-specific text.
func TestProfileTiers(t *testing.T) {
	tiers := []struct {
		tier   string
		expect string // substring expected in rendered output
	}{
		{"safe", "Limited access"},
		{"standard", "but you"},
		{"admin", "full read"},
		{"custom", "custom permission overrides"},
	}

	for _, tt := range tiers {
		t.Run(tt.tier, func(t *testing.T) {
			vars := testVars(TemplateVars{
				AgentName:   "hermes",
				ToolPrefix:  "mcp_openpass_",
				SlashPrefix: "/openpass:",
				ProfileTier: tt.tier,
			})

			rendered, err := Render("hermes", vars)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}

			if !bytes.Contains(rendered, []byte(tt.expect)) {
				t.Errorf("rendered content missing expected text %q for tier %q", tt.expect, tt.tier)
			}

			manifest, err := ParseManifest(rendered)
			if err != nil {
				t.Fatalf("ParseManifest: %v", err)
			}
			if manifest.ManagedProfileTier != tt.tier {
				t.Errorf("manifest.ManagedProfileTier = %q, want %q", manifest.ManagedProfileTier, tt.tier)
			}
		})
	}
}

// TestParseManifest_NoFrontmatter verifies ParseManifest error handling.
func TestParseManifest_NoFrontmatter(t *testing.T) {
	_, err := ParseManifest([]byte("no frontmatter here"))
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestParseManifest_Incomplete verifies error for incomplete frontmatter.
func TestParseManifest_Incomplete(t *testing.T) {
	_, err := ParseManifest([]byte("---\nkey: value\n"))
	if err == nil {
		t.Fatal("expected error for incomplete frontmatter")
	}
}

// TestParseHashValue verifies hash value parsing.
func TestParseHashValue(t *testing.T) {
	hexVal := "abc123def456"
	input := "sha256:" + hexVal

	got, err := ParseHashValue(input)
	if err != nil {
		t.Fatalf("ParseHashValue: %v", err)
	}
	if got != hexVal {
		t.Errorf("ParseHashValue = %q, want %q", got, hexVal)
	}

	// Missing prefix.
	_, err = ParseHashValue("abc123")
	if err == nil {
		t.Error("expected error for missing sha256: prefix")
	}

	// Empty hash.
	_, err = ParseHashValue("sha256:")
	if err == nil {
		t.Error("expected error for empty hash")
	}
}
