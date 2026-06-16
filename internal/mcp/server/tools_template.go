package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/template"
)

func (s *Server) handleGenerateTemplate(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	templateType, err := req.RequireString("template_type")
	if err != nil {
		return toolError("template_type is required"), nil
	}

	name := req.GetString("name", "app")
	outputPath := req.GetString("output_path", "")
	dryRun := req.GetBool("dry_run", false)

	refs := make(map[string]string)
	if refsArg, ok := req.Arguments["secret_refs"]; ok && refsArg != nil {
		if refsMap, ok := refsArg.(map[string]any); ok {
			for k, v := range refsMap {
				if str, ok := v.(string); ok {
					refs[k] = str
				}
			}
		}
	}

	_ = s.checkScope("")

	engine := template.NewEngine(s.vault)
	customDir := os.ExpandEnv("$HOME/.config/symvault/templates")
	_ = engine.LoadCustomTemplates(customDir)

	output, err := engine.Render(ctx, templateType, name, refs, dryRun)
	if err != nil {
		s.logAudit(ctx, "template_failed", templateType, false)
		return toolError(fmt.Sprintf("render template: %v", err)), nil
	}

	if outputPath != "" {
		if !s.canWrite() {
			s.logAudit(ctx, "write_denied", outputPath, false)
			return toolError("agent does not have write permission"), nil
		}
		if err := s.validateOutputPath(outputPath); err != nil {
			s.logAudit(ctx, "write_denied", outputPath, false)
			return toolError(fmt.Sprintf("invalid output_path: %v", err)), nil
		}
		if err := os.WriteFile(outputPath, []byte(output), 0600); err != nil {
			return toolError(fmt.Sprintf("write file: %v", err)), nil
		}
		s.logAudit(ctx, "template_written", outputPath, true)
		result := map[string]any{
			"output_path": outputPath,
			"dry_run":     dryRun,
		}
		jsonResult, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal result: %w", err)
		}
		return mcp.NewToolResultText(string(jsonResult)), nil
	}

	s.logAudit(ctx, "template_generated", templateType, true)
	return mcp.NewToolResultText(EmbedAsData("rendered_template", output)), nil
}

// validateOutputPath ensures the requested output path is confined to the
// vault directory. It resolves both paths to absolute form and rejects any
// path that escapes the vault root via .. segments or absolute paths outside
// the vault.
func (s *Server) validateOutputPath(outputPath string) error {
	if s.vault == nil || s.vault.Dir == "" {
		return fmt.Errorf("no vault directory configured")
	}

	vaultDir, err := filepath.Abs(s.vault.Dir)
	if err != nil {
		return fmt.Errorf("resolve vault directory: %w", err)
	}

	absPath, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}

	rel, err := filepath.Rel(vaultDir, absPath)
	if err != nil {
		return fmt.Errorf("compute relative path: %w", err)
	}

	if rel == ".." || rel == "." {
		return fmt.Errorf("output path must be inside the vault directory")
	}

	if filepath.IsAbs(rel) {
		return fmt.Errorf("output path must be inside the vault directory")
	}

	// Check for traversal: if any component is "..", the path escapes.
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == ".." {
			return fmt.Errorf("output path escapes vault directory")
		}
	}

	// Also verify the cleaned path doesn't start with ".."
	cleaned := filepath.Clean(rel)
	if cleaned == ".." || (len(cleaned) >= 3 && cleaned[:3] == "../") || (len(cleaned) >= 3 && cleaned[:3] == "..\\") {
		return fmt.Errorf("output path escapes vault directory")
	}

	return nil
}


