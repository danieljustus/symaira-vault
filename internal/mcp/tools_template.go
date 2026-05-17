package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/danieljustus/OpenPass/internal/template"
	"github.com/danieljustus/OpenPass/internal/vaultsvc"
)

func (s *Server) handleGenerateTemplate(ctx context.Context, req CallToolRequest) (*CallToolResult, error) {
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

	svc := vaultsvc.New(slog.Default(), s.vault)
	engine := template.NewEngine(svc)
	customDir := os.ExpandEnv("$HOME/.config/openpass/templates")
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
		return NewToolResultText(string(jsonResult)), nil
	}

	s.logAudit(ctx, "template_generated", templateType, true)
	return NewToolResultText(EmbedAsData("rendered_template", output)), nil
}
