package health

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/danieljustus/OpenPass/internal/audit"
	configpkg "github.com/danieljustus/OpenPass/internal/config"
	"github.com/danieljustus/OpenPass/internal/mcp"
	"github.com/danieljustus/OpenPass/internal/update"
	"github.com/danieljustus/OpenPass/internal/vault"
)

func checkMCPTokens(vaultDir string, _ Options) Result {
	r := Result{ID: "mcp.tokens", Name: "MCP tokens"}
	reg, _, err := mcp.LoadTokenSystem(vaultDir)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot load MCP token registry: " + err.Error()
		return r
	}
	tokens := reg.List()
	if len(tokens) == 0 {
		r.Status = StatusOK
		r.Message = "no MCP tokens configured"
		return r
	}

	const rotationThreshold = 90 * 24 * time.Hour
	var old, expired int
	for _, t := range tokens {
		if t.IsExpired() {
			expired++
		} else if time.Since(t.CreatedAt) > rotationThreshold {
			old++
		}
	}

	active := len(tokens) - expired
	if old > 0 || expired > 0 {
		r.Status = StatusWarn
		parts := []string{fmt.Sprintf("%d active", active)}
		if old > 0 {
			parts = append(parts, fmt.Sprintf("%d older than 90d", old))
		}
		if expired > 0 {
			parts = append(parts, fmt.Sprintf("%d expired/revoked", expired))
		}
		r.Message = strings.Join(parts, ", ")
		r.Hint = "rotate old tokens with `openpass mcp-token-rotate`"
	} else {
		r.Status = StatusOK
		r.Message = fmt.Sprintf("%d active token(s), all within rotation policy", active)
	}
	return r
}

func checkAuditLog(vaultDir string, _ Options) Result {
	r := Result{ID: "audit.log", Name: "Audit log"}
	// Find audit log files: ~/.openpass/audit-*.log
	pattern := filepath.Join(vaultDir, "audit-*.log")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		r.Status = StatusOK
		r.Message = "no audit logs (MCP not used yet)"
		return r
	}

	// HMAC key is shared across all audit logs in the vault directory.
	ks := audit.NewKeystore(vaultDir, vault.CurrentSearchIdentity())
	key, keyErr := ks.LoadHMACKey()
	if keyErr != nil {
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("cannot read hmac key: %v", keyErr)
		return r
	}

	var issues []string
	var totalSize int64
	for _, logPath := range matches {
		info, statErr := os.Stat(logPath)
		if statErr == nil {
			totalSize += info.Size()
		}
		result, verErr := audit.VerifyLog(logPath, key)
		if verErr != nil {
			issues = append(issues, fmt.Sprintf("%s: verify error: %v", filepath.Base(logPath), verErr))
			continue
		}
		if result != nil && !result.Valid {
			issues = append(issues, fmt.Sprintf("%s: integrity check failed", filepath.Base(logPath)))
		}
	}

	auditCfg := audit.GetConfig()
	if totalSize >= auditCfg.MaxFileSize {
		issues = append(issues, fmt.Sprintf("total audit size %.1f MB at limit", float64(totalSize)/1024/1024))
	}

	if len(issues) > 0 {
		r.Status = StatusWarn
		r.Message = strings.Join(issues, "; ")
	} else {
		r.Status = StatusOK
		r.Message = fmt.Sprintf("%d log file(s), total %.1f MB, integrity OK", len(matches), float64(totalSize)/1024/1024)
	}
	return r
}

func checkUpdateAvailable(vaultDir string, opts Options) Result {
	r := Result{ID: "update.available", Name: "Update check"}
	checker := update.NewChecker(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get current version from build info.
	result, err := checker.Check(ctx, opts.Version)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot check for updates: " + err.Error()
		return r
	}
	if !result.Checkable {
		r.Status = StatusOK
		r.Message = "update check not available (dev build)"
		return r
	}
	if result.UpdateAvailable {
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("%s → %s available", result.CurrentVersion, result.LatestVersion)
		r.Hint = result.ReleaseURL
	} else {
		r.Status = StatusOK
		r.Message = fmt.Sprintf("up to date (%s)", result.CurrentVersion)
	}
	return r
}

func checkMCPServer(vaultDir string, _ Options) Result {
	r := Result{ID: "mcp.server.reachable", Name: "MCP server reachable"}
	cfgPath := filepath.Join(vaultDir, "config.yaml")
	cfg, err := configpkg.Load(cfgPath)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot load config: " + err.Error()
		return r
	}
	port := 8080
	if cfg.MCP != nil && cfg.MCP.Port > 0 {
		port = cfg.MCP.Port
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/health", port)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot create request: " + err.Error()
		return r
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "MCP server not reachable at " + url
		r.Hint = "start the server with `openpass serve --port " + strconv.Itoa(port) + "`"
		return r
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		r.Status = StatusWarn
		r.Message = fmt.Sprintf("MCP server returned HTTP %d", resp.StatusCode)
		return r
	}
	r.Status = StatusOK
	r.Message = "server reachable at " + url
	// Check token presence for HTTP auth
	tokenPath := filepath.Join(vaultDir, "mcp-token")
	if _, err := os.Stat(tokenPath); err == nil {
		r.Message += ", token present"
	} else {
		r.Message += ", no token file"
		r.Hint = "generate an MCP token with `openpass mcp token create`"
	}
	return r
}

func checkDynamicSecretEngines(vaultDir string, _ Options) Result {
	r := Result{ID: "mcp.dynamic.engines", Name: "Dynamic secret engines"}
	cfgPath := filepath.Join(vaultDir, "config.yaml")
	cfg, err := configpkg.Load(cfgPath)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot load config: " + err.Error()
		return r
	}
	var configured bool
	for _, profile := range cfg.Agents {
		if len(profile.DynamicProviders) > 0 {
			configured = true
			break
		}
	}
	if !configured {
		r.Status = StatusOK
		r.Message = "no dynamic providers configured"
		return r
	}
	r.Status = StatusWarn
	r.Message = "dynamic providers configured but engines not registered"
	r.Hint = "dynamic provider engines were never wired to the MCP server"
	return r
}

func checkMCPAgents(vaultDir string, _ Options) Result {
	r := Result{ID: "mcp.agents", Name: "MCP agents configured"}
	cfgPath := filepath.Join(vaultDir, "config.yaml")
	cfg, err := configpkg.Load(cfgPath)
	if err != nil {
		r.Status = StatusWarn
		r.Message = "cannot load config: " + err.Error()
		return r
	}
	knownAgents := []string{"claude-code", "codex", "opencode", "hermes", "openclaw"}
	var found []string
	for _, agent := range knownAgents {
		if _, ok := cfg.Agents[agent]; ok {
			found = append(found, agent)
		}
	}
	if len(found) > 0 {
		r.Status = StatusOK
		r.Message = strings.Join(found, ", ") + " configured"
	} else {
		r.Status = StatusOK
		r.Message = "no AI agent MCP configs found"
		r.Hint = "run `openpass mcp-config <agent>` to generate config"
	}
	return r
}
