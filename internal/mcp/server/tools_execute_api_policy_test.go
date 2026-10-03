package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/config"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/policy"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

type apiEntryPolicyObservation struct {
	Name            string `json:"name"`
	EntryRef        string `json:"entry_ref"`
	PolicyAction    string `json:"policy_action"`
	PolicyOperation string `json:"policy_operation"`
	Error           string `json:"error"`
	CredentialReads int64  `json:"credential_reads"`
	Requests        int64  `json:"requests"`
}

type apiEntryPolicyCase struct {
	name      string
	entryRef  string
	action    policy.Action
	operation string
	wantError string
}

func apiEntryPolicyCases() []apiEntryPolicyCase {
	return []apiEntryPolicyCase{
		{"deny_bare_entry", "api-policy", policy.ActionDeny, "run", "policy denied by rule"},
		{"deny_op_entry", "op:///api-policy", policy.ActionDeny, "run", "policy denied by rule"},
		{"deny_op_vault_alias", "op://synthetic/api-policy", policy.ActionDeny, "run", "policy denied by rule"},
		{"deny_trimmed_entry", "  api-policy  ", policy.ActionDeny, "run", "policy denied by rule"},
		{"read_allow_does_not_authorize_run", "api-policy", policy.ActionAllow, "read", "policy: no matching rule"},
		{"prompt_blocks_credential_read", "api-policy", policy.ActionPrompt, "run", "policy requires approval"},
		{"biometry_blocks_credential_read", "api-policy", policy.ActionRequireBiometry, "run", "biometric verification required by policy"},
		{"allow_run", "api-policy", policy.ActionAllow, "run", ""},
		{"no_policy", "api-policy", "", "", ""},
	}
}

func observeAPIEntryPolicy(t *testing.T, input apiEntryPolicyCase) apiEntryPolicyObservation {
	t.Helper()
	var requests, reads atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer synthetic-api-policy-credential" {
			t.Error("unexpected synthetic request authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	vaultDir, identity := mockVaultWithEntry(t, "api-policy", map[string]any{"credential": "synthetic-api-policy-credential"})
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name: "policy-agent", AllowedPaths: []string{"*"},
		CanRunCommands: config.BoolPtr(true), ApprovalMode: config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity
	if input.action != "" {
		srv.policyEngine = policy.NewEngine([]*policy.Policy{{Version: "1.0", Rules: []policy.Rule{{
			Name: "entry-policy", Action: input.action,
			Conditions: policy.Conditions{AgentID: "policy-agent", Path: "api-policy", ActionType: input.operation},
		}}}})
	}
	writeTemplateOverride(t, vaultDir, "policy-template", fmt.Sprintf(`base_url: %s
auth_type: bearer
entry_ref: %q
allowed_endpoints: [/v1/*]
allowed_methods: [GET]
allow_private: true
`, upstream.URL, input.entryRef))
	originalReader := readExecuteAPIRequestEntry
	readExecuteAPIRequestEntry = func(dir, entryPath string, identity *age.X25519Identity) (*vaultpkg.Entry, error) {
		reads.Add(1)
		return originalReader(dir, entryPath, identity)
	}
	defer func() { readExecuteAPIRequestEntry = originalReader }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := srv.handleExecuteAPIRequest(ctx, mcp.CallToolRequest{Arguments: map[string]any{
		"template": "policy-template", "endpoint": "/v1/status", "timeout": float64(1),
		// An optional caller path is not the template's actual credential path.
		"path": "unrelated-allowed-entry",
	}})
	observation := apiEntryPolicyObservation{Name: input.name, EntryRef: input.entryRef,
		PolicyAction: string(input.action), PolicyOperation: input.operation,
		CredentialReads: reads.Load(), Requests: requests.Load()}
	if err != nil {
		observation.Error = err.Error()
	}
	if input.wantError != "" {
		if err == nil || !strings.Contains(err.Error(), input.wantError) {
			t.Errorf("%s: expected %q; result=%v error=%v", input.name, input.wantError, result, err)
		}
		if result != nil || observation.CredentialReads != 0 || observation.Requests != 0 {
			t.Errorf("%s: denial performed side effects: result=%v reads=%d requests=%d", input.name, result, observation.CredentialReads, observation.Requests)
		}
	} else if err != nil || result == nil || result.IsError || observation.CredentialReads != 1 || observation.Requests != 1 {
		t.Errorf("%s: legitimate control failed: result=%v error=%v reads=%d requests=%d", input.name, result, err, observation.CredentialReads, observation.Requests)
	}
	return observation
}

func TestHandleExecuteAPIRequest_ResolvedEntryPolicy(t *testing.T) {
	for _, input := range apiEntryPolicyCases() {
		t.Run(input.name, func(t *testing.T) { observeAPIEntryPolicy(t, input) })
	}
}
