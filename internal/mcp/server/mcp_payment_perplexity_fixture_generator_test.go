package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danieljustus/symaira-vault/internal/audit"
	"github.com/danieljustus/symaira-vault/internal/config"
	"github.com/danieljustus/symaira-vault/internal/mcp/transport"
	"github.com/danieljustus/symaira-vault/internal/payment"
	"github.com/danieljustus/symaira-vault/internal/ssrf"
	"github.com/danieljustus/symaira-vault/internal/vault"
)

// MCP-TOOLS-PP-001 fixture generator for prepare_payment, perplexity_search
// and perplexity_ask. It drives the real protocol handler and Server with the
// same seams the Go tests use (paymentAutotype, newPerplexityHTTPClient,
// openTTYDevice, assigned vault Config) and records the observable result:
// raw JSON-RPC frames, autotype calls, audit actions, tracker bytes and the
// upstream request.
//
//	SYMAIRA_GENERATE_MCP_PP_FIXTURE=1 go test ./internal/mcp/server -run TestGenerateMCPPaymentPerplexityFixtures
//	SYMAIRA_CHECK_MCP_PP_FIXTURE=1    (verifies the committed files are current)

const (
	ppOracleCommitSHA = "1f965f6e56f2507b9183cf30b822f58f7badb951"
	ppToday           = "<today>"
)

var ppSourceFiles = []string{
	"go.mod",
	"go.sum",
	"internal/mcp/server/approval.go",
	"internal/mcp/server/approval_helper.go",
	"internal/mcp/server/server_authorize.go",
	"internal/mcp/server/server_dispatch.go",
	"internal/mcp/server/tool_registry.go",
	"internal/mcp/server/tools_get.go",
	"internal/mcp/server/tools_perplexity.go",
	"internal/mcp/server/tools_prepare_payment.go",
	"internal/payment/decimal.go",
	"internal/payment/enforcer.go",
	"internal/payment/tracker.go",
	"internal/ssrf/ssrf.go",
	"internal/vault/payment.go",
}

var ppGeneratorFiles = []string{
	"internal/mcp/server/mcp_payment_perplexity_fixture_generator_test.go",
	"internal/mcp/server/approval_test.go",
	"internal/mcp/server/tools_test_helpers.go",
}

type ppOracle struct {
	CommitSHA      string   `json:"commit_sha"`
	SourceFiles    []string `json:"source_files"`
	SourceHash     string   `json:"source_hash"`
	GeneratorFiles []string `json:"generator_files"`
	GeneratorHash  string   `json:"generator_hash"`
	GoVersion      string   `json:"go_version"`
}

type ppEntry struct {
	Path string         `json:"path"`
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

type ppPolicy struct {
	Instrument       string   `json:"instrument"`
	AllowedMerchants []string `json:"allowed_merchants,omitempty"`
	PerTransaction   string   `json:"per_transaction,omitempty"`
	PerDay           string   `json:"per_day,omitempty"`
	Currency         string   `json:"currency,omitempty"`
}

type ppPaymentScenario struct {
	Name          string     `json:"name"`
	Tier          string     `json:"tier"`
	AllowedPaths  []string   `json:"allowed_paths"`
	ApprovalMode  string     `json:"approval_mode"`
	TTY           bool       `json:"tty"`
	ApprovalReply string     `json:"approval_reply,omitempty"`
	Entries       []ppEntry  `json:"entries"`
	Policy        *ppPolicy  `json:"policy,omitempty"`
	PreseedTotal  string     `json:"preseed_total,omitempty"`
	AutotypeFail  int        `json:"autotype_fail_on,omitempty"`
	Calls         []ppCall   `json:"calls"`
	Observed      *ppObserve `json:"observed,omitempty"`
}

type ppCall struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type ppAudit struct {
	Action string `json:"action"`
	Path   string `json:"path"`
	OK     bool   `json:"ok"`
}

type ppObserve struct {
	Input           []string          `json:"input"`
	Output          []json.RawMessage `json:"output"`
	AutotypeCalls   []string          `json:"autotype_calls"`
	ApprovalReads   int               `json:"approval_reads"`
	PromptContains  []string          `json:"prompt_contains"`
	Audit           []ppAudit         `json:"audit"`
	TrackerState    *string           `json:"tracker_state"`
	UpstreamRequest []ppUpstream      `json:"upstream_requests,omitempty"`
}

type ppUpstream struct {
	Method        string          `json:"method"`
	Path          string          `json:"path"`
	Authorization string          `json:"authorization"`
	ContentType   string          `json:"content_type"`
	Accept        string          `json:"accept"`
	RawBody       string          `json:"raw_body"`
	Body          json.RawMessage `json:"body"`
}

type ppPaymentFixture struct {
	SchemaVersion int                 `json:"schema_version"`
	Oracle        ppOracle            `json:"oracle"`
	ServerName    string              `json:"server_name"`
	ServerVersion string              `json:"server_version"`
	Cases         []ppPaymentScenario `json:"cases"`
}

func ppCard(path string) ppEntry {
	return ppEntry{Path: path, Type: "payment", Data: map[string]any{
		"card_number": "4111111111111111", "expiry_month": "12", "expiry_year": "2030",
		"cvc": "123", "cardholder": "Jane Doe", "subtype": "card",
	}}
}

func ppBank(path string, withIBAN bool) ppEntry {
	data := map[string]any{"subtype": "bank_account", "bic": "COBADEFF"}
	if withIBAN {
		data["iban"] = "DE89370400440532013000"
	}
	return ppEntry{Path: path, Type: "payment", Data: data}
}

func ppArgs(path, merchant, amount, currency string) map[string]any {
	return map[string]any{"entry_path": path, "merchant": merchant, "amount": amount, "currency": currency}
}

func ppPay(arguments map[string]any) ppCall {
	return ppCall{Name: "prepare_payment", Arguments: arguments}
}

func ppPaymentScenarios() []ppPaymentScenario {
	base := func(name string, calls ...ppCall) ppPaymentScenario {
		return ppPaymentScenario{
			Name: name, Tier: "admin", AllowedPaths: []string{"*"}, ApprovalMode: "none",
			Entries: []ppEntry{ppCard("payments/visa"), ppBank("payments/bank", true)},
			Calls:   calls,
		}
	}
	visa := ppArgs("payments/visa", "shop.example", "75.00", "EUR")
	list := []ppPaymentScenario{}
	add := func(s ppPaymentScenario) { list = append(list, s) }

	add(base("success_card", ppPay(visa)))
	add(base("success_bank_account", ppPay(ppArgs("payments/bank", "shop.example", "10", "EUR"))))
	add(base("success_cardholder_ignored_and_values_never_returned", ppPay(visa)))

	prompt := base("approval_prompt_approved_with_description", ppPay(map[string]any{
		"entry_path": "payments/visa", "merchant": "shop.example", "amount": "75.00",
		"currency": "EUR", "description": "order #42 <test> & more",
	}))
	prompt.ApprovalMode, prompt.TTY, prompt.ApprovalReply = "prompt", true, "y"
	add(prompt)

	remember := base("approval_prompt_remember_reply_is_not_remembered", ppPay(visa), ppPay(visa))
	remember.ApprovalMode, remember.TTY, remember.ApprovalReply = "prompt", true, "r"
	add(remember)

	denied := base("approval_prompt_denied", ppPay(visa))
	denied.ApprovalMode, denied.TTY, denied.ApprovalReply = "prompt", true, "n"
	add(denied)

	add(func() ppPaymentScenario {
		s := base("approval_deny_mode", ppPay(visa))
		s.ApprovalMode = "deny"
		return s
	}())

	add(base("missing_entry_path", ppPay(map[string]any{})))
	add(base("entry_path_not_string", ppPay(map[string]any{"entry_path": 7})))
	add(base("missing_merchant", ppPay(map[string]any{"entry_path": "payments/visa"})))
	add(base("merchant_not_string", ppPay(map[string]any{"entry_path": "payments/visa", "merchant": 1})))
	add(base("missing_amount", ppPay(map[string]any{"entry_path": "payments/visa", "merchant": "m"})))
	add(base("amount_not_string", ppPay(map[string]any{"entry_path": "payments/visa", "merchant": "m", "amount": 5})))
	add(base("missing_currency", ppPay(map[string]any{"entry_path": "payments/visa", "merchant": "m", "amount": "1"})))
	add(base("currency_not_string", ppPay(map[string]any{"entry_path": "payments/visa", "merchant": "m", "amount": "1", "currency": true})))

	scope := base("scope_denied", ppPay(visa))
	scope.AllowedPaths = []string{"other/*"}
	add(scope)

	add(base("entry_not_found", ppPay(ppArgs("payments/missing", "m", "1", "EUR"))))
	add(base("invalid_path_empty", ppPay(ppArgs("", "m", "1", "EUR"))))
	add(base("invalid_path_dotdot", ppPay(ppArgs("../x", "m", "1", "EUR"))))
	add(base("invalid_path_absolute", ppPay(ppArgs("/etc/passwd", "m", "1", "EUR"))))
	add(base("invalid_path_double_slash", ppPay(ppArgs("payments//visa", "m", "1", "EUR"))))
	add(base("invalid_path_dot_segment", ppPay(ppArgs("payments/./visa", "m", "1", "EUR"))))

	notPayment := base("not_a_payment_entry", ppPay(ppArgs("login", "m", "1", "EUR")))
	notPayment.Entries = append(notPayment.Entries, ppEntry{Path: "login", Type: "password", Data: map[string]any{"password": "p"}})
	add(notPayment)
	untyped := base("untyped_entry_is_not_payment", ppPay(ppArgs("plain", "m", "1", "EUR")))
	untyped.Entries = append(untyped.Entries, ppEntry{Path: "plain", Type: "", Data: map[string]any{"password": "p"}})
	add(untyped)

	readOnly := base("tier_read_only_blocks_tool", ppPay(visa))
	readOnly.Tier = "read-only"
	add(readOnly)

	missingIBAN := base("bank_account_without_iban", ppPay(ppArgs("payments/nobank", "m", "1", "EUR")))
	missingIBAN.Entries = append(missingIBAN.Entries, ppBank("payments/nobank", false))
	add(missingIBAN)

	nonString := base("card_number_not_string", ppPay(ppArgs("payments/odd", "m", "1", "EUR")))
	nonString.Entries = append(nonString.Entries, ppEntry{Path: "payments/odd", Type: "payment", Data: map[string]any{
		"card_number": 4111, "expiry_month": "12", "expiry_year": "2030", "cvc": "123",
	}})
	add(nonString)

	missingCVC := base("card_without_cvc", ppPay(ppArgs("payments/nocvc", "m", "1", "EUR")))
	missingCVC.Entries = append(missingCVC.Entries, ppEntry{Path: "payments/nocvc", Type: "payment", Data: map[string]any{
		"card_number": "4111111111111111", "expiry_month": "12", "expiry_year": "2030",
	}})
	add(missingCVC)

	unknownSubtype := base("unknown_subtype_defaults_to_card", ppPay(ppArgs("payments/weird", "m", "1", "EUR")))
	unknownSubtype.Entries = append(unknownSubtype.Entries, ppEntry{Path: "payments/weird", Type: "payment", Data: map[string]any{
		"subtype": "wire", "card_number": "4111111111111111", "expiry_month": "12", "expiry_year": "2030", "cvc": "123",
	}})
	add(unknownSubtype)

	failSecond := base("autotype_failure_after_first_field", ppPay(visa))
	failSecond.AutotypeFail = 2
	add(failSecond)

	policy := func(name string, p ppPolicy, preseed string, calls ...ppCall) ppPaymentScenario {
		s := base(name, calls...)
		s.Policy, s.PreseedTotal = &p, preseed
		return s
	}
	shop := ppPolicy{Instrument: "payments/visa", AllowedMerchants: []string{"Shop.Example", "otto.de"}, PerTransaction: "75.00", PerDay: "200.00", Currency: "EUR"}
	add(policy("policy_allows_case_insensitive_merchant_and_currency", shop, "", ppPay(ppArgs("payments/visa", "  shop.EXAMPLE ", "75.00", " eur "))))
	add(policy("policy_merchant_not_allowed", shop, "", ppPay(ppArgs("payments/visa", "evil.example", "10", "EUR"))))
	add(policy("policy_currency_mismatch", shop, "", ppPay(ppArgs("payments/visa", "shop.example", "10", "USD"))))
	add(policy("policy_over_per_transaction", shop, "", ppPay(ppArgs("payments/visa", "shop.example", "75.01", "EUR"))))
	add(policy("policy_over_per_day_from_preseed", shop, "150.00", ppPay(ppArgs("payments/visa", "shop.example", "60", "EUR"))))
	add(policy("policy_per_day_accumulates_then_denies", shop, "", ppPay(ppArgs("payments/visa", "shop.example", "70.25", "EUR")), ppPay(ppArgs("payments/visa", "shop.example", "70.25", "EUR")), ppPay(ppArgs("payments/visa", "shop.example", "60", "EUR"))))
	add(policy("policy_invalid_amount", shop, "", ppPay(ppArgs("payments/visa", "shop.example", "12abc", "EUR"))))
	add(policy("policy_amount_too_long", shop, "", ppPay(ppArgs("payments/visa", "shop.example", strings.Repeat("9", 31), "EUR"))))
	add(policy("policy_rational_and_octal_amounts", ppPolicy{Instrument: "payments/visa", PerDay: "100", Currency: "EUR"}, "", ppPay(ppArgs("payments/visa", "m", "1/3", "EUR")), ppPay(ppArgs("payments/visa", "m", "010/2", "EUR")), ppPay(ppArgs("payments/visa", "m", "08/2", "EUR")), ppPay(ppArgs("payments/visa", "m", "-5", "EUR")), ppPay(ppArgs("payments/visa", "m", ".5", "EUR"))))
	add(policy("policy_denial_precedes_approval", ppPolicy{Instrument: "payments/visa", AllowedMerchants: []string{"only.example"}}, "", ppPay(visa)))
	denyWithPolicy := policy("policy_ok_but_approval_denied_does_not_record", shop, "", ppPay(visa))
	denyWithPolicy.ApprovalMode, denyWithPolicy.TTY, denyWithPolicy.ApprovalReply = "prompt", true, "n"
	add(denyWithPolicy)
	add(policy("policy_bank_account_counts_toward_total", ppPolicy{Instrument: "payments/bank", PerDay: "20", Currency: "EUR"}, "", ppPay(ppArgs("payments/bank", "m", "15", "EUR")), ppPay(ppArgs("payments/bank", "m", "15", "EUR"))))
	return list
}

func TestGenerateMCPPaymentPerplexityFixtures(t *testing.T) {
	generate := os.Getenv("SYMAIRA_GENERATE_MCP_PP_FIXTURE") == "1"
	check := os.Getenv("SYMAIRA_CHECK_MCP_PP_FIXTURE") == "1"
	if !generate && !check {
		t.Skip("set SYMAIRA_GENERATE_MCP_PP_FIXTURE=1 or SYMAIRA_CHECK_MCP_PP_FIXTURE=1")
	}
	root := executeAPIRequestRepoRoot(t)
	oracle := ppOracle{
		CommitSHA: ppOracleCommitSHA, SourceFiles: ppSourceFiles,
		SourceHash:     executeAPIRequestWorkingDigest(t, root, ppSourceFiles),
		GeneratorFiles: ppGeneratorFiles,
		GeneratorHash:  executeAPIRequestWorkingDigest(t, root, ppGeneratorFiles),
		GoVersion:      localMCPOracleGoVersion,
	}

	scenarios := ppPaymentScenarios()
	for index := range scenarios {
		observed := runPaymentScenario(t, scenarios[index])
		scenarios[index].Observed = &observed
	}
	paymentFixture := ppPaymentFixture{
		SchemaVersion: 1, Oracle: oracle, ServerName: "symvault",
		ServerVersion: "0.0.0-payment-fixture", Cases: scenarios,
	}
	ppWriteOrCheck(t, root, "testdata/port/mcp/prepare-payment.json", paymentFixture, generate, check)

	perplexityFixture := ppPerplexityFixture{
		SchemaVersion: 1, Oracle: oracle, ServerName: "symvault",
		ServerVersion: "0.0.0-perplexity-fixture", Cases: ppPerplexityScenarios(),
	}
	for index := range perplexityFixture.Cases {
		observed := runPerplexityScenario(t, perplexityFixture.Cases[index])
		perplexityFixture.Cases[index].Observed = &observed
	}
	ppWriteOrCheck(t, root, "testdata/port/mcp/perplexity.json", perplexityFixture, generate, check)
}

func ppWriteOrCheck(t *testing.T, root, relative string, value any, generate, check bool) {
	t.Helper()
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		t.Fatalf("encode %s: %v", relative, err)
	}
	path := filepath.Join(root, relative)
	if check {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", relative, err)
		}
		if !bytes.Equal(got, buffer.Bytes()) {
			t.Fatalf("%s is stale; regenerate with SYMAIRA_GENERATE_MCP_PP_FIXTURE=1", relative)
		}
		return
	}
	if generate {
		if err := os.WriteFile(path, buffer.Bytes(), 0o644); err != nil {
			t.Fatalf("write %s: %v", relative, err)
		}
	}
}

func ppBuildServer(t *testing.T, scenarioName, tier string, allowedPaths []string, approvalMode string, entries []ppEntry) (*Server, string, *audit.Logger) {
	t.Helper()
	root, identity := mcpSetEntryFixtureVault(t)
	for _, entry := range entries {
		item := &vault.Entry{Data: entry.Data}
		if entry.Type != "" {
			item.SecretMetadata = vault.SecretMetadata{Type: vault.SecretType(entry.Type)}
		}
		if err := vault.WriteEntry(root, entry.Path, item, identity); err != nil {
			t.Fatalf("%s: write entry %s: %v", scenarioName, entry.Path, err)
		}
	}
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name: "pp-fixture", Tier: config.StrPtr(tier), AllowedPaths: allowedPaths,
		ApprovalMode: config.StrPtr(approvalMode),
	}, "stdio", root)
	srv.vault.Identity = identity
	srv.approvalCache = newApprovalCache()
	auditDir := t.TempDir()
	logger, err := audit.New("pp-fixture", auditDir, nil)
	if err != nil {
		t.Fatalf("%s: open audit log: %v", scenarioName, err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	srv.auditLog = logger
	return srv, auditDir, logger
}

func ppReadAudit(t *testing.T, dir string) []ppAudit {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(dir, "audit-*.log"))
	result := []ppAudit{}
	for _, name := range matches {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read audit log: %v", err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var entry struct {
				Action string `json:"action"`
				Path   string `json:"path"`
				OK     bool   `json:"ok"`
			}
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				t.Fatalf("decode audit line: %v", err)
			}
			result = append(result, ppAudit{Action: entry.Action, Path: entry.Path, OK: entry.OK})
		}
	}
	return result
}

func ppDrive(t *testing.T, srv *Server, version string, frames []string) []json.RawMessage {
	t.Helper()
	handler := NewProtocolHandler("symvault", version, srv)
	outputs := []json.RawMessage{}
	for _, line := range frames {
		var message transport.Message
		if err := json.Unmarshal([]byte(line), &message); err != nil {
			t.Fatalf("decode frame: %v", err)
		}
		response, err := handler.HandleMessage(context.Background(), &message)
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		if response == nil {
			continue
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("encode response: %v", err)
		}
		outputs = append(outputs, encoded)
	}
	return outputs
}

func ppFrames(t *testing.T, calls []ppCall) []string {
	t.Helper()
	frames := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"fixture","version":"1.0"},"capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	for index, call := range calls {
		arguments, err := json.Marshal(call.Arguments)
		if err != nil {
			t.Fatalf("encode arguments: %v", err)
		}
		frames = append(frames, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, index+2, call.Name, arguments))
	}
	return frames
}

func runPaymentScenario(t *testing.T, scenario ppPaymentScenario) ppObserve {
	t.Helper()
	srv, auditDir, _ := ppBuildServer(t, scenario.Name, scenario.Tier, scenario.AllowedPaths, scenario.ApprovalMode, scenario.Entries)

	statePath := filepath.Join(t.TempDir(), "state", "daily-totals.json")
	if scenario.Policy != nil {
		if scenario.PreseedTotal != "" {
			today := time.Now().UTC().Format("2006-01-02")
			seed := fmt.Sprintf(`{"entries":{%q:{%q:%q}}}`, scenario.Policy.Instrument, today, scenario.PreseedTotal)
			if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
				t.Fatalf("seed dir: %v", err)
			}
			if err := os.WriteFile(statePath, []byte(seed), 0o600); err != nil {
				t.Fatalf("seed tracker: %v", err)
			}
		}
		enforcer, err := payment.NewEnforcerFromFile(config.PaymentPolicy{
			Instrument: scenario.Policy.Instrument, AllowedMerchants: scenario.Policy.AllowedMerchants,
			MaxAmount: config.PaymentMaxAmount{PerTransaction: scenario.Policy.PerTransaction, PerDay: scenario.Policy.PerDay},
			Currency:  scenario.Policy.Currency,
		}, statePath)
		if err != nil {
			t.Fatalf("%s: enforcer: %v", scenario.Name, err)
		}
		srv.paymentEnforcer = enforcer
	}

	typed := []string{}
	originalAutotype := paymentAutotype
	paymentAutotype = func(text string) error {
		typed = append(typed, text)
		if scenario.AutotypeFail > 0 && len(typed) == scenario.AutotypeFail {
			return errors.New("synthetic autotype failure")
		}
		return nil
	}
	approvalFile, err := os.CreateTemp(t.TempDir(), "payment-approval-*")
	if err != nil {
		t.Fatalf("approval output: %v", err)
	}
	originalTTY := openTTYDevice
	reads := 0
	if scenario.TTY {
		openTTYDevice = func() (ttyDevice, error) {
			return &mockTTYDevice{output: approvalFile, readString: func() (string, error) {
				reads++
				return scenario.ApprovalReply, nil
			}}, nil
		}
	} else {
		openTTYDevice = func() (ttyDevice, error) { return nil, errors.New("synthetic no TTY") }
	}
	defer func() {
		paymentAutotype = originalAutotype
		openTTYDevice = originalTTY
		_ = approvalFile.Close()
	}()

	frames := ppFrames(t, scenario.Calls)
	outputs := ppDrive(t, srv, "0.0.0-payment-fixture", frames)
	for _, output := range outputs {
		for _, secret := range []string{"4111111111111111", "DE89370400440532013000"} {
			if bytes.Contains(output, []byte(secret)) {
				t.Fatalf("%s: card or bank value leaked into protocol output", scenario.Name)
			}
		}
	}
	_ = approvalFile.Sync()
	promptBytes, _ := os.ReadFile(approvalFile.Name())
	markers := []string{}
	for _, marker := range []string{
		"CRITICAL", "r=remember", "prepare_payment",
		"Allow payment of EUR 75.00 to shop.example?",
		"Description: order #42 <test> & more",
	} {
		if strings.Contains(string(promptBytes), marker) {
			markers = append(markers, marker)
		}
	}
	var trackerState *string
	if data, err := os.ReadFile(statePath); err == nil {
		text := strings.ReplaceAll(string(data), time.Now().UTC().Format("2006-01-02"), ppToday)
		trackerState = &text
	}
	return ppObserve{
		Input: frames, Output: outputs, AutotypeCalls: typed, ApprovalReads: reads,
		PromptContains: markers, Audit: ppReadAudit(t, auditDir), TrackerState: trackerState,
	}
}

// ---------------------------------------------------------------------------
// Perplexity
// ---------------------------------------------------------------------------

type ppUpstreamReply struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

type ppPerplexityScenario struct {
	Name         string           `json:"name"`
	Tier         string           `json:"tier"`
	Entries      []ppEntry        `json:"entries"`
	ConfigKey    string           `json:"config_key,omitempty"`
	BaseURL      string           `json:"base_url"` // "<mock>" selects the loopback TLS server
	AllowPrivate bool             `json:"allow_private"`
	RateLimit    int              `json:"rate_limit_per_min,omitempty"`
	Reply        *ppUpstreamReply `json:"reply,omitempty"`
	Calls        []ppCall         `json:"calls"`
	Observed     *ppObserve       `json:"observed,omitempty"`
}

type ppPerplexityFixture struct {
	SchemaVersion int                    `json:"schema_version"`
	Oracle        ppOracle               `json:"oracle"`
	ServerName    string                 `json:"server_name"`
	ServerVersion string                 `json:"server_version"`
	Cases         []ppPerplexityScenario `json:"cases"`
}

func ppSearch(query any) ppCall {
	return ppCall{Name: "perplexity_search", Arguments: map[string]any{"query": query}}
}

func ppAsk(arguments map[string]any) ppCall {
	return ppCall{Name: "perplexity_ask", Arguments: arguments}
}

func ppOKReply(answer string, citations []string, model string) *ppUpstreamReply {
	payload := map[string]any{
		"id": "chat-id", "model": model,
		"choices": []map[string]any{{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": answer}}},
		"usage":   map[string]any{"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12},
	}
	if citations != nil {
		payload["citations"] = citations
	}
	encoded, _ := json.Marshal(payload)
	return &ppUpstreamReply{Status: 200, Body: string(encoded)}
}

func ppPerplexityScenarios() []ppPerplexityScenario {
	keyed := func(name string, reply *ppUpstreamReply, calls ...ppCall) ppPerplexityScenario {
		return ppPerplexityScenario{
			Name: name, Tier: "admin", ConfigKey: "test-perplexity-key", BaseURL: "<mock>",
			AllowPrivate: true, RateLimit: 100, Reply: reply, Calls: calls,
		}
	}
	good := ppOKReply("Paris <is> the capital & largest city.", []string{"https://en.wikipedia.org/wiki/Paris", "https://www.britannica.com/place/Paris"}, "sonar-pro")
	list := []ppPerplexityScenario{}
	add := func(s ppPerplexityScenario) { list = append(list, s) }

	add(keyed("search_success", good, ppSearch("What is the capital of France? <b>&</b>")))
	add(keyed("search_success_without_model_or_citations", ppOKReply("plain answer", nil, ""), ppSearch("q")))
	add(keyed("search_empty_citations_array_omitted", ppOKReply("a", []string{}, "m"), ppSearch("q")))
	add(keyed("ask_success_without_context", good, ppAsk(map[string]any{"question": "Why?"})))
	add(keyed("ask_success_with_context", good, ppAsk(map[string]any{"question": "Why?", "context": "line one\nline two\n\nline four"})))
	add(keyed("ask_context_not_string_is_ignored", good, ppAsk(map[string]any{"question": "Why?", "context": 5})))
	add(keyed("ask_empty_context_string", good, ppAsk(map[string]any{"question": "Why?", "context": ""})))
	add(keyed("search_missing_query", good, ppCall{Name: "perplexity_search", Arguments: map[string]any{}}))
	add(keyed("search_query_not_string", good, ppSearch(3)))
	add(keyed("ask_missing_question", good, ppCall{Name: "perplexity_ask", Arguments: map[string]any{"context": "x"}}))
	add(keyed("ask_question_not_string", good, ppAsk(map[string]any{"question": []string{"x"}})))
	add(keyed("tier_read_only_still_allowed", good, ppSearch("q")))
	list[len(list)-1].Tier = "read-only"

	// Upstream behaviours.
	add(keyed("upstream_status_500", &ppUpstreamReply{Status: 500, Body: "boom"}, ppSearch("q")))
	add(keyed("upstream_status_429_ask", &ppUpstreamReply{Status: 429, Body: `{"error":"slow down"}`}, ppAsk(map[string]any{"question": "q"})))
	add(keyed("upstream_html_body", &ppUpstreamReply{Status: 200, Body: "<html>nope</html>"}, ppSearch("q")))
	add(keyed("upstream_empty_body", &ppUpstreamReply{Status: 200, Body: ""}, ppSearch("q")))
	add(keyed("upstream_empty_choices", &ppUpstreamReply{Status: 200, Body: `{"id":"x","model":"m","choices":[]}`}, ppSearch("q")))
	add(keyed("upstream_choices_missing", &ppUpstreamReply{Status: 200, Body: `{}`}, ppSearch("q")))
	add(keyed("upstream_null_json", &ppUpstreamReply{Status: 200, Body: `null`}, ppSearch("q")))
	add(keyed("upstream_array_json", &ppUpstreamReply{Status: 200, Body: `[]`}, ppSearch("q")))
	add(keyed("upstream_choices_wrong_type", &ppUpstreamReply{Status: 200, Body: `{"choices":"x"}`}, ppSearch("q")))
	add(keyed("upstream_content_wrong_type", &ppUpstreamReply{Status: 200, Body: `{"choices":[{"message":{"content":5}}]}`}, ppSearch("q")))
	add(keyed("upstream_null_content_is_empty_answer", &ppUpstreamReply{Status: 200, Body: `{"model":"m","choices":[{"message":{"content":null}}]}`}, ppSearch("q")))
	add(keyed("upstream_citations_wrong_type", &ppUpstreamReply{Status: 200, Body: `{"choices":[{"message":{"content":"a"}}],"citations":[1]}`}, ppSearch("q")))
	for _, shape := range []struct{ name, body string }{
		{"upstream_id_wrong_type", `{"id":5,"choices":[{"message":{"content":"a"}}]}`},
		{"upstream_model_wrong_type", `{"model":[],"choices":[{"message":{"content":"a"}}]}`},
		{"upstream_index_wrong_type", `{"choices":[{"index":"0","message":{"content":"a"}}]}`},
		{"upstream_index_fractional", `{"choices":[{"index":1.5,"message":{"content":"a"}}]}`},
		{"upstream_finish_reason_wrong_type", `{"choices":[{"finish_reason":false,"message":{"content":"a"}}]}`},
		{"upstream_message_wrong_type", `{"choices":[{"message":"x"}]}`},
		{"upstream_choice_wrong_type", `{"choices":["x"]}`},
		{"upstream_role_wrong_type", `{"choices":[{"message":{"role":1,"content":"a"}}]}`},
		{"upstream_second_choice_content_wrong_type", `{"choices":[{"message":{"content":"a"}},{"message":{"content":{}}}]}`},
		{"upstream_citations_string", `{"choices":[{"message":{"content":"a"}}],"citations":"x"}`},
		{"upstream_citations_null_element", `{"choices":[{"message":{"content":"a"}}],"citations":["x",null,"y"]}`},
		{"upstream_citations_object_element", `{"choices":[{"message":{"content":"a"}}],"citations":["x",{}]}`},
		{"upstream_usage_wrong_type", `{"choices":[{"message":{"content":"a"}}],"usage":"x"}`},
		{"upstream_usage_field_wrong_type", `{"choices":[{"message":{"content":"a"}}],"usage":{"total_tokens":"x"}}`},
		{"upstream_choices_null", `{"choices":null}`},
		{"upstream_true_json", `true`},
		{"upstream_string_json", `"x"`},
		{"upstream_number_json", `12`},
		{"upstream_truncated_json", `{"choices":[`},
		{"upstream_trailing_garbage", `{"choices":[]} x`},
		{"upstream_leading_whitespace_object", "  \n{\"model\":\"m\",\"choices\":[{\"message\":{\"content\":\"ok\"}}]}"},
		{"upstream_duplicate_keys_last_wins", `{"model":"first","model":"second","choices":[{"message":{"content":"a"}}]}`},
		{"upstream_invalid_utf8_and_escapes", `{"model":"m","choices":[{"message":{"content":"caf\u00e9 \ud83d\ude00 \u003cx\u003e"}}]}`},
	} {
		add(keyed(shape.name, &ppUpstreamReply{Status: 200, Body: shape.body}, ppSearch("q")))
	}
	add(keyed("upstream_mixed_case_keys", &ppUpstreamReply{Status: 200, Body: `{"Model":"M","Choices":[{"Message":{"Content":"hello"}}],"Citations":["c"]}`}, ppSearch("q")))
	add(keyed("upstream_redirect_status_is_not_ok", &ppUpstreamReply{Status: 204, Body: ""}, ppSearch("q")))

	// Rate limiting (global window, reset per scenario).
	limited := keyed("rate_limit_exceeded_on_second_call", good, ppSearch("one"), ppSearch("two"), ppAsk(map[string]any{"question": "three"}))
	limited.RateLimit = 1
	add(limited)

	// API key resolution.
	noKey := keyed("api_key_missing", good, ppSearch("q"))
	noKey.ConfigKey = ""
	add(noKey)
	for _, field := range []string{"credential", "token", "password", "api_key"} {
		viaEntry := keyed("api_key_from_vault_entry_"+field, good, ppSearch("q"))
		viaEntry.ConfigKey = ""
		viaEntry.Entries = []ppEntry{{Path: "perplexity", Data: map[string]any{field: "test-perplexity-key"}}}
		add(viaEntry)
	}
	precedence := keyed("api_key_field_precedence_credential_first", good, ppSearch("q"))
	precedence.ConfigKey = ""
	precedence.Entries = []ppEntry{{Path: "perplexity", Data: map[string]any{"api_key": "wrong", "password": "wrong", "token": "wrong", "credential": "test-perplexity-key"}}}
	add(precedence)
	skipsEmpty := keyed("api_key_skips_empty_and_non_string_fields", good, ppSearch("q"))
	skipsEmpty.ConfigKey = ""
	skipsEmpty.Entries = []ppEntry{{Path: "perplexity", Data: map[string]any{"credential": "", "token": 5, "password": "test-perplexity-key"}}}
	add(skipsEmpty)
	noField := keyed("api_key_entry_without_credential_field", good, ppSearch("q"))
	noField.ConfigKey = ""
	noField.Entries = []ppEntry{{Path: "perplexity", Data: map[string]any{"note": "x"}}}
	add(noField)
	configWins := keyed("api_key_config_wins_over_vault_entry", good, ppSearch("q"))
	configWins.Entries = []ppEntry{{Path: "perplexity", Data: map[string]any{"credential": "wrong"}}}
	add(configWins)
	askNoKey := keyed("ask_api_key_missing", good, ppAsk(map[string]any{"question": "q"}))
	askNoKey.ConfigKey = ""
	add(askNoKey)

	// Base URL validation (no network is reached for any of these).
	for _, target := range []struct{ name, url string }{
		{"base_url_http_rejected", "http://api.example.invalid"},
		{"base_url_without_scheme_rejected", "api.example.invalid/v1"},
		{"base_url_missing_protocol_scheme", "://x"},
		{"base_url_colon_in_first_segment", "1a:b"},
		{"base_url_control_character", "https://exa\x01mple.com"},
		{"base_url_scheme_uppercase_http", "HTTP://example.com"},
		{"base_url_ftp_rejected", "ftp://example.com"},
		{"base_url_loopback_ipv4_blocked", "https://127.0.0.1:9"},
		{"base_url_loopback_ipv6_blocked", "https://[::1]:9"},
		{"base_url_localhost_blocked", "https://localhost:9"},
		{"base_url_private_ipv4_blocked", "https://10.1.2.3"},
		{"base_url_link_local_blocked", "https://169.254.169.254/latest"},
		{"base_url_ipv4_mapped_private_blocked", "https://[::ffff:192.168.1.1]:443"},
		{"base_url_multicast_blocked", "https://224.0.0.1"},
		{"base_url_unspecified_blocked", "https://0.0.0.0:80"},
		{"base_url_empty_host_blocked", "https://"},
		{"base_url_userinfo_private_blocked", "https://user:pw@127.0.0.1:9"},
	} {
		s := keyed(target.name, good, ppSearch("q"))
		s.BaseURL, s.AllowPrivate = target.url, false
		add(s)
	}
	askHTTP := keyed("ask_base_url_http_rejected", good, ppAsk(map[string]any{"question": "q"}))
	askHTTP.BaseURL, askHTTP.AllowPrivate = "http://example.com", false
	add(askHTTP)
	return list
}

func runPerplexityScenario(t *testing.T, scenario ppPerplexityScenario) ppObserve {
	t.Helper()
	srv, auditDir, _ := ppBuildServer(t, scenario.Name, scenario.Tier, []string{"*"}, "none", scenario.Entries)

	upstream := []ppUpstream{}
	baseURL := scenario.BaseURL
	if baseURL == "<mock>" {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			entry := ppUpstream{
				Method: r.Method, Path: r.URL.Path, Authorization: r.Header.Get("Authorization"),
				ContentType: r.Header.Get("Content-Type"), Accept: r.Header.Get("Accept"),
				RawBody: string(body), Body: json.RawMessage(body),
			}
			upstream = append(upstream, entry)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(scenario.Reply.Status)
			_, _ = io.WriteString(w, scenario.Reply.Body)
		}))
		defer server.Close()
		baseURL = server.URL
	}
	srv.vault.Config = &config.Config{MCP: &config.MCPConfig{Perplexity: &config.PerplexityConfig{
		APIKey: scenario.ConfigKey, BaseURL: baseURL, RateLimitPerMin: scenario.RateLimit, AllowPrivate: scenario.AllowPrivate,
	}}}
	originalClient := newPerplexityHTTPClient
	newPerplexityHTTPClient = func(timeout time.Duration, allowPrivate bool) *http.Client {
		return ssrf.NewHTTPClientWithTLSConfig(timeout, allowPrivate, &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- loopback fixture server
	}
	originalLimiter := globalPerplexityRL
	globalPerplexityRL = &perplexityRateLimiter{}
	defer func() {
		newPerplexityHTTPClient = originalClient
		globalPerplexityRL = originalLimiter
	}()

	frames := ppFrames(t, scenario.Calls)
	outputs := ppDrive(t, srv, "0.0.0-perplexity-fixture", frames)
	for _, output := range outputs {
		if bytes.Contains(output, []byte("test-perplexity-key")) {
			t.Fatalf("%s: API key leaked into protocol output", scenario.Name)
		}
	}
	// Request bodies embed the mock's loopback URL nowhere; nothing to scrub.
	return ppObserve{
		Input: frames, Output: outputs, AutotypeCalls: []string{}, PromptContains: []string{},
		Audit: ppReadAudit(t, auditDir), UpstreamRequest: upstream,
	}
}
