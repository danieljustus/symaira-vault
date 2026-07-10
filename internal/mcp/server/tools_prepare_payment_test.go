package server

import (
	"context"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"

	"github.com/danieljustus/symaira-vault/internal/autotype"
	"github.com/danieljustus/symaira-vault/internal/config"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/payment"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

func mockPaymentVault(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()

	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	entry := &vaultpkg.Entry{
		SecretMetadata: vaultpkg.SecretMetadata{
			Type: vaultpkg.SecretTypePayment,
		},
		Data: map[string]any{
			vaultpkg.PaymentFieldCardNumber:  "4111111111111111",
			vaultpkg.PaymentFieldExpiryMonth: "12",
			vaultpkg.PaymentFieldExpiryYear:  "2028",
			vaultpkg.PaymentFieldCVC:         "123",
			vaultpkg.PaymentFieldCardholder:  "Jane Doe",
			vaultpkg.PaymentFieldSubtype:     "card",
		},
	}
	if err := vaultpkg.WriteEntry(dir, "payments/mycard", entry, identity); err != nil {
		t.Fatalf("write payment entry: %v", err)
	}

	return dir, identity
}

func mockBankAccountVault(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()

	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	entry := &vaultpkg.Entry{
		SecretMetadata: vaultpkg.SecretMetadata{
			Type: vaultpkg.SecretTypePayment,
		},
		Data: map[string]any{
			vaultpkg.PaymentFieldIBAN:       "DE89370400440532013000",
			vaultpkg.PaymentFieldBIC:        "COBADEFFXXX",
			vaultpkg.PaymentFieldCardholder: "Jane Doe",
			vaultpkg.PaymentFieldSubtype:    "bank_account",
		},
	}
	if err := vaultpkg.WriteEntry(dir, "payments/mybank", entry, identity); err != nil {
		t.Fatalf("write bank account entry: %v", err)
	}

	return dir, identity
}

func mockNonPaymentVault(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()

	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}

	entry := &vaultpkg.Entry{
		Data: map[string]any{
			"password": "testpass123",
			"username": "testuser",
		},
	}
	if err := vaultpkg.WriteEntry(dir, "github", entry, identity); err != nil {
		t.Fatalf("write entry: %v", err)
	}

	return dir, identity
}

type trackingAutotype struct {
	mu     sync.Mutex
	fields []string
}

func (a *trackingAutotype) Type(text string) error {
	a.mu.Lock()
	a.fields = append(a.fields, text)
	a.mu.Unlock()
	return nil
}

func (a *trackingAutotype) typedFields() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := make([]string, len(a.fields))
	copy(result, a.fields)
	return result
}

func TestHandlePreparePayment(t *testing.T) {
	t.Run("success_card_entry", func(t *testing.T) {
		vaultDir, identity := mockPaymentVault(t)
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:           "test",
			AllowedPaths:   []string{"*"},
			CanUseAutotype: config.BoolPtr(true),
			ApprovalMode:   config.StrPtr("none"),
		}, "stdio", vaultDir)
		srv.vault.Identity = identity

		mockAT := &trackingAutotype{}
		autotype.SetAutotype(mockAT)
		defer autotype.SetAutotype(nil)
		origPaymentAutotype := paymentAutotype
		paymentAutotype = mockAT.Type
		defer func() { paymentAutotype = origPaymentAutotype }()

		req := mcp.CallToolRequest{
			Arguments: map[string]any{
				"entry_path": "payments/mycard",
				"merchant":   "shop.example",
				"amount":     "75.00",
				"currency":   "EUR",
			},
		}

		result, err := srv.handlePreparePayment(context.Background(), req)
		if err != nil {
			t.Fatalf("handlePreparePayment() error = %v", err)
		}
		if result == nil {
			t.Fatal("handlePreparePayment() returned nil result")
		}
		if result.IsError {
			t.Fatalf("handlePreparePayment() returned error result: %s", result.Text)
		}

		typed := mockAT.typedFields()
		expected := []string{
			"4111111111111111",
			"12",
			"2028",
			"123",
		}
		if len(typed) != len(expected) {
			t.Fatalf("typed %d fields, want %d", len(typed), len(expected))
		}
		for i, got := range typed {
			if got != expected[i] {
				t.Errorf("typed field[%d] = %q, want %q", i, got, expected[i])
			}
		}

		if strings.Contains(result.Text, "4111111111111111") {
			t.Error("result contains card number — must not expose payment data")
		}
		if strings.Contains(result.Text, "123") {
			t.Error("result contains CVC — must not expose payment data")
		}
	})

	t.Run("success_bank_account_entry", func(t *testing.T) {
		vaultDir, identity := mockBankAccountVault(t)
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:           "test",
			AllowedPaths:   []string{"*"},
			CanUseAutotype: config.BoolPtr(true),
			ApprovalMode:   config.StrPtr("none"),
		}, "stdio", vaultDir)
		srv.vault.Identity = identity

		mockAT := &trackingAutotype{}
		autotype.SetAutotype(mockAT)
		defer autotype.SetAutotype(nil)
		origPaymentAutotype := paymentAutotype
		paymentAutotype = mockAT.Type
		defer func() { paymentAutotype = origPaymentAutotype }()

		req := mcp.CallToolRequest{
			Arguments: map[string]any{
				"entry_path": "payments/mybank",
				"merchant":   "rent.example",
				"amount":     "1200.00",
				"currency":   "EUR",
			},
		}

		result, err := srv.handlePreparePayment(context.Background(), req)
		if err != nil {
			t.Fatalf("handlePreparePayment() error = %v", err)
		}
		if result == nil {
			t.Fatal("handlePreparePayment() returned nil result")
		}
		if result.IsError {
			t.Fatalf("handlePreparePayment() returned error result: %s", result.Text)
		}

		typed := mockAT.typedFields()
		if len(typed) != 1 {
			t.Fatalf("typed %d fields, want 1 (IBAN only)", len(typed))
		}
		if typed[0] != "DE89370400440532013000" {
			t.Errorf("typed field = %q, want IBAN value", typed[0])
		}

		if strings.Contains(result.Text, "DE89370400440532013000") {
			t.Error("result contains IBAN — must not expose payment data")
		}
	})

	t.Run("denial_no_autotype", func(t *testing.T) {
		vaultDir, identity := mockPaymentVault(t)
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:           "test",
			AllowedPaths:   []string{"*"},
			CanUseAutotype: config.BoolPtr(true),
			ApprovalMode:   config.StrPtr("deny"),
		}, "stdio", vaultDir)
		srv.vault.Identity = identity

		mockAT := &trackingAutotype{}
		autotype.SetAutotype(mockAT)
		defer autotype.SetAutotype(nil)
		origPaymentAutotype := paymentAutotype
		paymentAutotype = mockAT.Type
		defer func() { paymentAutotype = origPaymentAutotype }()

		req := mcp.CallToolRequest{
			Arguments: map[string]any{
				"entry_path": "payments/mycard",
				"merchant":   "shop.example",
				"amount":     "75.00",
				"currency":   "EUR",
			},
		}

		_, err := srv.handlePreparePayment(context.Background(), req)
		if err == nil {
			t.Fatal("handlePreparePayment() expected error for denied approval, got nil")
		}
		if !strings.Contains(err.Error(), "denied") {
			t.Fatalf("handlePreparePayment() error = %v, want 'denied'", err)
		}

		typed := mockAT.typedFields()
		if len(typed) != 0 {
			t.Errorf("autotype called %d times after denial, want 0", len(typed))
		}
	})

	t.Run("non_payment_entry_rejected", func(t *testing.T) {
		vaultDir, identity := mockNonPaymentVault(t)
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:           "test",
			AllowedPaths:   []string{"*"},
			CanUseAutotype: config.BoolPtr(true),
			ApprovalMode:   config.StrPtr("none"),
		}, "stdio", vaultDir)
		srv.vault.Identity = identity

		req := mcp.CallToolRequest{
			Arguments: map[string]any{
				"entry_path": "github",
				"merchant":   "shop.example",
				"amount":     "10.00",
				"currency":   "USD",
			},
		}

		result, err := srv.handlePreparePayment(context.Background(), req)
		if err != nil {
			t.Fatalf("handlePreparePayment() error = %v", err)
		}
		if result == nil {
			t.Fatal("handlePreparePayment() returned nil result")
		}
		if !result.IsError {
			t.Fatal("handlePreparePayment() expected error result for non-payment entry")
		}
		if !strings.Contains(result.Text, "not a payment entry") {
			t.Errorf("result = %q, want 'not a payment entry'", result.Text)
		}
	})

	t.Run("missing_required_fields", func(t *testing.T) {
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:           "test",
			AllowedPaths:   []string{"*"},
			CanUseAutotype: config.BoolPtr(true),
			ApprovalMode:   config.StrPtr("none"),
		}, "stdio", "")

		tests := []struct {
			name string
			args map[string]any
		}{
			{
				name: "missing_entry_path",
				args: map[string]any{"merchant": "x", "amount": "1", "currency": "USD"},
			},
			{
				name: "missing_merchant",
				args: map[string]any{"entry_path": "x", "amount": "1", "currency": "USD"},
			},
			{
				name: "missing_amount",
				args: map[string]any{"entry_path": "x", "merchant": "x", "currency": "USD"},
			},
			{
				name: "missing_currency",
				args: map[string]any{"entry_path": "x", "merchant": "x", "amount": "1"},
			},
			{
				name: "empty_args",
				args: map[string]any{},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := mcp.CallToolRequest{Arguments: tt.args}
				result, err := srv.handlePreparePayment(context.Background(), req)
				if err != nil {
					t.Fatalf("handlePreparePayment() error = %v", err)
				}
				if result == nil {
					t.Fatal("handlePreparePayment() returned nil result")
				}
				if !result.IsError {
					t.Fatalf("handlePreparePayment() expected error result for %s", tt.name)
				}
			})
		}
	})

	t.Run("outside_scope", func(t *testing.T) {
		vaultDir, identity := mockPaymentVault(t)
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:           "test",
			AllowedPaths:   []string{"work/"},
			CanUseAutotype: config.BoolPtr(true),
			ApprovalMode:   config.StrPtr("none"),
		}, "stdio", vaultDir)
		srv.vault.Identity = identity

		req := mcp.CallToolRequest{
			Arguments: map[string]any{
				"entry_path": "payments/mycard",
				"merchant":   "shop.example",
				"amount":     "75.00",
				"currency":   "EUR",
			},
		}

		_, err := srv.handlePreparePayment(context.Background(), req)
		if err == nil {
			t.Fatal("handlePreparePayment() expected error for out-of-scope path, got nil")
		}
		if !strings.Contains(err.Error(), "outside allowed scope") {
			t.Fatalf("handlePreparePayment() error = %v, want 'outside allowed scope'", err)
		}
	})

	t.Run("entry_not_found", func(t *testing.T) {
		dir := t.TempDir()
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatalf("generate identity: %v", err)
		}
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:           "test",
			AllowedPaths:   []string{"*"},
			CanUseAutotype: config.BoolPtr(true),
			ApprovalMode:   config.StrPtr("none"),
		}, "stdio", dir)
		srv.vault.Identity = identity

		req := mcp.CallToolRequest{
			Arguments: map[string]any{
				"entry_path": "nonexistent",
				"merchant":   "shop.example",
				"amount":     "75.00",
				"currency":   "EUR",
			},
		}

		result, err := srv.handlePreparePayment(context.Background(), req)
		if err != nil {
			t.Fatalf("handlePreparePayment() error = %v", err)
		}
		if result == nil {
			t.Fatal("handlePreparePayment() returned nil result")
		}
		if !result.IsError {
			t.Fatal("handlePreparePayment() expected error result for not found")
		}
	})

	t.Run("response_exposes_no_card_values", func(t *testing.T) {
		vaultDir, identity := mockPaymentVault(t)
		srv := newTestServerWithVault(t, config.AgentProfile{
			Name:           "test",
			AllowedPaths:   []string{"*"},
			CanUseAutotype: config.BoolPtr(true),
			ApprovalMode:   config.StrPtr("none"),
		}, "stdio", vaultDir)
		srv.vault.Identity = identity

		origPaymentAutotype := paymentAutotype
		paymentAutotype = func(text string) error { return nil }
		defer func() { paymentAutotype = origPaymentAutotype }()

		req := mcp.CallToolRequest{
			Arguments: map[string]any{
				"entry_path": "payments/mycard",
				"merchant":   "shop.example",
				"amount":     "75.00",
				"currency":   "EUR",
			},
		}

		result, err := srv.handlePreparePayment(context.Background(), req)
		if err != nil {
			t.Fatalf("handlePreparePayment() error = %v", err)
		}
		if result == nil {
			t.Fatal("nil result")
		}

		sensitiveValues := []string{
			"4111111111111111",
			"123",
			"Jane Doe",
		}
		for _, v := range sensitiveValues {
			if strings.Contains(result.Text, v) {
				t.Errorf("result contains sensitive value %q — must never be exposed", v)
			}
		}
	})
}

func TestPaymentFieldOrder(t *testing.T) {
	card := paymentFieldOrder(vaultpkg.PaymentSubtypeCard)
	if len(card) != 4 {
		t.Fatalf("card fields = %d, want 4", len(card))
	}
	if card[0] != vaultpkg.PaymentFieldCardNumber || card[3] != vaultpkg.PaymentFieldCVC {
		t.Errorf("card order = %v, want [card_number, expiry_month, expiry_year, cvc]", card)
	}

	bank := paymentFieldOrder(vaultpkg.PaymentSubtypeBankAccount)
	if len(bank) != 1 {
		t.Fatalf("bank fields = %d, want 1", len(bank))
	}
	if bank[0] != vaultpkg.PaymentFieldIBAN {
		t.Errorf("bank field[0] = %q, want %q", bank[0], vaultpkg.PaymentFieldIBAN)
	}
}

func TestBuildPaymentSummary(t *testing.T) {
	summary := buildPaymentSummary("shop.example", "75.00", "EUR", "")
	if !strings.Contains(summary, "75.00") || !strings.Contains(summary, "shop.example") || !strings.Contains(summary, "EUR") {
		t.Errorf("summary = %q, want merchant/amount/currency", summary)
	}

	withDesc := buildPaymentSummary("shop.example", "75.00", "EUR", "Gift for mom")
	if !strings.Contains(withDesc, "Gift for mom") {
		t.Errorf("summary = %q, want description", withDesc)
	}
}

func TestHandlePreparePayment_Policy_DeniedMerchant(t *testing.T) {
	vaultDir, identity := mockPaymentVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanUseAutotype: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	origPaymentAutotype := paymentAutotype
	paymentAutotype = func(text string) error { return nil }
	defer func() { paymentAutotype = origPaymentAutotype }()

	srv.paymentEnforcer = payment.NewEnforcer(
		config.PaymentPolicy{
			Instrument:      "payments/mycard",
			AllowedMerchants: []string{"amazon.de"},
			MaxAmount:       config.PaymentMaxAmount{PerTransaction: "100.00", PerDay: "200.00"},
			Currency:        "EUR",
		},
		nil,
	)

	req := mcp.CallToolRequest{
		Arguments: map[string]any{
			"entry_path": "payments/mycard",
			"merchant":   "evil.com",
			"amount":     "50.00",
			"currency":   "EUR",
		},
	}

	result, err := srv.handlePreparePayment(context.Background(), req)
	if err != nil {
		t.Fatalf("handlePreparePayment() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected error result for denied merchant")
	}
	if !strings.Contains(result.Text, "merchant_not_allowed") {
		t.Errorf("result = %q, want 'merchant_not_allowed'", result.Text)
	}
}

func TestHandlePreparePayment_Policy_CurrencyMismatch(t *testing.T) {
	vaultDir, identity := mockPaymentVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanUseAutotype: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	origPaymentAutotype := paymentAutotype
	paymentAutotype = func(text string) error { return nil }
	defer func() { paymentAutotype = origPaymentAutotype }()

	srv.paymentEnforcer = payment.NewEnforcer(
		config.PaymentPolicy{
			Instrument:      "payments/mycard",
			AllowedMerchants: []string{"shop.example"},
			MaxAmount:       config.PaymentMaxAmount{PerTransaction: "100.00"},
			Currency:        "EUR",
		},
		nil,
	)

	req := mcp.CallToolRequest{
		Arguments: map[string]any{
			"entry_path": "payments/mycard",
			"merchant":   "shop.example",
			"amount":     "50.00",
			"currency":   "USD",
		},
	}

	result, err := srv.handlePreparePayment(context.Background(), req)
	if err != nil {
		t.Fatalf("handlePreparePayment() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected error result for currency mismatch")
	}
	if !strings.Contains(result.Text, "currency_mismatch") {
		t.Errorf("result = %q, want 'currency_mismatch'", result.Text)
	}
}

func TestHandlePreparePayment_Policy_OverPerTransaction(t *testing.T) {
	vaultDir, identity := mockPaymentVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanUseAutotype: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	origPaymentAutotype := paymentAutotype
	paymentAutotype = func(text string) error { return nil }
	defer func() { paymentAutotype = origPaymentAutotype }()

	srv.paymentEnforcer = payment.NewEnforcer(
		config.PaymentPolicy{
			Instrument:      "payments/mycard",
			AllowedMerchants: []string{"shop.example"},
			MaxAmount:       config.PaymentMaxAmount{PerTransaction: "75.00"},
			Currency:        "EUR",
		},
		nil,
	)

	req := mcp.CallToolRequest{
		Arguments: map[string]any{
			"entry_path": "payments/mycard",
			"merchant":   "shop.example",
			"amount":     "100.00",
			"currency":   "EUR",
		},
	}

	result, err := srv.handlePreparePayment(context.Background(), req)
	if err != nil {
		t.Fatalf("handlePreparePayment() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected error result for over per-transaction")
	}
	if !strings.Contains(result.Text, "over_per_transaction") {
		t.Errorf("result = %q, want 'over_per_transaction'", result.Text)
	}
}

func TestHandlePreparePayment_Policy_OverPerDay(t *testing.T) {
	vaultDir, identity := mockPaymentVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanUseAutotype: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	origPaymentAutotype := paymentAutotype
	paymentAutotype = func(text string) error { return nil }
	defer func() { paymentAutotype = origPaymentAutotype }()

	// Pre-populate the tracker with a previous total
	dir := t.TempDir()
	tracker, err := payment.LoadDailyTotals(dir + "/test-totals.json")
	if err != nil {
		t.Fatalf("LoadDailyTotals() error = %v", err)
	}
	if err := tracker.AddToToday("payments/mycard", "150.00"); err != nil {
		t.Fatalf("AddToToday() error = %v", err)
	}

	srv.paymentEnforcer = payment.NewEnforcer(
		config.PaymentPolicy{
			Instrument:      "payments/mycard",
			AllowedMerchants: []string{"shop.example"},
			MaxAmount:       config.PaymentMaxAmount{PerTransaction: "100.00", PerDay: "200.00"},
			Currency:        "EUR",
		},
		tracker,
	)

	req := mcp.CallToolRequest{
		Arguments: map[string]any{
			"entry_path": "payments/mycard",
			"merchant":   "shop.example",
			"amount":     "60.00",
			"currency":   "EUR",
		},
	}

	result, err := srv.handlePreparePayment(context.Background(), req)
	if err != nil {
		t.Fatalf("handlePreparePayment() error = %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatal("expected error result for over per-day")
	}
	if !strings.Contains(result.Text, "over_per_day") {
		t.Errorf("result = %q, want 'over_per_day'", result.Text)
	}
}

func TestHandlePreparePayment_Policy_PassesAndIncrements(t *testing.T) {
	vaultDir, identity := mockPaymentVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanUseAutotype: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	mockAT := &trackingAutotype{}
	autotype.SetAutotype(mockAT)
	defer autotype.SetAutotype(nil)
	origPaymentAutotype := paymentAutotype
	paymentAutotype = mockAT.Type
	defer func() { paymentAutotype = origPaymentAutotype }()

	dir := t.TempDir()
	tracker, err := payment.LoadDailyTotals(dir + "/test-totals.json")
	if err != nil {
		t.Fatalf("LoadDailyTotals() error = %v", err)
	}

	srv.paymentEnforcer = payment.NewEnforcer(
		config.PaymentPolicy{
			Instrument:      "payments/mycard",
			AllowedMerchants: []string{"shop.example"},
			MaxAmount:       config.PaymentMaxAmount{PerTransaction: "75.00", PerDay: "200.00"},
			Currency:        "EUR",
		},
		tracker,
	)

	req := mcp.CallToolRequest{
		Arguments: map[string]any{
			"entry_path": "payments/mycard",
			"merchant":   "shop.example",
			"amount":     "60.00",
			"currency":   "EUR",
		},
	}

	result, err := srv.handlePreparePayment(context.Background(), req)
	if err != nil {
		t.Fatalf("handlePreparePayment() error = %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", result.Text)
	}

	typed := mockAT.typedFields()
	if len(typed) != 4 {
		t.Fatalf("typed %d fields, want 4", len(typed))
	}

	if got := tracker.TodayTotal("payments/mycard"); got != "60" {
		t.Errorf("TodayTotal() = %q, want \"60\"", got)
	}
}

func TestHandlePreparePayment_NoPolicy_AllowsEverything(t *testing.T) {
	vaultDir, identity := mockPaymentVault(t)
	srv := newTestServerWithVault(t, config.AgentProfile{
		Name:           "test",
		AllowedPaths:   []string{"*"},
		CanUseAutotype: config.BoolPtr(true),
		ApprovalMode:   config.StrPtr("none"),
	}, "stdio", vaultDir)
	srv.vault.Identity = identity

	mockAT := &trackingAutotype{}
	autotype.SetAutotype(mockAT)
	defer autotype.SetAutotype(nil)
	origPaymentAutotype := paymentAutotype
	paymentAutotype = mockAT.Type
	defer func() { paymentAutotype = origPaymentAutotype }()

	srv.paymentEnforcer = nil

	req := mcp.CallToolRequest{
		Arguments: map[string]any{
			"entry_path": "payments/mycard",
			"merchant":   "any-merchant",
			"amount":     "99999.99",
			"currency":   "USD",
		},
	}

	result, err := srv.handlePreparePayment(context.Background(), req)
	if err != nil {
		t.Fatalf("handlePreparePayment() error = %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", result.Text)
	}
}
