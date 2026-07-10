package payment

import (
	"testing"

	"github.com/danieljustus/symaira-vault/internal/config"
)

func newTestEnforcer(t *testing.T, policy config.PaymentPolicy) *Enforcer {
	t.Helper()
	dir := t.TempDir()
	tracker, err := LoadDailyTotals(dir + "/test-daily-totals.json")
	if err != nil {
		t.Fatalf("LoadDailyTotals() error = %v", err)
	}
	return NewEnforcer(policy, tracker)
}

func TestCheck_Allowlist_AllowedMerchant(t *testing.T) {
	e := newTestEnforcer(t, config.PaymentPolicy{
		Instrument:      "payments/visa",
		AllowedMerchants: []string{"amazon.de", "otto.de"},
		Currency:        "EUR",
	})
	err := e.Check(PaymentRequest{
		EntryPath: "payments/visa",
		Merchant:  "amazon.de",
		Amount:    "50.00",
		Currency:  "EUR",
	})
	if err != nil {
		t.Errorf("Check() error = %v, want nil", err)
	}
}

func TestCheck_Allowlist_DeniedMerchant(t *testing.T) {
	e := newTestEnforcer(t, config.PaymentPolicy{
		Instrument:      "payments/visa",
		AllowedMerchants: []string{"amazon.de"},
		Currency:        "EUR",
	})
	err := e.Check(PaymentRequest{
		EntryPath: "payments/visa",
		Merchant:  "evil.com",
		Amount:    "10.00",
		Currency:  "EUR",
	})
	if err == nil {
		t.Error("Check() error = nil, want merchant_not_allowed")
	}
	var denial *DenialError
	if ok := asDenialError(err, &denial); ok {
		if denial.Reason != DenialMerchantNotAllowed {
			t.Errorf("Reason = %q, want %q", denial.Reason, DenialMerchantNotAllowed)
		}
	}
}

func TestCheck_Allowlist_CaseInsensitive(t *testing.T) {
	e := newTestEnforcer(t, config.PaymentPolicy{
		Instrument:      "payments/visa",
		AllowedMerchants: []string{"Amazon.de"},
		Currency:        "EUR",
	})
	err := e.Check(PaymentRequest{
		EntryPath: "payments/visa",
		Merchant:  "amazon.de",
		Amount:    "5.00",
		Currency:  "EUR",
	})
	if err != nil {
		t.Errorf("Check() error = %v, want nil (case-insensitive match)", err)
	}
}

func TestCheck_CurrencyMismatch(t *testing.T) {
	e := newTestEnforcer(t, config.PaymentPolicy{
		Instrument:      "payments/visa",
		AllowedMerchants: []string{"shop.com"},
		MaxAmount:       config.PaymentMaxAmount{PerTransaction: "100.00"},
		Currency:        "EUR",
	})
	err := e.Check(PaymentRequest{
		EntryPath: "payments/visa",
		Merchant:  "shop.com",
		Amount:    "50.00",
		Currency:  "USD",
	})
	if err == nil {
		t.Error("Check() error = nil, want currency_mismatch")
	}
	var denial *DenialError
	if ok := asDenialError(err, &denial); ok {
		if denial.Reason != DenialCurrencyMismatch {
			t.Errorf("Reason = %q, want %q", denial.Reason, DenialCurrencyMismatch)
		}
	}
}

func TestCheck_OverPerTransaction(t *testing.T) {
	e := newTestEnforcer(t, config.PaymentPolicy{
		Instrument:      "payments/visa",
		AllowedMerchants: []string{"shop.com"},
		MaxAmount:       config.PaymentMaxAmount{PerTransaction: "75.00"},
		Currency:        "EUR",
	})
	err := e.Check(PaymentRequest{
		EntryPath: "payments/visa",
		Merchant:  "shop.com",
		Amount:    "100.00",
		Currency:  "EUR",
	})
	if err == nil {
		t.Error("Check() error = nil, want over_per_transaction")
	}
	var denial *DenialError
	if ok := asDenialError(err, &denial); ok {
		if denial.Reason != DenialOverPerTransaction {
			t.Errorf("Reason = %q, want %q", denial.Reason, DenialOverPerTransaction)
		}
	}
}

func TestCheck_OverPerDay(t *testing.T) {
	e := newTestEnforcer(t, config.PaymentPolicy{
		Instrument:      "payments/visa",
		AllowedMerchants: []string{"shop.com"},
		MaxAmount:       config.PaymentMaxAmount{PerDay: "200.00"},
		Currency:        "EUR",
	})
	if err := e.tracker.AddToToday("payments/visa", "150.00"); err != nil {
		t.Fatalf("AddToToday() error = %v", err)
	}
	err := e.Check(PaymentRequest{
		EntryPath: "payments/visa",
		Merchant:  "shop.com",
		Amount:    "60.00",
		Currency:  "EUR",
	})
	if err == nil {
		t.Error("Check() error = nil, want over_per_day")
	}
	var denial *DenialError
	if ok := asDenialError(err, &denial); ok {
		if denial.Reason != DenialOverPerDay {
			t.Errorf("Reason = %q, want %q", denial.Reason, DenialOverPerDay)
		}
	}
}

func TestCheck_UnderLimits(t *testing.T) {
	e := newTestEnforcer(t, config.PaymentPolicy{
		Instrument:      "payments/visa",
		AllowedMerchants: []string{"shop.com"},
		MaxAmount:       config.PaymentMaxAmount{PerTransaction: "75.00", PerDay: "200.00"},
		Currency:        "EUR",
	})
	if err := e.tracker.AddToToday("payments/visa", "100.00"); err != nil {
		t.Fatalf("AddToToday() error = %v", err)
	}
	err := e.Check(PaymentRequest{
		EntryPath: "payments/visa",
		Merchant:  "shop.com",
		Amount:    "50.00",
		Currency:  "EUR",
	})
	if err != nil {
		t.Errorf("Check() error = %v, want nil", err)
	}
}

func TestRecordApproved(t *testing.T) {
	e := newTestEnforcer(t, config.PaymentPolicy{
		Instrument: "payments/visa",
		MaxAmount:  config.PaymentMaxAmount{PerDay: "200.00"},
		Currency:   "EUR",
	})
	if err := e.RecordApproved(PaymentRequest{
		EntryPath: "payments/visa",
		Merchant:  "shop.com",
		Amount:    "50.00",
		Currency:  "EUR",
	}); err != nil {
		t.Fatalf("RecordApproved() error = %v", err)
	}
	if got := e.tracker.TodayTotal("payments/visa"); got != "50" {
		t.Errorf("TodayTotal() = %q, want \"50\"", got)
	}
}

func asDenialError(err error, target **DenialError) bool {
	if de, ok := err.(*DenialError); ok {
		*target = de
		return true
	}
	return false
}
