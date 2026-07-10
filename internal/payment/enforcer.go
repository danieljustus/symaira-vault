package payment

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/config"
)

type DenialReason string

const (
	DenialMerchantNotAllowed DenialReason = "merchant_not_allowed"
	DenialCurrencyMismatch   DenialReason = "currency_mismatch"
	DenialOverPerTransaction DenialReason = "over_per_transaction"
	DenialOverPerDay         DenialReason = "over_per_day"
)

type DenialError struct {
	Reason DenialReason
	Detail string
}

func (e *DenialError) Error() string {
	return fmt.Sprintf("payment policy denied: %s — %s", e.Reason, e.Detail)
}

type Enforcer struct {
	policy   config.PaymentPolicy
	tracker  *DailyTotals
	stateDir string
}

func NewEnforcer(policy config.PaymentPolicy, tracker *DailyTotals) *Enforcer {
	return &Enforcer{
		policy:  policy,
		tracker: tracker,
	}
}

func NewEnforcerFromFile(policy config.PaymentPolicy, statePath string) (*Enforcer, error) {
	tracker, err := LoadDailyTotals(statePath)
	if err != nil {
		return nil, fmt.Errorf("load daily totals: %w", err)
	}
	return &Enforcer{
		policy:   policy,
		tracker:  tracker,
		stateDir: statePath,
	}, nil
}

type PaymentRequest struct {
	EntryPath string
	Merchant  string
	Amount    string
	Currency  string
}

func (e *Enforcer) Check(req PaymentRequest) error {
	if len(e.policy.AllowedMerchants) > 0 {
		allowed := false
		reqMerchant := strings.ToLower(strings.TrimSpace(req.Merchant))
		for _, m := range e.policy.AllowedMerchants {
			if strings.ToLower(strings.TrimSpace(m)) == reqMerchant {
				allowed = true
				break
			}
		}
		if !allowed {
			return &DenialError{
				Reason: DenialMerchantNotAllowed,
				Detail: fmt.Sprintf("merchant %q not in allowed list", req.Merchant),
			}
		}
	}

	if e.policy.Currency != "" && strings.ToUpper(strings.TrimSpace(req.Currency)) != strings.ToUpper(strings.TrimSpace(e.policy.Currency)) {
		return &DenialError{
			Reason: DenialCurrencyMismatch,
			Detail: fmt.Sprintf("requested currency %q does not match policy currency %q", req.Currency, e.policy.Currency),
		}
	}

	reqAmount, ok := new(big.Rat).SetString(req.Amount)
	if !ok {
		return fmt.Errorf("invalid amount %q", req.Amount)
	}

	if e.policy.MaxAmount.PerTransaction != "" {
		limit, ok := new(big.Rat).SetString(e.policy.MaxAmount.PerTransaction)
		if !ok {
			return fmt.Errorf("invalid per_transaction limit %q", e.policy.MaxAmount.PerTransaction)
		}
		if reqAmount.Cmp(limit) > 0 {
			return &DenialError{
				Reason: DenialOverPerTransaction,
				Detail: fmt.Sprintf("amount %s exceeds per-transaction limit %s", req.Amount, e.policy.MaxAmount.PerTransaction),
			}
		}
	}

	if e.policy.MaxAmount.PerDay != "" && e.tracker != nil {
		dayLimit, ok := new(big.Rat).SetString(e.policy.MaxAmount.PerDay)
		if !ok {
			return fmt.Errorf("invalid per_day limit %q", e.policy.MaxAmount.PerDay)
		}
		todayTotal := e.tracker.TodayTotal(e.policy.Instrument)
		if todayTotal == "" {
			todayTotal = "0"
		}
		todayRat, ok := new(big.Rat).SetString(todayTotal)
		if !ok {
			todayRat = new(big.Rat)
		}
		projected := new(big.Rat).Add(todayRat, reqAmount)
		if projected.Cmp(dayLimit) > 0 {
			return &DenialError{
				Reason: DenialOverPerDay,
				Detail: fmt.Sprintf("amount %s + today's total %s would exceed per-day limit %s", req.Amount, todayTotal, e.policy.MaxAmount.PerDay),
			}
		}
	}

	return nil
}

func (e *Enforcer) RecordApproved(req PaymentRequest) error {
	if e.tracker == nil {
		return nil
	}
	return e.tracker.AddToToday(e.policy.Instrument, req.Amount)
}

func (e *Enforcer) PolicyName() string {
	return e.policy.Instrument
}
