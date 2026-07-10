package server

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/danieljustus/symaira-vault/internal/autotype"
	mcp "github.com/danieljustus/symaira-vault/internal/mcp"
	"github.com/danieljustus/symaira-vault/internal/metrics"
	"github.com/danieljustus/symaira-vault/internal/payment"
	vaultpkg "github.com/danieljustus/symaira-vault/internal/vault"
)

// paymentAutotype is the function used to type payment fields.
// Extracted for testability.
var paymentAutotype = func(text string) error {
	at := autotype.DefaultAutotype()
	if at == nil {
		return fmt.Errorf("autotype not available on this platform")
	}
	return at.Type(text)
}

// handlePreparePayment validates a payment entry, shows a native approval
// prompt with merchant/amount/currency details, and on approval autotypes
// the payment card or bank account fields into the focused checkout window.
// Card number, CVC, and IBAN values are never returned in the tool response.
func (s *Server) handlePreparePayment(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := req.RequireString("entry_path")
	if err != nil {
		s.logAudit(ctx, "payment.requested", "<invalid>", false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	merchant, err := req.RequireString("merchant")
	if err != nil {
		s.logAudit(ctx, "payment.requested", path, false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	amount, err := req.RequireString("amount")
	if err != nil {
		s.logAudit(ctx, "payment.requested", path, false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	currency, err := req.RequireString("currency")
	if err != nil {
		s.logAudit(ctx, "payment.requested", path, false)
		return mcp.NewToolResultError(err.Error()), nil
	}

	description := req.GetString("description", "")

	// --- Scope check ---
	if !s.checkScope(path) {
		s.logAudit(ctx, "payment.denied", path, false)
		metrics.RecordAuthDenial("scope_denied", s.agent.Name)
		return nil, fmt.Errorf("access denied: path %q outside allowed scope", path)
	}

	// --- Read entry and validate payment type ---
	entry, err := vaultpkg.ReadEntry(s.vault.Dir, path, s.vault.Identity)
	if err != nil {
		s.logAudit(ctx, "payment.requested", path, false)
		metrics.RecordVaultOperation("read", "error")
		return vaultServiceErrorResult(err)
	}

	if entry.SecretMetadata.Type != vaultpkg.SecretTypePayment {
		s.logAudit(ctx, "payment.denied", path, false)
		return mcp.NewToolResultError(fmt.Sprintf("entry %s is not a payment entry (type: %s)", path, entry.SecretMetadata.Type)), nil
	}

	// --- Build approval summary ---
	summary := buildPaymentSummary(merchant, amount, currency, description)

	// --- Enforce payment policy ---
	if s.paymentEnforcer != nil {
		req := payment.PaymentRequest{
			EntryPath: path,
			Merchant:  merchant,
			Amount:    amount,
			Currency:  currency,
		}
		if err := s.paymentEnforcer.Check(req); err != nil {
			s.logAudit(ctx, "payment.policy_denied", path, false)
			return mcp.NewToolResultError(err.Error()), nil
		}
	}

	// --- Require user approval ---
	if err := s.requireApproval(ctx, Intent{
		Action:    "prepare_payment",
		EntryPath: path,
		Summary:   summary,
	}); err != nil {
		s.logAudit(ctx, "payment.denied", path, false)
		return nil, fmt.Errorf("payment denied: %w", err)
	}

	s.logAudit(ctx, "payment.approved", path, true)

	if s.paymentEnforcer != nil {
		if recErr := s.paymentEnforcer.RecordApproved(payment.PaymentRequest{
			EntryPath: path,
			Merchant:  merchant,
			Amount:    amount,
			Currency:  currency,
		}); recErr != nil {
			slog.Default().Warn("failed to record payment total", "err", recErr)
		}
	}

	// --- Determine payment subtype and field order ---
	subtype := vaultpkg.PaymentSubtypeCard
	if st, ok := entry.Data[vaultpkg.PaymentFieldSubtype]; ok {
		subtype = vaultpkg.PaymentSubtypeFromString(fmt.Sprintf("%v", st))
	}

	fields := paymentFieldOrder(subtype)

	// --- Autotype each field ---
	for _, field := range fields {
		value, ok := entry.Data[field]
		if !ok {
			s.logAudit(ctx, "payment.denied", path, false)
			return mcp.NewToolResultError(fmt.Sprintf("payment field %q not found in entry %s", field, path)), nil
		}

		strValue, ok := value.(string)
		if !ok {
			s.logAudit(ctx, "payment.denied", path, false)
			return mcp.NewToolResultError(fmt.Sprintf("payment field %q is not a string", field)), nil
		}

		if err := paymentAutotype(strValue); err != nil {
			s.logAudit(ctx, "payment.denied", path, false)
			return mcp.NewToolResultError(fmt.Sprintf("autotype failed on field %q: %v", field, err)), nil
		}
	}

	s.logAudit(ctx, "payment.typed", path, true)
	metrics.RecordVaultOperation("autotype", "success")

	return mcp.NewToolResultText(`{"success": true}`), nil
}

// paymentFieldOrder returns the fields to autotype in order for the given
// payment subtype. Card entries use: card_number, expiry_month, expiry_year,
// cvc. Bank account entries use: iban.
func paymentFieldOrder(subtype vaultpkg.PaymentSubtype) []string {
	switch subtype {
	case vaultpkg.PaymentSubtypeBankAccount:
		return []string{vaultpkg.PaymentFieldIBAN}
	default:
		return []string{
			vaultpkg.PaymentFieldCardNumber,
			vaultpkg.PaymentFieldExpiryMonth,
			vaultpkg.PaymentFieldExpiryYear,
			vaultpkg.PaymentFieldCVC,
		}
	}
}

// buildPaymentSummary produces a human-readable approval prompt for payment.
func buildPaymentSummary(merchant, amount, currency, description string) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("Allow payment of %s %s to %s?", currency, amount, merchant))
	if description != "" {
		parts = append(parts, fmt.Sprintf("Description: %s", description))
	}
	return strings.Join(parts, "\n")
}
