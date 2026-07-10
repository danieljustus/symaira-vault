package vault

// Payment field names used across the vault and MCP layers.
const (
	PaymentFieldCardNumber  = "card_number"
	PaymentFieldExpiryMonth = "expiry_month"
	PaymentFieldExpiryYear  = "expiry_year"
	PaymentFieldCVC         = "cvc"
	PaymentFieldCardholder  = "cardholder"
	PaymentFieldIBAN        = "iban"
	PaymentFieldBIC         = "bic"
	PaymentFieldSubtype     = "subtype"
)

// PaymentSubtype represents the subtype of a payment entry.
type PaymentSubtype string

const (
	// PaymentSubtypeCard represents a credit or debit card.
	PaymentSubtypeCard PaymentSubtype = "card"
	// PaymentSubtypeBankAccount represents a bank account (IBAN/BIC).
	PaymentSubtypeBankAccount PaymentSubtype = "bank_account"
)

// AllPaymentSubtypes returns all valid payment subtypes.
func AllPaymentSubtypes() []PaymentSubtype {
	return []PaymentSubtype{PaymentSubtypeCard, PaymentSubtypeBankAccount}
}

// IsValidPaymentSubtype checks if the given string is a valid payment subtype.
func IsValidPaymentSubtype(s string) bool {
	switch PaymentSubtype(s) {
	case PaymentSubtypeCard, PaymentSubtypeBankAccount:
		return true
	}
	return false
}

// PaymentSubtypeFromString parses a payment subtype from string, defaulting
// to card when the input is empty or unrecognized.
func PaymentSubtypeFromString(s string) PaymentSubtype {
	switch PaymentSubtype(s) {
	case PaymentSubtypeCard:
		return PaymentSubtypeCard
	case PaymentSubtypeBankAccount:
		return PaymentSubtypeBankAccount
	default:
		return PaymentSubtypeCard
	}
}

// paymentField describes a single field in the payment schema.
type paymentField struct {
	Name      string
	Sensitive bool
}

// PaymentFields defines the allowed data fields for payment entries,
// partitioned by subtype. Sensitive fields are redacted by default in
// agent responses.
var PaymentFields = map[PaymentSubtype][]paymentField{
	PaymentSubtypeCard: {
		{Name: PaymentFieldCardNumber, Sensitive: true},
		{Name: PaymentFieldExpiryMonth, Sensitive: false},
		{Name: PaymentFieldExpiryYear, Sensitive: false},
		{Name: PaymentFieldCVC, Sensitive: true},
		{Name: PaymentFieldCardholder, Sensitive: false},
		{Name: PaymentFieldSubtype, Sensitive: false},
	},
	PaymentSubtypeBankAccount: {
		{Name: PaymentFieldIBAN, Sensitive: true},
		{Name: PaymentFieldBIC, Sensitive: false},
		{Name: PaymentFieldCardholder, Sensitive: false},
		{Name: PaymentFieldSubtype, Sensitive: false},
	},
}

// PaymentSensitiveFields returns the field names that are automatically
// redacted for the given payment subtype. These are redacted independently
// of per-profile redactFields configuration.
func PaymentSensitiveFields(subtype PaymentSubtype) []string {
	fields, ok := PaymentFields[subtype]
	if !ok {
		return nil
	}
	var result []string
	for _, f := range fields {
		if f.Sensitive {
			result = append(result, f.Name)
		}
	}
	return result
}

// AllPaymentSensitiveFields returns the union of sensitive field names across
// all payment subtypes. Use this when the subtype is not yet known.
func AllPaymentSensitiveFields() []string {
	return []string{PaymentFieldCardNumber, PaymentFieldCVC, PaymentFieldIBAN}
}
