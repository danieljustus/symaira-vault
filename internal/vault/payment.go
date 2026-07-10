package vault

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
		{Name: "card_number", Sensitive: true},
		{Name: "expiry_month", Sensitive: false},
		{Name: "expiry_year", Sensitive: false},
		{Name: "cvc", Sensitive: true},
		{Name: "cardholder", Sensitive: false},
		{Name: "subtype", Sensitive: false},
	},
	PaymentSubtypeBankAccount: {
		{Name: "iban", Sensitive: true},
		{Name: "bic", Sensitive: false},
		{Name: "cardholder", Sensitive: false},
		{Name: "subtype", Sensitive: false},
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
	return []string{"card_number", "cvc", "iban"}
}
