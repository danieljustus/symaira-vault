package mcp

import "time"

// ShareStatus represents the status of a secret share grant between agents.
type ShareStatus string

const (
	SharePending  ShareStatus = "pending"
	ShareApproved ShareStatus = "approved"
	ShareRevoked  ShareStatus = "revoked"
	ShareExpired  ShareStatus = "expired"
	ShareRejected ShareStatus = "rejected"
)

// ShareGrant represents a secret sharing request between agents. A grant
// progresses through states: pending → approved → revoked (or expired),
// or pending → rejected.
type ShareGrant struct {
	ID          string        `json:"id"`
	FromAgent   string        `json:"from_agent"`
	ToAgent     string        `json:"to_agent"`
	SecretPath  string        `json:"secret_path"`
	SecretField string        `json:"secret_field,omitempty"`
	Status      ShareStatus   `json:"status"`
	CreatedAt   time.Time     `json:"created_at"`
	ExpiresAt   *time.Time    `json:"expires_at,omitempty"`
	ApprovedAt  *time.Time    `json:"approved_at,omitempty"`
	RevokedAt   *time.Time    `json:"revoked_at,omitempty"`
	ApprovedBy  string        `json:"approved_by,omitempty"`
	TTL         time.Duration `json:"ttl,omitempty"`
}

// IsExpired returns true if the grant has a defined expiration time that has
// already passed.
func (g *ShareGrant) IsExpired() bool {
	if g == nil {
		return true
	}
	if g.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*g.ExpiresAt)
}

// ShareFilter is used for listing shares with optional filters.
type ShareFilter struct {
	Status     *ShareStatus
	FromAgent  string
	ToAgent    string
	SecretPath string
}
