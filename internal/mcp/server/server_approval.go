package server

import (
	"github.com/danieljustus/symaira-vault/internal/approval"
	"github.com/danieljustus/symaira-vault/internal/policy"
)

// AttachApprovalQueue wires a pending-approval queue into this server's
// authorizer. In approval mode "prompt" the authorizer then enqueues write
// requests and blocks until an enrolled approval device decides, instead of
// degrading to an instant deny. Call once during server bootstrap, before
// handling requests.
func (s *Server) AttachApprovalQueue(queue *approval.Queue) {
	if s == nil || queue == nil {
		return
	}
	opts := []policy.AuthorizerOption{
		policy.WithApprovalQueue(queue),
	}
	if s.policyEngine != nil {
		opts = append(opts, policy.WithPolicyEngine(s.policyEngine))
	}
	if s.auditLog != nil {
		opts = append(opts, policy.WithAuditLog(s.auditLog))
	}
	s.authorizer = policy.NewAuthorizer(s.authorizerConfig, opts...)
}
