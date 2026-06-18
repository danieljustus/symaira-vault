# Research Handoff: EU Compliance and Commercialization

This document preserves the actionable findings from the local research folders:

- `sonstiges/Research/Kimi_Research_symvault-EU-Compliance`
- `sonstiges/Research/Kimi_Research_symvault-exopenpass-kommerzialisierung`

The original folders can be deleted once the linked GitHub issues are visible.
This file keeps only the parts that belong in the public MIT self-hosted core.
Hosted service, billing, tenant operations, SSO/SCIM, hosted RBAC, SIEM export,
and compliance operations belong to `symaira-vault-pro`.

## Current Public-Core Status

| Research item | Current status | Evidence |
|---|---|---|
| Local-first/self-hosted positioning | Implemented | README, `docs/commercial-boundary.md`, `SECURITY.md` |
| age X25519 + ChaCha20-Poly1305 encryption | Implemented | `internal/crypto/age.go`, README, `SECURITY.md` |
| Multi-recipient shared vaults | Implemented | `internal/vault/recipients.go`, `SECURITY.md` |
| TOTP storage and code generation | Implemented | `cmd`, `internal/mcp/server/tools_totp.go`, `docs/mcp-api.md` |
| MCP stdio and HTTP integrations | Implemented | `internal/mcp/server/`, `docs/mcp-api.md` |
| Scoped agent tokens and path/tool controls | Implemented | `internal/mcp/auth/`, `internal/agentctx/`, `SECURITY.md` |
| Out-of-band approval and policy gates | Implemented | `internal/policy/`, `SECURITY.md`, `docs/threat-model.md` |
| Output sanitization and taint controls | Implemented | `internal/mcp/render.go`, `internal/vault/taint/`, `SECURITY.md` |
| Local audit logging with integrity | Implemented | `internal/audit/`, `docs/audit-schema.md`, `docs/audit-retention.md` |
| Configurable local audit retention | Implemented | `docs/audit-retention.md`, `config.yaml.example` |
| Release hardening, checksums, signing, SBOM direction | Mostly implemented | `.goreleaser.yml`, `SECURITY.md`, `docs/distribution.md`, `docs/reproducible-builds.md` |
| Redacted audit evidence export for self-hosted users | Open | `docs/error-tracking-strategy.md` marks audit export as future work |
| Post-quantum transition planning | Open | No public PQC or ML-KEM migration plan is documented |
| Enterprise SSO, SCIM, hosted RBAC, SIEM, compliance UI | Out of scope here | Tracked in `symaira-vault-pro` |

## Core Decisions

- Keep Symaira Vault self-hosted free and MIT licensed.
- Do not add Cloud Pro, billing, customer-support, tenant-management, or hosted
  compliance code to this repo.
- General core/runtime capabilities that Pro needs must be implemented here
  first, released, and then consumed by Pro through versioned runtime artifacts.
- Public compliance work should help self-hosted users prove what the local
  tool does: encryption, no telemetry, local audit integrity, scoped MCP access,
  release verification, and operational runbooks.

## Preserved Research Takeaways

1. The strongest public differentiators are AI-agent credential safety,
   local-first operation, zero telemetry, file-level age encryption, Git-backed
   history, scoped MCP access, and local audit integrity.
2. Public self-hosted users still need a safer way to prepare auditor evidence
   without leaking secret values or raw vault paths.
3. X25519 and ChaCha20-Poly1305 remain the current cryptographic baseline, but
   German/EU regulated buyers will ask for a documented post-quantum transition
   plan before long-term procurement decisions.
4. Hardware-backed unlock and FIDO2/WebAuthn are enterprise-relevant, but hosted
   MFA enforcement belongs to Pro. Public core may later evaluate local
   hardware-key unlock without creating paid gates.
5. The old OpenPass commercialization advice is now partially obsolete: the repo
   has been renamed and substantially hardened, and Pro has its own private
   service layer. The still-useful part is the positioning around AI-agent
   credentials and local-first trust.

## GitHub Tracking

The following issues preserve the remaining public-core work:

- [#484](https://github.com/danieljustus/symaira-vault/issues/484):
  add a redacted self-hosted audit evidence export.
- [#485](https://github.com/danieljustus/symaira-vault/issues/485):
  document the post-quantum transition plan for the public crypto envelope.
