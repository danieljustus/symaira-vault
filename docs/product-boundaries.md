# Symaira product and execution boundaries

**Contract ID: PB-2026-09-09. Revision: 2 (Scope → Brain; Cockpit-only naming). Status: accepted target architecture; implementation pending.**

This decision governs product ownership, optional modules, credential UI, distribution and migration gates. It does not claim that code has moved or a replacement UI has shipped. Existing commands, data formats and supported releases remain valid until their explicit cutovers.

The canonical workspace text is `docs/product-boundaries.md`. Repository-local copies of this contract are identical, versioned snapshots for standalone checkouts. Change the canonical contract deliberately, then update all snapshots together and verify byte equality; do not maintain independent variants. Product-specific implementation instructions remain in their owning repositories. This document does not move domain ownership into CoreKit.

## 1. Product ownership

| Owner | Owns | Does not own |
|---|---|---|
| **Symaira Desktop** (`symdesk`) | Documents, notes, document retrieval, ingest/OCR, meeting artifacts, contacts, PDF output and project journals; human knowledge-work UI plus CLI/MCP/API | A universal tool launcher, a duplicate agent-memory store, credential cryptography or Mac hardware control |
| **Symaira Brain** (`symbrain`) | Portable agent context, memory/entities, skills, harness profiles/inventory, exposure control, audit and the separate guard layer; human administration UI and CLI; optional Browse, Operate and Scope modules | Document ownership, an autonomous replacement for every harness, compulsory system-wide mediation or credential master-key storage |
| **Symaira Cockpit** (`symcockpit`) | Mac hardware/system tuning: thermals, power, display and sensors/HUD (formerly Tune) | Long-term ownership of Operate, Scope or harness-configuration inventory |
| **Symaira Vault** (`symvault`) | Independently usable credential CLI/service, encryption/storage, unlock, authorization, grants, credential execution and recovery | A separate long-term general-purpose management app or a dependency on Brain to use credentials |
| **Symaira EraseMe** | Privacy/data-broker removal workflows and their user interface | Generic agent context or machine management |
| **Symaira Fritz** (`symfritz`) | FRITZ!Box/network-device administration | Generic agent context or a mandatory Brain dependency |

Desktop and Brain are the two primary products. Cockpit, EraseMe and Fritz remain specialized products. Browse, Operate and Scope are optional Brain capabilities, not additional primary products. Vault remains an independently distributable technical service/CLI; its normal graphical management experience belongs to Brain. CoreKit and AppKit are infrastructure libraries, not user-facing applications.

A human-facing UI and an agent-facing API may coexist in any product. Data ownership follows the domain, not the caller. Desktop remains usable without Brain; Brain remains usable without Desktop, Browse, Operate, Scope or Vault.

## 2. Browse, Operate and Scope belong to Brain

**Browse remains actively developed.** Its target source/release ownership is Brain, as an optional web module. Static fetch, browser engines, sessions, human handoff, extraction and automation retain explicit internal boundaries. Do not retire Browse merely because a harness includes browser tools. Keep the current Browse repository and `symbrowse` distribution operational until the replacement and compatibility gates pass.

**Operate is retained as an optional Brain module.** Its target source ownership moves from Cockpit to Brain. This decision supersedes the earlier proposal to discontinue Operate's generic driver development. It does not require replacing its implementation with Cua Driver, nor forbids a later evidence-backed backend adapter. External computer-use tools remain valid alternatives; no mandatory Hermes or Cua dependency is introduced.

**Scope is retained as an optional Brain module.** Its source ownership moves from Cockpit to Brain, covering ports, containers, daemons, local service health and machine diagnostics. Brain owns its administration UI and CLI/MCP exposure. Enabling Scope must not automatically enable Operate, Browse, hardware control or privileged writes. OS-specific probes run behind bounded platform adapters/helpers; Scope-disabled Brain starts no probes, watchers or diagnostics workers. Separate read-only inventory from state-changing actions, require explicit capabilities for the latter, and redact credentials and sensitive process arguments. Do not make macOS tooling a prerequisite for the portable Brain core. Direct documented diagnostics access must remain usable without Brain memory or an agent profile.

Optional means independently selectable, installable where appropriate, disabled without starting its workers, and permission-scoped. Browser automation runs in a worker with its own session lifecycle; native desktop automation runs in an OS-specific helper with its own permission identity. Neither native automation frameworks nor a browser runtime become prerequisites for the portable Brain core. Unsupported platforms report the capability as unavailable without breaking context, skills or profiles.

Direct non-agent consumers, including Desktop web clipping, must be able to call a documented worker/CLI/API surface without running Brain memory, its gateway or an agent profile. The existing `symbrowse`, `symcockpit operate` and `symcockpit scope` entrypoints remain compatibility surfaces until a tested migration replaces them. No new CLI spelling is established by this contract.

Do not duplicate policy hops or create a loop between a module, Brain's gateway and guard. Each supported route declares its controlling policy layer and failure behavior. Governance only covers calls on that route; it is not an OS sandbox against a harness with independent shell/network access.

## 3. Credential service and Brain management UI

Keep `symaira-vault` as the independently testable/releasable credential-service repository. Preserve the standalone `symvault` CLI and its documented API/MCP surfaces; users who only need credentials do not install Brain. Existing TUI/editor integrations are not removed by this UI consolidation decision.

Brain GUI and CLI become the normal integrated entrypoints for credential management. The management UI belongs to Brain and talks to the separate credential service; do not copy the crypto/store into Brain or CoreKit. Human management capabilities must not automatically appear in an agent's MCP profile. Service-side authorization remains authoritative regardless of whether a request came from Brain GUI, Brain CLI or a direct client.

**The separate Vault management GUI is retired only after replacement is verified.** Until then it remains supported transitional functionality; no release asset, cask, app target or signing identity is removed just because this document exists. Freeze duplicate GUI expansion and implement new shared management work toward Brain; retain security, compatibility and usability fixes needed by existing users during the transition.

The retirement gate inventories and verifies the actual existing workflows: initialization/unlock/relock, search and metadata, create/edit/delete, generation, intentional reveal/copy with expiry, import/review where exposed, TOTP, grants/approval, errors, backup/export and recovery. Unsupported or out-of-scope capabilities must be explicitly accounted for rather than silently dropped. Reuse existing UI concepts/code where appropriate, but do not put credential-domain views in AppKit merely to bridge the move.

A secure unlock/input dialog, biometric helper or approval companion is not a second general management GUI. Keep such minimal trusted UI if required to preserve authorization or avoid sending passphrases through Brain, logs or chat. Default automation returns references, handles or sanitized results; explicit human reveal is short-lived and never copied into memory, telemetry or general audit payloads. Existing value/unseal exceptions must be documented and capability-gated, not described as impossible.

Separate processes are defense-in-depth, not complete isolation against a compromised same-user account. Preserve authorization, scoped grants, authenticated/restricted IPC, OS permissions, revocation, safe logging and threat-model testing. Credential unlock is never a global Symaira unlock. Browser sessions, desktop input permission and credential grants are independent.

## 4. Desktop, Cockpit and data boundaries

Desktop owns original work artifacts; Brain may store explicitly promoted, provenance-bearing context and references, not a second independently editable document source of truth. Define deletion/refresh behavior for derived context. Secret values must not enter either product's general search index or durable memory.

Cockpit remains the independent hardware/system-tuning product: thermals, power, display, sensors and HUD. Its functionality does not require Brain or the optional Scope module. Scope owns ports, containers, daemons, local service health and machine diagnostics in Brain; harness inventory remains Brain-owned, not duplicated. Neither Scope nor Operate transfers hardware-control ownership or Cockpit privileged helpers into Brain. Shared facts must use a bounded interface rather than duplicate a domain store.

The sole target product name is **Symaira Cockpit**, with `symcockpit` as CLI and `symaira-cockpit` as repository. Tune/SymTune ceases to be a separate product or visible module name. The redundant `symcockpit tune …` layer is retired toward direct Cockpit commands only through a reviewed command map with collision checks, help/completion/MCP tests and a documented deprecation window. Existing spellings below describe current implementation, not new target commands. Internal `SymTune*` targets, source paths and legacy identifiers are migration work, not a permanent naming exception; preserve compatibility until their consumers are migrated. Do not cosmetically rename shipped helper, signing, Keychain, bundle or data identifiers without an explicit tested migration and rollback.

Keep browser session/profile data and optional activity episodes separate from long-lived agent memory. Observation or action history is opt-in, bounded, redacted and provenance-bearing. Moving code does not authorize screenshots, keylogging, clipboard capture or automatic memory promotion.

## 5. Shared libraries and contracts

CoreKit and AppKit remain separate repositories with independent versioning. CoreKit owns shared backend infrastructure and language-neutral wire fixtures; AppKit owns genuinely shared Swift/native foundations. The Go-to-Rust transition does not change domain ownership. Read actual manifests for implementation language and supported platforms; do not treat historical Go-only descriptions as perpetual requirements.

A module belongs in a kit only when at least two real consumers need the same semantics and coordination costs are justified. No credential cryptography, document business rules, browser engine, hardware control or agent policy is moved to a kit merely to bypass a product boundary. Product-specific views, models and IPC adapters remain product-owned.

Use immutable dependency pins and explicit compatibility tests. Cross-language schema fixtures have one authoritative source and verified snapshots; no compulsory cross-language release version. No new shared service, account, billing system or commercial edition is introduced.

## 6. Standalone-first and failure policy

Standalone-first applies to independently delivered products and to the expressly retained credential CLI/service and direct worker contracts. Absorbed internal modules do not need their own application, setup wizard, repository or release pipeline. Internal interfaces and tests remain required.

Repository, product, package, process, permission identity and release boundaries are separate decisions. Sharing a repository does not require sharing an address space. Separate products do not import each other's implementation; shared infrastructure belongs in kits. Internal modules may link in-process only where doing so preserves the specified trust and platform boundaries.

A missing optional feature may degrade visibly. A required authorization, signature, integrity or policy check must fail closed. Never fall back from rejected verification to an unverified binary or silently bypass a configured guard. Retain existing naming, JSON/MCP, secret-reference, data-format and storage contracts unless a separately reviewed migration changes them.

## 7. Onboarding and distribution

Target onboarding: install Brain, choose context/skills and optional web, desktop-control, machine-inventory/diagnostics and credential capabilities, review the exact components and permissions, then connect selected harnesses through an explicit profile. No mandatory manual multi-tool setup for the integrated path.

Reuse existing managed-runtime, discovery and configuration-writing machinery rather than creating another installer or inventory. Detect existing installations and respect their update owner. Never overwrite a Homebrew-managed binary with an app-managed update. Verify publisher/signature/checksum, platform and protocol compatibility before use; checksum alone does not establish publisher trust.

Defaults are least-privilege: no background capture, browser attachment to logged-in profiles, system input permission, credential unlock or write-capable tool exposure merely from installation. Request permissions when enabling the relevant capability, explain their scope and make revocation visible.

Harness changes must be previewable, backed up, idempotent and restricted to selected managed entries; preserve unrelated MCP servers and user content. GUI and CLI configure the same state, not parallel stores. Provide a noninteractive CLI route with explicit flags and useful errors, without requiring native UI for ordinary standalone CLI use. A policy that requires human approval still requires it.

Disabling/uninstalling a module stops its workers and revokes relevant grants; it does not delete credentials, documents, browser profiles or recovery material by default. Updates and rollback preserve data and ownership.

## 8. Cutover gates and non-goals

A docs-only update records this target; it does not complete any cutover. Avoid coupling a source/repository move with unverified backend, protocol, storage and identifier changes in one step.

Before retiring Browse's source/release home, transferring Operate or Scope from Cockpit, retiring the Tune naming layer, or removing the Vault management app, verify: direct CLI/MCP clients and compatibility aliases; relevant native GUI replacement; data backup/restore and rollback; worker lifecycle/cancellation; secure-field behavior and permission denial; schema/version handshakes; signed release artifacts and package-manager migration. Action results must distinguish submitted from confirmed and include read-back evidence where confirmation is claimed.

Specifically test Brain with each optional component absent, Desktop without Brain, direct `symvault` without Brain, direct web-worker access, independent restarts and revocation, and fail-closed behavior when required policy is unavailable. Also verify Scope-disabled Brain starts no probes, Scope works without Operate/Browse, diagnostics retain redaction and permission-denial behavior, legacy `symcockpit scope` clients migrate correctly, and Cockpit tuning/HUD work with Brain completely absent. Native UI parity must be assessed per supported platform; an iOS client must not assume desktop subprocess APIs.

Do not rename shipped bundle identifiers, Keychain namespaces, `symvault://` references, CLI/MCP names or data directories as a cosmetic side effect. The actual UI retirement needs release notes, existing-install migration, TCC/Keychain/signing checks and an explicit rollback path.

## 9. Supersession

This contract supersedes conflicting product-placement/UI rules in the workspace `repo-konsolidierung.md` (Browse independence, Operate/Scope-in-Cockpit, separate credential-product UI), `desk-brain-vault-merge-design.md` (separate management product), and the earlier architecture consultation (Operate retirement recommendation). It retains Desktop/Brain separation, independent credential execution, independent Cockpit hardware/system tuning, and separate CoreKit/AppKit.

Brain ADR 0001 remains applicable to controlled MCP forwarding and the distinction between exposure policy and call-time guard enforcement. Its historical state-core-only examples do not prohibit the optional modules accepted here. Existing language-port parity, safety and data contracts remain in force; historical rationale is preserved with supersession notices, not rewritten into fictitious history.
