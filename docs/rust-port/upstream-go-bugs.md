# Upstream Go bugs found by the Rust port

Go behaviour that the port deliberately does **not** copy, or that it copies only because the contract is
byte-for-byte. Each entry is a candidate GitHub issue for the Go code base (`internal/...`); none has been filed
yet. Each says what Go does, how to reproduce it, and what it should do. Evidence for an entry is a recorded
Go oracle, never a reading of the source alone.

## 1. `Config.SaveTo` drops `paymentPolicies` (data loss, dangling reference)

- **Where:** `internal/config/config_save.go` builds a `raw := Config{...}` and copies a fixed list of fields;
  `PaymentPolicies` is not on it.
- **Repro:** a `config.yaml` with `paymentPolicies: {card: {instrument: cards/visa}}` and
  `agents: {bot: {paymentPolicy: card}}`; run any command that rewrites the config
  (`symvault agent uninstall other --yes`, `agent install`, `agent upgrade`, `doctor --fix`,
  `config validate --fix`). The saved file keeps `agents.bot.paymentPolicy: card` but has no
  `paymentPolicies` section. The next `Load` fails validation (`agent "bot": paymentPolicy "card" is not
  defined in paymentPolicies`).
- **Expected:** the section survives a rewrite, byte-identical in content, placed after `scan_patterns`
  (the struct order).
- **Rust:** keeps it (`write_payment_policies`). Declared deviation in `cli-gap-inventory.md` (CONFIG-WRITER);
  the only sections the byte differential treats as different are this one and `security`.
- **Evidence:** `testdata/port/config/rewrite.json` (`payment_policies_only`, `payment_policy_agent`; the
  recorded Go bytes have no `paymentPolicies`), live: `config_rewrite_differential.rs`.

## 2. `Config.SaveTo` drops `security`

- **Where:** same `raw` struct; `Security` is not copied.
- **Repro:** `security: {disable_env_passphrase: true}` or `{allow_env_passphrase: true}`, then any rewriting
  command. The section is gone, so the passphrase-from-environment policy silently reverts to the default.
- **Expected:** the section survives (it sits between `logging` and `vaultDir` in the struct).
- **Rust:** keeps it (`write_security`). Same declared deviation.
- **Evidence:** `rewrite.json` (`security_flags`, `security_empty`, `all_sections`).

## 3. `Config.SaveTo` drops `envAllowlist` / `envWhitelist` (not fixed in Rust)

- **Where:** `EnvAllowlist` and `EnvWhitelist` are not copied into `raw`.
- **Repro:** `envAllowlist: [A, B]`, rewrite: the key is gone.
- **Expected:** the allowlist survives a rewrite.
- **Rust:** the typed config does not model the list at all (no Rust caller consumes it), so it is dropped
  exactly like Go. This is the same class of data loss as 1 and 2 and is **not** a declared difference: the
  differential pins Go's bytes (`top_level_fields`). Fix both sides together when a Rust consumer needs it.

## 4. `Config.SaveTo` drops `vault.listing_cache_ttl`, `vault.manifest_generation` and `vault.sync`

- **Where:** the `VaultConfig` copy in `config_save.go` lists the other fields explicitly.
- **Repro:** set `vault.sync.method: icloud_drive`, rewrite: gone (recorded in `bytes.json` writer case
  `vault_all_modeled_fields`, `omitted_fields`).
- **Expected:** every field the loader reads is written back.
- **Rust:** copies Go (not emitted), by the byte contract; revisit with the Go fix.

## 5. `omitempty` on values whose zero is meaningful

- `audit.maxSizeMb: 0` is written without the key, so the next load reads the 100 MiB default instead of the
  operator's `0`. `logging.level: ''` / `format: ''` likewise reload as `warn` / `text`.
- `git.auto_push: false`, `git.auto_pull: false` and `clipboard.copyByDefault: false` are dropped, and the
  loader's default is `true`, so an unrelated rewrite turns an opt-out into an opt-in.
- **Expected:** pointer fields (or no `omitempty`) for the booleans and counts whose zero value differs from
  the default.
- **Rust:** `audit`/`logging` follow Go's bytes (the round trip is pinned in `config_rewrite_contract.rs`);
  `git` and `clipboard` booleans are the older declared Rust-safer deviation (`cli-gap-inventory.md`,
  CONFIG-LOAD-001).

## 6. `mergeAgentProfiles` never reads `pre_call_hooks` / `post_call_hooks`

- **Where:** `config_merge.go` merges every other agent field; the two hook lists are decoded but never copied
  into the merged profile, so a configured hook is silently ignored and lost on the first rewrite.
- **Repro:** `agents: {x: {pre_call_hooks: [/bin/pre]}}`; load, save: no hooks (`agent_all_fields` in
  `rewrite.json`).
- **Expected:** hooks are merged like the other lists, or the keys are rejected as unknown.
- **Rust:** does not model the hooks (matches Go's effective behaviour).

## 7. `profiles: {p: null}` panics the loader

- `mergeTopLevel` dereferences the nil `*Profile` (`config_merge.go:106`): `panic: runtime error: invalid
  memory address or nil pointer dereference`, exit 2 with a goroutine trace.
- **Expected:** a validation error (`profiles.p: profile must not be null`).
- **Rust:** returns that error (declared deviation, CONFIG-RESID).

## 8. `Config.SaveTo` drops `mcp.oauth`

- **Where:** the `raw.MCP = &MCPConfig{...}` copy in `config_save.go` lists the fields one by one and never copies
  `OAuth`.
- **Repro:** `mcp: {oauth: {access_token_ttl: 2h, refresh_token_ttl: 90m}}`, then `agent uninstall other --yes`:
  the `oauth` block is gone and the OAuth server falls back to its default token lifetimes.
- **Expected:** the block survives.
- **Rust:** keeps it (`write_mcp`), a declared difference like 1 and 2 (`declared_line_differences` of
  `rewrite.json`, case `mcp_oauth`; live: `agent_uninstall_keeps_every_mcp_field_go_keeps`).

## 9. yaml.v3 writes literal blocks that start with a line break or a space wrongly

- **Where:** `gopkg.in/yaml.v3` emitter, hit by `Config.SaveTo` for any string value.
- **Repro (a):** `scan_patterns: [{name: n, pattern: p, description: "\nlead", severity: low}]`, or
  `agents.bot.allowedPaths: ["\nlead", " sp\nx"]`, then any rewriting command. The saved file contains
  `severity: |4-` / `- |4-` with the content indented by the emitter's depth, and **neither Go nor Rust can load
  it** (`yaml: line N: did not find expected key`): the `4` indentation indicator is relative to the parent
  column while the emitter wrote the content at its own indent, and the two agree only at mapping depth 4 / 8.
  Recorded: cases `leading_break_list_item`, `leading_break_scan_pattern` (`go_saved_faithful: false`).
- **Repro (b):** `vault.path: "\nlead\nx"`: the file loads, but as `lead\nx` (the leading break is lost).
- **Expected:** a double-quoted scalar for these strings (or a correct indicator).
- **Rust:** writes them double-quoted (`yaml::string_value`), so the file always loads and reloads equal; every
  other string, multi-line included, is byte-identical to Go.

## 10. `Config.SaveTo` also drops `mcp.perplexity`, `mcp.approval_required`, `git.author`, `git.email`, `clipboard.printByDefault`

- Same `raw` copy. `mcp.perplexity.api_key` and `base_url` are lost on every rewrite, so a configured Perplexity
  client stops working silently after `agent install`. Recorded in `dropped_by_save_to` of `rewrite.json` (case
  `all_fields_non_zero`).
- **Rust:** does not model them and drops them like Go (fix both sides together).

