.PHONY: keyring-key-fixtures-generate keyring-key-fixtures-check all build install test test-fast test-coverage test-verbose test-race test-ci cover clean lint lint-fix fmt fmt-check vet passlint completions manpages port-fixtures-generate port-fixtures-check core-fixtures-generate core-fixtures-check quota-fixtures-generate quota-fixtures-check policy-fixtures-generate policy-fixtures-check store-metadata-fixtures-check rust-007-fixtures-generate rust-007-fixtures-check rust-007-differential config-session-differential sync-io-differential git-io-differential pairing-fixtures-generate pairing-fixtures-check pairing-differential differential-go-selftest crypto-differential crypto-fuzz-smoke port-contract store-reopen-fixture store-differential audit-fixtures-generate audit-fixtures-check audit-differential rust-build rust-check rust-lint rust-test rust-miri rust-features rust-coverage rust-security rust-version-contract rust-fuzz-lock rust-fuzz-smoke rust-fuzz rust-gates help docs-check

# Variables
BINARY_NAME := symvault
GO := go
CARGO := cargo
GOFLAGS := -v
GOLANGCI_LINT_VERSION := v2.11.4
GO_TOOLCHAIN ?= go1.26.6
# Keep harness binary paths aligned with Cargo's externally provided target dir.
CARGO_TARGET_DIR ?= target
# Cargo must receive command-line overrides through the environment too.
export CARGO_TARGET_DIR
MIRI_TOOLCHAIN := nightly-2026-09-03
MIRI_TARGET_DIR := target/miri-2026-09-03
MIRI_FLAGS := -Zmiri-disable-isolation
RUST_FUZZ_TOOLCHAIN := nightly-2026-09-03
RUST_FUZZ_RUNS ?= 128
RUST_FUZZ_MAX_TOTAL_TIME ?= 10
RUST_FUZZ_MAX_LEN ?= 4096
RUST_FUZZ_TIMEOUT ?= 5
RUST_FUZZ_RSS_LIMIT_MB ?= 512
RUST_FUZZ_DIR := fuzz
RUST_FUZZ_MANIFEST := $(RUST_FUZZ_DIR)/Cargo.toml
RUST_FUZZ_LOCK := $(RUST_FUZZ_DIR)/Cargo.lock
RUST_FUZZ_DENY := $(RUST_FUZZ_DIR)/deny.toml
COVERAGE_DIR := coverage
COVERAGE_FILE := $(COVERAGE_DIR)/coverage.out
COVERAGE_HTML := $(COVERAGE_DIR)/coverage.html
PREFIX ?= /usr/local
DESTDIR ?=

# Default target
all: build

# Version info (used by go install and builds)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

# Build the binary
build:
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) .

# Run all tests with race detector (default, for CI-like local testing)
test:
	$(GO) test ./... -race -v

# Run all tests without race detector (faster, for quick iteration)
test-fast:
	$(GO) test ./... -v

# Run tests with coverage
test-coverage:
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test ./... -coverprofile=$(COVERAGE_FILE) -covermode=atomic
	$(GO) tool cover -func=$(COVERAGE_FILE)
	@echo ""
	@echo "Coverage report saved to $(COVERAGE_FILE)"

# Generate HTML coverage report
test-coverage-html: test-coverage
	$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "HTML coverage report saved to $(COVERAGE_HTML)"

# Run tests with race detector
test-race:
	$(GO) test ./... -race -timeout=30m -v

# Run tests for core packages only (vault, config, crypto)
test-core:
	$(GO) test ./internal/vault/... ./internal/config/... ./internal/crypto/... -v

# Run tests for core packages with coverage
test-core-coverage:
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test ./internal/vault/... ./internal/config/... ./internal/crypto/... \
		-coverprofile=$(COVERAGE_FILE) -covermode=atomic
	$(GO) tool cover -func=$(COVERAGE_FILE) | grep "total:"
	$(GO) tool cover -func=$(COVERAGE_FILE)

# Run specific package tests
test-vault:
	$(GO) test ./internal/vault/... -v

test-config:
	$(GO) test ./internal/config/... -v

test-crypto:
	$(GO) test ./internal/crypto/... -v

# Run benchmarks
test-bench:
	$(GO) test ./... -bench=. -benchmem

# Generate coverage report (canonical single-file output)
cover:
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test ./... -coverprofile=$(COVERAGE_FILE) -covermode=atomic
	$(GO) tool cover -func=$(COVERAGE_FILE)
	@echo ""
	@echo "Coverage report: $(COVERAGE_FILE)"

# Clean build artifacts, coverage files, and scratch directories
clean:
	rm -f $(BINARY_NAME) *.test *.test.exe *.out coverage*.out *_output.txt
	rm -rf $(COVERAGE_DIR) dist/ coverage.html vault_coverage.html
	$(GO) clean -cache -testcache

# Run linter
# GOTOOLCHAIN is pinned like every other Go target here. Without it the linter
# builds against whatever Go the host has, and a newer one makes it report
# hundreds of bogus "could not import" typecheck errors that bury the real
# findings -- which is exactly how a batch of misspell hits reached CI.
lint:
	GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m --verbose

# Format code
fmt:
	$(GO) fmt ./...

# Run go vet (includes passlint analyzer in self-test mode)
vet:
	$(GO) vet ./...
	$(GO) vet ./cmd/passlint/...

# Run passlint analyzer tests
passlint:
	$(GO) vet ./cmd/passlint/...

# Check formatting (fails if gofmt would change files)
fmt-check:
	@echo "Checking Go formatting..."
	@fmt_files=$$($(GO) fmt ./...); \
	if [ -n "$$fmt_files" ]; then \
		echo "The following files need formatting:"; \
		echo "$$fmt_files"; \
		exit 1; \
	fi; \
	echo "All Go files are properly formatted."

# Run linter with auto-fix
lint-fix:
	GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --fix --timeout=5m --verbose

# Run CI-like tests (race + coverage + timeout, same as CI)
test-ci:
	@echo "Running CI-like test suite..."
	GOWORK=off $(GO) test -v -race -timeout=30m -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	@echo ""
	@echo "Coverage summary:"
	$(GO) tool cover -func=$(COVERAGE_FILE) | grep "total:"

# Install binary
install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BINARY_NAME) $(DESTDIR)$(PREFIX)/bin/$(BINARY_NAME)

# Generate shell completions
completions: build
	@mkdir -p completions
	./$(BINARY_NAME) completion bash > completions/symvault.bash
	./$(BINARY_NAME) completion zsh > completions/symvault.zsh
	./$(BINARY_NAME) completion fish > completions/symvault.fish

# Generate manual pages
manpages: build
	@mkdir -p docs/man
	./$(BINARY_NAME) generate manpages docs/man

# Go-oracle fixtures and neutral black-box harness for the staged Rust port.
PORT_ORACLE_COMMIT ?= caadd5e
PORT_ORACLE_RELEASE ?= v0.22.1
# QUOTA-001's pure transition helper was extracted in 8913d64e and does not
# exist at the v0.22.1 baseline, so this row cannot share PORT_ORACLE_COMMIT:
# the fixture was naming a commit that does not contain the code it pins.
QUOTA_ORACLE_COMMIT ?= 8913d64e
QUOTA_ORACLE_RELEASE ?= unreleased
# Same reason for the session/persistent-quota fixtures: internal/policy/
# ratelimit.go changed, and ratelimit_transition.go was created, after v0.22.1.
SESSION_ORACLE_COMMIT ?= 29c5e5ef
SESSION_ORACLE_RELEASE ?= unreleased
# CLI-001's command tree is built from cmd/, so its pin advances with the CLI
# rather than sitting on the frozen v0.22.1 baseline. portgen used to read the
# oracle back out of the fixture it was certifying, which made the claim
# unfalsifiable; it now verifies cmd/ against this commit's blobs.
CLI_ORACLE_COMMIT ?= a518124f
CLI_ORACLE_RELEASE ?= unreleased
KEYRING_KEY_FIXTURE := testdata/port/session/keyring-keys.json
# SESSION-002's portable half. The native keychain round-trip stays a
# macOS-gated diagnostic; these addressing rules are platform-independent and
# must be verifiable on every OS, which is what this row was missing.
KEYRING_ORACLE_COMMIT ?= 29c5e5ef
KEYRING_ORACLE_RELEASE ?= unreleased
# POLICY-001 deliberately advances only its own production-Go oracle to the
# adjudicated path-matching contract. policygen verifies this commit against
# git objects, so it cannot drift from the code the generator executes.
POLICY_ORACLE_COMMIT ?= f195aab
POLICY_ORACLE_RELEASE ?= unreleased
PORT_CLI_FIXTURE := testdata/port/cli/command-tree.json
PORT_CLI_CASES := testdata/port/cli/cases.json
PORT_ERROR_FIXTURE := testdata/port/core/error-contract.json
PORT_SECRET_REF_FIXTURE := testdata/port/core/secret-ref-contract.json
PORT_REDACT_FIXTURE := testdata/port/core/redact-contract.json
PORT_CRYPTO_FIXTURE := testdata/port/core/password-totp-contract.json
PORT_QUOTA_FIXTURE := testdata/port/core/quota-contract.json
PORT_POLICY_FIXTURE := testdata/port/core/policy-contract.json
PORT_MCP_INIT_FIXTURE := testdata/port/mcp/initialize.json
PORT_MCP_STDIO_FIXTURE := testdata/port/mcp/stdio-hygiene.json
PORT_GIT_WINNER_FIXTURE := testdata/port/sync/version-winner.json
PORT_GIT_OFFLINE_FIXTURE := testdata/port/sync/git-offline.json
CFG_PATH_FIXTURE := testdata/port/config/paths.json
# CFG-001 pins its own production-Go oracle. configpathgen verifies this commit
# against git objects, so a stale pin fails loudly rather than mislabelling.
CFG_ORACLE_COMMIT ?= fc9eddc0
CFG_BYTES_FIXTURE := testdata/port/config/bytes.json
CFG_BYTES_ORACLE_COMMIT ?= aa21ec4e
CFG_PRECEDENCE_FIXTURE := testdata/port/config/precedence.json
CFG_PRECEDENCE_ORACLE_COMMIT ?= aa21ec4e
CFG_ORACLE_RELEASE ?= unreleased
# RUST-007's config fixture pins its own production-Go oracle, separately from
# PORT_ORACLE_COMMIT: it covers internal/config, which the CFG rows keep moving,
# while the session/quota fixtures still sit on the frozen v0.22.1 baseline.
CONFIG_ORACLE_COMMIT ?= aa21ec4e
CONFIG_ORACLE_RELEASE ?= unreleased
PORT_SYNC_FIXTURE := testdata/port/sync/sync.json
PORT_PAIRING_FIXTURE := testdata/port/pairing/contract.json
PORT_CONFIG_FIXTURE := testdata/port/config/contract.json
PORT_SESSION_FIXTURE := testdata/port/session/contract.json
PORT_PLATFORM_FIXTURE := testdata/port/platform/contract.json
PORT_PERSISTENT_QUOTA_FIXTURE := testdata/port/quotas/contract.json
PORT_GO_BINARY := target/port/symvault-go
RUST_BINARY := $(CARGO_TARGET_DIR)/debug/symvault
PORT_CONTRACT_VERSION ?= v0.0.0-port

port-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/portgen \
		--output $(PORT_CLI_FIXTURE) \
		--oracle-commit $(CLI_ORACLE_COMMIT) \
		--oracle-release $(CLI_ORACLE_RELEASE)

port-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/portgen \
		--check --output $(PORT_CLI_FIXTURE)

keyring-key-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/keyringkeygen \
		--output $(KEYRING_KEY_FIXTURE) \
		--oracle-commit $(KEYRING_ORACLE_COMMIT) \
		--oracle-release $(KEYRING_ORACLE_RELEASE)

keyring-key-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/keyringkeygen \
		--check --output $(KEYRING_KEY_FIXTURE)
	$(CARGO) test -p symvault-core --test keyring_keys_contract --locked

quota-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/quotagen \
		--output $(PORT_QUOTA_FIXTURE) \
		--oracle-commit $(QUOTA_ORACLE_COMMIT) \
		--oracle-release $(QUOTA_ORACLE_RELEASE)

quota-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/quotagen \
		--check --output $(PORT_QUOTA_FIXTURE)

core-fixtures-generate: quota-fixtures-generate
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/coregen \
		--error-output $(PORT_ERROR_FIXTURE) \
		--secret-ref-output $(PORT_SECRET_REF_FIXTURE) \
		--redact-output $(PORT_REDACT_FIXTURE) \
		--crypto-output $(PORT_CRYPTO_FIXTURE)

core-fixtures-check: quota-fixtures-check
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/coregen \
		--check \
		--error-output $(PORT_ERROR_FIXTURE) \
		--secret-ref-output $(PORT_SECRET_REF_FIXTURE) \
		--redact-output $(PORT_REDACT_FIXTURE) \
		--crypto-output $(PORT_CRYPTO_FIXTURE)

# STORE-002's fixture advances its own oracle past the frozen baseline
# (fe098b91, "unreleased"), same pattern as AUDIT-001/002 and APPROVAL-001;
# storemetagen has no built-in default, unlike sibling *gen tools, so the
# pin lives here rather than as a Go constant.
STORE_METADATA_ORACLE_COMMIT := fe098b917a72125207bc711915f8daa791d1658f
STORE_METADATA_ORACLE_RELEASE := unreleased

store-metadata-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/storemetagen \
		--check \
		--oracle-commit $(STORE_METADATA_ORACLE_COMMIT) \
		--oracle-release $(STORE_METADATA_ORACLE_RELEASE)

# MCP-001. mcpinitgen pins the baseline oracle caadd5e as a Go constant: the
# three transport/protocol sources it claims are byte-identical there and at
# HEAD, so this row needs no deliberate oracle advance.
mcp-init-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/mcpinitgen \
		--output $(PORT_MCP_INIT_FIXTURE) \
		--oracle-commit caadd5e \
		--oracle-release v0.22.1

# MCP-004. Same pinned oracle and sources as MCP-001.
mcp-stdio-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/mcpstdiogen \
		--output $(PORT_MCP_STDIO_FIXTURE) \
		--oracle-commit caadd5e \
		--oracle-release v0.22.1

# GIT-003 version-winner corpus. Same baseline oracle; the sources it claims
# are unchanged there.
git-winner-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/gitwinnergen \
		--output $(PORT_GIT_WINNER_FIXTURE) \
		--oracle-commit caadd5e \
		--oracle-release v0.22.1

# GIT-002 offline classifier.
git-offline-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/gitofflinegen \
		--output $(PORT_GIT_OFFLINE_FIXTURE) \
		--oracle-commit caadd5e \
		--oracle-release v0.22.1

policy-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/policygen \
		--output $(PORT_POLICY_FIXTURE) \
		--oracle-commit $(POLICY_ORACLE_COMMIT) \
		--oracle-release $(POLICY_ORACLE_RELEASE)

# PAIRING-001. pairinggen pins its own oracle commit as a Go constant, like
# syncgen, so no oracle flags are passed here.
pairing-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/pairinggen \
		--output $(PORT_PAIRING_FIXTURE)

pairing-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/pairinggen \
		--check --output $(PORT_PAIRING_FIXTURE)

pairing-differential: pairing-fixtures-check
	$(CARGO) test -p symvault-sync --test pairing_contract --locked
	$(CARGO) test -p symvault-sync --lib --locked

.PHONY: device-list-differential
DEVICE_LIST_REPORT ?= $(CARGO_TARGET_DIR)/device-list-differential-$(shell date -u +%Y%m%dT%H%M%SZ).json
device-list-differential:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/rust-port/test_device_list_differential.py
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/devicelistdriver --report "$(DEVICE_LIST_REPORT)"

sync-io-differential: pairing-fixtures-check git-io-differential
	GOFLAGS= GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/syncgen --check --output $(PORT_SYNC_FIXTURE)
	$(CARGO) test -p symvault-sync --all-features --locked

oracle-reachability-check:
	./scripts/rust-port/check_oracle_reachability.sh

cfg-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/configpathgen \
		--output $(CFG_PATH_FIXTURE) \
		--oracle-commit $(CFG_ORACLE_COMMIT) \
		--oracle-release $(CFG_ORACLE_RELEASE)

cfg-precedence-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/configprecedencegen \
		--output $(CFG_PRECEDENCE_FIXTURE) \
		--oracle-commit $(CFG_PRECEDENCE_ORACLE_COMMIT) \
		--oracle-release $(CFG_ORACLE_RELEASE)

cfg-precedence-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/configprecedencegen \
		--check --output $(CFG_PRECEDENCE_FIXTURE)
	$(CARGO) test -p symvault-core --test config_precedence_contract --locked

cfg-bytes-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/configbytesgen \
		--output $(CFG_BYTES_FIXTURE) \
		--oracle-commit $(CFG_BYTES_ORACLE_COMMIT) \
		--oracle-release $(CFG_ORACLE_RELEASE)

cfg-bytes-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/configbytesgen \
		--check --output $(CFG_BYTES_FIXTURE)
	$(CARGO) test -p symvault-core --test config_bytes_contract --locked

cfg-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/configpathgen \
		--check --output $(CFG_PATH_FIXTURE)
	$(CARGO) test -p symvault-core --test config_paths_contract --locked

mcp-init-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/mcpinitgen \
		--check --output $(PORT_MCP_INIT_FIXTURE)

# MCP-001 differential: the Go corpus replayed against the Rust transport.
mcp-init-differential: mcp-init-fixtures-check
	$(CARGO) test -p symvault-mcp --test initialize_contract --locked

mcp-stdio-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/mcpstdiogen \
		--check --output $(PORT_MCP_STDIO_FIXTURE)

# MCP-004 differential: the hostile-frame corpus replayed against Rust.
mcp-stdio-differential: mcp-stdio-fixtures-check
	$(CARGO) test -p symvault-mcp --test stdio_hygiene_contract --locked

git-winner-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/gitwinnergen \
		--check --output $(PORT_GIT_WINNER_FIXTURE)

# GIT-003 differential: the version-winner corpus replayed against Rust.
git-winner-differential: git-winner-fixtures-check
	$(CARGO) test -p symvault-sync --test version_winner_contract --locked

# GIT-002 productive transport/cleanup cases replaying the source-bound Go fixture.
git-io-differential:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/gitio --check --output testdata/port/sync/git-io.json
	$(CARGO) test -p symvault-sync --test git_io_gaps --locked -- --test-threads=1

git-offline-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/gitofflinegen \
		--check --output $(PORT_GIT_OFFLINE_FIXTURE)

# GIT-002 differential: the offline-classification corpus replayed against Rust.
git-offline-differential: git-offline-fixtures-check
	$(CARGO) test -p symvault-sync --test git_offline_contract --locked

policy-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/policygen \
		--check --output $(PORT_POLICY_FIXTURE)

rust-007-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/configgen \
		--config-output $(PORT_CONFIG_FIXTURE) \
		--platform-output $(PORT_PLATFORM_FIXTURE) \
		--oracle-commit $(CONFIG_ORACLE_COMMIT) \
		--oracle-release $(CONFIG_ORACLE_RELEASE)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/sessionquotagen \
		--session-output $(PORT_SESSION_FIXTURE) \
		--quota-output $(PORT_PERSISTENT_QUOTA_FIXTURE) \
		--oracle-commit $(SESSION_ORACLE_COMMIT) \
		--oracle-release $(SESSION_ORACLE_RELEASE)

rust-007-fixtures-check: config-profile-fixtures-check
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/configgen \
		--check --config-output $(PORT_CONFIG_FIXTURE) \
		--platform-output $(PORT_PLATFORM_FIXTURE)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/sessionquotagen \
		--check --session-output $(PORT_SESSION_FIXTURE) \
		--quota-output $(PORT_PERSISTENT_QUOTA_FIXTURE)

rust-007-differential: rust-007-fixtures-check
	$(CARGO) test -p symvault-core --test config_session_contract --all-features --locked
	$(CARGO) test -p symvault-platform --test platform_contract --test quota_platform_contract --all-features --locked

.PHONY: config-profile-fixtures-check config-profile-differential
config-profile-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/configprofilegen --check

config-profile-differential: config-profile-fixtures-check
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./scripts/rust-port/cmd/configprofilegen -count=1 -v -timeout=10m
	$(CARGO) test -p symvault-core --test config_profiles_contract --locked

config-session-differential: rust-007-differential config-profile-differential

differential-go-selftest:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(MAKE) build
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/diffharness \
		--left ./$(BINARY_NAME) --right ./$(BINARY_NAME) --cases $(PORT_CLI_CASES)

crypto-differential:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/cryptogen \
		--check --output testdata/port/crypto/age-kdf.json
	$(CARGO) test -p symvault-crypto --all-features --locked
	@mkdir -p target/crypto
	$(CARGO) run -p symvault-crypto --example crypto_emit --locked > target/crypto/rust-output.txt
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/cryptoverify target/crypto/rust-output.txt
	$(MAKE) crypto-fuzz-smoke

crypto-fuzz-smoke:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test -run '^$$' -fuzz=FuzzParseArgon2idParams -fuzztime=3s -timeout=30s ./internal/crypto
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test -run '^$$' -fuzz=FuzzDecryptAgeEnvelope -fuzztime=3s -timeout=30s ./internal/crypto

# Verify the independent fuzz workspace has a present, consistent lockfile.
# cargo-fuzz 0.13.2 has no --locked flag; the locked Cargo check validates
# checksums before the run, and the hash guard rejects any lockfile mutation.
rust-fuzz-lock:
	@set -eu; \
	test -f "$(RUST_FUZZ_MANIFEST)" || { echo "Missing $(RUST_FUZZ_MANIFEST)" >&2; exit 1; }; \
	test -f "$(RUST_FUZZ_LOCK)" || { echo "Missing $(RUST_FUZZ_LOCK)" >&2; exit 1; }; \
	test -f "$(RUST_FUZZ_DENY)" || { echo "Missing $(RUST_FUZZ_DENY)" >&2; exit 1; }; \
	$(CARGO) metadata --manifest-path "$(RUST_FUZZ_MANIFEST)" --locked --format-version 1 --no-deps >/dev/null; \
	$(CARGO) check --manifest-path "$(RUST_FUZZ_MANIFEST)" --locked; \
	echo "Fuzz manifest and lockfile are present and locked."

# Bounded PR smoke; the corpus is copied because libFuzzer may add files to it.
rust-fuzz-smoke: rust-fuzz-lock
	@set -eu; \
	corpus="$$(mktemp -d)"; \
	runs_arg=""; \
	lock_before="$$(shasum -a 256 "$(RUST_FUZZ_LOCK)")"; \
	if [ -n "$(RUST_FUZZ_RUNS)" ]; then runs_arg="-runs=$(RUST_FUZZ_RUNS)"; fi; \
	trap 'rm -rf "$$corpus"' EXIT; \
	cp -R "$(RUST_FUZZ_DIR)/corpus/age_envelope/." "$$corpus/"; \
	CARGOFLAGS=--locked $(CARGO) +$(RUST_FUZZ_TOOLCHAIN) fuzz run --fuzz-dir "$(RUST_FUZZ_DIR)" --sanitizer none age_envelope "$$corpus" -- \
		$$runs_arg -max_total_time=$(RUST_FUZZ_MAX_TOTAL_TIME) \
		-max_len=$(RUST_FUZZ_MAX_LEN) -timeout=$(RUST_FUZZ_TIMEOUT) \
		-rss_limit_mb=$(RUST_FUZZ_RSS_LIMIT_MB) -seed=992 -verbosity=0 \
		-print_final_stats=1 -dict="$(CURDIR)/$(RUST_FUZZ_DIR)/dictionaries/age_envelope.dict"; \
	lock_after="$$(shasum -a 256 "$(RUST_FUZZ_LOCK)")"; \
	test "$$lock_before" = "$$lock_after" || { echo "Fuzz run modified $(RUST_FUZZ_LOCK)" >&2; exit 1; }

# Main/scheduled coverage run; still has a hard wall-clock bound.
rust-fuzz:
	$(MAKE) rust-fuzz-smoke RUST_FUZZ_RUNS= RUST_FUZZ_MAX_TOTAL_TIME=60

# rust-007-fixtures-check is a dependency again. The first attempt at this, on
# 2026-09-14, was rejected by native CI because sessionquotagen stamped the
# generating host's runtime.GOOS into the compared bytes, so a Linux runner
# could only ever call a darwin-frozen fixture stale. That field is gone now:
# it described the machine, not the pinned oracle. Verified before re-wiring
# that goos was the only host-dependent value in these four fixtures.
# Everything CI will run that can run here, in fail-fast order: formatting and
# lint first because they are seconds, then the contract corpora, then the
# workspace.
#
# This exists because a CI round trip costs ten minutes and two of this
# migration's three rounds were avoidable. `lint` in particular pins CI's
# golangci-lint version through `go run`; a golangci-lint on the host PATH is a
# different version and reports a different set, so it is not a substitute --
# the comment on the lint target above records the same lesson from an earlier
# batch of misspell hits that reached CI.
#
# Not covered here, deliberately: the native macOS/Windows matrix. `rust-native`
# carries `if: github.event_name != 'pull_request'`, so it does not run on a PR
# at all and cannot be pre-empted locally -- waiting on a PR for native evidence
# is waiting for something that will not happen.
preflight: fmt-check lint
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets --all-features --locked -- -D warnings
	$(MAKE) port-contract
	$(CARGO) test --workspace --all-features --locked
	$(CARGO) test --workspace --doc --all-features --locked
	@echo "PASS preflight: every CI gate that can run on this host"

port-contract: oracle-reachability-check port-fixtures-check keyring-key-fixtures-check core-fixtures-check policy-fixtures-check mcp-init-fixtures-check mcp-stdio-fixtures-check git-winner-fixtures-check git-offline-fixtures-check git-io-differential cfg-fixtures-check cfg-precedence-fixtures-check cfg-bytes-fixtures-check store-metadata-fixtures-check rust-007-fixtures-check sync-io-differential differential-go-selftest crypto-differential

rust-build:
	$(CARGO) build --workspace --locked

rust-check:
	$(CARGO) check --workspace --all-targets --all-features --locked

rust-lint:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --workspace --all-targets --all-features --locked -- -D warnings

rust-test:
	$(CARGO) nextest run --workspace --all-features --locked
	$(CARGO) test --workspace --doc --all-features --locked

rust-miri:
	MIRIFLAGS=$(MIRI_FLAGS) CARGO_TARGET_DIR="$(MIRI_TARGET_DIR)" $(CARGO) +$(MIRI_TOOLCHAIN) miri test -p symvault-core --locked

rust-features:
	# Keep the committed lockfile usable while checking every feature combination.
	# cargo-hack mutates manifests for --no-dev-deps, which requires a different lockfile.
	$(CARGO) hack check --workspace --each-feature --locked

rust-coverage:
	$(CARGO) llvm-cov nextest --workspace --all-features --locked --summary-only

rust-security:
	$(CARGO) audit --file Cargo.lock
	$(CARGO) deny --locked check
	$(CARGO) audit --file $(RUST_FUZZ_LOCK)
	$(CARGO) deny --manifest-path $(RUST_FUZZ_MANIFEST) --config $(RUST_FUZZ_DENY) --locked check

rust-version-contract:
	@mkdir -p target/port
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) build -ldflags "-s -w -X main.version=$(PORT_CONTRACT_VERSION) -X main.commit=none -X main.date=unknown" -o $(PORT_GO_BINARY) .
	SYMVAULT_VERSION=$(PORT_CONTRACT_VERSION) $(CARGO) build -p symvault-cli --bin symvault --locked
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/diffharness \
		--left "$(PORT_GO_BINARY)" --right "$(RUST_BINARY)" \
		--cases $(PORT_CLI_CASES) --stage version

store-reopen-fixture:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/storereopen --generate --fixture testdata/port/store/reopen.json

store-differential:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/storereopen --fixture testdata/port/store/reopen.json
	$(CARGO) build -p symvault-store --example store-reopen --locked
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/storereopen --run --fixture testdata/port/store/reopen.json --rust-binary "$(CARGO_TARGET_DIR)/debug/examples/store-reopen"
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/storegen --check --output testdata/port/store/store.json
	$(CARGO) test -p symvault-store --locked

audit-fixtures-generate:
	UPDATE_AUDIT_FIXTURE=1 GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/audit -run '^TestAuditFixture$$' -count=1

audit-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/audit -run '^TestAuditFixture$$' -count=1

audit-differential: audit-fixtures-check
	@set -eu; rm -rf target/audit; mkdir -p target/audit
	$(CARGO) test -p symvault-store --test audit --locked
	$(CARGO) run -p symvault-store --example audit-emit --locked -- target/audit/rust-output.jsonl >/dev/null
	@test -s target/audit/rust-output.jsonl
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/auditverify target/audit/rust-output.jsonl

rust-gates: store-differential audit-differential
	$(MAKE) rust-lint
	$(MAKE) rust-check
	$(MAKE) rust-test
	$(MAKE) rust-security
	$(MAKE) rust-fuzz-smoke
	$(MAKE) rust-miri
	$(MAKE) rust-features
	$(MAKE) rust-coverage
	$(MAKE) rust-version-contract

# Install dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

# Help target
help:
	@echo "Available targets:"
	@echo "  build              - Build the binary"
	@echo "  test               - Run all tests with race detector"
	@echo "  test-fast          - Run all tests without race detector (quick iteration)"
	@echo "  test-coverage      - Run tests with coverage report"
	@echo "  cover              - Generate canonical coverage.out report"
	@echo "  test-coverage-html - Generate HTML coverage report"
	@echo "  test-race          - Run tests with race detector"
	@echo "  test-ci            - Run CI-like tests (race + coverage + timeout)"
	@echo "  test-core          - Run tests for core packages only"
	@echo "  test-core-coverage - Run core package tests with coverage"
	@echo "  test-vault         - Run vault package tests"
	@echo "  test-config        - Run config package tests"
	@echo "  test-crypto        - Run crypto package tests"
	@echo "  test-bench         - Run benchmarks"
	@echo "  clean              - Clean build artifacts, coverage files, and scratch dirs"
	@echo "  lint               - Run linter"
	@echo "  lint-fix           - Run linter with auto-fix"
	@echo "  fmt                - Format code"
	@echo "  fmt-check          - Check formatting (fails if gofmt would change files)"
	@echo "  vet                - Run go vet (includes passlint)"
	@echo "  passlint           - Run passlint analyzer tests"
	@echo "  deps               - Download and tidy dependencies"
	@echo "  completions        - Generate shell completions"
	@echo "  manpages           - Generate manual pages"
	@echo "  port-fixtures-generate - Regenerate frozen Go-oracle CLI fixtures"
	@echo "  port-fixtures-check    - Verify Go-oracle CLI fixtures have not drifted"
	@echo "  core-fixtures-generate - Regenerate frozen Go-oracle core fixtures"
	@echo "  core-fixtures-check    - Verify Go-oracle core fixtures have not drifted"
	@echo "  quota-fixtures-generate - Regenerate pure quota transition vectors"
	@echo "  quota-fixtures-check    - Verify pure quota transition vectors have not drifted"
	@echo "  policy-fixtures-generate - Regenerate frozen Go-oracle policy/tier fixtures"
	@echo "  policy-fixtures-check    - Verify Go-oracle policy/tier fixtures have not drifted"
	@echo "  sync-io-differential - Verify Go-generated sync/import/archive/intake contracts"
	@echo "  differential-go-selftest - Compare the Go oracle with itself in isolated sandboxes"
	@echo "  crypto-differential - Verify Go↔Rust age and KDF cross-decryption"
	@echo "  crypto-fuzz-smoke - Run the bounded Argon2id parser fuzz smoke"
	@echo "  store-reopen-fixture  - Generate the deterministic Go↔Rust reopen fixture"
	@echo "  store-differential - Verify Go↔Rust storage reopen and read-only fixtures"
	@echo "  audit-fixtures-generate - Generate the production-Go audit fixture"
	@echo "  audit-fixtures-check - Verify audit fixture provenance and drift"
	@echo "  audit-differential - Verify Go↔Rust audit chain, rotation, and export"
	@echo "  rust-fuzz-smoke   - Run the deterministic bounded Rust age/KDF fuzz smoke"
	@echo "  rust-fuzz         - Run the bounded main/scheduled Rust age/KDF fuzz pass"
	@echo "  port-contract      - Run all Rust-port contract preparation gates"
	@echo "  rust-007-differential - Check Go-derived config/session/quota/platform contracts"
	@echo "  rust-build         - Build the staged Rust workspace"
	@echo "  rust-check         - Check all Rust targets and features"
	@echo "  rust-lint          - Run rustfmt and Clippy with warnings denied"
	@echo "  rust-test          - Run Rust nextest and doctests"
	@echo "  rust-miri          - Run symvault-core tests under Miri"
	@echo "  rust-features      - Check each Rust feature independently"
	@echo "  rust-coverage      - Measure Rust workspace coverage"
	@echo "  rust-security      - Run Rust advisory and dependency-policy gates"
	@echo "  rust-fuzz-lock     - Verify the independent fuzz manifest and lockfile"
	@echo "  rust-version-contract - Compare Go and Rust version slices"
	@echo "  rust-gates         - Run every staged Rust gate"
	@echo "  docs-check         - Check documentation for deprecated terms and incorrect syntax"
	@echo "  editors-build      - Build all editor plugins (VS Code, Cursor, Neovim)"
	@echo "  editors-test       - Test all editor plugins"
	@echo "  editors-package    - Package editor plugins (.vsix, .tar.gz)"
	@echo "  editors-clean      - Clean editor build artifacts"
	@echo "  help               - Show this help message"

# Editor plugin targets
editors-build:
	@echo "Building editor plugins..."
	@bash scripts/build-editors.sh

editors-test:
	@echo "Testing editor plugins..."
	@cd editors/mcp-client && npm test
	@cd editors/vscode && npm test

editors-package:
	@echo "Packaging editor plugins..."
	@bash scripts/package-vscode.sh
	@bash scripts/package-cursor.sh
	@bash scripts/package-nvim.sh

editors-clean:
	@echo "Cleaning editor build artifacts..."
	@rm -rf editors/mcp-client/out editors/mcp-client/node_modules
	@rm -rf editors/vscode/out editors/vscode/node_modules
	@rm -rf editors/cursor/out editors/cursor/node_modules
	@rm -f editors/**/*.vsix editors/**/*.tar.gz

# Check documentation for deprecated terms and incorrect syntax
docs-check:
	@echo "Checking documentation for deprecated terms and incorrect syntax..."
	@errors=0; \
	for pattern in "brew install --cask openpass" "mcp-config --agent" "mcp_openpass_openpass" "X-Symaira Vault-Agent"; do \
		if grep -r "$$pattern" README.md docs homebrew .gitignore --exclude-dir=dist --exclude-dir=coverage --exclude-dir=node_modules 2>/dev/null; then \
			echo "Found deprecated pattern: $$pattern"; \
			errors=$$((errors + 1)); \
		fi; \
	done; \
	for pattern in "symvault mcp-config" "symvault mcp token" "symvault mcp-token-rotate"; do \
		if grep -r "$$pattern" README.md SECURITY.md .goreleaser.yml docs homebrew internal/agentskill \
			--exclude="migration-v3-to-v4.md" \
			--exclude="MIGRATION-RENAME.md" \
			--exclude-dir=adr \
			--exclude-dir=man \
			--exclude-dir=skills \
			--exclude-dir=dist \
			--exclude-dir=coverage \
			--exclude-dir=node_modules 2>/dev/null; then \
			echo "Found deprecated active documentation command: $$pattern"; \
			errors=$$((errors + 1)); \
		fi; \
	done; \
	for pattern in 'symvault agent token [^[:space:]`]+ (new|list|revoke|rotate)' 'symvault agent profile [^[:space:]`]+ (show|edit|export)'; do \
		if grep -rE "$$pattern" README.md SECURITY.md .goreleaser.yml docs homebrew internal/agentskill \
			--exclude-dir=man \
			--exclude-dir=dist \
			--exclude-dir=coverage \
			--exclude-dir=node_modules 2>/dev/null; then \
			echo "Found agent argument before its action; use action-first command order: $$pattern"; \
			errors=$$((errors + 1)); \
		fi; \
	done; \
	if grep -rE 'symvault agent token new [^[:space:]`]+ .*--expires' README.md SECURITY.md docs homebrew internal/agentskill \
		--exclude="migration-v3-to-v4.md" \
		--exclude-dir=adr \
		--exclude-dir=man \
		--exclude-dir=skills \
		--exclude-dir=dist \
		--exclude-dir=coverage \
		--exclude-dir=node_modules 2>/dev/null; then \
		echo "Found deprecated --expires flag on agent token command; use --ttl"; \
		errors=$$((errors + 1)); \
	fi; \
	for tool in "openpass_list" "openpass_get" "openpass_generate" "openpass_health"; do \
		if grep -rE "\b$$tool\b" README.md docs homebrew .gitignore --exclude-dir=dist --exclude-dir=coverage --exclude-dir=node_modules 2>/dev/null; then \
			echo "Found deprecated tool name: $$tool"; \
			errors=$$((errors + 1)); \
		fi; \
	done; \
	for pattern in "./openpass" "cd Symaira Vault"; do \
		if grep -rF "$$pattern" CONTRIBUTING.md 2>/dev/null; then \
			echo "Found stale post-rename example in CONTRIBUTING.md: $$pattern"; \
			errors=$$((errors + 1)); \
		fi; \
	done; \
	echo "Checking README.md links..."; \
	for link in $$(grep -oE '\[([^]]+)\]\(([^)]+)\)' README.md | grep -v '^http' | grep -v '^#' | sed 's/.*](\([^)]*\)).*/\1/'); do \
		case "$$link" in \
			CODE_OF_CONDUCT.md|CONTRIBUTING.md|LICENSE|SECURITY.md|config.yaml.example) \
				if [ ! -f "$$link" ]; then \
					echo "Broken link in README.md: $$link"; \
					errors=$$((errors + 1)); \
				fi; \
				;; \
			docs/*) \
				if [ ! -f "$$link" ]; then \
					echo "Broken link in README.md: $$link"; \
					errors=$$((errors + 1)); \
				fi; \
				;; \
		esac; \
	done; \
	if [ $$errors -gt 0 ]; then \
		echo "Found $$errors documentation issues."; \
		exit 1; \
	fi; \
	echo "Documentation check passed."
