.PHONY: keyring-key-fixtures-generate keyring-key-fixtures-check biometric-fixtures-generate biometric-fixtures-check biometric-differential all build install test test-fast test-coverage test-verbose test-race test-ci cover clean lint lint-fix fmt fmt-check vet passlint completions manpages release-manpages release-contract release-contract-selftest rust-cli manpages-differential port-fixtures-generate port-fixtures-check core-fixtures-generate core-fixtures-check quota-fixtures-generate quota-fixtures-check policy-fixtures-generate policy-fixtures-check store-metadata-fixtures-check rust-007-fixtures-generate rust-007-fixtures-check rust-007-differential config-session-differential sync-io-differential git-io-differential pairing-fixtures-generate pairing-fixtures-check pairing-differential differential-go-selftest crypto-differential crypto-fuzz-smoke port-contract store-reopen-fixture store-differential audit-fixtures-generate audit-fixtures-check audit-differential rust-build rust-check rust-lint rust-test rust-miri rust-features rust-coverage rust-security rust-version-contract rust-fuzz-lock rust-fuzz-smoke rust-fuzz rust-gates rust-gates-core help docs-check ffi-fixtures-generate ffi-fixtures-check ffi-differential ffi-xcframework ffi-ios-simulator-test

# Variables
BINARY_NAME := symvault
GO := go
CARGO := cargo
# Vault-containing suites require the real Rust CLI. Caller-supplied binaries
# are preserved; otherwise Cargo supplies the native/custom-target artifact.
GO_TEST := python3 scripts/run_go_tests.py $(CARGO) -- $(GO) test
GOFLAGS := -v
GOLANGCI_LINT_VERSION := v2.11.4
# Historical oracle generation keeps its measured compiler identity.
GO_TOOLCHAIN ?= go1.26.6
BUILD_GO_TOOLCHAIN ?= go1.26.10
export GOTOOLCHAIN ?= $(BUILD_GO_TOOLCHAIN)
# These fixture generators link packages whose backend is chosen during Go
# package initialization. Select memory in Make, before `go run` starts; setting
# the variable from a generator's main function is too late for package init.
GO_KEYRING_FIXTURE_TARGETS := \
	port-fixtures-generate port-fixtures-check \
	keyring-key-fixtures-generate keyring-key-fixtures-check \
	quota-fixtures-generate quota-fixtures-check \
	policy-fixtures-generate policy-fixtures-check \
	mcp-init-fixtures-generate mcp-init-fixtures-check \
	mcp-stdio-fixtures-generate mcp-stdio-fixtures-check \
	mcp-http-init-fixtures-generate mcp-http-init-fixtures-check \
	mcp-http-init-fixtures-run mcp-http-init-differential mcp-render-differential mcp-call-fixtures-check \
	rust-007-fixtures-generate rust-007-fixtures-check
$(GO_KEYRING_FIXTURE_TARGETS): export SYMVAULT_TEST_KEYRING := memory

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
	$(GO_TEST) ./... -race -v

# Run all tests without race detector (faster, for quick iteration)
test-fast:
	$(GO_TEST) ./... -v

# Run tests with coverage
test-coverage:
	@mkdir -p $(COVERAGE_DIR)
	$(GO_TEST) ./... -coverprofile=$(COVERAGE_FILE) -covermode=atomic
	$(GO) tool cover -func=$(COVERAGE_FILE)
	@echo ""
	@echo "Coverage report saved to $(COVERAGE_FILE)"

# Generate HTML coverage report
test-coverage-html: test-coverage
	$(GO) tool cover -html=$(COVERAGE_FILE) -o $(COVERAGE_HTML)
	@echo "HTML coverage report saved to $(COVERAGE_HTML)"

# Run tests with race detector
test-race:
	$(GO_TEST) ./... -race -timeout=30m -v

# Run tests for core packages only (vault, config, crypto)
test-core:
	$(GO_TEST) ./internal/vault/... ./internal/config/... ./internal/crypto/... -v

# Run tests for core packages with coverage
test-core-coverage:
	@mkdir -p $(COVERAGE_DIR)
	$(GO_TEST) ./internal/vault/... ./internal/config/... ./internal/crypto/... \
		-coverprofile=$(COVERAGE_FILE) -covermode=atomic
	$(GO) tool cover -func=$(COVERAGE_FILE) | grep "total:"
	$(GO) tool cover -func=$(COVERAGE_FILE)

# Run specific package tests
test-vault:
	$(GO_TEST) ./internal/vault/... -v

test-config:
	$(GO) test ./internal/config/... -v

test-crypto:
	$(GO) test ./internal/crypto/... -v

# Run benchmarks
test-bench:
	$(GO_TEST) ./... -bench=. -benchmem

# Generate coverage report (canonical single-file output)
cover:
	@mkdir -p $(COVERAGE_DIR)
	$(GO_TEST) ./... -coverprofile=$(COVERAGE_FILE) -covermode=atomic
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
	GOWORK=off GOTOOLCHAIN=$(BUILD_GO_TOOLCHAIN) $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m --verbose

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
	GOWORK=off GOTOOLCHAIN=$(BUILD_GO_TOOLCHAIN) $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --fix --timeout=5m --verbose

# Run CI-like tests (race + coverage + timeout, same as CI)
test-ci:
	@echo "Running CI-like test suite..."
	GOWORK=off $(GO_TEST) -v -race -timeout=30m -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	@echo ""
	@echo "Coverage summary:"
	$(GO) tool cover -func=$(COVERAGE_FILE) | grep "total:"

# Install binary
install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BINARY_NAME) $(DESTDIR)$(PREFIX)/bin/$(BINARY_NAME)

# Rust symvault CLI for the host, built in the release profile. The release
# pipeline (.goreleaser.yml) and the generators below use it; SYMVAULT_VERSION
# is the only build-time stamp the Rust CLI reads (crates/symvault-cli/src/main.rs).
RUST_RELEASE_BINARY := $(CARGO_TARGET_DIR)/release/symvault
SYMVAULT_VERSION ?= $(patsubst v%,%,$(VERSION))

.PHONY: rust-cli
rust-cli:
	SYMVAULT_VERSION="$(SYMVAULT_VERSION)" $(CARGO) build --release --locked -p symvault-cli --bin symvault

# Generate shell completions
completions: rust-cli
	@mkdir -p completions
	$(RUST_RELEASE_BINARY) completion bash > completions/symvault.bash
	$(RUST_RELEASE_BINARY) completion zsh > completions/symvault.zsh
	$(RUST_RELEASE_BINARY) completion fish > completions/symvault.fish

# Generate manual pages
manpages: rust-cli
	@mkdir -p docs/man
	$(RUST_RELEASE_BINARY) generate manpages docs/man

# Generate release manuals in ignored output so GoReleaser does not dirty docs/man.
# MAN_DIR is overridden by `make release-contract`, which keeps dist/ outside the repo.
MAN_DIR ?= dist/man
release-manpages: rust-cli
	@mkdir -p $(MAN_DIR)
	$(RUST_RELEASE_BINARY) generate manpages $(MAN_DIR)

# DIST-001/002: snapshot the release pipeline into an external dist dir and
# check names, members, checksums, packages, MCPB, SBOM and native runs.
RELEASE_CONTRACT_DIST ?= /Volumes/1TB_NVMe_SN850X/Dev/Symaira_Dev/builds/symaira-vault/dist
.PHONY: release-contract
release-contract:
	python3 scripts/rust-port/release_contract.py --dist "$(RELEASE_CONTRACT_DIST)"

# Self-test of the checker on a synthetic dist (no build, no docker, no disk):
# it must accept a well-formed dist and reject every tamper control.
release-contract-selftest:
	python3 scripts/rust-port/test_release_contract.py
	python3 scripts/test_supported_platforms.py

# VALUE-001 value gate (Go-free, stdlib Python; measured and reported, decision
# D5). Measures stripped release binaries, never builds them: pass the Go
# release binary and the Rust release binary, e.g.
#   make value-gate GO_BIN=/path/symvault-go RUST_BIN=target/release/symvault
# Refuses to run when the host 1-min load average is above 4. Set
# VALUE_GATE_ENFORCE=1 to make a missed rule exit non-zero.
GO_BIN ?=
RUST_BIN ?= target/release/symvault
VALUE_GATE_OUT ?= target/value-gate/value-gate.json
VALUE_GATE_FLAGS ?=
.PHONY: value-gate value-gate-selftest
value-gate:
	@test -n "$(GO_BIN)" || { echo "value-gate: set GO_BIN=<Go release binary> (RUST_BIN defaults to $(RUST_BIN))" >&2; exit 2; }
	python3 -B scripts/rust-port/valuegate.py measure --go "$(GO_BIN)" --rust "$(RUST_BIN)" --out "$(VALUE_GATE_OUT)" $(VALUE_GATE_FLAGS)
	python3 -B scripts/rust-port/valuegate.py check "$(VALUE_GATE_OUT)" $(if $(VALUE_GATE_ENFORCE),,--report-only)

# Unit tests of the value gate on fake shell-script binaries (no build, no Go).
value-gate-selftest:
	python3 -B scripts/rust-port/test_valuegate.py

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
CLI_ORACLE_COMMIT ?= dda01b562696136dd65e958b6abdce2f29fe297f
CLI_ORACLE_RELEASE ?= unreleased
KEYRING_KEY_FIXTURE := testdata/port/session/keyring-keys.json
BIOMETRIC_FIXTURE := testdata/port/session/biometric.json
BIOMETRIC_ORACLE_COMMIT ?= d13e5d0b
BIOMETRIC_ORACLE_RELEASE ?= unreleased
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
PORT_MCP_HTTP_INIT_FIXTURE := testdata/port/mcp/http-initialize.json
PORT_MCP_HTTP_RATELIMIT_FIXTURE := testdata/port/mcp/http-ratelimit.json
PORT_MCP_STDIO_FIXTURE := testdata/port/mcp/stdio-hygiene.json
PORT_GIT_WINNER_FIXTURE := testdata/port/sync/version-winner.json
PORT_GIT_OFFLINE_FIXTURE := testdata/port/sync/git-offline.json
CFG_PATH_FIXTURE := testdata/port/config/paths.json
# CFG-001 pins its own production-Go oracle. configpathgen verifies this commit
# against git objects, so a stale pin fails loudly rather than mislabelling.
CFG_ORACLE_COMMIT ?= fc9eddc0
CFG_BYTES_FIXTURE := testdata/port/config/bytes.json
CFG_BYTES_ORACLE_COMMIT ?= 58d978bb53a1dc6257b3a0e3154f7bd29fdd3fd9
CFG_PRECEDENCE_FIXTURE := testdata/port/config/precedence.json
CFG_PRECEDENCE_ORACLE_COMMIT ?= aa21ec4e
CFG_SECTIONS_FIXTURE := testdata/port/config/sections.json
CFG_SECTIONS_ORACLE_COMMIT ?= 58d978bb53a1dc6257b3a0e3154f7bd29fdd3fd9
CFG_ORACLE_RELEASE ?= unreleased
# RUST-007's config fixture pins its own production-Go oracle, separately from
# PORT_ORACLE_COMMIT: it covers internal/config, which the CFG rows keep moving,
# while the session/quota fixtures still sit on the frozen v0.22.1 baseline.
CONFIG_ORACLE_COMMIT ?= 58d978bb53a1dc6257b3a0e3154f7bd29fdd3fd9
CONFIG_ORACLE_RELEASE ?= unreleased
PORT_SYNC_FIXTURE := testdata/port/sync/sync.json
PORT_PAIRING_FIXTURE := testdata/port/pairing/contract.json
PORT_CONFIG_FIXTURE := testdata/port/config/contract.json
PORT_SESSION_FIXTURE := testdata/port/session/contract.json
PORT_PLATFORM_FIXTURE := testdata/port/platform/contract.json
PORT_PERSISTENT_QUOTA_FIXTURE := testdata/port/quotas/contract.json
PORT_GO_BINARY := target/port/symvault-go
MANPAGES_GO_BINARY := target/port/symvault-manpages-go
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

# SESSION-003 (non-interactive half): keychain OSStatus contract, no-op
# biometric manager and Touch ID item layout, frozen from the pinned Go sources.
# The Rust replay runs everywhere; the Security-framework test is macOS-only and
# uses disposable keychains (it compiles to zero tests elsewhere).
biometric-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/biometricgen \
		--output $(BIOMETRIC_FIXTURE) \
		--oracle-commit $(BIOMETRIC_ORACLE_COMMIT) \
		--oracle-release $(BIOMETRIC_ORACLE_RELEASE)

biometric-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/biometricgen \
		--check --output $(BIOMETRIC_FIXTURE)

# One cargo invocation per target: a positional test filter applies to every
# target of a `cargo test` run, so `--lib keychain_status --test biometric_contract`
# filtered the whole contract replay away ("0 passed; 10 filtered out") and the
# gate stayed green. The integration targets therefore run without a filter.
biometric-differential: biometric-fixtures-check
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./scripts/rust-port/cmd/biometricgen -count=1
	$(CARGO) test -p symvault-core --lib --locked keychain_status
	$(CARGO) test -p symvault-core --test biometric_contract --locked
	$(CARGO) test -p symvault-platform --test native_biometric_item --locked

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
# (1605b180, "unreleased"), same pattern as AUDIT-001/002 and APPROVAL-001;
# storemetagen has no built-in default, unlike sibling *gen tools, so the
# pin lives here rather than as a Go constant.
STORE_METADATA_ORACLE_COMMIT := b13189220519de245d8972d7af2e2d81618f0432
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

.PHONY: device-session-fixtures-generate device-session-fixtures-check device-session-differential
device-session-fixtures-generate:
	UPDATE_DEVICE_SESSION_FIXTURE=1 GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/pairing -run '^TestDeviceSessionFixture$$' -count=1

device-session-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/pairing -run '^TestDeviceSessionFixture$$' -count=1

device-session-differential: device-session-fixtures-check
	$(CARGO) test -p symvault-sync --test device_sessions_contract --locked
	$(CARGO) test -p symvault-sync --lib --locked

# APPROVAL-001 frozen local-approval-CLI contract. approvalgen records the real
# Go LocalHTTPHandler + Go CLI exchanges (pinned oracle sources, fixed certs);
# the replay needs no Go and is the evidence that survives Go removal.
.PHONY: approval-fixtures-generate approval-fixtures-check approval-replay
approval-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/approvalgen

approval-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/approvalgen --check

approval-replay:
	$(CARGO) test -p symvault-cli --test approval_queue_replay --locked

# APPROVAL-001 end to end: the Rust CLI against the production Rust listener
# (seeded queue, TLS and mTLS) and against a real `symvault mcp` process, plus
# the mTLS settings refusals frozen from the real Go `symvault mcp` by
# approvaltlsgen (pinned oracle sources). The e2e needs no Go.
.PHONY: approval-tls-fixtures-generate approval-tls-fixtures-check approval-e2e
approval-tls-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/approvaltlsgen

approval-tls-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/approvaltlsgen --check

approval-e2e:
	$(CARGO) test -p symvault-cli --test approval_e2e --locked

# APPROVAL-001 device-token /api/v1/approvals endpoint. deviceapprovalgen records
# the real Go HTTPHandler + DeviceSessionStore behind Go's ServeMux; the replay
# drives the Rust MCP HTTP server with the same scenarios and needs no Go.
.PHONY: device-approval-fixtures-generate device-approval-fixtures-check device-approval-replay
device-approval-fixtures-generate:
	SYMVAULT_TEST_KEYRING=memory GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/deviceapprovalgen

device-approval-fixtures-check:
	SYMVAULT_TEST_KEYRING=memory GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/deviceapprovalgen --check

device-approval-replay:
	$(CARGO) test -p symvault-mcp --test device_approvals_replay --locked

# PAIRING-001 / APPROVAL-001 server-side device enrollment routes
# (/api/v1/devices/enroll-code and /enroll). deviceenrollgen records the real Go
# handlers over the real pairing.TokenStore and DeviceSessionStore behind Go's
# ServeMux (about 4 s of real-clock pauses); the replay drives the Rust MCP HTTP
# server with the same scenarios and needs no Go. Throttling of both routes is
# recorded by http002ratelimitgen (mcp-http-ratelimit-differential).
.PHONY: device-enroll-fixtures-generate device-enroll-fixtures-check device-enroll-replay
device-enroll-fixtures-generate:
	SYMVAULT_TEST_KEYRING=memory GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/deviceenrollgen

device-enroll-fixtures-check:
	SYMVAULT_TEST_KEYRING=memory GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/deviceenrollgen --check

device-enroll-replay:
	$(CARGO) test -p symvault-mcp --test device_enroll_replay --locked

.PHONY: device-list-differential
DEVICE_LIST_REPORT ?= $(CARGO_TARGET_DIR)/device-list-differential-$(shell date -u +%Y%m%dT%H%M%SZ).json
device-list-differential:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/rust-port/test_device_list_differential.py
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/devicelistdriver --report "$(DEVICE_LIST_REPORT)"

sync-io-differential: export-differential export-cli-differential restore-errors-differential cxf-import-differential onepass-import-differential zip-errors-differential pass-gpg-differential csv-import-differential pairing-fixtures-check git-io-differential
	GOFLAGS= GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/syncgen --check --output $(PORT_SYNC_FIXTURE)
	# Other sync integration suites already run through the prerequisites above.
	$(CARGO) test -p symvault-sync --all-features --locked --lib \
		--test contracts --test pairing_contract --test version_winner_contract --test git_offline_contract

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

.PHONY: cfg-overrides-fixtures-generate cfg-overrides-fixtures-check
cfg-overrides-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/configoverridesgen

cfg-overrides-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/configoverridesgen --check
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./scripts/rust-port/cmd/configoverridesgen -count=1 -v
	$(CARGO) test -p symvault-cli --bin symvault config_override_tests:: --locked -- --nocapture

cfg-sections-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/configsectionsgen \
		--output $(CFG_SECTIONS_FIXTURE) \
		--oracle-commit $(CFG_SECTIONS_ORACLE_COMMIT) \
		--oracle-release $(CFG_ORACLE_RELEASE)

cfg-sections-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/configsectionsgen \
		--check --output $(CFG_SECTIONS_FIXTURE)
	$(CARGO) test -p symvault-core --test config_sections_contract --test config_sections_process_guard --locked

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

# Generation is permitted only inside the immutable historical source context.
# The producer also verifies every declared production source against its pin.
.PHONY: mcp-http-init-fixtures-generate mcp-http-init-fixtures-check mcp-http-init-fixtures-run mcp-http-init-differential
mcp-http-init-fixtures-generate:
	@test "$$(git rev-parse HEAD)" = d1cd0f97ac550bc3020bc86b0514989f8d28d95c || { echo 'HTTP fixture generation requires a disposable historical oracle checkout' >&2; exit 1; }
	SYMVAULT_TEST_KEYRING=memory GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/http001initgen --output $(PORT_MCP_HTTP_INIT_FIXTURE)

mcp-http-init-fixtures-check: mcp-ordered-fixtures-check
	PYTHONDONTWRITEBYTECODE=1 GOTOOLCHAIN=$(GO_TOOLCHAIN) python3 scripts/rust-port/test_http001init_isolation.py

mcp-http-init-fixtures-run: mcp-http-init-fixtures-check


mcp-http-init-differential: mcp-http-init-fixtures-check
	SYMVAULT_TEST_KEYRING=memory GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/mcp/serverbootstrap -run '^(TestRunHTTPServer_HTTP10ErrorFramingAndKeepAlive|TestRunHTTPServer_OAuthProtectedResource)$$' -count=1
	$(CARGO) test -p symvault-mcp --lib http::tests --locked
	$(CARGO) test -p symvault-mcp --test http_initialize --locked

# HTTP-001/HTTP-002 per-client rate limiter. The producer verifies every declared
# production source against its pin (b1da45d1), so generation needs a checkout
# whose limiter sources are unchanged; the check is non-writing, uses a short
# real clock (about 10 s of sleeps) and is not part of port-contract.
# PLATFORM-002 / ADR 0034 item 29: the MCP anomaly detector. anomalygen records
# the real internal/anomaly detector (rate, off-hours, canary, sweep, tool
# chain) plus source-bound dispatch facts at the ordered reference
# mcp-anomaly-ordered-v1 (24acdb08); the replay and process tests need no Go.
.PHONY: mcp-anomaly-fixtures-generate mcp-anomaly-fixtures-check mcp-anomaly-replay
mcp-anomaly-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/anomalygen

mcp-anomaly-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/anomalygen --check
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./scripts/rust-port/cmd/anomalygen -count=1

mcp-anomaly-replay: mcp-anomaly-fixtures-check
	$(CARGO) test -p symvault-mcp --test anomaly_replay --test anomaly_dispatch --locked

.PHONY: mcp-http-ratelimit-fixtures-generate mcp-http-ratelimit-fixtures-check mcp-http-ratelimit-differential
mcp-http-ratelimit-fixtures-generate:
	SYMVAULT_TEST_KEYRING=memory GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/http002ratelimitgen --output $(PORT_MCP_HTTP_RATELIMIT_FIXTURE)

mcp-http-ratelimit-fixtures-check:
	SYMVAULT_TEST_KEYRING=memory GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/http002ratelimitgen --check --output $(PORT_MCP_HTTP_RATELIMIT_FIXTURE)

mcp-http-ratelimit-differential: mcp-http-ratelimit-fixtures-check
	$(CARGO) test -p symvault-mcp --lib ratelimit::tests --locked
	$(CARGO) test -p symvault-mcp --test http_ratelimit --locked

# HTTP-003 paired production-handler and Rust adapter lifecycle contracts.
.PHONY: mcp-oauth-contract
mcp-oauth-contract:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/mcp/serverbootstrap -run '^(TestOAuthRefreshToken_FullFlow|TestOAuthRefreshToken_ExpiredRefreshDenied|TestOAuthRefreshToken_RegisterResponseIncludesRefresh|TestOAuthRegisterValidationCases|TestOAuthRegisterAcceptsCustomSchemeWithoutUserinfo|TestOAuthRegisterBoundsPersistentClientStore|TestOAuthRefreshToken_WellKnownIncludesRefresh|TestOAuthRefreshToken_UnsupportedGrantType|TestOAuthRefreshToken_MissingRefreshToken)$$' -count=1
	$(CARGO) test -p symvault-mcp --lib oauth::tests --locked
	$(CARGO) test -p symvault-mcp --lib http::tests::authorization_server_discovery_is_reachable_through_oauth_listener --locked

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

rust-007-differential: rust-007-fixtures-check cfg-overrides-fixtures-check
	$(CARGO) test -p symvault-core --test config_session_contract --test session_cache_contract --all-features --locked
	$(CARGO) test -p symvault-platform --test platform_contract --test quota_platform_contract --test session_cache_fallback_contract --all-features --locked

.PHONY: config-profile-fixtures-check config-profile-differential
config-profile-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/configprofilegen --check

config-profile-differential: config-profile-fixtures-check
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./scripts/rust-port/cmd/configprofilegen -count=1 -v -timeout=10m
	$(CARGO) test -p symvault-core --test config_profiles_contract --locked

config-session-differential: rust-007-differential config-profile-differential cfg-sections-fixtures-check

config-cli-differential:
	python3 -B scripts/rust-port/test_gen_config_schema.py
	python3 scripts/rust-port/gen_config_schema.py --check
	./scripts/rust-port/check_config_cli.sh

# CONFIG-WRITER: Go-recorded SaveTo bytes (pinned oracle 690647c5) replayed
# against the Rust writer, plus the rewriting commands on the live Go binary.
.PHONY: config-rewrite-fixtures-generate config-rewrite-differential
config-rewrite-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/configrewritegen \
		--output testdata/port/config/rewrite.json \
		--oracle-commit 690647c5068a818a4b237738882bb20c865a134a \
		--oracle-release unreleased

config-rewrite-differential:
	./scripts/rust-port/check_config_rewrite.sh

# CLI-005: go-yaml scanner/parser/reader error wording of config.yaml. Re-verifies
# the frozen Go corpus (pinned oracle 0cc78062) and replays it against the Rust CLI.
.PHONY: yaml-syntax-cli-differential
yaml-syntax-cli-differential:
	./scripts/rust-port/check_yaml_syntax_cli.sh

# CLI-005/CLI-006: cobra usage errors, argument validators, the output-format gate
# and the "vault not initialized" failure. Re-verifies the frozen Go corpus
# (pinned oracle 0cc78062) and replays it against the Rust CLI.
.PHONY: error-taxonomy-cli-differential
error-taxonomy-cli-differential:
	./scripts/rust-port/check_error_taxonomy_cli.sh

# IO-001: the complete `symvault import <source>` command (every flag, every
# format, existing-entry collisions, error paths and the resulting vault state)
# against the pinned Go binary (oracle bf7f687b). Re-verifies the frozen corpus
# against a rebuilt oracle, then replays it against the Rust CLI.
.PHONY: import-cli-differential
import-cli-differential:
	./scripts/rust-port/check_import_cli.sh

# Deliberate regeneration of the import-command fixture from the pinned oracle.
.PHONY: import-cli-regenerate
import-cli-regenerate:
	SYMVAULT_IMPORT_CLI_REGENERATE=1 ./scripts/rust-port/check_import_cli.sh

# IO-002: `export`, `backup` and `restore` end to end against the pinned Go
# binary (173 cases, oracle bf7f687b), then the Rust replay.
.PHONY: export-cli-differential
export-cli-differential:
	./scripts/rust-port/check_export_cli.sh

# CLI-006 (positive side): the accepted text, --json, --output yaml/json and
# --quiet output of every command path whose output-format gate lets --json
# and/or --output through, against the pinned Go binary (oracle bf7f687b).
# Re-verifies the frozen corpus against a rebuilt oracle, then replays it
# against the Rust CLI. The refusal side is error-taxonomy-cli-differential.
.PHONY: output-modes-cli-differential
output-modes-cli-differential:
	./scripts/rust-port/check_output_modes_cli.sh

# CLI-006: how the pinned gopkg.in/yaml.v3 renders odd strings (leading line
# break, astral characters, U+2028, BEL, U+FEFF, NEL, `<<`, ...) as a map value,
# map key, sequence item, nested field and document root, replayed against the
# Rust renderer behind `--output yaml`. Host independent: it records the module
# pinned in go.mod, not a CLI build.
.PHONY: yaml-scalar-differential
yaml-scalar-differential:
	GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/yamlscalargen --check
	$(CARGO) test -p symvault-gojson --test yaml_scalars --locked

# Deliberate regeneration of the yaml scalar corpus (rewrites
# testdata/port/cli/yaml-scalars.json from the pinned module).
.PHONY: yaml-scalar-regenerate
yaml-scalar-regenerate:
	GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/yamlscalargen

# Deliberate regeneration of the output-modes fixture from the pinned oracle
# (frozen seed vaults are kept; add SYMVAULT_OUTPUT_MODES_NEW_SEEDS=1 to rebuild).
.PHONY: output-modes-regenerate
output-modes-regenerate:
	SYMVAULT_OUTPUT_MODES_REGENERATE=1 ./scripts/rust-port/check_output_modes_cli.sh

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
	GOTOOLCHAIN=$(GO_TOOLCHAIN) GO=$(GO) ./scripts/go-fuzz-target.sh -run '^$$' -fuzz=FuzzParseArgon2idParams -fuzztime=3s -timeout=30s ./internal/crypto
	GOTOOLCHAIN=$(GO_TOOLCHAIN) GO=$(GO) ./scripts/go-fuzz-target.sh -run '^$$' -fuzz=FuzzDecryptAgeEnvelope -fuzztime=3s -timeout=30s ./internal/crypto

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

# Build the Go oracle from this checked-out source revision so the page tree is
# compared against the exact CLI tree under review, never an ambient binary.
manpages-differential:
	@mkdir -p "$(dir $(MANPAGES_GO_BINARY))"
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) build -buildvcs=true -o "$(MANPAGES_GO_BINARY)" .
	SYMVAULT_GO_BINARY="$(abspath $(MANPAGES_GO_BINARY))" SYMVAULT_MANPAGES_REQUIRE_GO_ORACLE=1 $(CARGO) test -p symvault-cli --test cli_generate_manpages --locked

.PHONY: cli-help-differential
cli-help-differential: manpages-differential
	SYMVAULT_GO_BINARY="$(abspath $(MANPAGES_GO_BINARY))" SYMVAULT_HELP_REQUIRE_GO_ORACLE=1 $(CARGO) test -p symvault-cli --test cli_help --test cli_get_list_help_differential --test cli_completion_args --test cli_dynamic_setup_help --test cli_update_help --locked

# SETUP-001: `symvault setup` through a real PTY against a no-cgo Go oracle built
# from this checked-out source (a no-cgo build cannot see Touch ID; see
# docs/rust-port/setup-wizard.md). Not part of port-contract: it needs a PTY and
# the recording is darwin's. The replay without Go is part of `cargo test`.
SETUP_GO_BINARY := target/port/symvault-setup-go
.PHONY: setup-wizard-differential
setup-wizard-differential:
	@mkdir -p "$(dir $(SETUP_GO_BINARY))"
	CGO_ENABLED=0 GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) build -buildvcs=true -trimpath -o "$(SETUP_GO_BINARY)" .
	SYMVAULT_GO_BINARY="$(abspath $(SETUP_GO_BINARY))" $(CARGO) test -p symvault-cli --test setup_wizard_differential --locked

.PHONY: store004-isolation-check
store004-isolation-check:
	PYTHONDONTWRITEBYTECODE=1 GOTOOLCHAIN=$(GO_TOOLCHAIN) python3 scripts/rust-port/test_store004_isolation.py

port-contract: timestamp-fixtures-check cfg-overrides-fixtures-check mcp-oauth-contract store004-isolation-check update-fixtures-check

.PHONY: update-fixtures-check
update-fixtures-check:
	python3 -B scripts/rust-port/test_update_fixture_provenance.py
	GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) python3 scripts/rust-port/refresh-update-fixtures.py --commit 58d978bb53a1dc6257b3a0e3154f7bd29fdd3fd9 --check
port-contract: reencrypt-journal-differential export-cli-fixtures-check mcp-call-fixtures-check focus-differential desktop-differential get-clipboard-differential clipboard-linux-differential mcp-prompts-differential mcp-render-differential config-cli-differential config-rewrite-differential yaml-syntax-cli-differential error-taxonomy-cli-differential output-modes-cli-differential yaml-scalar-differential import-cli-differential mcp-list-fixtures-check oracle-reachability-check port-fixtures-check keyring-key-fixtures-check biometric-differential core-fixtures-check policy-fixtures-check mcp-init-fixtures-check mcp-http-init-differential mcp-stdio-fixtures-check git-winner-fixtures-check git-offline-fixtures-check git-io-differential cfg-fixtures-check cfg-precedence-fixtures-check cfg-bytes-fixtures-check cfg-sections-fixtures-check store-metadata-fixtures-check rust-007-fixtures-check sync-io-differential differential-go-selftest crypto-differential cli-help-differential token-lookup-fixtures-check tool-registry-hash-differential ffi-differential

# TOOLHASH-001: Go-recorded tool-registry hash + call-time drift refusal. The
# process-level Go/Rust/cross-binary check needs prebuilt binaries (see
# scripts/rust-port/toolhash_process_contract.py) and is run explicitly.
.PHONY: tool-registry-hash-fixtures-check tool-registry-hash-differential
tool-registry-hash-fixtures-check:
	SYMVAULT_TEST_KEYRING=memory SYMAIRA_CHECK_TOOL_REGISTRY_HASH_FIXTURE=1 GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/mcp/server -run '^TestGenerateToolRegistryHashFixture$$' -count=1

tool-registry-hash-differential: tool-registry-hash-fixtures-check
	$(CARGO) test -p symvault-mcp --test tool_registry_hash_contract --locked

# HTTP-001 / HTTP-002 / TOOLHASH-001 process contracts (mcp-http-replay-contract,
# mcp-http-token-contract, toolhash-process-contract): recipes in the area
# section below, where they are members of LOCAL_AREA_PROCESS_TARGETS. They
# are not part of port-contract. Set HTTP_CONTRACT_ARGS=--allow-dirty-for-development
# for an uncommitted candidate (the receipt check then rightly fails).
HTTP_CONTRACT_ARGS ?=

# Go-recorded RFC3339 acceptance + table display (scripts/rust-port/go_timestamp_fixtures.py).
# -check re-records in memory and never writes; -generate is the only writer.
.PHONY: timestamp-fixtures-generate timestamp-fixtures-check
timestamp-fixtures-generate:
	GO_TOOLCHAIN=$(GO_TOOLCHAIN) python3 -B scripts/rust-port/go_timestamp_fixtures.py --generate

timestamp-fixtures-check:
	GO_TOOLCHAIN=$(GO_TOOLCHAIN) python3 -B scripts/rust-port/go_timestamp_fixtures.py --check

.PHONY: token-lookup-fixtures-check
token-lookup-fixtures-check:
	SYMAIRA_CHECK_TOKEN_PORT_FIXTURE=1 GOWORK=off GOTOOLCHAIN=go1.26.6 go test ./internal/mcp/auth -run '^TestTokenPortFixture$$' -count=1

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

# DIST-005 / RUST-014 (decision D1): the first mutation of a vault without a
# Rust marker is preceded by a verified backup. Runs the real Rust CLI and the
# Go oracle over Go-created seed vaults (frozen mobilebind seed, Go `init`, the
# Go zero-key identity) and exercises the negative controls.
DATA_SAFETY_GO_BINARY := target/port/symvault-go-data-safety
.PHONY: data-safety-differential
data-safety-differential:
	@mkdir -p "$(dir $(DATA_SAFETY_GO_BINARY))"
	CGO_ENABLED=0 GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) build -buildvcs=true -o "$(DATA_SAFETY_GO_BINARY)" .
	$(CARGO) build -p symvault-cli --bin symvault --locked
	$(CARGO) build -p symvault-sync --example data_safety_probe --locked
	python3 -I scripts/rust-port/data_safety_contract.py --rust "$(RUST_BINARY)" --go "$(DATA_SAFETY_GO_BINARY)" --probe "$(CARGO_TARGET_DIR)/debug/examples/data_safety_probe"

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

# FFI-001: the Rust replacement for the gomobile pkg/mobilebind bridge.
#
#   ffi-fixtures-generate  re-record testdata/port/ffi/mobilebind.json from the
#                          real Go functions (explicit; never part of a check)
#   ffi-fixtures-check     re-run Go and fail on any byte of drift
#   ffi-differential       Go --check, then the Rust tests (fixture replay,
#                          Go<->Rust interoperability against the live Go
#                          driver, C ABI), then on macOS the Swift package test
#                          against the release-grade staticlib. Off macOS the
#                          Swift part prints a visible SKIP.
SWIFT ?= swift
FFI_TARGET_ABS := $(abspath $(CARGO_TARGET_DIR))
FFI_DRIVER := $(FFI_TARGET_ABS)/ffi-driver/mobilebindgen
ffi-fixtures-generate ffi-fixtures-check ffi-differential: export SYMVAULT_TEST_KEYRING := memory

# FFI_GENERATE_FLAGS=--keep-seed regenerates from the seed already stored in the
# fixture: existing cases stay byte-identical and only new or changed cases and
# the provenance header move (without it a fresh random seed rewrites every
# ciphertext).
FFI_GENERATE_FLAGS ?=
ffi-fixtures-generate:
	GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/mobilebindgen \
		$(FFI_GENERATE_FLAGS) --output testdata/port/ffi/mobilebind.json

ffi-fixtures-check:
	GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/mobilebindgen \
		--check --output testdata/port/ffi/mobilebind.json

ffi-differential: ffi-fixtures-check
	@mkdir -p $(dir $(FFI_DRIVER))
	GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) build -o $(FFI_DRIVER) ./scripts/rust-port/cmd/mobilebindgen
	SYMVAULT_FFI_GO_DRIVER=$(FFI_DRIVER) $(CARGO) test -p symvault-ffi --locked
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		set -eu; \
		$(CARGO) build -p symvault-ffi --profile ffi --locked; \
		cd crates/symvault-ffi/swift && \
		SYMVAULT_FFI_LIB_DIR=$(FFI_TARGET_ABS)/ffi $(SWIFT) test --scratch-path $(FFI_TARGET_ABS)/ffi-swift; \
	else \
		echo "SKIP ffi-differential: Swift package test needs macOS (host: $$(uname -s)); Go check and Rust tests passed"; \
	fi

# FFI-001 iOS: SymvaultFFI.xcframework (macOS arm64, iOS device arm64, iOS
# Simulator arm64; `ffi` profile) under $(CARGO_TARGET_DIR)/xcframework, never in
# the tracked tree. Prints per-slice and total sizes (recorded in ADR 0031).
# Needs `rustup target add aarch64-apple-ios aarch64-apple-ios-sim`.
ffi-xcframework:
	CARGO="$(CARGO)" CARGO_TARGET_DIR="$(FFI_TARGET_ABS)" \
		scripts/rust-port/build-ffi-xcframework.sh

# FFI-001 iOS: replay the recorded fixture through the Swift package on an iOS
# Simulator (xcodebuild test) against the XCFramework's simulator slice. Needs a
# working CoreSimulator and an installed iOS runtime; see the script header for
# SIMCTL / IOS_SIM_UDID. Not part of `port-contract` (needs a simulator).
ffi-ios-simulator-test: ffi-xcframework
	CARGO_TARGET_DIR="$(FFI_TARGET_ABS)" scripts/rust-port/ffi-ios-simulator-test.sh

# Split from `rust-gates` so CI can run the interpreter-heavy Miri pass in its
# own parallel job: Miri accounts for roughly two thirds of the aggregate gate
# wall clock (see docs/rust-port/ci-runtime.md), and it needs a different
# toolchain and target directory than every other gate.
# Differential and fixture targets that neither ci.yml (rust-native,
# port-contract, rust-gates-core) nor an area workflow's make step reaches.
# The local gate runs them on both legs (docs/rust-port/local-first.md).
# The area targets run strictly one after the other: they share one cargo
# target directory, one set of evidence paths and (macOS) the real tree.
.NOTPARALLEL:
LOCAL_AREA_DIFFERENTIAL_TARGETS := mcp-init-differential mcp-stdio-differential mcp-list-differential \
	mcp-call-differential mcp-clipboard-signals-differential \
	mcp-execute-api-policy-differential mcp-http-ratelimit-differential mcp-oauth-contract api-templates-differential \
	config-profile-differential config-session-differential cfg-overrides-fixtures-check \
	device-list-differential device-session-differential pairing-differential \
	git-offline-differential git-winner-differential rust-007-differential \
	store004-isolation-check update-fixtures-check

# Process contracts of the area workflows (.github/workflows/rust-http-*.yml,
# rust-mcp-*.yml, rust-broker-*.yml, rust-api-transport.yml,
# rust-cli-artifacts.yml, rust-intake-cli.yml, rust-serve-cli.yml,
# rust-signal-process.yml, rust-store*.yml, rust-sync-observations.yml,
# rust-pairing.yml, rust-tui.yml, kdf-resource-policy.yml,
# vault-read-resource-policy.yml, mcp-http-shutdown.yml). Each target runs the
# workflow's contract step plus the test_*_contract.py / *_mutation.py negative
# controls and the named cargo/go tests the workflow ran next to it, then
# gate_area_check.py with the workflow's own counts and names (profiles).
# Windows steps are out of scope. mcp-http-replay-contract,
# mcp-http-token-contract and toolhash-process-contract belong to no workflow
# step; they are local-only process contracts (HTTP-001, HTTP-002,
# TOOLHASH-001) against a real Go oracle and join the list so that their rows
# can carry a receipt of the full gate. Hosted CI ran the HTTP contracts
# on ubuntu (rust-http-*.yml) and macOS (rust-http-macos.yml); every other
# contract ran on both, so both lanes run all of them. Lane-only targets:
#   linux: tui-contract (the contract needs Xvfb/xclip; on macOS it drives the
#          real pasteboard and refuses to run outside a disposable CI host)
#   macos: tui-harness-check (the harness checks without the clipboard half)
LOCAL_AREA_PROCESS_TARGETS := area-check-selftest worktree-prune-check http-framing-contract http-head-contract \
	http-origin-contract http-slow-peer-contract http-timeout-contract \
	http-tls-contract http-write-contract http-oauth-contract \
	http-process-contract mcp-process-contract mcp-named-tests api-transport-contract \
	broker-connect-contract broker-egress-contract cli-artifacts-contract \
	intake-cli-contract serve-cli-contract kdf-resource-policy-contract \
	read-resource-policy-contract mcp-http-shutdown-contract \
	signal-process-contract store-live-contract store-observations-contract \
	sync-observations-contract pairing-oracle-contract tui-named-tests \
	mcp-http-replay-contract mcp-http-token-contract toolhash-process-contract
LOCAL_AREA_LANE ?= $(if $(filter Darwin,$(shell uname -s)),macos,linux)
LOCAL_AREA_LANE_TARGETS_macos := tui-harness-check
LOCAL_AREA_LANE_TARGETS_linux := tui-contract
LOCAL_AREA_TARGETS := $(LOCAL_AREA_DIFFERENTIAL_TARGETS) $(LOCAL_AREA_PROCESS_TARGETS) \
	$(LOCAL_AREA_LANE_TARGETS_$(LOCAL_AREA_LANE))

.PHONY: local-area local-area-list $(LOCAL_AREA_PROCESS_TARGETS) tui-contract tui-harness-check
local-area: $(LOCAL_AREA_TARGETS)

# One target per word, for scripts/rust-port/local-gate-area.sh.
local-area-list:
	@echo $(LOCAL_AREA_TARGETS)

AREA_EVIDENCE ?= $(CARGO_TARGET_DIR)/area-evidence
AREA_ENV := GOWORK=off TZ=UTC PYTHONDONTWRITEBYTECODE=1 SYMVAULT_TEST_KEYRING=memory
AREA_CHECK := python3 -B scripts/rust-port/gate_area_check.py
AREA_PROBES := $(CARGO_TARGET_DIR)/debug/examples
# HTTP and MCP-process contracts pin the oracle toolchain their workflows used
# (the MCP oracle refuses anything but an actual go1.26.6); the other area
# workflows ran go1.26.10.
AREA_HTTP_GO := GOTOOLCHAIN=$(GO_TOOLCHAIN)
AREA_GO := GOTOOLCHAIN=$(BUILD_GO_TOOLCHAIN)
# The contracts hash the binary before and after a run, and another build in
# the shared cargo target dir (a concurrent gate lane) replaces it mid-run, so
# they run against a private copy under the evidence directory.
AREA_BIN := $(AREA_EVIDENCE)/bin
AREA_CLI := $(AREA_BIN)/symvault
AREA_BUILD_CLI := $(CARGO) build -p symvault-cli --bin symvault --locked && mkdir -p "$(AREA_BIN)" && cp -f "$(RUST_BINARY)" "$(AREA_CLI)"
# Python 3.13 is what the workflows pinned (setup-python); tui_contract.py
# asserts it, and a python.org 3.14 on macOS lacks the CA bundle the shell
# completion check needs for its one download.
AREA_PYTHON := $(or $(shell command -v python3.13),python3)
# One venv per interpreter version, so a stale one never outlives a switch.
AREA_VENV := $(AREA_EVIDENCE)/tui-venv-$(shell $(AREA_PYTHON) -c 'import sys; print("%d.%d" % sys.version_info[:2])')
# The contracts build their Go oracle through this runner; the workflows build
# it into target/ before the first contract that needs it.
AREA_ORACLE_RUNNER := $(AREA_EVIDENCE)/oraclebuild
AREA_ORACLE := SYMVAULT_ORACLE_BUILD_RUNNER=$(abspath $(AREA_ORACLE_RUNNER))

# AREA_LOGGED: capture a command's stdout and stderr in separate files below the
# evidence directory (the named-test checks read stdout, so stderr noise cannot
# split a `test x ... ok` line), print stdout on success and both on failure.
define AREA_LOGGED
> "$(AREA_EVIDENCE)/$(1)" 2> "$(AREA_EVIDENCE)/$(1).stderr" || { cat "$(AREA_EVIDENCE)/$(1)" "$(AREA_EVIDENCE)/$(1).stderr"; exit 1; }; cat "$(AREA_EVIDENCE)/$(1)"
endef
# The number of `migrate_kdf_commands::tests` the kdf workflow asserted as "9
# passed"; a tenth (`policy_migration_wraps_config_failures_like_go`) was added
# since, so the gate asserts 10.
AREA_KDF_MIGRATION_TESTS := 10
# The unit-test count of `cargo test -p symvault-mcp --all-targets` (non-Windows)
# that the HTTP, MCP and API workflows assert exactly. They still hard-code 246,
# which the tree outgrew (296 at the merge of local/rust-port 6ac34423, 304 at
# ca0f2300 after the MCP authz-order tests, 305 at ae6f8340 after the
# crate-local API template drift guard `apitemplate_assets_sync`, which stays a
# passing test, early return, once the Go copy is deleted), 339 at the
# local/integ2 merge (MCP audit ids, policy BuildContext, OAuth expiry, HTTP
# drain and token-registry overlay tests), 346 at fc806ff4 (approval proof window,
# scope boundary, sharing corpus and clipboard auto-clear replays), 354 on
# local/device-approvals (device-token approvals replay: 4 tests, plus 4 unit
# tests in approval.rs), 369 at local/integ5 after local/http-ratelimit (limiter
# unit tests and the 5 http_ratelimit tests; measured: 52 result lines, 0 failed),
# 385 on local/device-enroll (device enrollment routes: 11 unit tests in
# enroll.rs and the 5 device_enroll_replay tests; measured: 53 result lines,
# 385 passed, 0 failed); the
# gate asserts the real count, so a shrunken run still fails. Raise it together
# with the new tests (and the workflows' constant when they run again).
# 386 after merging local/tls-write-deadline (+1 TLS write-deadline regression).
# 408 on local/anomaly (+22: 9 detector unit tests in anomaly.rs, 3
# anomaly_replay and 10 anomaly_dispatch tests; measured: 408 passed, 0 failed).
# 415 after the security review (+7: 5 anomaly.rs unit tests for the stderr
# write and the poisoned detector lock, 2 anomaly_dispatch sink-ordering tests;
# measured: 415 passed, 0 failed).
# +14 from local/pin-tests (302 redirect pin, duplicate/wrong-typed params, go_params
# walker, exact InitializeParams error text); measured at the integ6 merge.
# 438 from local/mcp-envelope (+9: 5 envelope.rs unit tests, 4 stdio_hygiene_contract
# tests for the Go-recorded envelope members, the duplicate probes and the HTTP
# replay; measured: 438 passed, 0 failed over 55 result lines).
# 441 from local/envelope-data (+2 of the +3 measured: 1 envelope.rs unit test, 1
# stdio_hygiene_contract test for the error.data float64 overflow; measured: 441
# passed, 0 failed over 56 result lines).
# 447 from local/args-raw (+6: 3 stdio_hygiene_contract tests for the tools/call
# `arguments` probes recorded from the oracle, 3 call.rs unit tests for the
# raw-text arguments decode; measured: 447 passed, 0 failed over 56 result lines).
# 448 after the coordinator's anomaly_dispatch order pin (decode before lookup/token scope).
AREA_MCP_TEST_COUNT := 448

.PHONY: area-oracle-runner
area-oracle-runner:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_GO) $(GO) test -count=1 ./scripts/rust-port/internal/diff
	$(AREA_GO) $(GO) build -trimpath -o "$(AREA_ORACLE_RUNNER)" ./scripts/rust-port/cmd/oraclebuild
	$(AREA_ENV) $(AREA_ORACLE) $(AREA_PYTHON) -B scripts/rust-port/test_oracle_build.py

# Negative controls of the checker every area target below ends with: shrunken,
# partial and malformed receipts and logs must all fail it; the gate receipt's
# area_complete (dirty/partial/short runs) and the pinned target list of each lane.
area-check-selftest:
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_gate_area_check.py
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_local_gate_receipt.py
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_local_area_list.py

# No gate script may prune worktrees globally (the Linux container deleted the
# host worktrees' admin dirs that way); the container git guards must stay.
worktree-prune-check:
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_check_worktree_prune.py
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_worktree_remove.py
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/check_worktree_prune.py

http-framing-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_BUILD_CLI)
	$(AREA_ENV) $(AREA_HTTP_GO) $(AREA_PYTHON) scripts/rust-port/http_framing_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-http-framing.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-http-framing.json" --profile http-framing

http-head-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_BUILD_CLI)
	$(AREA_ENV) $(AREA_HTTP_GO) $(AREA_PYTHON) scripts/rust-port/http_head_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-http-head.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-http-head.json" --profile http-head

http-origin-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_BUILD_CLI)
	$(AREA_ENV) $(AREA_HTTP_GO) $(AREA_PYTHON) scripts/rust-port/http_origin_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-http-origin.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-http-origin.json" --profile http-origin

# rust-http-read-deadlines.yml
http-slow-peer-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_BUILD_CLI)
	$(AREA_ENV) $(AREA_HTTP_GO) $(AREA_PYTHON) scripts/rust-port/http_slow_peer_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-http-read-deadlines.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-http-read-deadlines.json" --profile http-read-deadlines

http-timeout-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_BUILD_CLI)
	$(AREA_ENV) $(AREA_HTTP_GO) $(AREA_PYTHON) scripts/rust-port/http_timeout_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-http-timeouts.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-http-timeouts.json" --profile http-timeouts

http-tls-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_http_tls_contract.py
	$(AREA_BUILD_CLI)
	$(AREA_ENV) $(AREA_HTTP_GO) $(AREA_PYTHON) scripts/rust-port/http_tls_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-http-tls.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-http-tls.json" --profile http-tls

# rust-http-write.yml: negative controls, TLS backpressure probe and its
# mutation, then the full write contract. http_write_mutation.py edits
# crates/symvault-mcp/src/http.rs and rebuilds the CLI, and insists on the
# cargo output path of the tree it lives in. It therefore runs in a detached
# worktree of HEAD with its own CARGO_TARGET_DIR: the live tree, its sources and
# $(RUST_BINARY) are never mutated. The guards around it fail the target (and
# restore the file) should the live tree change anyway.
AREA_MUTATION_TREE := $(AREA_EVIDENCE)/mutation-tree
AREA_MUTATION_TARGET := $(AREA_EVIDENCE)/mutation-target
http-write-contract: area-oracle-runner
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_http_write_contract.py
	$(AREA_BUILD_CLI)
	$(AREA_ENV) $(AREA_HTTP_GO) $(AREA_ORACLE) $(AREA_PYTHON) -B scripts/rust-port/http_write_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-tls-output.json" --tls-output-probe-only
	rm -f "$(AREA_EVIDENCE)"/native-tls-output-mutation*.json
	scripts/rust-port/area_http_write_mutation.sh "$(CURDIR)" "$(AREA_MUTATION_TREE)" "$(AREA_MUTATION_TARGET)" "$(RUST_BINARY)" \
		"$(AREA_EVIDENCE)/native-tls-output-mutation.json" "$(AREA_ENV) $(AREA_HTTP_GO) $(AREA_ORACLE) $(AREA_PYTHON)"
	$(AREA_ENV) $(AREA_HTTP_GO) $(AREA_ORACLE) $(AREA_PYTHON) scripts/rust-port/http_write_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-http-write.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-http-write.json" --profile http-write

# rust-http-oauth.yml
http-oauth-contract: area-oracle-runner
	$(AREA_BUILD_CLI)
	$(AREA_ENV) $(AREA_HTTP_GO) $(AREA_ORACLE) $(AREA_PYTHON) scripts/rust-port/http_oauth_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-http-oauth.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-http-oauth.json" --profile http-oauth

# rust-mcp-http-process.yml
http-process-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_http_process_contract.py
	$(AREA_BUILD_CLI)
	$(AREA_ENV) $(AREA_GO) $(AREA_PYTHON) scripts/rust-port/http_process_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-http-process.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-http-process.json" --profile http-process

# HTTP-001 (no workflow step): SSE negotiation, replay, JSON-RPC envelope, route
# and request-framing corpus against the Go oracle (276 cases, ADR 0032 declared
# differences). The oracle is built from the pinned commit by the driver.
mcp-http-replay-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_http_replay_contract.py
	$(AREA_BUILD_CLI)
	$(AREA_ENV) $(AREA_HTTP_GO) $(AREA_PYTHON) -B scripts/rust-port/http_replay_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-http-replay.json" $(HTTP_CONTRACT_ARGS)
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-http-replay.json" --profile http-replay

# HTTP-002 (no workflow step): bearer-token state, clock and storage matrix; it
# waits several seconds on the registry poller (real clock). The prerequisite
# re-records the Go timestamp fixtures in memory (never writes).
mcp-http-token-contract: timestamp-fixtures-check
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_http_replay_contract.py
	$(AREA_BUILD_CLI)
	$(AREA_ENV) $(AREA_HTTP_GO) $(AREA_PYTHON) -B scripts/rust-port/http_token_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-http-token.json" $(HTTP_CONTRACT_ARGS)
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-http-token.json" --profile http-token

# TOOLHASH-001 (no workflow step): Go CLI and Go seed built from this checkout
# (the driver takes prebuilt binaries); both CLIs stamp the Go-recorded registry
# hash, the actual Go and Rust servers answer 14 HTTP outcomes identically and
# write identical audit rows. Negative control: with the Rust audit ids dropped
# the comparison must fail on the audit rows, not on anything else.
toolhash-process-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_toolhash_process_contract.py
	$(AREA_BUILD_CLI)
	$(AREA_GO) $(GO) build -trimpath -buildvcs=false -o "$(AREA_BIN)/toolhash-go-cli" .
	$(AREA_GO) $(GO) build -trimpath -buildvcs=false -o "$(AREA_BIN)/toolhash-go-seed" ./scripts/rust-port/cmd/toolhashseed
	$(AREA_ENV) $(AREA_GO) $(AREA_PYTHON) scripts/rust-port/toolhash_process_contract.py \
		--go-cli "$(AREA_BIN)/toolhash-go-cli" --go-seed "$(AREA_BIN)/toolhash-go-seed" --rust "$(AREA_CLI)" \
		--receipt "$(AREA_EVIDENCE)/native-toolhash.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-toolhash.json" --profile toolhash
	! $(AREA_ENV) $(AREA_GO) $(AREA_PYTHON) scripts/rust-port/toolhash_process_contract.py \
		--go-cli "$(AREA_BIN)/toolhash-go-cli" --go-seed "$(AREA_BIN)/toolhash-go-seed" --rust "$(AREA_CLI)" \
		--drop-audit-ids > "$(AREA_EVIDENCE)/native-toolhash-drop-ids.txt" 2>&1
	grep -q "Go/Rust audit rows differ" "$(AREA_EVIDENCE)/native-toolhash-drop-ids.txt"

# The cargo runs next to the HTTP, MCP-process and API-transport contracts of
# rust-http-*.yml, rust-mcp-http-process.yml, rust-mcp-process.yml and
# rust-api-transport.yml: one `symvault-mcp --all-targets` run whose log must
# contain every test name those workflows required, no ignored test and the
# workflow's total; the config, CLI-owner and API-template-fixture runs.
MCP_NAMED_TESTS := \
	loopback_listener_rejects_foreign_origin_before_authentication \
	browser_consent_requires_the_vault_passphrase_before_issuing_a_code \
	keep_alive_idle_timeout_matches_go_source_and_closes_socket \
	mtls_listener_requires_valid_client_certificate \
	consent_pkce_access_and_refresh_are_connected_and_single_use \
	oversized_body_errors_follow_admission_without_creating_sessions \
	nonmcp_oversized_prefixes_preserve_accepted_main_wire_response \
	public_http_adapter_bounds_oversized_json_before_deserialization \
	tier_overrides_never_reach_handlers_or_storage \
	explicit_operator_allowlist_restricts_discovery_and_direct_calls \
	command_capability_denial_preserves_rpc_error_without_dispatch \
	oversized_stdio_frame_is_drained_with_bounded_storage \
	exact_frame_limit_is_accepted_and_next_request_recovers_after_oversize \
	oversized_unterminated_fragment_keeps_the_eof_contract \
	cancelled_stdio_answers_the_frame_it_was_blocked_on_then_stops \
	stdio_cancelled_before_the_first_read_answers_nothing \
	actual_dns_accepts_public_answers_and_rejects_mixed_private_and_oversize \
	cancelled_dns_releases_the_actual_owned_udp_socket \
	cancelling_pending_api_headers_closes_upstream_and_joins \
	progressing_api_body_still_reaches_absolute_deadline \
	execute_api_request_transport_returns_302_without_following_redirect \
	actual_dns_https_verifies_chain_hostname_and_redacts_positive_control \
	protocol_context_cancels_actual_encrypted_api_request
mcp-named-tests:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(CARGO) test -p symvault-core --all-targets --locked $(call AREA_LOGGED,native-core-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-core-tests.txt" mcp_tls_settings_survive_config_roundtrip --results-ok
	$(CARGO) test -p symvault-mcp --all-targets --locked $(call AREA_LOGGED,native-mcp-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-mcp-tests.txt" $(MCP_NAMED_TESTS) --sum-passed $(AREA_MCP_TEST_COUNT)
	$(CARGO) test -p symvault-cli --bin symvault --locked mcp_commands::tests $(call AREA_LOGGED,native-mcp-cli-owner.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-mcp-cli-owner.txt" --results-ok
	$(CARGO) test -p symvault-cli --test mcp_commands_contract --locked api_template_fixture $(call AREA_LOGGED,native-mcp-cli-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-mcp-cli-tests.txt" \
		cli_runtime_executes_source_bound_api_template_fixture api_template_fixture_slow_setup_preserves_serving_budget \
		--exact-prefix "" --contains "test result: ok. 2 passed; 0 failed; 0 ignored;"
	test "$$($(AREA_HTTP_GO) $(GO) env GOVERSION)" = go1.26.6

# rust-mcp-process.yml (unit controls, ordered approval fixtures, contract).
# The inline diagnostic and receipt-finalization controls live in
# test_mcp_process_contract.py.
mcp-process-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_mcp_oracle.py
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_mcp_process_contract.py
	$(MAKE) mcp-ordered-fixtures-check
	$(AREA_BUILD_CLI)
	test "$$($(AREA_HTTP_GO) $(GO) env GOVERSION)" = go1.26.6
	$(AREA_ENV) $(AREA_HTTP_GO) $(AREA_PYTHON) scripts/rust-port/mcp_process_contract.py \
		--reference mcp-anomaly-ordered-v1 --rust "$(AREA_CLI)" \
		--receipt "$(AREA_EVIDENCE)/native-mcp-process.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-mcp-process.json" --profile mcp-process

# rust-api-transport.yml
api-transport-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_api_transport_contract.py -v
	$(CARGO) build -p symvault-mcp --example api_transport_probe --locked
	mkdir -p "$(AREA_BIN)" && cp -f "$(AREA_PROBES)/api_transport_probe" "$(AREA_BIN)/"
	$(AREA_ENV) $(AREA_GO) $(AREA_PYTHON) scripts/rust-port/api_transport_contract.py \
		--rust-probe "$(AREA_BIN)/api_transport_probe" \
		--receipt "$(AREA_EVIDENCE)/native-api-transport.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-api-transport.json" --profile api-transport

# rust-broker-connect.yml
broker-connect-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(CARGO) test -p symvault-mcp --lib --locked broker::connect::tests:: $(call AREA_LOGGED,native-connect-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-connect-tests.txt" \
		accepted_socket_reset_preserves_delayed_payload connect_passthrough_tunnels_only_allowlisted_loopback_hosts \
		stopping_joins_idle_relay_and_closes_upstream private_and_unlisted_targets_do_not_connect_upstream \
		--contains "4 passed; 0 failed; 0 ignored"
	$(CARGO) build -p symvault-mcp --example connect_contract_probe --locked
	mkdir -p "$(AREA_BIN)" && cp -f "$(AREA_PROBES)/connect_contract_probe" "$(AREA_BIN)/"
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/connect_contract.py \
		--rust "$(AREA_BIN)/connect_contract_probe" \
		--receipt "$(AREA_EVIDENCE)/native-connect.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-connect.json" --profile connect

# rust-broker-egress.yml
broker-egress-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(CARGO) test -p symvault-core --test policy_contract --locked bounded_network_globs_match_captured_go_unicode_and_escape_cases \
		$(call AREA_LOGGED,native-egress-policy-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-egress-policy-tests.txt" bounded_network_globs_match_captured_go_unicode_and_escape_cases --results-ok
	$(CARGO) test -p symvault-mcp --test egress_broker --locked $(call AREA_LOGGED,native-egress-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-egress-tests.txt" \
		egress_preflight_denies_before_credential_read_or_upstream_contact \
		egress_decoded_path_acl_denies_before_entry_read_or_normalization \
		egress_verified_mitm_injects_and_masks_real_encrypted_credentials \
		egress_callback_error_joins_idle_clients_and_releases_listener \
		egress_stop_cancels_owned_upstream_request_without_waiting_for_network_timeout \
		--contains "5 passed; 0 failed; 0 ignored"
	$(CARGO) build -p symvault-cli --bin symvault -p symvault-mcp --example egress_contract_probe --locked
	mkdir -p "$(AREA_BIN)" && cp -f "$(RUST_BINARY)" "$(AREA_CLI)" && cp -f "$(AREA_PROBES)/egress_contract_probe" "$(AREA_BIN)/"
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/egress_contract.py \
		--rust-cli "$(AREA_CLI)" --rust-probe "$(AREA_BIN)/egress_contract_probe" \
		--receipt "$(AREA_EVIDENCE)/native-egress.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-egress.json" --profile egress
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/cligap.py --binary "$(AREA_CLI)" \
		--output "$(AREA_EVIDENCE)/native-broker-gaps.json"
	$(AREA_CHECK) gaps "$(AREA_EVIDENCE)/native-broker-gaps.json" \
		--exact-path "symvault broker" --exact-path "symvault run" --min-paths 134:100

# rust-cli-artifacts.yml. Native shells: bash (Homebrew bash on macOS, as in
# CI), zsh and fish must exist; the contract fails without them.
CLI_ARTIFACT_TEST_TARGETS := --test completions --test cli_generate_manpages --test cli_help \
	--test cli_help_subcommand --test cli_update_help --test cli_get_list_help_differential --test cli_completion_args --test cli_dynamic_setup_help
cli-artifacts-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_GO) $(GO) test ./scripts/rust-port/cmd/cligap -count=1
	$(AREA_GO) $(GO) test ./internal/manpages ./scripts/rust-port/cmd/portgen -count=1 -v \
		> "$(AREA_EVIDENCE)/native-go-manual-tests.txt" 2>&1 || { cat "$(AREA_EVIDENCE)/native-go-manual-tests.txt"; exit 1; }
	$(AREA_CHECK) go-text-pass "$(AREA_EVIDENCE)/native-go-manual-tests.txt" \
		TestManpageLiteralText TestManualConfigPathIsLiteralAndDescriptionsAreRestored \
		TestManualLiteralPathDoesNotRewriteOtherDescriptions
	$(MAKE) port-fixtures-check
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/manual_path_contract_test.py
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_cli_artifacts_contract.py
	$(AREA_ENV) $(AREA_GO) $(AREA_PYTHON) scripts/run_go_tests.py $(CARGO) -- $(CARGO) test -p symvault-cli --locked --bin symvault \
		actual_go_protocol_queries_replay_through_real_rust_sessions_and_store $(call AREA_LOGGED,native-cli-protocol-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-cli-protocol-tests.txt" \
		actual_go_protocol_queries_replay_through_real_rust_sessions_and_store --results-ok
	$(AREA_ENV) $(AREA_GO) $(AREA_PYTHON) scripts/run_go_tests.py $(CARGO) -- $(CARGO) test -p symvault-cli --locked \
		$(CLI_ARTIFACT_TEST_TARGETS) $(call AREA_LOGGED,native-cli-help-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-cli-help-tests.txt" --results-ok
	$(AREA_BUILD_CLI)
	$(AREA_ENV) $(AREA_GO) $(if $(wildcard /opt/homebrew/bin/bash),CLI_ARTIFACTS_BASH=/opt/homebrew/bin/bash) \
		$(AREA_PYTHON) scripts/run_go_tests.py $(CARGO) -- $(AREA_PYTHON) scripts/rust-port/cli_artifacts_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-cli-artifacts.json" \
		--captured-output "$(AREA_EVIDENCE)/native-cli-go-artifacts.json" --require-native-shells
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-cli-artifacts.json" --profile cli-artifacts
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/cligap.py --binary "$(AREA_CLI)" \
		--output "$(AREA_EVIDENCE)/native-cli-artifact-gaps.json"
	$(AREA_CHECK) gaps "$(AREA_EVIDENCE)/native-cli-artifact-gaps.json" --no-missing-paths --min-paths 134:100

# rust-intake-cli.yml
intake-cli-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_ENV) $(AREA_GO) $(AREA_PYTHON) scripts/run_go_tests.py $(CARGO) -- $(CARGO) test -p symvault-sync --locked \
		--test intake_spool_security --test intake_scan_summary --test intake_watcher_contract --test intake_run_loop \
		$(call AREA_LOGGED,native-intake-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-intake-tests.txt" --results-ok
	$(AREA_BUILD_CLI)
	$(AREA_ENV) $(AREA_GO) $(AREA_PYTHON) scripts/run_go_tests.py $(CARGO) -- $(AREA_PYTHON) scripts/rust-port/intake_watch_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-intake-cli.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-intake-cli.json" --profile intake
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/cligap.py --binary "$(AREA_CLI)" \
		--output "$(AREA_EVIDENCE)/native-intake-gaps.json"
	$(AREA_CHECK) gaps "$(AREA_EVIDENCE)/native-intake-gaps.json" --prefix "symvault intake"

# rust-serve-cli.yml
serve-cli-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(CARGO) test -p symvault-cli --locked --test cli_agent_setup_serve_stubs $(call AREA_LOGGED,native-serve-stubs-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-serve-stubs-tests.txt" --results-ok
	$(CARGO) test -p symvault-cli --locked --test cli_mcp_http_flags $(call AREA_LOGGED,native-serve-flags-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-serve-flags-tests.txt" --results-ok
	$(CARGO) test -p symvault-cli --bin symvault --locked daemon_commands::tests:: $(call AREA_LOGGED,native-serve-daemon-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-serve-daemon-tests.txt" --results-ok
	$(AREA_BUILD_CLI)
	$(AREA_ENV) $(AREA_GO) $(AREA_PYTHON) scripts/rust-port/serve_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-serve-cli.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-serve-cli.json" --profile serve
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/cligap.py --binary "$(AREA_CLI)" \
		--output "$(AREA_EVIDENCE)/native-serve-gaps.json"
	$(AREA_CHECK) gaps "$(AREA_EVIDENCE)/native-serve-gaps.json" --prefix "symvault serve"

# rust-signal-process.yml. signal-process-differential (Makefile, above) writes
# the receipt; the workflow's receipt assertions run here.
signal-process-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(CARGO) test -p symvault-cli --bin symvault --locked run_commands $(call AREA_LOGGED,native-signal-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-signal-tests.txt" --results-ok
	$(CARGO) test -p symvault-cli --bin symvault --locked -- tui::tests mcp_shutdown::tests process_signals::tests $(call AREA_LOGGED,native-signal-clipboard-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-signal-clipboard-tests.txt" ui_signal_with_held_copy_process_contract armed_signal_clear_follows_the_copy_lifetime sigquit_shutdown_clears_an_armed_clipboard http_signal_shutdown_clears_an_armed_clipboard http_sighup_follows_the_armed_clipboard_timer http_shutdown_bounds_a_hung_clipboard_backend sigquit_shutdown_bounds_a_hung_clipboard_backend armed_clipboard_guard_takes_over_an_inherited_sighup_ignore --results-ok
	$(CARGO) test -p symvault-mcp --test clipboard_http_signal_clear --locked $(call AREA_LOGGED,native-signal-http-clipboard-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-signal-http-clipboard-tests.txt" http_shutdown_clears_the_clipboard_armed_by_copy_to_clipboard --results-ok
	$(CARGO) test -p symvault-platform --lib --locked text_clipboard::tests $(call AREA_LOGGED,native-signal-text-clipboard-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-signal-text-clipboard-tests.txt" clear_before_exit_refuses_a_racing_copy failed_expiry_clear_is_retried_and_surfaced failed_explicit_clear_keeps_the_copy_and_schedules_a_retry --results-ok
	rm -f "$(CARGO_TARGET_DIR)/native-signals.json"
	$(MAKE) signal-process-differential
	$(AREA_CHECK) receipt "$(CARGO_TARGET_DIR)/native-signals.json" --profile signal

# rust-store.yml: live Go and Rust writers, manifests and indexes.
store-live-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(CARGO) test -p symvault-store --all-targets --all-features --locked $(call AREA_LOGGED,rust-store-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/rust-store-tests.txt" --results-ok
	$(AREA_ENV) $(AREA_GO) CARGO_TARGET_DIR="$(CARGO_TARGET_DIR)" $(GO) test ./internal/vault \
		-run '^(TestEntryWriterGoRustLiveAcceptance|TestManifestSequenceGoRustDifferential|TestManifestSequenceJSONTransportControls|TestEncryptedIndexGoRustLiveAcceptance|TestEncryptedIndexBuildEmptyGoRust)$$' \
		-count=1 -timeout=15m -json > "$(AREA_EVIDENCE)/storage-differential.jsonl"
	$(AREA_CHECK) go-json "$(AREA_EVIDENCE)/storage-differential.jsonl" \
		TestEntryWriterGoRustLiveAcceptance TestManifestSequenceGoRustDifferential \
		TestManifestSequenceJSONTransportControls TestEncryptedIndexGoRustLiveAcceptance TestEncryptedIndexBuildEmptyGoRust

# rust-store-observations.yml
store-observations-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	test "$$($(AREA_HTTP_GO) $(GO) env GOVERSION)" = go1.26.6
	$(AREA_ENV) $(AREA_HTTP_GO) $(GO) test -race ./scripts/rust-port/cmd/storegen -count=1 -json > "$(AREA_EVIDENCE)/store-observations.jsonl"
	$(AREA_CHECK) go-json "$(AREA_EVIDENCE)/store-observations.jsonl" \
		TestRepeatedPinnedStoreObservationsHaveStableProjection TestClockProjectionPreservesOtherJSONBytes
	$(AREA_ENV) $(AREA_HTTP_GO) $(GO) run ./scripts/rust-port/cmd/storegen --check --output testdata/port/store/store.json

# rust-sync-observations.yml (including the Git I/O observation step)
sync-observations-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	test "$$($(AREA_HTTP_GO) $(GO) env GOVERSION)" = go1.26.6
	$(AREA_ENV) $(AREA_HTTP_GO) $(GO) test -race ./scripts/rust-port/cmd/syncgen -count=1 -json > "$(AREA_EVIDENCE)/sync-observations.jsonl"
	$(AREA_ENV) $(AREA_HTTP_GO) $(GO) test -race ./cmd/admin -run '^TestCreateBackup_NormalizesTarMemberSeparators$$' -count=1 -json \
		>> "$(AREA_EVIDENCE)/sync-observations.jsonl"
	$(AREA_CHECK) go-json "$(AREA_EVIDENCE)/sync-observations.jsonl" \
		TestPinnedSyncOracleIsRepeatable TestPinnedSyncArchiveContract TestCreateBackup_NormalizesTarMemberSeparators
	$(AREA_ENV) $(AREA_HTTP_GO) $(GO) run ./scripts/rust-port/cmd/syncgen --portable --check --output testdata/port/sync/portable.json
	$(AREA_ENV) $(AREA_HTTP_GO) $(GO) run ./scripts/rust-port/cmd/gitio --check --output testdata/port/sync/git-io.json

# rust-pairing.yml: oracle-bound steps not covered by pairing-differential,
# config-profile-differential and device-list-differential.
# The macOS trusted-alias auth case needs TMPDIR below the root-owned /var ->
# /private/var alias (the same rule as config-cli-differential in local-gate.sh).
AREA_PAIRING_TMP := $(if $(filter Darwin,$(shell uname -s)),TMPDIR="$(shell getconf DARWIN_USER_TEMP_DIR)")
pairing-oracle-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_ENV) $(AREA_PAIRING_TMP) CARGO="$(CARGO)" GO="$(GO)" BUILD_GO_TOOLCHAIN="$(BUILD_GO_TOOLCHAIN)" AREA_CHECK="$(AREA_CHECK)" \
		scripts/rust-port/area_pairing_oracle.sh "$(abspath $(AREA_EVIDENCE))"

# rust-tui.yml: the named browser tests of `cargo test -p symvault-cli
# -p symvault-platform --all-targets` (the whole run is rust-test).
tui-named-tests:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(CARGO) test -p symvault-cli --bin symvault --locked tui::tests:: $(call AREA_LOGGED,tui-tests.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/tui-tests.txt" --exact-prefix "tui::tests::" --results-ok \
		encrypted_browser_masks_sensitive_values_until_explicit_reveal \
		browser_filters_navigation_and_canceled_delete_preserve_encrypted_entries \
		successful_copy_owns_ttl_and_quit_cleanup_even_with_disabled_timer \
		all_sensitive_fields_and_terminal_escape_surfaces_remain_masked \
		updated_sort_compares_instants_and_generator_does_not_write_entry

# kdf-resource-policy.yml (live Go oracle tests with -race; the Go binary the
# differential needs is built for that one cargo command only).
kdf-resource-policy-contract:
	@mkdir -p "$(AREA_EVIDENCE)/kdf-policy"
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/check_argon2_upstream.py
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/kdf_policy_fixtures.py
	$(CARGO) test --manifest-path third_party/argon2/Cargo.toml --all-features --locked
	$(AREA_ENV) $(AREA_GO) $(GO) test -race ./internal/crypto -count=1 -json > "$(AREA_EVIDENCE)/kdf-go.jsonl"
	$(AREA_ENV) $(AREA_GO) $(GO) test -race ./internal/vault -run '^TestKDFPolicyMigration' -count=1 -json >> "$(AREA_EVIDENCE)/kdf-go.jsonl"
	$(AREA_CHECK) go-json "$(AREA_EVIDENCE)/kdf-go.jsonl" TestArgon2ResourcePolicyLimits \
		TestArgon2PreflightRejectsWholeEnvelopeBeforeKDF TestHistoricalGoKDFPolicyEnvelopes \
		TestArgon2BoundedAdmissionRunsRealDerivations TestArgon2LegacyAdmissionExcludesAutomaticDerivation \
		TestKDFPolicyMigrationVerifiesIdentityAndRetainsBothBackups \
		TestKDFPolicyMigrationWrongPassphraseAndExistingBackupLeaveFilesIntact \
		TestKDFPolicyMigrationRollsBackAfterConfigReplacementFailure TestKDFPolicyMigrationAcceptsNullVaultConfig
	$(CARGO) test -p symvault-crypto --all-features --locked
	$(CARGO) test -p symvault-cli --bin symvault --locked migrate_kdf_commands::tests $(call AREA_LOGGED,kdf-rust-migration.log)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/kdf-rust-migration.log" --exact-prefix "migrate_kdf_commands::tests::" \
		policy_migration_retains_originals_and_rewrites_same_identity \
		policy_migration_wrong_passphrase_and_old_backup_do_not_mutate_files \
		policy_migration_restores_both_files_after_post_replacement_failure \
		policy_migration_accepts_null_vault_configuration \
		--contains "$(AREA_KDF_MIGRATION_TESTS) passed; 0 failed; 0 ignored"
	$(AREA_GO) CGO_ENABLED=0 $(GO) build -o "$(AREA_EVIDENCE)/kdf-policy/go-cli" .
	$(AREA_ENV) $(AREA_GO) SYMVAULT_GO_BINARY="$(abspath $(AREA_EVIDENCE))/kdf-policy/go-cli" \
		$(CARGO) test -p symvault-cli --test migrate_kdf_differential --locked -- --ignored $(call AREA_LOGGED,kdf-cli.log)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/kdf-cli.log" --exact-prefix "" \
		kdf_resource_policy_go_rust_integration migrate_kdf_go_rust_integration \
		--contains "2 passed; 0 failed; 0 ignored"

# vault-read-resource-policy.yml
read-resource-policy-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_ENV) $(AREA_GO) $(AREA_PYTHON) scripts/run_go_tests.py $(CARGO) -- $(GO) test -race -json \
		./internal/vault ./internal/template ./internal/mcp/server -run TestResourcePolicy -count=1 \
		> "$(AREA_EVIDENCE)/go-read-policy.jsonl"
	$(AREA_CHECK) go-json "$(AREA_EVIDENCE)/go-read-policy.jsonl" \
		TestResourcePolicyAdmissionBoundsActualEntryReads \
		TestResourcePolicyFailedIndexPreservesFileAndFindFallsBack \
		TestResourcePolicyRecoveryRejectsOversizeBeforeMutation \
		TestResourcePolicyTemplateResolutionsShareOneAllowance \
		TestResourcePolicyCommandRefsShareOneAllowance
	$(AREA_ENV) $(AREA_GO) $(AREA_PYTHON) scripts/rust-port/refresh-read-policy-fixtures.py --check \
		--receipt "$(AREA_EVIDENCE)/native-read-policy.json"
	$(CARGO) test -p symvault-store --lib --all-features > "$(AREA_EVIDENCE)/rust-read-store.log" 2>&1 || { cat "$(AREA_EVIDENCE)/rust-read-store.log"; exit 1; }
	$(CARGO) test -p symvault-cli --bin symvault template_resolutions_share_the_operation_allowance \
		> "$(AREA_EVIDENCE)/rust-read-template.log" 2>&1 || { cat "$(AREA_EVIDENCE)/rust-read-template.log"; exit 1; }
	$(CARGO) test -p symvault-mcp --lib run_command_secret_refs_share_one_resource_allowance \
		> "$(AREA_EVIDENCE)/rust-read-mcp.log" 2>&1 || { cat "$(AREA_EVIDENCE)/rust-read-mcp.log"; exit 1; }
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/rust-read-store.log" \
		actual_go_resource_policy_observations_match_rust recovery_resource_failures_preserve_journal_and_originals
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/rust-read-template.log" template_resolutions_share_the_operation_allowance
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/rust-read-mcp.log" run_command_secret_refs_share_one_resource_allowance

# mcp-http-shutdown.yml (live Go -race tests of the frozen oracle), plus the
# Rust leg (MCP-003/HTTP-004/CLI-007): the real Go oracle and the Rust CLI each
# drain a real `mcp` HTTP server on SIGINT/SIGTERM/SIGQUIT with a request in
# flight (finishing inside the 5 s window and exceeding it); the unit tests
# are the HttpShutdown drain controls it relies on.
mcp-http-shutdown-contract:
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_ENV) $(AREA_GO) $(AREA_PYTHON) scripts/run_go_tests.py $(CARGO) -- $(GO) test -race -json \
		./internal/mcp/serverbootstrap ./internal/secureui ./internal/approval ./internal/policy -count=1 \
		> "$(AREA_EVIDENCE)/native-http-shutdown.jsonl"
	$(AREA_ENV) $(AREA_GO) $(AREA_PYTHON) scripts/run_go_tests.py $(CARGO) -- $(GO) test -race -json \
		./internal/mcp/server -count=1 \
		-run "TestApprovalCancellation|TestApprovalUninterruptible|^TestAuthorize|TestScopeCheckHook|TestHandleGet_OutsideScope|TestHandleDelete_OutsideScope|TestHandleGetMetadata_OutsideScope" \
		>> "$(AREA_EVIDENCE)/native-http-shutdown.jsonl"
	$(AREA_CHECK) go-json "$(AREA_EVIDENCE)/native-http-shutdown.jsonl" \
		TestHTTPShutdownActiveFactoryContract/drain TestHTTPShutdownActiveFactoryContract/deadline \
		TestHTTPShutdownIdleTransportContract TestHTTPShutdownPartialRequestDoesNotReachFactory \
		TestHTTPShutdownCleanupRetainsActiveOwnership TestApprovalUninterruptibleTerminalFailsClosed \
		TestSecurePromptContextCancelsActualProcess TestSecurePromptContextRejectsLateAffirmative \
		TestAuthorizationCancellationRetiresOwnPendingConsent/ordinary-approval \
		TestAuthorizationCancellationRetiresOwnPendingConsent/late-approval-after-cancel \
		TestApprovalCancellationDeniesPendingAndLateReply/blocked-read \
		TestApprovalCancellationDeniesPendingAndLateReply/late-yes
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_http_drain_contract.py
	$(CARGO) test -p symvault-mcp --lib --locked http::shutdown::tests::drain $(call AREA_LOGGED,native-http-drain-unit.txt)
	$(AREA_CHECK) log-ok "$(AREA_EVIDENCE)/native-http-drain-unit.txt" \
		drain_lets_the_request_in_flight_finish_cooperative_io drain_force_closes_at_the_deadline_cooperative_io \
		drain_without_connections_is_clean_and_immediate --results-ok
	$(AREA_BUILD_CLI)
	$(AREA_ENV) $(AREA_HTTP_GO) $(AREA_PYTHON) scripts/rust-port/http_drain_contract.py \
		--rust "$(AREA_CLI)" --receipt "$(AREA_EVIDENCE)/native-http-drain.json"
	$(AREA_CHECK) receipt "$(AREA_EVIDENCE)/native-http-drain.json" --profile http-drain

# rust-tui.yml. Validation tools (pyte) live in a venv under the evidence dir.
$(AREA_VENV)/.ready: scripts/rust-port/tui-validation-requirements.txt
	@mkdir -p "$(AREA_EVIDENCE)"
	$(AREA_PYTHON) -m venv "$(AREA_VENV)"
	"$(AREA_VENV)/bin/pip" install --quiet --disable-pip-version-check -r scripts/rust-port/tui-validation-requirements.txt
	@touch "$@"

# macOS: the harness checks only. tui_contract.py on Darwin reads and writes
# the real pasteboard and asserts GITHUB_ACTIONS=true plus a disposable host,
# so the local gate does not run it there (repository rule: never touch the
# real clipboard). The Linux lane runs the contract against a private Xvfb.
tui-harness-check: $(AREA_VENV)/.ready
	$(AREA_ENV) "$(AREA_VENV)/bin/python3" scripts/rust-port/tui_harness_test.py

# tui_contract.py rebuilds the CLI from source with the acceptance profile
# below and compares bytes, so the binary under test is built the same way, in
# its own target dir (it would otherwise rebuild every crate of the shared
# target dir in a different profile).
TUI_TARGET := $(AREA_EVIDENCE)/tui-candidate
TUI_BUILD_ENV := CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0

tui-contract: $(AREA_VENV)/.ready
	@rm -rf "$(AREA_EVIDENCE)/tui" && mkdir -p "$(AREA_EVIDENCE)/tui"
	CARGO_TARGET_DIR="$(TUI_TARGET)" $(TUI_BUILD_ENV) $(CARGO) build -p symvault-cli --bin symvault --locked
	$(AREA_ENV) "$(AREA_VENV)/bin/python3" scripts/rust-port/tui_harness_test.py
	$(AREA_ENV) $(AREA_HTTP_GO) "$(AREA_VENV)/bin/python3" scripts/rust-port/tui_contract.py \
		--rust-cli "$(TUI_TARGET)/debug/symvault" --receipt "$(AREA_EVIDENCE)/tui/native-tui.json"
	$(AREA_ENV) $(AREA_HTTP_GO) "$(AREA_VENV)/bin/python3" scripts/rust-port/tui_contract.py \
		--rust-cli "$(TUI_TARGET)/debug/symvault" --receipt "$(AREA_EVIDENCE)/tui/native-tui.json" --validate-receipt \
		--candidate "$$(git rev-parse HEAD)" \
		--expected-receipt-sha256 "$$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$(AREA_EVIDENCE)/tui/native-tui.json")"
	$(AREA_ENV) $(AREA_HTTP_GO) "$(AREA_VENV)/bin/python3" scripts/rust-port/tui_mutation_test.py \
		--rust-cli "$(TUI_TARGET)/debug/symvault" --native-receipt "$(AREA_EVIDENCE)/tui/native-tui.json" \
		--receipt "$(AREA_EVIDENCE)/tui/native-mutation.json"

rust-gates-core: store-differential audit-differential
	$(MAKE) rust-lint
	$(MAKE) rust-check
	$(MAKE) rust-test
	$(MAKE) rust-security
	$(MAKE) rust-fuzz-smoke
	$(MAKE) rust-features
	$(MAKE) rust-coverage
	$(MAKE) rust-version-contract

rust-gates: rust-gates-core rust-miri

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
	@echo "  pass-gpg-differential - Verify the pass importer against real gpg (Go oracle)"
	@echo "  differential-go-selftest - Compare the Go oracle with itself in isolated sandboxes"
	@echo "  crypto-differential - Verify Go↔Rust age and KDF cross-decryption"
	@echo "  crypto-fuzz-smoke - Run the bounded Argon2id parser fuzz smoke"
	@echo "  store-reopen-fixture  - Generate the deterministic Go↔Rust reopen fixture"
	@echo "  store-differential - Verify Go↔Rust storage reopen and read-only fixtures"
	@echo "  data-safety-differential - Verify the pre-Rust-mutation backup gate over Go-created vaults"
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
	@echo "  rust-gates-core    - Run every staged Rust gate except Miri"
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

.PHONY: mcp-list-fixtures-check mcp-list-differential mcp-call-fixtures-check mcp-call-differential
mcp-list-fixtures-check: mcp-ordered-fixtures-check

mcp-list-differential: mcp-list-fixtures-check
	$(CARGO) test -p symvault-mcp --test tool_list_contract --locked

.PHONY: csv-import-differential
csv-import-differential:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/importcsvgen --check
	$(CARGO) test -p symvault-sync --test csv_contract --locked

.PHONY: mcp-render-differential
mcp-render-differential:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/mcprendergen -check
	$(CARGO) test -p symvault-mcp --test render_contract --locked

.PHONY: onepass-import-differential
onepass-import-differential:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/import1passgen -check
	$(CARGO) test -p symvault-sync --test onepass_contract --locked

# IO-001: the pass importer against REAL gpg (disposable GNUPGHOME, test-only
# keys). Go re-verification of the frozen corpus, then the Rust replay.
.PHONY: pass-gpg-differential
pass-gpg-differential:
	GO="$(GO)" CARGO="$(CARGO)" GO_TOOLCHAIN="$(GO_TOOLCHAIN)" ./scripts/rust-port/check_pass_gpg.sh

.PHONY: mcp-prompts-differential
mcp-prompts-differential: mcp-ordered-fixtures-check
	$(CARGO) test -p symvault-mcp --test prompts_contract --locked

# IO-001: every Go archive/zip and compress/flate failure of the 1PUX and CXF
# importers (hand-assembled and systematically damaged archives run through the
# REAL Go importers), replayed against the Rust zip reader port.
.PHONY: zip-errors-differential
zip-errors-differential:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/zipgen -check
	$(CARGO) test -p symvault-sync --test zip_errors_contract --test zip_limit_contract --test zip_nonutf8_name_pin --locked

.PHONY: cxf-import-differential
cxf-import-differential:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/cxfgen -check -output testdata/port/import/cxf.json
	$(CARGO) test -p symvault-sync --test cxf_contract --locked

.PHONY: focus-differential
FOCUS_ORACLE_COMMIT := fca3f89401833b5e14ec4ec74ef736b0f63bca74
focus-differential:
	SYMVAULT_FOCUS_FIXTURE=check GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/autotype -run '^TestGenerateFocusFixture$$' -count=1
	$(CARGO) test -p symvault-platform --lib focus_guard_matches_go_oracle --locked

# PLATFORM-001 (#1244): Linux desktop clipboard/autotype routing and the shared
# autotype escapers, frozen from the production Go code. The Linux fixture is
# generated by driving the real GOOS=linux packages with fake desktop tools, so
# the generator needs a Linux host: on any other host it runs in a Linux
# container (Docker). The oracle sources are verified against the pinned commit
# on the host first, because a container's older git cannot read a worktree.
DESKTOP_LINUX_FIXTURE := testdata/port/platform/desktop_linux.json
DESKTOP_DOCKER_IMAGE ?= golang:1.26
DESKTOP_REPO_COMMON := $(abspath $(shell git rev-parse --git-common-dir)/..)
DESKTOP_GOMODCACHE = $(shell $(GO) env GOMODCACHE)

.PHONY: autotype-escape-fixtures-check desktop-linux-fixtures-check desktop-linux-fixtures-generate desktop-linux-fixtures-ci desktop-differential
autotype-escape-fixtures-check:
	SYMVAULT_AUTOTYPE_ESCAPE_FIXTURE=check GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/autotype -run '^TestGenerateAutotypeEscapeFixture$$' -count=1

desktop-linux-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/desktopgen -provenance-only
ifeq ($(shell uname -s),Linux)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/desktopgen -check -output $(DESKTOP_LINUX_FIXTURE)
else
	docker run --rm -v "$(DESKTOP_REPO_COMMON):$(DESKTOP_REPO_COMMON)" -v "$(DESKTOP_GOMODCACHE):/gomod" -v desktopgen-gocache:/gocache -w "$(CURDIR)" \
		-e GOMODCACHE=/gomod -e GOCACHE=/gocache -e GOWORK=off -e GOTOOLCHAIN=local -e GOFLAGS=-mod=mod -e GOPROXY=off \
		$(DESKTOP_DOCKER_IMAGE) go run ./scripts/rust-port/cmd/desktopgen -check -provenance-host-verified -output $(DESKTOP_LINUX_FIXTURE)
endif

desktop-linux-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/desktopgen -provenance-only
ifeq ($(shell uname -s),Linux)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/desktopgen -output $(DESKTOP_LINUX_FIXTURE)
else
	docker run --rm -v "$(DESKTOP_REPO_COMMON):$(DESKTOP_REPO_COMMON)" -v "$(DESKTOP_GOMODCACHE):/gomod" -v desktopgen-gocache:/gocache -w "$(CURDIR)" \
		-e GOMODCACHE=/gomod -e GOCACHE=/gocache -e GOWORK=off -e GOTOOLCHAIN=local -e GOFLAGS=-mod=mod -e GOPROXY=off \
		$(DESKTOP_DOCKER_IMAGE) go run ./scripts/rust-port/cmd/desktopgen -provenance-host-verified -output $(DESKTOP_LINUX_FIXTURE)
endif

# Aggregate-gate variant: on a Linux host the fixture is checked natively; on
# any other host it is NOT verified (the Linux job owns it) and says so, rather
# than requiring Docker on every runner. Use desktop-linux-fixtures-check to
# verify it explicitly off Linux.
desktop-linux-fixtures-ci:
ifeq ($(shell uname -s),Linux)
	$(MAKE) desktop-linux-fixtures-check
else
	@echo "NOTE desktop_linux.json: not regenerated on $(shell uname -s); the Linux 'Rust port contract' job verifies it. Run 'make desktop-linux-fixtures-check' (Docker) to verify here."
endif

desktop-differential: autotype-escape-fixtures-check desktop-linux-fixtures-ci
	$(CARGO) test -p symvault-platform --test desktop_linux_contract --locked
	$(CARGO) test -p symvault-platform --lib desktop_commands --locked

# PLATFORM-001 slice 2 (#1244): the clipboard path of `symvault get` (routing,
# Countdown, VerifyCleared / ErrClipboardNotCleared). The fixture is recorded
# from the production Go command with an in-memory clipboard; no host clipboard
# or credential is touched. Rust replays it with injected clipboard/clock/stderr.
.PHONY: get-clipboard-fixtures-check get-clipboard-fixtures-generate get-clipboard-differential
get-clipboard-fixtures-check:
	SYMVAULT_GET_CLIPBOARD_FIXTURE=check GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./cmd -run '^TestGenerateGetClipboardFixture$$' -count=1
	SYMVAULT_TUI_CLIPBOARD_FIXTURE=check GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/ui -run '^TestGenerateTUIClipboardFixture$$' -count=1
	SYMAIRA_CHECK_MCP_CLIPBOARD_AUTO_CLEAR_FIXTURE=1 GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/mcp/server -run '^TestGenerateMCPClipboardAutoClearFixture$$' -count=1
	@if [ "$$(uname -s)" = Darwin ]; then \
	  SYMVAULT_GET_CLIPBOARD_FIXTURE=check GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./cmd -run '^TestGenerateGetClipboardDarwinFixture$$' -count=1; \
	else \
	  echo "NOTE get_clipboard_darwin.json: the macOS pasteboard oracle is only regenerated on macOS; the Rust replay (macOS only) reads it as recorded."; \
	fi

get-clipboard-fixtures-generate:
	SYMVAULT_GET_CLIPBOARD_FIXTURE=write GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./cmd -run '^TestGenerateGetClipboardFixture$$' -count=1
	SYMVAULT_TUI_CLIPBOARD_FIXTURE=write GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/ui -run '^TestGenerateTUIClipboardFixture$$' -count=1
	SYMAIRA_GENERATE_MCP_CLIPBOARD_AUTO_CLEAR_FIXTURE=1 GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/mcp/server -run '^TestGenerateMCPClipboardAutoClearFixture$$' -count=1
	@if [ "$$(uname -s)" = Darwin ]; then \
	  SYMVAULT_GET_CLIPBOARD_FIXTURE=write GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./cmd -run '^TestGenerateGetClipboardDarwinFixture$$' -count=1; \
	fi

get-clipboard-differential: get-clipboard-fixtures-check
	$(CARGO) test -p symvault-platform --test get_clipboard_contract --test get_clipboard_darwin_contract --locked
	$(CARGO) test -p symvault-mcp --test clipboard_auto_clear_contract --locked
	$(CARGO) test -p symvault-cli --bin symvault --locked -- get_clipboard_wiring_tests tui::

# PLATFORM-WIRE-001: the clipboard Go really uses on Linux (atotto command
# backend, tool choice fixed in that package's init() from PATH and
# WAYLAND_DISPLAY) behind MCP copy_to_clipboard, `symvault get` and the TUI.
# Two fixtures are recorded by the real Go commands on GOOS=linux with fake
# POSIX-shell tools on a disposable PATH (re-executed child per scenario). On a
# Linux host they are checked natively; elsewhere the Linux Go toolchain runs in
# a container (clipboard-linux-fixtures-check) and the aggregate gate prints a
# NOTE like desktop-linux-fixtures-ci. The Rust replays run on every Unix; the
# real-binary test (mcp --stdio and `get` on a pty) is Linux-only and, with
# SYMVAULT_GATE=1 (or CI), fails instead of skipping when python3/pty is missing.
MCP_CLIPBOARD_LINUX_FIXTURE := testdata/port/mcp/copy-clipboard-linux.json
GET_CLIPBOARD_LINUX_FIXTURE := testdata/port/platform/get_clipboard_linux.json

# Off Linux the generators run in a container whose git cannot read a worktree
# checkout and whose Go is not the pinned toolchain. The oracle pin (the
# working-tree sources equal the blobs of the reachable pinned commit) is
# therefore verified on the host first and handed to the container as a file.
CLIPBOARD_LINUX_DOCKER = docker run --rm --name "symvault-clipboard-linux-$$$$" -v "$(CURDIR):$(CURDIR)" -v "$(DESKTOP_REPO_COMMON):$(DESKTOP_REPO_COMMON)" -v "$$pin:$$pin" -v "$(DESKTOP_GOMODCACHE):/gomod" -v desktopgen-gocache:/gocache -w "$(CURDIR)" \
	-e GOMODCACHE=/gomod -e GOCACHE=/gocache -e GOWORK=off -e GOTOOLCHAIN=local -e GOFLAGS=-mod=mod -e GOPROXY=off -e CGO_ENABLED=0 \
	-e SYMAIRA_MCP_COPY_CLIPBOARD_LINUX_PIN_FILE="$$pin/mcp.json" -e SYMVAULT_GET_CLIPBOARD_LINUX_PIN_FILE="$$pin/get.json"
CLIPBOARD_LINUX_HOST_PIN = SYMAIRA_MCP_COPY_CLIPBOARD_LINUX_PIN_FILE="$$pin/mcp.json" GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/mcp/server -run '^TestMCPCopyClipboardLinuxOraclePin$$' -count=1 \
	&& SYMVAULT_GET_CLIPBOARD_LINUX_PIN_FILE="$$pin/get.json" GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./cmd -run '^TestGetClipboardLinuxOraclePin$$' -count=1

.PHONY: clipboard-linux-fixtures-check clipboard-linux-fixtures-generate clipboard-linux-fixtures-ci clipboard-linux-differential
clipboard-linux-fixtures-check:
ifeq ($(shell uname -s),Linux)
	SYMAIRA_CHECK_MCP_COPY_CLIPBOARD_LINUX_FIXTURE=1 GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/mcp/server -run '^TestGenerateMCPCopyClipboardLinuxFixture$$' -count=1
	SYMVAULT_GET_CLIPBOARD_LINUX_FIXTURE=check GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./cmd -run '^TestGenerateGetClipboardLinuxFixture$$' -count=1
else
	pin=$$(mktemp -d) && trap 'rm -rf "$$pin"' EXIT && $(CLIPBOARD_LINUX_HOST_PIN) \
	&& $(CLIPBOARD_LINUX_DOCKER) -e SYMAIRA_CHECK_MCP_COPY_CLIPBOARD_LINUX_FIXTURE=1 -e SYMVAULT_GET_CLIPBOARD_LINUX_FIXTURE=check \
		$(DESKTOP_DOCKER_IMAGE) sh -c "go test ./internal/mcp/server -run '^TestGenerateMCPCopyClipboardLinuxFixture\$$' -count=1 && go test ./cmd -run '^TestGenerateGetClipboardLinuxFixture\$$' -count=1"
endif

clipboard-linux-fixtures-generate:
ifeq ($(shell uname -s),Linux)
	SYMAIRA_GENERATE_MCP_COPY_CLIPBOARD_LINUX_FIXTURE=1 GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/mcp/server -run '^TestGenerateMCPCopyClipboardLinuxFixture$$' -count=1
	SYMVAULT_GET_CLIPBOARD_LINUX_FIXTURE=write GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./cmd -run '^TestGenerateGetClipboardLinuxFixture$$' -count=1
else
	pin=$$(mktemp -d) && trap 'rm -rf "$$pin"' EXIT && $(CLIPBOARD_LINUX_HOST_PIN) \
	&& $(CLIPBOARD_LINUX_DOCKER) -e SYMAIRA_GENERATE_MCP_COPY_CLIPBOARD_LINUX_FIXTURE=1 -e SYMVAULT_GET_CLIPBOARD_LINUX_FIXTURE=write \
		$(DESKTOP_DOCKER_IMAGE) sh -c "go test ./internal/mcp/server -run '^TestGenerateMCPCopyClipboardLinuxFixture\$$' -count=1 && go test ./cmd -run '^TestGenerateGetClipboardLinuxFixture\$$' -count=1"
endif

clipboard-linux-fixtures-ci:
ifeq ($(shell uname -s),Linux)
	$(MAKE) clipboard-linux-fixtures-check
else
	@echo "NOTE copy-clipboard-linux.json / get_clipboard_linux.json: not regenerated on $(shell uname -s); the Linux 'Rust port contract' job verifies them. Run 'make clipboard-linux-fixtures-check' (Docker) to verify here."
endif

clipboard-linux-differential: clipboard-linux-fixtures-ci
	$(CARGO) test -p symvault-mcp --test tools_copy_to_clipboard_linux_contract --locked
	$(CARGO) test -p symvault-platform --test get_clipboard_linux_contract --test owned_clipboard_command_contract --locked
ifeq ($(shell uname -s),Linux)
	SYMVAULT_GATE=1 $(CARGO) test -p symvault-cli --test clipboard_linux_entrypoints --locked
endif

.PHONY: export-differential
export-differential:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/exportgen -check
	$(CARGO) test -p symvault-sync --test export_contract --locked

# IO-002: production-Go RestoreBackup error text and side effects for hostile
# and malformed archives, replayed through the Rust restore path.
.PHONY: restore-errors-differential
restore-errors-differential:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/restoregen -check
	$(CARGO) test -p symvault-cli --test restore_errors_contract --locked
	$(CARGO) test -p symvault-cli --test restore_gzip_multistream_contract --locked
	$(CARGO) test -p symvault-sync --test restore_limits --test restore_gzip_multistream --locked

.PHONY: mcp-call-fixtures-check mcp-call-differential mcp-execute-with-secret-fixtures-check mcp-execute-with-secret-differential
mcp-execute-with-secret-fixtures-check: mcp-ordered-fixtures-check

mcp-execute-with-secret-differential: mcp-execute-with-secret-fixtures-check
	$(CARGO) test -p symvault-mcp --test execute_with_secret_contract --locked

.PHONY: mcp-execute-api-request-fixtures-check mcp-execute-api-request-differential
.PHONY: api-templates-fixtures-check api-templates-differential
api-templates-fixtures-check:
	SYMAIRA_CHECK_API_TEMPLATES_FIXTURE=1 GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/mcp/server -run '^TestGenerateAPITemplatesFixture$$' -count=1

api-templates-differential: api-templates-fixtures-check
	$(CARGO) test -p symvault-mcp --test api_templates_contract --locked

# MCP-003: Go-recorded request_share/approve_share/revoke_share/list_shares corpus
# (testdata/port/mcp/tools-sharing.json) driven through the real Go protocol
# handler over a seeded share store. The check is non-writing and needs the
# pinned toolchain (GOWORK=off); generation is the explicit -generate target.
.PHONY: mcp-sharing-fixtures-check mcp-sharing-fixtures-generate mcp-sharing-differential
mcp-sharing-fixtures-check:
	SYMAIRA_CHECK_MCP_SHARING_FIXTURE=1 GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/mcp/server -run '^TestGenerateMCPSharingFixture$$' -count=1

mcp-sharing-fixtures-generate:
	SYMAIRA_GENERATE_MCP_SHARING_FIXTURE=1 GOWORK=off GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/mcp/server -run '^TestGenerateMCPSharingFixture$$' -count=1

mcp-sharing-differential: mcp-sharing-fixtures-check
	$(CARGO) test -p symvault-mcp --test tools_sharing_contract --locked

mcp-execute-api-request-fixtures-check: mcp-ordered-fixtures-check

mcp-execute-api-request-differential: mcp-execute-api-request-fixtures-check mcp-execute-api-policy-differential
	$(CARGO) test -p symvault-cli --test mcp_commands_contract --locked -- cli_runtime_executes_source_bound_api_template_fixture --exact

.PHONY: mcp-execute-api-policy-fixtures-check mcp-execute-api-policy-differential
mcp-execute-api-policy-fixtures-check: mcp-ordered-fixtures-check

mcp-execute-api-policy-differential: mcp-execute-api-policy-fixtures-check
	$(CARGO) test -p symvault-mcp --lib --locked -- api_review_entry_policy_matches_corrected_go_observations

.PHONY: mcp-execute-api-https-fixtures-check mcp-execute-api-https-differential
mcp-execute-api-https-fixtures-check: mcp-ordered-fixtures-check

mcp-execute-api-https-differential: mcp-execute-api-https-fixtures-check
	$(CARGO) test -p symvault-mcp --lib --locked -- broker::tests::https_is_verified_for_local_targets_and_public_dns_remains_blocked --exact
	$(CARGO) test -p symvault-mcp --lib --locked -- broker::tests::local_https_contract_matches_the_source_bound_go_handler_fixture --exact

# CLI-007 (#1242): real SIGINT/SIGTERM/SIGHUP/SIGQUIT delivery to the actual Go
# oracle (pinned in the driver, built from `git archive`) and the Rust CLI for
# broker, run, run --broker and intake watch: ending status, output, listener,
# orphaned child and on-disk state. Windows Ctrl-Break is covered by
# egress_contract.py / intake_watch_contract.py; this Unix driver is skipped there.
# Set SIGNAL_PROCESS_ARGS=--allow-dirty-for-development for an uncommitted candidate.
SIGNAL_PROCESS_ARGS ?=
.PHONY: signal-process-differential
signal-process-differential:
ifeq ($(OS),Windows_NT)
	@echo "SKIP Unix signal process contract: Windows Ctrl-Break evidence comes from egress_contract.py and intake_watch_contract.py"
else
	python3 -B scripts/rust-port/test_signal_process_contract.py
	$(CARGO) build -p symvault-cli --bin symvault --locked
	GOTOOLCHAIN=$(GO_TOOLCHAIN) python3 -B scripts/rust-port/signal_process_contract.py \
		--rust "$(RUST_BINARY)" \
		--receipt "$(CARGO_TARGET_DIR)/native-signals.json" $(SIGNAL_PROCESS_ARGS)
endif

.PHONY: mcp-copy-clipboard-fixtures-check mcp-copy-clipboard-differential mcp-clipboard-signals-differential
mcp-clipboard-signals-differential:
ifeq ($(OS),Windows_NT)
	@echo "SKIP Unix clipboard signal contract: native Windows signal behavior remains unverified"
else
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/clipboard -run '^TestStartAutoClearSignalRouterProcessContract$$' -count=1
	$(CARGO) test -p symvault-platform --lib --locked -- approval::tests::stdio_clipboard_signal_router_process_contract --exact
endif

mcp-copy-clipboard-fixtures-check: mcp-ordered-fixtures-check

mcp-copy-clipboard-differential: mcp-copy-clipboard-fixtures-check mcp-clipboard-signals-differential
	$(CARGO) test -p symvault-mcp --test tools_copy_to_clipboard_contract --locked

.PHONY: mcp-secure-input-fixtures-check mcp-secure-input-differential
mcp-secure-input-fixtures-check: mcp-ordered-fixtures-check
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/secure_input_unicode

mcp-secure-input-differential: mcp-secure-input-fixtures-check
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/secureui -run '^(TestTTYReadStringRuneEditing|TestPrompt_TTYBackend_SignalCancel)$$' -count=1
	$(CARGO) test -p symvault-mcp --test secure_input_contract --locked
	$(CARGO) test -p symvault-platform --lib --locked -- approval::tests::secure_input_

.PHONY: mcp-approval-pty-acceptance
mcp-approval-pty-acceptance:
	python3 scripts/rust-port/mcp-approval-pty.py -- $(CARGO) test -p symvault-cli --test mcp_commands_contract --locked -- --ignored --exact unix_platform_approval_pty_acceptance --nocapture

.PHONY: mcp-write-tty-approval-fixtures-check mcp-write-tty-approval-differential
mcp-write-tty-approval-fixtures-check: mcp-ordered-fixtures-check

mcp-write-tty-approval-differential: mcp-write-tty-approval-fixtures-check
	$(CARGO) test -p symvault-mcp --test write_tty_approval_contract --locked

mcp-call-fixtures-check: mcp-copy-clipboard-fixtures-check mcp-secure-input-fixtures-check mcp-execute-api-https-fixtures-check mcp-execute-with-secret-fixtures-check mcp-write-tty-approval-fixtures-check mcp-execute-api-request-fixtures-check api-templates-fixtures-check mcp-sharing-fixtures-check

# Historical fixtures stay immutable. Execute the reviewed approval lifetime
# generator on both source references; compare every behavior and identity field.
# The producer's default original mode remains available for historical diagnosis.
.PHONY: mcp-ordered-fixtures-check mcp-oracle-controls
MCP_FIXTURE_EVIDENCE ?= target/mcp-fixture-evidence
mcp-oracle-controls:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/rust-port/test_build_timeout.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/rust-port/test_mcp_oracle.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/rust-port/test_mcp_compiler_adapter.py

mcp-ordered-fixtures-check: mcp-oracle-controls
	GOTOOLCHAIN=$(GO_TOOLCHAIN) PYTHONDONTWRITEBYTECODE=1 python3 scripts/rust-port/mcp_fixture_contract.py --approval-generator approval-lifetime-v1 --output-root "$(MCP_FIXTURE_EVIDENCE)"

mcp-call-differential: mcp-call-fixtures-check mcp-authz-differential policy-context-differential mcp-copy-clipboard-differential mcp-secure-input-differential mcp-execute-api-https-differential mcp-execute-with-secret-differential mcp-write-tty-approval-differential mcp-execute-api-request-differential api-templates-differential
	$(CARGO) test -p symvault-mcp --test tools_call_contract --test tools_call_fixture --test tools_call_store --test tools_get_value --test tools_list_entries --test tools_generate_password --test tools_generate_totp --test tools_set_entry --test tools_delete_entry --test tools_auth_status --test tools_audit_self --test tools_sanitize_output --test tools_symaira_search --test tools_generate_template --test tools_search_fetch --test tools_secret_unseal --test tools_sharing_contract --locked

# MCP-002/MCP-003: Go-recorded tools/call outcome of every tool under 22 agent
# profiles and three token scopes, replayed through the production CLI assembly.
# The check rebuilds the corrected Go oracle out of tree (non-CGO,
# -buildvcs=false) and requires byte equality with the committed fixture.
# Go-recorded policy.BuildContext field mapping and the policy outcomes it yields
# (allowed_tools matches every tool, ~/ expansion, working_dir, HOME/GIT_BRANCH
# env). Rust must build every evaluation context the same way, so no
# deny/prompt/biometry rule that Go applies is skipped.
.PHONY: policy-context-fixtures-generate policy-context-fixtures-check policy-context-differential
policy-context-fixtures-generate:
	SYMAIRA_GENERATE_POLICY_CONTEXT_FIXTURE=1 GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/policy -run '^TestGeneratePolicyBuildContextFixture$$' -count=1

policy-context-fixtures-check:
	SYMAIRA_CHECK_POLICY_CONTEXT_FIXTURE=1 GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/policy -run '^TestGeneratePolicyBuildContextFixture$$' -count=1

policy-context-differential: policy-context-fixtures-check
	$(CARGO) test -p symvault-mcp --test policy_build_context_contract --test policy_context_authorize --locked
	$(CARGO) test -p symvault-mcp --lib --locked -- policy_context::

.PHONY: mcp-authz-fixtures-check mcp-authz-differential
mcp-authz-fixtures-check:
	python3 -B scripts/rust-port/test_mcp_authz_matrix.py
	GOTOOLCHAIN=$(GO_TOOLCHAIN) PYTHONDONTWRITEBYTECODE=1 python3 scripts/rust-port/mcp_authz_matrix.py --check

mcp-authz-differential: mcp-authz-fixtures-check
	SYMVAULT_SECUREUI=none $(CARGO) test -p symvault-cli --test mcp_authz_matrix --locked authorization_matrix -- --nocapture

.PHONY: export-cli-fixtures-check
export-cli-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./cmd/admin -run '^TestExportFixture$$' -count=1

.PHONY: reencrypt-journal-differential
reencrypt-journal-differential:
	$(CARGO) build -p symvault-cli --locked
	SYMVAULT_RUST_BINARY="$(abspath $(RUST_BINARY))" GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./internal/vault -run '^TestReencryptJournalGoRustIntegration$$' -count=1

# Capture the Go side of the non-HTTP process contracts and live-Go differentials
# once (needs Go; writes scripts/rust-port/fixtures/go-observations/<contract>.<goos>.json).
# Every contract target replays these files and runs Rust only. A missing
# observation fails the target. Both local-gate lanes capture: darwin natively, linux
# through scripts/rust-port/go-observations-capture-linux.sh (Go-only, gate image).
.PHONY: go-observations-capture-other go-observations-selftest
GO_OBS_CAPTURE := $(AREA_ENV) $(AREA_GO) $(AREA_PYTHON)
go-observations-capture-other:
	$(GO_OBS_CAPTURE) scripts/rust-port/connect_contract.py --capture-go
	$(GO_OBS_CAPTURE) scripts/rust-port/egress_contract.py --capture-go

go-observations-selftest:
	$(AREA_ENV) $(AREA_PYTHON) scripts/rust-port/test_go_observations_common.py
