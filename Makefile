.PHONY: all build install test test-fast test-coverage test-verbose test-race test-ci cover clean lint lint-fix fmt fmt-check vet passlint completions manpages port-fixtures-generate port-fixtures-check core-fixtures-generate core-fixtures-check quota-fixtures-generate quota-fixtures-check policy-fixtures-generate policy-fixtures-check differential-go-selftest crypto-differential crypto-fuzz-smoke port-contract store-reopen-fixture store-differential rust-build rust-check rust-lint rust-test rust-miri rust-features rust-coverage rust-security rust-version-contract rust-fuzz-lock rust-fuzz-smoke rust-fuzz rust-gates help docs-check

# Variables
BINARY_NAME := symvault
GO := go
CARGO := cargo
GOFLAGS := -v
GOLANGCI_LINT_VERSION := v2.11.4
GO_TOOLCHAIN ?= go1.26.6
MIRI_TOOLCHAIN := nightly-2026-09-03
MIRI_TARGET_DIR := target/miri-2026-09-03
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
lint:
	GOWORK=off $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --timeout=5m --verbose

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
	GOWORK=off $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --fix --timeout=5m --verbose

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
PORT_CLI_FIXTURE := testdata/port/cli/command-tree.json
PORT_CLI_CASES := testdata/port/cli/cases.json
PORT_ERROR_FIXTURE := testdata/port/core/error-contract.json
PORT_SECRET_REF_FIXTURE := testdata/port/core/secret-ref-contract.json
PORT_REDACT_FIXTURE := testdata/port/core/redact-contract.json
PORT_CRYPTO_FIXTURE := testdata/port/core/password-totp-contract.json
PORT_QUOTA_FIXTURE := testdata/port/core/quota-contract.json
PORT_POLICY_FIXTURE := testdata/port/core/policy-contract.json
PORT_GO_BINARY := target/port/symvault-go
RUST_BINARY := target/debug/symvault
PORT_CONTRACT_VERSION ?= v0.0.0-port

port-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/portgen \
		--output $(PORT_CLI_FIXTURE) \
		--oracle-commit $(PORT_ORACLE_COMMIT) \
		--oracle-release $(PORT_ORACLE_RELEASE)

port-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/portgen \
		--check --output $(PORT_CLI_FIXTURE)

quota-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/quotagen \
		--output $(PORT_QUOTA_FIXTURE) \
		--oracle-commit $(PORT_ORACLE_COMMIT) \
		--oracle-release $(PORT_ORACLE_RELEASE)

quota-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/quotagen \
		--check --output $(PORT_QUOTA_FIXTURE)

core-fixtures-generate: quota-fixtures-generate
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/coregen \
		--error-output $(PORT_ERROR_FIXTURE) \
		--secret-ref-output $(PORT_SECRET_REF_FIXTURE) \
		--redact-output $(PORT_REDACT_FIXTURE) \
		--crypto-output $(PORT_CRYPTO_FIXTURE) \
		--oracle-commit $(PORT_ORACLE_COMMIT) \
		--oracle-release $(PORT_ORACLE_RELEASE)

core-fixtures-check: quota-fixtures-check
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/coregen \
		--check \
		--error-output $(PORT_ERROR_FIXTURE) \
		--secret-ref-output $(PORT_SECRET_REF_FIXTURE) \
		--redact-output $(PORT_REDACT_FIXTURE) \
		--crypto-output $(PORT_CRYPTO_FIXTURE)

policy-fixtures-generate:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/policygen \
		--output $(PORT_POLICY_FIXTURE) \
		--oracle-commit $(PORT_ORACLE_COMMIT) \
		--oracle-release $(PORT_ORACLE_RELEASE)

policy-fixtures-check:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/policygen \
		--check --output $(PORT_POLICY_FIXTURE)

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

port-contract: port-fixtures-check core-fixtures-check policy-fixtures-check differential-go-selftest crypto-differential

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
	CARGO_TARGET_DIR=$(MIRI_TARGET_DIR) $(CARGO) +$(MIRI_TOOLCHAIN) miri test -p symvault-core --locked

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
		--left ./$(PORT_GO_BINARY) --right ./$(RUST_BINARY) \
		--cases $(PORT_CLI_CASES) --stage version

store-reopen-fixture:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/storereopen --generate --fixture testdata/port/store/reopen.json

store-differential:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/storereopen --fixture testdata/port/store/reopen.json
	$(CARGO) build -p symvault-store --example store-reopen --locked
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/storereopen --run --fixture testdata/port/store/reopen.json --rust-binary target/debug/examples/store-reopen
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run ./scripts/rust-port/cmd/storegen --check --output testdata/port/store/store.json
	$(CARGO) test -p symvault-store --locked

rust-gates: store-differential
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
	@echo "  differential-go-selftest - Compare the Go oracle with itself in isolated sandboxes"
	@echo "  crypto-differential - Verify Go↔Rust age and KDF cross-decryption"
	@echo "  crypto-fuzz-smoke - Run the bounded Argon2id parser fuzz smoke"
	@echo "  store-reopen-fixture  - Generate the deterministic Go↔Rust reopen fixture"
	@echo "  store-differential - Verify Go↔Rust storage reopen and read-only fixtures"
	@echo "  rust-fuzz-smoke   - Run the deterministic bounded Rust age/KDF fuzz smoke"
	@echo "  rust-fuzz         - Run the bounded main/scheduled Rust age/KDF fuzz pass"
	@echo "  port-contract      - Run all Rust-port contract preparation gates"
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
