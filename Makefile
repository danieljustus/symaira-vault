.PHONY: all build install test test-fast test-coverage test-verbose test-race test-ci clean lint lint-fix fmt fmt-check vet passlint completions manpages help docs-check

# Variables
BINARY_NAME := openpass
GO := go
GOFLAGS := -v
GOLANGCI_LINT_VERSION := v2.11.4
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

# Clean build artifacts and coverage files
clean:
	rm -f $(BINARY_NAME) *.test *.out *_output.txt
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
	./$(BINARY_NAME) completion bash > completions/openpass.bash
	./$(BINARY_NAME) completion zsh > completions/openpass.zsh
	./$(BINARY_NAME) completion fish > completions/openpass.fish

# Generate manual pages
manpages: build
	@mkdir -p docs/man
	./$(BINARY_NAME) generate manpages docs/man

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
	@echo "  test-coverage-html - Generate HTML coverage report"
	@echo "  test-race          - Run tests with race detector"
	@echo "  test-ci            - Run CI-like tests (race + coverage + timeout)"
	@echo "  test-core          - Run tests for core packages only"
	@echo "  test-core-coverage - Run core package tests with coverage"
	@echo "  test-vault         - Run vault package tests"
	@echo "  test-config        - Run config package tests"
	@echo "  test-crypto        - Run crypto package tests"
	@echo "  test-bench         - Run benchmarks"
	@echo "  clean              - Clean build artifacts"
	@echo "  lint               - Run linter"
	@echo "  lint-fix           - Run linter with auto-fix"
	@echo "  fmt                - Format code"
	@echo "  fmt-check          - Check formatting (fails if gofmt would change files)"
	@echo "  vet                - Run go vet (includes passlint)"
	@echo "  passlint           - Run passlint analyzer tests"
	@echo "  deps               - Download and tidy dependencies"
	@echo "  completions        - Generate shell completions"
	@echo "  manpages           - Generate manual pages"
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
	for pattern in "brew install --cask openpass" "mcp-config --agent" "mcp_openpass_openpass"; do \
		if grep -r "$$pattern" README.md docs homebrew .gitignore --exclude-dir=dist --exclude-dir=coverage --exclude-dir=node_modules 2>/dev/null; then \
			echo "Found deprecated pattern: $$pattern"; \
			errors=$$((errors + 1)); \
		fi; \
	done; \
	for tool in "openpass_list" "openpass_get" "openpass_generate" "openpass_health"; do \
		if grep -rE "\b$$tool\b" README.md docs homebrew .gitignore --exclude-dir=dist --exclude-dir=coverage --exclude-dir=node_modules 2>/dev/null; then \
			echo "Found deprecated tool name: $$tool"; \
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
