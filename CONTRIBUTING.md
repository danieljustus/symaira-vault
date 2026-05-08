# Contributing to OpenPass

Thank you for your interest in contributing to OpenPass! This document provides guidelines and instructions for contributing.

## Development Setup

### Quick Setup (Recommended)

Use the automated setup script to install all required tools:

```bash
git clone https://github.com/danieljustus/OpenPass
cd OpenPass
./scripts/setup-dev.sh
```

The script is idempotent and safe to run multiple times. Use `./scripts/setup-dev.sh --check` to verify your environment without installing anything.

### Manual Setup

If you prefer manual setup, ensure you have:

- **Go 1.26.3 or later** (CI and release workflows currently validate with Go 1.26.3)
- **git**
- **make**
- **golangci-lint** v2.11.4: `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4`
- **pre-commit** (optional but recommended): `pip install pre-commit` or `brew install pre-commit`

### Clone and Build

```bash
git clone https://github.com/danieljustus/OpenPass
cd OpenPass
go build -o openpass .
```

### Pre-commit Hooks

After running the setup script (or installing pre-commit manually):

```bash
pre-commit install
```

This installs git hooks that run formatting, linting, and short tests before each commit, catching issues locally before they reach CI.

### Running from Source

```bash
./openpass --help
```

### Project Structure

```
openpass/
├── main.go              # Entry point
├── cmd/                 # CLI commands (Cobra)
│   ├── root.go          # Root command
│   ├── get.go           # Get entry
│   ├── set.go           # Set entry
│   ├── list.go          # List entries
│   ├── find.go          # Find entries
│   ├── generate.go      # Generate password
│   ├── delete.go        # Delete entry
│   ├── init.go          # Initialize vault
│   ├── lock.go          # Lock vault
│   ├── unlock.go        # Unlock vault
│   ├── edit.go          # Edit entry
│   ├── add.go           # Add entry
│   ├── git.go           # Git operations
│   ├── serve.go         # MCP server
│   ├── recipients.go    # Manage recipients
│   └── mcp_config.go    # MCP config generation
├── internal/
│   ├── vault/           # Core vault logic
│   ├── crypto/          # Age encryption layer
│   ├── session/         # OS keyring caching
│   ├── config/          # YAML config
│   ├── git/             # Git integration
│   ├── mcp/             # MCP server implementation
│   └── audit/           # Audit logging

```

## Code Style Guidelines

### EditorConfig

OpenPass uses [EditorConfig](https://editorconfig.org) to maintain consistent formatting across editors. The `.editorconfig` file in the repository root defines the rules:

- **Go files** (`*.go`, `go.mod`): tab indentation
- **YAML files** (`*.yaml`, `*.yml`): 2-space indentation
- **Markdown files** (`*.md`): trailing whitespace preserved (for line breaks), max line length 80
- **JSON files** (`*.json`): 2-space indentation
- **Shell scripts** (`*.sh`): 2-space indentation

Most editors support EditorConfig natively or via plugin. See [editorconfig.org](https://editorconfig.org) for setup instructions.

### Go Standards

- Follow [Effective Go](https://go.dev/doc/effective_go) conventions
- Use `gofmt` for formatting (enforced via `make fmt`)
- Run `go vet` before committing (enforced via `make lint`)

### Naming Conventions

- **Files**: lowercase with underscores (`vault.go`, `age_crypto.go`)
- **Functions**: PascalCase for exported, camelCase for unexported
- **Constants**: CamelCase or SCREAMING_SNAKE_CASE for magic values
- **Interfaces**: PascalCase, typically with `-er` suffix (e.g., `Reader`, `Writer`)

### Error Handling

- Return errors rather than logging them in library code
- Prefix error messages with lowercase context: `"vault: failed to open"`
- Use `fmt.Errorf` with `%w` for error wrapping

### File Handle Management

Always use `defer` to close file handles immediately after opening:

```go
// Correct: defer close immediately after error check
file, err := os.Open(path)
if err != nil {
    return err
}
defer func() { _ = file.Close() }()

// For long-lived resources (e.g., loggers), store the handle in a struct
// and provide a Close() method for cleanup:
type Logger struct {
    file *os.File
}

func (l *Logger) Close() error {
    if l.file != nil {
        return l.file.Close()
    }
    return nil
}
```

This ensures file handles are closed even on early returns or panics.

### Output Streams

OpenPass follows standard Unix conventions for output streams:

- **stdout**: Normal output, data, success messages
- **stderr**: Errors, warnings, interactive prompts

**Examples:**

```go
// Correct: prompts to stderr
fmt.Fprint(os.Stderr, "Passphrase: ")

// Correct: normal output to stdout
fmt.Println("Entry created: path/to/entry")

// Correct: errors to stderr
fmt.Fprintf(os.Stderr, "Error: %v\n", err)
```

This allows users to pipe normal output to other commands while still seeing errors.

```bash
openpass list | grep work        # Filter list output
openpass get pass 2>/dev/null   # Hide errors
```

### Comments

- Comment exported functions and types
- Use doc comments (`// FunctionName does...`) for public APIs
- Keep comments concise but informative

## Testing Requirements

### Running Tests

```bash
# Run all tests with race detector (recommended for local validation)
make test

# Run tests without race detector (faster, for quick iteration)
make test-fast

# Run tests with race detector and extended timeout (used in CI)
make test-race

# Run specific package tests
go test ./internal/vault/... -v

# Run specific test
go test ./internal/vault/... -run TestFoo -v
```

### Test Coverage

```bash
# Generate text coverage report
make test-coverage

# Generate HTML coverage report
make test-coverage-html
```

### Code Quality Checks

```bash
# Install golangci-lint v2 (required for local linting)
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4

# Run all linters (golangci-lint must be installed)
make lint

# Format code
make fmt

# Run go vet
make vet

# Run gosec SAST scanner (blocking in CI)
go install github.com/securego/gosec/v2/cmd/gosec@latest
gosec ./...
```

### Writing Tests

- Tests should be in `*_test.go` files in the same package
- Use descriptive test names: `TestVault_Open_WithValidIdentity`
- Use table-driven tests for multiple scenarios
- Ensure tests clean up after themselves (temp files, etc.)

## Commit Message Format

OpenPass uses a structured commit format based on [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only changes
- `style`: Code style changes (formatting, no logic change)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Examples

```
feat(vault): add auto-commit functionality

Add automatic git commit after each vault modification.
The commit message includes the operation type and entry path.

Closes #123
```

```
fix(crypto): handle empty passphrase gracefully

Previously, an empty passphrase would cause a panic.
Now returns a descriptive error instead.

Closes #456
```

```
docs(readme): update installation instructions
```

## Pull Request Process

### Before Submitting

1. **Fork the repository** and create a feature branch
2. **Keep changes focused** — one feature or fix per PR
3. **Run local checks**:
   ```bash
   make fmt
   make vet
   make lint
   make test
   ```
4. **Add tests** for new functionality
5. **Update documentation** if needed

### PR Description

Include in your PR description:

- **What**: Brief description of changes
- **Why**: Context or motivation
- **How**: Summary of implementation approach
- **Testing**: How you tested the changes
- **Screenshots/evidence** (if applicable)

### Review Process

1. Maintainers will review your PR
2. Address any feedback promptly
3. Once approved, a maintainer will merge
4. Do not force push to PR branches

### Merge Requirements

- All CI checks must pass
- At least one approval required
- No unresolved discussions

## Issue Reporting Guidelines

### Before Filing an Issue

- Search existing issues to avoid duplicates
- Verify the issue with latest version
- Check if it occurs on multiple platforms

### Filing an Issue

For **bugs**, include:
- OpenPass version (`openpass --version` or git commit)
- Go version (`go version`)
- Operating system and version
- Steps to reproduce
- Expected vs actual behavior
- Error messages or logs

For **feature requests**:
- Clear description of the feature
- Use case / motivation
- Potential alternatives considered
- Whether you're willing to implement (optional)

### Security Issues

For security vulnerabilities, **do not** file a public issue. Instead:

1. Submit a private vulnerability report via [GitHub Security Advisories](https://github.com/danieljustus/OpenPass/security/advisories/new)
2. Wait for acknowledgment
3. Coordinate disclosure timeline

See [SECURITY.md](SECURITY.md) for details.

## Code of Conduct

By participating, you agree to uphold our community standards:
- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards other community members

For full details, see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Getting Help

- **Issues**: Use [GitHub Issues](https://github.com/danieljustus/OpenPass/issues) for bugs, feature requests, and questions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
