# Contributing to Symaira Vault

Thank you for your interest in contributing to Symaira Vault! This document provides guidelines and instructions for contributing.

## License and Commercial Boundary

Contributions to this public repository are made under the Apache-2.0 License used by
Symaira Vault self-hosted. The self-hosted product must remain buildable,
testable, and runnable without any private commercial code.

Symaira Vault ships as one self-hosted product, with no separate Pro edition or
private counterpart repository. Hosted-account, billing and tenant-management
code are out of scope. See [the commercial boundary](docs/commercial-boundary.md).

## Development Setup

### Quick Setup (Recommended)

Use the automated setup script to install all required tools:

```bash
git clone https://github.com/danieljustus/symaira-vault
cd symaira-vault
./scripts/setup-dev.sh
```

The script is idempotent and safe to run multiple times. Use `./scripts/setup-dev.sh --check` to verify your environment without installing anything.

### Manual Setup

If you prefer manual setup, ensure you have:

- **Rust/Cargo:** the toolchain pinned in `rust-toolchain.toml` (installed automatically by `rustup`), with `clippy` and `rustfmt`
- **cargo-nextest**, **cargo-deny**, **cargo-audit**: `cargo install --locked cargo-nextest cargo-deny cargo-audit` (see `scripts/setup-dev.sh` for the pinned versions)
- **Python 3:** the contract and CI helper scripts under `scripts/` are Python
- **git**
- **make**
- **pre-commit** (optional but recommended): `pip install pre-commit` or `brew install pre-commit`

No Go toolchain is needed: the project is Rust-only, and the differential tests
replay committed observations of the original Go implementation.

### Clone and Build

```bash
git clone https://github.com/danieljustus/symaira-vault
cd symaira-vault
make rust-cli        # cargo build --release --locked -p symvault-cli --bin symvault
```

The binary is written to `target/release/symvault`.

### Pre-commit Hooks

After running the setup script (or installing pre-commit manually):

```bash
pre-commit install
```

This installs git hooks that run `cargo fmt --check` and `make rust-lint` (rustfmt and Clippy with `-D warnings`) on Rust changes before each commit, catching issues locally before they reach CI.

### Test Workflow

| Command | Purpose | What it runs |
|---------|---------|-------------|
| `make rust-lint` | Pre-commit, before pushing | `cargo fmt --all --check` and `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` |
| `make rust-test` | Local iteration, CI gate | `cargo nextest run --workspace --all-features --locked` plus doctests |
| `make rust-security` | Dependency audit | `cargo audit` and `cargo deny` |

Use `cargo test -p <crate>` or `cargo nextest run -p <crate> <filter>` for fast feedback on one crate. See `.github/workflows/ci.yml` for the exact CI invocations.

### Running from Source

```bash
target/release/symvault --help
# or, without a release build:
cargo run -p symvault-cli --bin symvault -- --help
```

### Project Structure

```
symaira-vault/
├── Cargo.toml            # Workspace manifest (Cargo.lock is committed)
├── crates/
│   ├── symvault-cli/     # CLI binary (`symvault`)
│   ├── symvault-core/    # Config, policy and shared types
│   ├── symvault-crypto/  # age encryption and KDF
│   ├── symvault-store/   # Vault storage, audit log
│   ├── symvault-sync/    # Git sync and intake
│   ├── symvault-mcp/     # MCP server (stdio and HTTP)
│   ├── symvault-platform/# OS keyring and platform glue
│   ├── symvault-ffi/     # SymvaultFFI for the Swift clients
│   └── symvault-gojson/  # Go-compatible JSON encoding
├── client/               # SwiftUI macOS/iOS client
├── editors/              # Editor integrations
├── scripts/              # Build, packaging and CI helpers
└── testdata/             # Committed fixtures and recorded observations
```

## Code Style Guidelines

### EditorConfig

Symaira Vault uses [EditorConfig](https://editorconfig.org) to maintain consistent formatting across editors. The `.editorconfig` file in the repository root defines the rules:

- **Rust files** (`*.rs`): 4-space indentation, owned by `rustfmt`
- **YAML files** (`*.yaml`, `*.yml`): 2-space indentation
- **Markdown files** (`*.md`): trailing whitespace preserved (for line breaks), max line length 80
- **JSON files** (`*.json`): 2-space indentation
- **Shell scripts** (`*.sh`): 2-space indentation

Most editors support EditorConfig natively or via plugin. See [editorconfig.org](https://editorconfig.org) for setup instructions.

### Rust Standards

- Format with `cargo fmt --all` (enforced via `make rust-lint`)
- Clippy must be clean with `-D warnings` on all targets and features
- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Prefer typed errors (`thiserror`) in library crates and propagate with `?`; keep the underlying error as `source()` instead of formatting it into a new string
- Library crates must not print: return errors to the caller

### Naming Conventions

- **Files and modules**: `snake_case` (`vault.rs`, `age_crypto.rs`)
- **Types and traits**: `PascalCase`; **functions and variables**: `snake_case`
- **Constants**: `SCREAMING_SNAKE_CASE`

### Output Streams

Symaira Vault follows standard Unix conventions for output streams:

- **stdout**: Normal output, data, success messages
- **stderr**: Errors, warnings, interactive prompts

This allows users to pipe normal output to other commands while still seeing errors.

```bash
symvault list | grep work        # Filter list output
symvault get pass 2>/dev/null   # Hide errors
```

### Comments

- Document public items with `///` doc comments
- Keep comments concise but informative

## Testing Requirements

### Running Tests

```bash
# Run the whole workspace (nextest + doctests)
make rust-test

# Run one crate, or one test
cargo test -p symvault-store
cargo test -p symvault-store -- <test name filter>
```

### Test Coverage

```bash
make rust-coverage
```

### Code Quality Checks

```bash
# Format check + Clippy (-D warnings)
make rust-lint

# Dependency audit (cargo audit + cargo deny)
make rust-security
```

### Writing Tests

- Unit tests live next to the code (`#[cfg(test)] mod tests`); integration tests in each crate's `tests/` directory
- Use descriptive test names: `open_with_valid_identity_succeeds`
- Use table-driven tests for multiple scenarios
- Ensure tests clean up after themselves (use `tempfile`); never touch the real keyring or home directory
- Differential tests compare against committed observations of the original Go implementation (`testdata/port/`); they run without a Go toolchain

## Commit Message Format

Symaira Vault uses a structured commit format based on [Conventional Commits](https://www.conventionalcommits.org/):

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
   make rust-lint
   make rust-test
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
- Maintainer review; `main` currently requires zero GitHub approving reviews for the solo-maintained repository (GitHub does not count the author's own review)
- No unresolved discussions

## Issue Reporting Guidelines

### Before Filing an Issue

- Search existing issues to avoid duplicates
- Verify the issue with latest version
- Check if it occurs on multiple platforms

### Filing an Issue

For **bugs**, include:
- Symaira Vault version (`symvault --version` or git commit)
- Rust version (`rustc --version`) if you built from source
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

1. Submit a private vulnerability report via [GitHub Security Advisories](https://github.com/danieljustus/symaira-vault/security/advisories/new)
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

- **Issues**: Use [GitHub Issues](https://github.com/danieljustus/symaira-vault/issues) for bugs, feature requests, and questions

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.
