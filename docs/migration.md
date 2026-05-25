# Migration Guide

Symaira Vault can import entries from other password managers and common export formats. Imports read the source export, convert supported fields to Symaira Vault entries, and write them into your configured vault.

Use `--dry-run` first to preview what would be imported before writing to the vault.

```bash
symvault import 1password export.1pux --dry-run
```

## 1Password

Export from 1Password as a 1PUX file:

1. Open the 1Password desktop app.
2. Select the account or vault you want to export.
3. Choose **File > Export**.
4. Select the **1Password Unencrypted Export (.1pux)** format.
5. Save the export file locally.

Import the 1PUX file into Symaira Vault:

```bash
symvault import 1password export.1pux
```

### Supported Fields

| 1Password Field | Symaira Vault Field |
|-----------------|----------------|
| title | title/path |
| username | username |
| password | password |
| URL | url |
| notes | notes |
| tags | tags |
| TOTP | otp |

### Limitations

- Only unencrypted 1Password exports are supported.

## Bitwarden

Export from Bitwarden as an unencrypted JSON file:

1. Open Bitwarden Web Vault or the desktop app.
2. Go to **Tools > Export vault**.
3. Choose **JSON** as the file format.
4. Select the unencrypted export option.
5. Save the export file locally.

Import the JSON file into Symaira Vault:

```bash
symvault import bitwarden export.json
```

### Supported Fields

| Bitwarden Field | Symaira Vault Field |
|-----------------|----------------|
| name | title/path |
| username | username |
| password | password |
| URIs | url |
| notes | notes |
| TOTP | otp |
| custom fields | custom fields |

### Limitations

- Only unencrypted Bitwarden exports are supported.

## pass (password-store)

Symaira Vault can import from a local `pass` password store.

### Prerequisites

- `gpg` must be installed and available in `PATH`.
- The password store must be readable by the current user.

Import a password store into Symaira Vault:

```bash
symvault import pass ~/.password-store
```

### Supported Fields

| pass Data | Symaira Vault Field |
|-----------|----------------|
| first line | password |
| url | url |
| username | username |
| otpauth URI | otp |

### Directory Structure

The password store directory structure is preserved when creating Symaira Vault entry paths. For example, `~/.password-store/work/github.gpg` imports under the `work/github` path.

## CSV

CSV imports expect a header row with named columns.

```csv
title,username,password,url,notes,otp
github,octocat,secret,https://github.com,Main GitHub account,otpauth://totp/...
```

Import a CSV file into Symaira Vault:

```bash
symvault import csv export.csv
```

### Default Columns

| CSV Column | Symaira Vault Field |
|------------|----------------|
| title | title/path |
| username | username |
| password | password |
| url | url |
| notes | notes |
| otp | otp |

### Custom Mapping

Use `--mapping` when your CSV headers use different names:

```bash
symvault import csv export.csv --mapping "title=path,username=user,password=pass"
```

The mapping format is a comma-separated list of `openpass_field=csv_column` pairs.

## Common Options

| Option | Description |
|--------|-------------|
| `--dry-run` | Preview entries without importing them |
| `--prefix` | Group imported entries under a path prefix |
| `--skip-existing` | Skip entries that already exist |
| `--overwrite` | Replace existing entries |

### Examples

Preview a Bitwarden import:

```bash
symvault import bitwarden export.json --dry-run
```

Import entries under a path prefix:

```bash
symvault import 1password export.1pux --prefix imported/1password
```

Skip existing entries:

```bash
symvault import csv export.csv --skip-existing
```

Replace existing entries:

```bash
symvault import pass ~/.password-store --overwrite
```

## Troubleshooting

### GPG Not Found for pass Import

The `pass` importer requires `gpg` to decrypt `.gpg` files. Install GPG and confirm it is available in `PATH`:

```bash
gpg --version
```

Then rerun the import:

```bash
symvault import pass ~/.password-store
```

### Invalid Mapping Format

CSV mappings must use comma-separated `openpass_field=csv_column` pairs:

```bash
symvault import csv export.csv --mapping "title=path,username=user,password=pass"
```

Check for missing `=` separators, extra commas, or column names that do not exist in the CSV header row.

### Missing Fields in Export

If imported entries are missing usernames, URLs, notes, or OTP values, verify that the source export contains those fields and that the importer supports them for that format.

For CSV imports, confirm the header row uses the default column names or provide a custom mapping:

```bash
symvault import csv export.csv --mapping "title=entry,username=login,password=secret,url=website,notes=comment,otp=totp"
```
