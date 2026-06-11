<#
.SYNOPSIS
    Installs Symaira Vault from GitHub releases.

.DESCRIPTION
    Downloads the latest (or specified) Symaira Vault release from GitHub,
    verifies the SHA-256 checksum, and installs the binary.

.PARAMETER Version
    Specific version to install (default: latest).

.PARAMETER InstallDir
    Installation directory (default: $env:LOCALAPPDATA\Programs\symvault).

.PARAMETER DryRun
    Download and verify but do not install.

.EXAMPLE
    irm https://raw.githubusercontent.com/danieljustus/symaira-vault/main/scripts/install.ps1 | iex
    install.ps1 -Version 1.2.3
    install.ps1 -InstallDir C:\Tools
#>

[CmdletBinding()]
param(
    [string]$Version,
    [string]$InstallDir,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Constants ────────────────────────────────────────────────────────────────

$Repo        = 'danieljustus/symaira-vault'
$Binary      = 'symvault.exe'
$Project     = 'symvault'
$GitHubApi   = 'https://api.github.com'
$GitHubDl    = "https://github.com/$Repo/releases/download"
$CosignIdentityRegexp = 'https://github\.com/danieljustus/symaira-vault/\.github/workflows/release\.yml@refs/tags/v.*'
$CosignOIDCIssuer     = 'https://token.actions.githubusercontent.com'

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Info  { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor Blue }
function Write-Warn  { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err   { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

# ── Platform detection ───────────────────────────────────────────────────────

function Get-Architecture {
    $arch = if ([Environment]::Is64BitOperatingSystem) {
        if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
    } else {
        throw 'Symaira Vault requires a 64-bit operating system.'
    }
    return $arch
}

# ── Version resolution ───────────────────────────────────────────────────────

function Get-LatestVersion {
    Write-Info 'Fetching latest release version...'
    $url = "$GitHubApi/repos/$Repo/releases/latest"
    $headers = @{
        Accept        = 'application/json'
        'User-Agent'  = 'symvault-installer'
    }
    $response = Invoke-RestMethod -Uri $url -Headers $headers -UseBasicParsing
    if (-not $response.tag_name) {
        throw 'Could not determine latest release version.'
    }
    return $response.tag_name
}

# ── SHA-256 verification ─────────────────────────────────────────────────────

function Test-Checksum {
    param(
        [string]$FilePath,
        [string]$ChecksumsPath,
        [string]$FileName
    )

    $expected = (Get-Content $ChecksumsPath | Where-Object { $_ -match [regex]::Escape($FileName) } |
                 ForEach-Object { ($_ -split '\s+')[0] })
    if (-not $expected) {
        throw "Checksum for $FileName not found in checksums file."
    }

    $actual = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
    if ($expected.ToLower() -ne $actual) {
        throw "Checksum verification failed for $FileName.`n  Expected: $expected`n  Got:      $actual"
    }
    Write-Info "Checksum verified for $FileName."
}

# ── Cosign signature verification ────────────────────────────────────────────

function Test-CosignAvailable {
    $null -ne (Get-Command cosign -ErrorAction SilentlyContinue)
}

function Test-ChecksumsSignature {
    param(
        [string]$ChecksumsPath,
        [string]$ChecksumsSigUrl,
        [string]$ChecksumsPemUrl
    )

    if (-not (Test-CosignAvailable)) {
        Write-Warn 'cosign not found — skipping checksums.txt signature verification.'
        Write-Host ''
        Write-Host '  The checksums file has NOT been signature-verified. A tampered release' -ForegroundColor Yellow
        Write-Host '  asset could ship with matching tampered checksums.' -ForegroundColor Yellow
        Write-Host ''
        Write-Host '  To verify manually:' -ForegroundColor Yellow
        Write-Host "    cosign verify-blob --certificate <checksums.pem> --signature <checksums.sig> ``" -ForegroundColor Yellow
        Write-Host "      --certificate-identity-regexp '$CosignIdentityRegexp' ``" -ForegroundColor Yellow
        Write-Host "      --certificate-oidc-issuer '$CosignOIDCIssuer' ``" -ForegroundColor Yellow
        Write-Host "      checksums.txt" -ForegroundColor Yellow
        Write-Host ''
        Write-Host '  Install cosign: https://docs.sigstore.dev/cosign/installation/' -ForegroundColor Yellow
        return
    }

    $sigPath = "${ChecksumsPath}.sig"
    $pemPath = "${ChecksumsPath}.pem"

    Write-Info 'Downloading checksums signature...'
    Invoke-WebRequest -Uri $ChecksumsSigUrl -OutFile $sigPath -UseBasicParsing

    Write-Info 'Downloading checksums certificate...'
    Invoke-WebRequest -Uri $ChecksumsPemUrl -OutFile $pemPath -UseBasicParsing

    Write-Info 'Verifying cosign signature on checksums.txt...'
    $process = Start-Process -FilePath 'cosign' -ArgumentList @(
        'verify-blob',
        '--certificate', $pemPath,
        '--signature', $sigPath,
        '--certificate-identity-regexp', $CosignIdentityRegexp,
        '--certificate-oidc-issuer', $CosignOIDCIssuer,
        $ChecksumsPath
    ) -NoNewWindow -Wait -PassThru

    if ($process.ExitCode -ne 0) {
        throw @"
Cosign signature verification failed for checksums.txt.
  The checksums file may have been tampered with.
  See: https://docs.sigstore.dev/cosign/overview/
"@
    }

    Write-Info 'Cosign signature verified on checksums.txt.'
}

# ── Main ─────────────────────────────────────────────────────────────────────

function Install-SymairaVault {
    # Resolve version.
    if (-not $Version) {
        $resolvedVersion = Get-LatestVersion
    } else {
        $resolvedVersion = $Version
    }
    $versionNoV = $resolvedVersion -replace '^v', ''
    Write-Info "Installing Symaira Vault $resolvedVersion..."

    # Detect architecture.
    $arch = Get-Architecture
    Write-Info "Detected platform: windows/$arch"

    # Build download URLs.
    $archiveName = "${Project}_${versionNoV}_windows_${arch}"
    $archiveFile = "$archiveName.zip"
    $checksumsFile = "${Project}_${versionNoV}_checksums.txt"

    $archiveUrl = "$GitHubDl/$resolvedVersion/$archiveFile"
    $checksumsUrl = "$GitHubDl/$resolvedVersion/$checksumsFile"

    # Create temp workspace.
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "symvault-install-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    try {
        # Download checksums.
        Write-Info 'Downloading checksums...'
        $checksumsPath = Join-Path $tmpDir $checksumsFile
        Invoke-WebRequest -Uri $checksumsUrl -OutFile $checksumsPath -UseBasicParsing

        # Verify checksums signature with cosign.
        $checksumsSigUrl = "$GitHubDl/$resolvedVersion/${checksumsFile}.sig"
        $checksumsPemUrl = "$GitHubDl/$resolvedVersion/${checksumsFile}.pem"
        Test-ChecksumsSignature -ChecksumsPath $checksumsPath -ChecksumsSigUrl $checksumsSigUrl -ChecksumsPemUrl $checksumsPemUrl

        # Download archive.
        Write-Info "Downloading $archiveFile..."
        $archivePath = Join-Path $tmpDir $archiveFile
        Invoke-WebRequest -Uri $archiveUrl -OutFile $archivePath -UseBasicParsing

        # Verify checksum.
        Write-Info 'Verifying checksum...'
        Test-Checksum -FilePath $archivePath -ChecksumsPath $checksumsPath -FileName $archiveFile

        # Extract.
        Write-Info 'Extracting archive...'
        $extractDir = Join-Path $tmpDir 'extract'
        Expand-Archive -Path $archivePath -DestinationPath $extractDir -Force

        # Find binary.
        $binaryPath = Get-ChildItem -Path $extractDir -Recurse -Filter $Binary | Select-Object -First 1
        if (-not $binaryPath) {
            throw "Binary '$Binary' not found in archive."
        }

        if ($DryRun) {
            Write-Info "[DRY RUN] Would install $Binary to $InstallDir\$Binary"
            Write-Info '[DRY RUN] Binary verified successfully. Skipping installation.'
            return
        }

        # Install.
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        }
        Copy-Item -Path $binaryPath.FullName -Destination (Join-Path $InstallDir $Binary) -Force
        Write-Info "Symaira Vault $resolvedVersion installed to $InstallDir\$Binary"

        # PATH guidance.
        $currentPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if ($currentPath -notlike "*$InstallDir*") {
            Write-Warn "$InstallDir is not in your PATH."
            Write-Host ''
            Write-Host 'Add it to your PATH with:'
            Write-Host ''
            Write-Host "  [Environment]::SetEnvironmentVariable('Path', `"`$env:Path;$InstallDir`, 'User')"
            Write-Host ''
            Write-Host 'Then restart your terminal.'
        }

        # Verify installation.
        $installedVersion = & (Join-Path $InstallDir $Binary) version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Info "Installed version: $installedVersion"
        }

        Write-Info 'Done!'
    }
    finally {
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ── Entry point ──────────────────────────────────────────────────────────────

if (-not $InstallDir) {
    $InstallDir = if ($env:INSTALL_DIR) {
        $env:INSTALL_DIR
    } else {
        Join-Path $env:LOCALAPPDATA 'Programs\symvault'
    }
}

if (-not $DryRun -and $env:DRY_RUN -eq 'true') {
    $DryRun = $true
}

if (-not $Version -and $env:VERSION) {
    $Version = $env:VERSION
}

Install-SymairaVault
