#Requires -Module Pester

BeforeAll {
    # Dot-source the installer to load function definitions.
    # We suppress the entry point execution by temporarily overriding Install-SymairaVault.
    $scriptPath = Join-Path $PSScriptRoot 'install.ps1'

    # Read the script content and extract only function definitions (skip entry point).
    $content = Get-Content $scriptPath -Raw

    # Remove the entry point block at the bottom that calls Install-SymairaVault.
    $content = $content -replace '(?s)# ── Entry point ─.*$', ''

    # Remove the call to Install-SymairaVault if it exists standalone.
    $content = $content -replace '(?m)^Install-SymairaVault\s*$', ''

    # Execute the modified content to define functions.
    Invoke-Expression $content
}

Describe 'Test-ChecksumsSignature' {

    Context 'when cosign is NOT available' {

        BeforeEach {
            # Mock cosign as unavailable.
            Mock Test-CosignAvailable { return $false }
        }

        It 'should throw an error when SkipCosignVerification is false' {
            { Test-ChecksumsSignature -ChecksumsPath 'dummy checksums.txt' -ChecksumsSigUrl 'https://example.com/sig' -ChecksumsPemUrl 'https://example.com/pem' } |
                Should -Throw -ExpectedMessage '*cosign is required but was not found*'
        }

        It 'should throw an error when SkipCosignVerification is not specified (default)' {
            { Test-ChecksumsSignature -ChecksumsPath 'dummy checksums.txt' -ChecksumsSigUrl 'https://example.com/sig' -ChecksumsPemUrl 'https://example.com/pem' } |
                Should -Throw -ExpectedMessage '*cosign is required but was not found*'
        }

        It 'should succeed with a warning when SkipCosignVerification is true' {
            Mock Write-Host { }

            { Test-ChecksumsSignature -ChecksumsPath 'dummy checksums.txt' -ChecksumsSigUrl 'https://example.com/sig' -ChecksumsPemUrl 'https://example.com/pem' -SkipCosignVerification } |
                Should -Not -Throw
        }

        It 'should warn about unauthenticated checksums when SkipCosignVerification is true' {
            $warnings = @()
            Mock Write-Host { param($Object, $ForegroundColor) if ($ForegroundColor -eq [ConsoleColor]::Yellow) { $warnings += $Object } }

            Test-ChecksumsSignature -ChecksumsPath 'dummy checksums.txt' -ChecksumsSigUrl 'https://example.com/sig' -ChecksumsPemUrl 'https://example.com/pem' -SkipCosignVerification

            $warnings | Should -Contain '  WARNING: You are installing with -SkipCosignVerification.'
        }
    }

    Context 'when cosign IS available' {

        BeforeEach {
            Mock Test-CosignAvailable { return $true }
            Mock Invoke-WebRequest { }
            Mock Start-Process { return [PSCustomObject]@{ ExitCode = 0 } }
        }

        It 'should proceed with verification without throwing' {
            { Test-ChecksumsSignature -ChecksumsPath 'dummy checksums.txt' -ChecksumsSigUrl 'https://example.com/sig' -ChecksumsPemUrl 'https://example.com/pem' } |
                Should -Not -Throw
        }

        It 'should download the signature file' {
            Test-ChecksumsSignature -ChecksumsPath 'dummy checksums.txt' -ChecksumsSigUrl 'https://example.com/sig' -ChecksumsPemUrl 'https://example.com/pem'

            Should -Invoke Invoke-WebRequest -Times 1 -ParameterFilter {
                $Uri -eq 'https://example.com/sig'
            }
        }

        It 'should download the certificate file' {
            Test-ChecksumsSignature -ChecksumsPath 'dummy checksums.txt' -ChecksumsSigUrl 'https://example.com/sig' -ChecksumsPemUrl 'https://example.com/pem'

            Should -Invoke Invoke-WebRequest -Times 1 -ParameterFilter {
                $Uri -eq 'https://example.com/pem'
            }
        }

        It 'should invoke cosign verify-blob' {
            Test-ChecksumsSignature -ChecksumsPath 'dummy checksums.txt' -ChecksumsSigUrl 'https://example.com/sig' -ChecksumsPemUrl 'https://example.com/pem'

            Should -Invoke Start-Process -Times 1 -ParameterFilter {
                $FilePath -eq 'cosign' -and
                ($ArgumentList -join ' ') -match 'verify-blob'
            }
        }
    }

    Context 'when cosign verification fails' {

        BeforeEach {
            Mock Test-CosignAvailable { return $true }
            Mock Invoke-WebRequest { }
            Mock Start-Process { return [PSCustomObject]@{ ExitCode = 1 } }
        }

        It 'should throw when cosign exits with non-zero code' {
            { Test-ChecksumsSignature -ChecksumsPath 'dummy checksums.txt' -ChecksumsSigUrl 'https://example.com/sig' -ChecksumsPemUrl 'https://example.com/pem' } |
                Should -Throw -ExpectedMessage '*Cosign signature verification failed*'
        }
    }
}
