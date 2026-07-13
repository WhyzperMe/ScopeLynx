[CmdletBinding()]
param(
    [switch]$InstallOptionalTools,
    [switch]$IncludeReleaseTests,
    [switch]$SkipOptionalAudits
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $true
}

$RepositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

function Invoke-Gate {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )

    Write-Host "`n==> $Name"
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "Quality gate '$Name' failed with exit code $LASTEXITCODE."
    }
    Write-Host "PASS: $Name"
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error 'Cargo was not found. Install Rust through rustup first.'
    exit 2
}

Push-Location -LiteralPath $RepositoryRoot
try {
    Invoke-Gate 'Toolchain' { rustc --version; cargo --version; rustup show active-toolchain }
    Invoke-Gate 'Locked dependency metadata' { cargo metadata --locked --format-version 1 | Out-Null }
    Invoke-Gate 'Rustfmt' { cargo fmt --all -- --check }
    Invoke-Gate 'Clippy' { cargo clippy --workspace --all-targets --all-features -- -D warnings }
    Invoke-Gate 'Tests' { cargo test --workspace --all-targets --all-features }
    Invoke-Gate 'Documentation tests' { cargo test --workspace --doc --all-features }

    if ($IncludeReleaseTests) {
        Invoke-Gate 'Release tests' { cargo test --workspace --release --all-features }
    }

    Invoke-Gate 'Release build' { cargo build --workspace --release --all-features }

    if (-not $SkipOptionalAudits) {
        if ($InstallOptionalTools) {
            if (-not (Get-Command cargo-audit -ErrorAction SilentlyContinue)) {
                Invoke-Gate 'Install cargo-audit' { cargo install cargo-audit --locked }
            }
            if (-not (Get-Command cargo-deny -ErrorAction SilentlyContinue)) {
                Invoke-Gate 'Install cargo-deny' { cargo install cargo-deny --locked }
            }
        }

        if (Get-Command cargo-audit -ErrorAction SilentlyContinue) {
            Invoke-Gate 'Cargo audit' { cargo audit }
        } else {
            Write-Warning 'SKIPPED: cargo audit (cargo-audit is not installed).'
        }

        if (Get-Command cargo-deny -ErrorAction SilentlyContinue) {
            Invoke-Gate 'Cargo deny' { cargo deny check }
        } else {
            Write-Warning 'SKIPPED: cargo deny check (cargo-deny is not installed).'
        }
    }

    Write-Host "`nAll mandatory quality gates passed."
}
finally {
    Pop-Location
}
