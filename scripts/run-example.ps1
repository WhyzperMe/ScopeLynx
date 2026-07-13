param(
    [Parameter(Mandatory = $true)]
    [string]$Target,

    [string]$Profile = "profiles/safe.toml",

    [string]$Wordlist = ""
)

$ErrorActionPreference = "Stop"

$RepositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Push-Location -LiteralPath $RepositoryRoot
try {

    $CargoArguments = @(
        'run', '--release', '--', 'scan', $Target,
        '--profile', $Profile,
        '--output', 'output'
    )
    if (-not [string]::IsNullOrWhiteSpace($Wordlist)) {
        $CargoArguments += @('--wordlist', $Wordlist)
    }
    & cargo @CargoArguments
}
finally {
    Pop-Location
}
