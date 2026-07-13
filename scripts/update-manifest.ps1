[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RepositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$ManifestPath = Join-Path $RepositoryRoot 'MANIFEST.sha256'
$ExcludedDirectories = @('.git', '.idea', '.vscode', 'output', 'target')

$Files = Get-ChildItem -LiteralPath $RepositoryRoot -Recurse -File -Force |
    Where-Object {
        $Relative = $_.FullName.Substring($RepositoryRoot.Length + 1)
        $Segments = $Relative -split '[\\/]'
        $_.FullName -ne $ManifestPath -and
        -not ($Segments | Where-Object { $_ -in $ExcludedDirectories }) -and
        $_.Extension -notin @('.log', '.tmp')
    } |
    ForEach-Object {
        $Relative = $_.FullName.Substring($RepositoryRoot.Length + 1).Replace('\', '/')
        [PSCustomObject]@{
            Path = $Relative
            Hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    } |
    Sort-Object -Property Path -CaseSensitive

$Lines = $Files | ForEach-Object { '{0}  {1}' -f $_.Hash, $_.Path }
Set-Content -LiteralPath $ManifestPath -Value $Lines -Encoding utf8NoBOM
Write-Host "Wrote $($Files.Count) entries to $ManifestPath"
