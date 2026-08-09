<#
.SYNOPSIS
    Audit one or more repositories locally.

.DESCRIPTION
    Installs Trivy if it is missing, then runs watch/audit.py against each path
    and leaves a Markdown report next to its JSON in out/. Nothing is committed
    and nothing is pushed: the output describes a real dependency tree, so where
    it goes is your call.

    Same audit as CI, minus the deduplication and the issue. Hand the JSON to an
    agent afterwards if you want the summary -- see docs/claude-routine.md.

    Base images declared in a Dockerfile are pulled from their registry and
    scanned too. -NoImages skips that when bandwidth or disk is short.

.EXAMPLE
    .\scan.ps1 ..\some-project
    .\scan.ps1 ..\front, ..\api -OutDir ~\audits
    .\scan.ps1 . -Name "Safari-digital/safaridigital.fr" -NoDotnet -NoImages
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Repo = @("."),
    [string]$Name,
    [string]$OutDir,
    [switch]$NoDotnet,
    [switch]$NoImages,
    [int]$Timeout
)

$ErrorActionPreference = "Stop"
$RootDir = $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $RootDir "out" }

function Step($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }

if ($Name -and $Repo.Count -gt 1) { throw "-Name ne vaut que pour un seul depot." }

$python = (Get-Command python -ErrorAction SilentlyContinue)?.Source
if (-not $python) { $python = (Get-Command py -ErrorAction SilentlyContinue)?.Source }
if (-not $python) { throw "Python introuvable. winget install Python.Python.3.12" }

Step "Verification de Trivy"
$trivy = (Get-Command trivy -ErrorAction SilentlyContinue)?.Source
if (-not $trivy) {
    Warn "Trivy absent, installation via winget (Apache 2.0, gratuit)"
    winget install --id AquaSecurity.Trivy --exact `
        --accept-source-agreements --accept-package-agreements --disable-interactivity
    # winget updates PATH for the next session only; reload it here.
    $env:PATH = [Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                [Environment]::GetEnvironmentVariable("PATH", "User")
    $trivy = (Get-Command trivy -ErrorAction SilentlyContinue)?.Source
    if (-not $trivy) { throw "Trivy installe mais absent du PATH. Rouvre ton terminal et relance." }
}
Ok "Trivy : $trivy"

New-Item -ItemType Directory -Force $OutDir | Out-Null
$date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd")
$failed = 0

foreach ($path in $Repo) {
    if (-not (Test-Path $path -PathType Container)) {
        Warn "$path n'est pas un repertoire — ignore"
        $failed = 1
        continue
    }
    $label = if ($Name) { $Name } else { (Resolve-Path $path).Path.TrimEnd('\').Split('\')[-1] }
    # Slashes in an org/repo name would open a directory that is not wanted.
    $slug = ($label -replace '[/\s]', '-') -replace '[^\w.\-]', ''

    Step "Audit de $label"
    $auditArgs = @(
        (Join-Path $RootDir "watch\audit.py")
        "--repo", $path
        "--out-md", (Join-Path $OutDir "$slug-$date.md")
        "--out-json", (Join-Path $OutDir "$slug-$date.findings.json")
    )
    if ($Name)     { $auditArgs += @("--name", $Name) }
    if ($NoDotnet) { $auditArgs += "--no-dotnet" }
    if ($NoImages) { $auditArgs += "--no-images" }
    if ($Timeout)  { $auditArgs += @("--timeout", $Timeout) }

    & $python @auditArgs
    if ($LASTEXITCODE -ne 0) {
        Warn "$label : code $LASTEXITCODE"
        $failed = 1
    }
}

Write-Host ""
if ($failed -eq 0) { Ok "Rapports dans $OutDir" }
else { Warn "Termine avec des erreurs — relis les avertissements ci-dessus." }
exit $failed
