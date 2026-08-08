<#
.SYNOPSIS
    Updates this machine's snapshot in security-watch. Manual action.

.DESCRIPTION
    Syncs the repo, ensures Trivy is installed, scans repositories and installed
    software, writes snapshots/<machine>.json, then commits and pushes.

    Re-run when dependencies moved or after a system update. Not needed daily:
    the watch reads the snapshot and flags it once it goes stale.

.EXAMPLE
    .\scan.ps1
    .\scan.ps1 -Machine laptop -Role "dev laptop"
    .\scan.ps1 -NoPush
#>

[CmdletBinding()]
param(
    [string]$Machine,
    [string]$Role,
    [switch]$NoPush
)

$ErrorActionPreference = "Stop"
$RootDir = $PSScriptRoot
$AgentDir = Join-Path $RootDir "agent"

function Step($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }

$python = (Get-Command python -ErrorAction SilentlyContinue)?.Source
if (-not $python) { $python = (Get-Command py -ErrorAction SilentlyContinue)?.Source }
if (-not $python) { throw "Python introuvable. winget install Python.Python.3.12" }

# Pull other machines' snapshots first so the final push does not conflict.
Step "Synchronisation du depot"
git -C $RootDir pull --rebase --autostash 2>&1 | Out-String | Write-Verbose
if ($LASTEXITCODE -ne 0) {
    Warn "git pull a echoue — on continue, le push pourra necessiter une resolution manuelle"
}

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

$configPath = Join-Path $AgentDir "config.json"
if (-not (Test-Path $configPath)) {
    Copy-Item (Join-Path $AgentDir "config.example.json") $configPath
    Ok "config.json cree depuis l'exemple"
    Warn "Renseigne machine.label pour distinguer ce poste des autres"
}

Step "Scan en cours (quelques minutes au premier passage)"
$agentArgs = @((Join-Path $AgentDir "agent.py"))
if ($Machine) { $agentArgs += @("--machine", $Machine) }
if ($Role)    { $agentArgs += @("--role", $Role) }
if (-not $NoPush) { $agentArgs += "--push" }

& $python @agentArgs
$code = $LASTEXITCODE

Write-Host ""
if ($code -eq 0) {
    Ok "Snapshot a jour. La veille quotidienne s'appuiera dessus."
} else {
    Warn "Le scan s'est termine avec le code $code — relis les avertissements ci-dessus."
}
exit $code
