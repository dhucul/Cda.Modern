# Builds the x64 CDA release installer end-to-end:
#   1) publishes Cda.App self-contained (win-x64) into tools\installer\publish-x64
#   2) compiles tools\installer\Cda.iss into tools\installer\Output
#
# Produces: tools\installer\Output\CDA-Setup-<version>-x64.exe
#
# The x64 build is the universal host for native x64 and WOW64 x86 targets.
# ClrMD cannot discover managed methods in a 32-bit .NET target cross-bitness;
# that one managed-only feature is intentionally unavailable.
#
# Usage: pwsh tools\build-installer.ps1

[CmdletBinding()]
param(
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'

$repoRoot   = Split-Path -Parent $PSScriptRoot
$appProj    = Join-Path $repoRoot 'Cda.App\Cda.App.csproj'
$installDir = Join-Path $PSScriptRoot 'installer'
$issFile    = Join-Path $installDir 'Cda.iss'
$publishDir = Join-Path $installDir 'publish-x64'
$outputDir  = Join-Path $installDir 'Output'

$isccCandidates = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
    'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
    'C:\Program Files\Inno Setup 6\ISCC.exe'
)
$iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    throw 'ISCC.exe (Inno Setup 6) not found. Install it: winget install --id JRSoftware.InnoSetup -e'
}

# A clean publish prevents stale runtime/package assemblies from surviving from
# an earlier release and being bundled into the installer.
if (Test-Path $publishDir) {
    Write-Host "Cleaning $publishDir ..." -ForegroundColor Cyan
    Remove-Item $publishDir -Recurse -Force
}

# This repository now ships one universal x64 host. Remove installers left by
# the retired x86 packaging path so they cannot be mistaken for current output.
if (Test-Path $outputDir) {
    Get-ChildItem -LiteralPath $outputDir -Filter 'CDA-Setup-*-x86.exe' -File |
        Remove-Item -Force
}

Write-Host "Publishing self-contained x64 ($Configuration) ..." -ForegroundColor Cyan
dotnet publish $appProj -c $Configuration -p:Platform=x64 -r win-x64 `
    --self-contained true -p:PublishSingleFile=false -o $publishDir --nologo
if ($LASTEXITCODE -ne 0) { throw "dotnet publish (x64) failed (exit $LASTEXITCODE)" }

Write-Host "Compiling x64 installer with $iscc ..." -ForegroundColor Cyan
& $iscc $issFile
if ($LASTEXITCODE -ne 0) { throw "ISCC (x64) failed (exit $LASTEXITCODE)" }

Write-Host ''
Get-ChildItem $outputDir -Filter 'CDA-Setup-*-x64.exe' |
    Sort-Object LastWriteTime -Descending |
    ForEach-Object { Write-Host ("Installer: {0} ({1:N1} MB)" -f $_.Name, ($_.Length / 1MB)) -ForegroundColor Green }
