# Builds the CDA release installer end-to-end:
#   1) publishes Cda.App self-contained for win-x64 into tools\installer\publish-x64
#   2) compiles tools\installer\Cda.iss with Inno Setup into tools\installer\Output
#
# Produces: tools\installer\Output\CDA-Setup-<version>-x64.exe
#
# Usage:  pwsh tools\build-installer.ps1            (Release, x64)
#         pwsh tools\build-installer.ps1 -Clean     (wipe publish dir first)

[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$repoRoot   = Split-Path -Parent $PSScriptRoot
$appProj    = Join-Path $repoRoot 'Cda.App\Cda.App.csproj'
$installDir = Join-Path $PSScriptRoot 'installer'
$publishDir = Join-Path $installDir 'publish-x64'
$issFile    = Join-Path $installDir 'Cda.iss'

# Locate the Inno Setup command-line compiler.
$isccCandidates = @(
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
    'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
    'C:\Program Files\Inno Setup 6\ISCC.exe'
)
$iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    throw "ISCC.exe (Inno Setup 6) not found. Install it: winget install --id JRSoftware.InnoSetup -e"
}

if ($Clean -and (Test-Path $publishDir)) {
    Write-Host "Cleaning $publishDir ..." -ForegroundColor Cyan
    Remove-Item $publishDir -Recurse -Force
}

Write-Host "Publishing self-contained x64 ($Configuration) ..." -ForegroundColor Cyan
dotnet publish $appProj -c $Configuration -p:Platform=x64 -r win-x64 `
    --self-contained true -p:PublishSingleFile=false -o $publishDir --nologo
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed (exit $LASTEXITCODE)" }

Write-Host "Compiling installer with $iscc ..." -ForegroundColor Cyan
& $iscc $issFile
if ($LASTEXITCODE -ne 0) { throw "ISCC failed (exit $LASTEXITCODE)" }

$out = Get-ChildItem (Join-Path $installDir 'Output') -Filter '*.exe' |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($out) {
    Write-Host ("`nInstaller built: {0} ({1:N1} MB)" -f $out.FullName, ($out.Length/1MB)) -ForegroundColor Green
}
