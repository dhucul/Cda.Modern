# Builds the CDA release installers end-to-end for BOTH x64 and x86:
#   for each arch:
#     1) publishes Cda.App self-contained (win-<arch>) into tools\installer\publish-<arch>
#     2) compiles tools\installer\Cda.iss (ISCC /DArch=<arch>) into tools\installer\Output
#
# Produces: tools\installer\Output\CDA-Setup-<version>-x64.exe
#           tools\installer\Output\CDA-Setup-<version>-x86.exe
#
# The x64 build is the universal host for 64-bit (and WOW64) targets; the x86
# build is for instrumenting 32-bit .NET targets (ClrMD managed discovery is
# bitness-locked to the host). They install to separate locations and can coexist.
#
# Usage:  pwsh tools\build-installer.ps1                 (Release, both arches)
#         pwsh tools\build-installer.ps1 -Arch x64       (just one)
#         pwsh tools\build-installer.ps1 -Clean          (wipe publish dirs first)

[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [ValidateSet('x64', 'x86', 'both')]
    [string]$Arch = 'both',
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$repoRoot   = Split-Path -Parent $PSScriptRoot
$appProj    = Join-Path $repoRoot 'Cda.App\Cda.App.csproj'
$installDir = Join-Path $PSScriptRoot 'installer'
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

$arches = if ($Arch -eq 'both') { @('x64', 'x86') } else { @($Arch) }

foreach ($a in $arches) {
    $publishDir = Join-Path $installDir "publish-$a"

    # Always wipe the publish dir first. A non-clean publish can leave a STALE
    # assembly behind that dotnet publish doesn't overwrite — e.g. an old .NET 8
    # runtime System.Reflection.Metadata.dll (8.0.x) surviving over the required
    # package version (9.0.x from ICSharpCode.Decompiler), which then throws
    # FileNotFoundException at startup. A release installer must ship only freshly
    # resolved binaries, so cleaning is unconditional (the -Clean switch is kept
    # for back-compat but no longer needed).
    if (Test-Path $publishDir) {
        Write-Host "Cleaning $publishDir ..." -ForegroundColor Cyan
        Remove-Item $publishDir -Recurse -Force
    }

    Write-Host "Publishing self-contained $a ($Configuration) ..." -ForegroundColor Cyan
    dotnet publish $appProj -c $Configuration -p:Platform=$a -r "win-$a" `
        --self-contained true -p:PublishSingleFile=false -o $publishDir --nologo
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish ($a) failed (exit $LASTEXITCODE)" }

    Write-Host "Compiling $a installer with $iscc ..." -ForegroundColor Cyan
    & $iscc "/DArch=$a" $issFile
    if ($LASTEXITCODE -ne 0) { throw "ISCC ($a) failed (exit $LASTEXITCODE)" }
}

Write-Host ""
Get-ChildItem (Join-Path $installDir 'Output') -Filter 'CDA-Setup-*.exe' |
    Sort-Object LastWriteTime -Descending |
    ForEach-Object { Write-Host ("Installer: {0} ({1:N1} MB)" -f $_.Name, ($_.Length / 1MB)) -ForegroundColor Green }
