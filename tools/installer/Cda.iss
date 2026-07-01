; ============================================================================
;  CDA - Modern  -  Inno Setup installer script
;
;  Builds a self-contained x64 installer for the CDA dynamic-analysis tool.
;  The app is published self-contained (the .NET 8 runtime is bundled), so the
;  target machine needs nothing pre-installed.
;
;  Build steps (or run tools\build-installer.ps1 which does both):
;    1) dotnet publish Cda.App\Cda.App.csproj -c Release -p:Platform=x64 ^
;         -r win-x64 --self-contained true -o tools\installer\publish-x64
;    2) "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" tools\installer\Cda.iss
;
;  Output: tools\installer\Output\CDA-Setup-<version>-x64.exe
; ============================================================================

#define AppName        "CDA"
#define AppFullName     "CDA - Modern"
#define AppVersion      "1.7.0"
#define AppPublisher    "CDA"
#define AppExeName      "Cda.App.exe"
#define PublishDir      "publish-x64"

[Setup]
; A stable, unique AppId keeps upgrades/uninstalls coherent across versions.
; Do NOT change this GUID between releases of the same product.
AppId={{A7F3C2E1-9B4D-4E8A-B6C1-2D5F8E0A3C71}
AppName={#AppFullName}
AppVersion={#AppVersion}
AppVerName={#AppFullName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppFullName}

; Install per-machine into Program Files. The app instruments other processes
; and ships with a requireAdministrator manifest, so an elevated, per-machine
; install matches how it actually runs.
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppFullName}
PrivilegesRequired=admin
UninstallDisplayName={#AppFullName}
UninstallDisplayIcon={app}\{#AppExeName}

; This payload is x64-only (the universal host: it instruments both x64 and
; 32-bit WOW64 targets). Refuse to install on non-x64 Windows.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; The bundled .NET runtime needs Windows 10 (1607 / build 10.0.14393) or later.
MinVersion=10.0.14393

LicenseFile=..\..\LICENSE.txt
SetupIconFile=..\..\Cda.App\app.ico
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
OutputDir=Output
OutputBaseFilename=CDA-Setup-{#AppVersion}-x64
DisableProgramGroupPage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Ship the entire self-contained publish output (exe + .NET runtime + Iced +
; the generated runtimeconfig/deps). recursesubdirs picks up the runtimes\
; and any locale folders the publish produced.
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppFullName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\{cm:UninstallProgram,{#AppFullName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppFullName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
; Offer to launch right after install. The app self-elevates via its manifest,
; so it will raise its own UAC prompt; runasoriginaluser avoids a double prompt
; from the (already elevated) installer.
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppFullName}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallDelete]
; The app writes a diagnostic log and reads optional skip/range files next to
; its exe at runtime; remove them on uninstall so {app} is left clean.
Type: files; Name: "{app}\cda-error.log"
Type: files; Name: "{app}\cda_hook_skip.txt"
Type: files; Name: "{app}\cda_hook_range.txt"
