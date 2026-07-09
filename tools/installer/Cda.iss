; ============================================================================
;  CDA - Modern  -  Inno Setup installer script (x64 and x86)
;
;  Builds a self-contained installer for the CDA dynamic-analysis tool. The app
;  is published self-contained (the .NET 8 runtime is bundled), so the target
;  machine needs nothing pre-installed.
;
;  Architecture is selected with the ISPP define "Arch" (x64 | x86), default x64:
;    ISCC.exe /DArch=x64 Cda.iss      -> publish-x64  -> CDA-Setup-<ver>-x64.exe
;    ISCC.exe /DArch=x86 Cda.iss      -> publish-x86  -> CDA-Setup-<ver>-x86.exe
;  The x64 and x86 builds have distinct AppIds and install locations, so both can
;  be installed at once (x64 CDA for 64-bit targets, x86 CDA for 32-bit targets).
;
;  Build both with tools\build-installer.ps1 (publishes both, compiles both).
;  Output: tools\installer\Output\CDA-Setup-<version>-<arch>.exe
; ============================================================================

#ifndef Arch
  #define Arch "x64"
#endif

#define AppVersion   "1.9.0"
#define AppExeName   "Cda.App.exe"
#define AppPublisher "CDA"
#define PublishDir   "publish-" + Arch

; Arch-specific name so the two builds are distinct in Add/Remove Programs.
#if Arch == "x64"
  #define AppFullName "CDA - Modern"
#else
  #define AppFullName "CDA - Modern (x86)"
#endif

[Setup]
; A stable, unique AppId keeps upgrades/uninstalls coherent across versions, and
; the x64/x86 builds use DISTINCT AppIds so both can be installed at once. Written
; literally (Inno's {{GUID} escaped-brace form) rather than via a define, to avoid
; the preprocessor colliding with Inno's brace escaping. Do NOT change per release.
#if Arch == "x64"
AppId={{A7F3C2E1-9B4D-4E8A-B6C1-2D5F8E0A3C71}
#else
AppId={{B8E4D3F2-A05E-4F9B-C7D2-3E6A9F1B4D82}
#endif
AppName={#AppFullName}
AppVersion={#AppVersion}
AppVerName={#AppFullName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppFullName}

; Install per-machine into Program Files. The app instruments other processes
; and ships with a requireAdministrator manifest, so an elevated, per-machine
; install matches how it actually runs. On 64-bit Windows the x64 build lands in
; Program Files and the x86 build in Program Files (x86), so they don't collide.
DefaultDirName={autopf}\{#AppFullName}
DefaultGroupName={#AppFullName}
PrivilegesRequired=admin
UninstallDisplayName={#AppFullName}
UninstallDisplayIcon={app}\{#AppExeName}

#if Arch == "x64"
; The x64 build is the universal host: it instruments both x64 and 32-bit WOW64
; targets. Refuse to install on non-x64 Windows.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#endif
; The x86 build has no ArchitecturesAllowed restriction: it installs on 32-bit
; Windows and (in 32-bit mode) on 64-bit Windows, where it is used to instrument
; 32-bit .NET targets (ClrMD's managed discovery is bitness-locked to the host).

; The bundled .NET runtime needs Windows 10 (1607 / build 10.0.14393) or later.
MinVersion=10.0.14393

LicenseFile=..\..\LICENSE.txt
SetupIconFile=..\..\Cda.App\app.ico
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
OutputDir=Output
OutputBaseFilename=CDA-Setup-{#AppVersion}-{#Arch}
DisableProgramGroupPage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Ship the entire self-contained publish output (exe + .NET runtime + Iced +
; ICSharpCode.Decompiler + Microsoft.Diagnostics.Runtime + the generated
; runtimeconfig/deps). recursesubdirs picks up runtimes\ and locale folders.
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; The app exe embeds app.ico (ApplicationIcon in the csproj), so the shortcuts
; and the installed exe show the CDA icon; SetupIconFile gives the installer exe
; its icon too.
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
