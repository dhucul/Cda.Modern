; ============================================================================
;  CDA - Modern - x64 Inno Setup installer
;
;  The application is published self-contained, so the target machine needs no
;  separate .NET installation. One x64 host instruments native x64 and WOW64
;  x86 targets.
;
;  Build with tools\build-installer.ps1.
;  Output: tools\installer\Output\CDA-Setup-<version>-x64.exe
; ============================================================================

#define AppVersion   "1.19.0"
#define AppExeName   "Cda.App.exe"
#define AppPublisher "CDA"
#define AppFullName  "CDA - Modern"
#define PublishDir   "publish-x64"

[Setup]
; Stable AppId: do not change it between releases.
AppId={{A7F3C2E1-9B4D-4E8A-B6C1-2D5F8E0A3C71}
AppName={#AppFullName}
AppVersion={#AppVersion}
AppVerName={#AppFullName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppFullName}

; Install per-machine into Program Files. The app instruments other processes
; and ships with a requireAdministrator manifest.
DefaultDirName={autopf}\{#AppFullName}
DefaultGroupName={#AppFullName}
PrivilegesRequired=admin
UninstallDisplayName={#AppFullName}
UninstallDisplayIcon={app}\{#AppExeName}

; The x64 build is the universal native host. Refuse non-x64 Windows.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; The bundled .NET 8 runtime needs Windows 10 1607 or later.
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
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppFullName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\{cm:UninstallProgram,{#AppFullName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppFullName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppFullName}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallDelete]
Type: files; Name: "{app}\cda-error.log"
Type: files; Name: "{app}\cda_hook_skip.txt"
Type: files; Name: "{app}\cda_hook_range.txt"
