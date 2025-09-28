; ================================================================
; Advanced Inno Setup Script for Google Account Automation Tool
; Professional Installation Package with Modern Features
; ================================================================

#define MyAppName "Google Account Automation Tool"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Algolizen Solutions"
#define MyAppURL "https://algolizen.com"
#define MyAppExeName "GoogleAccountAutomationGUI.exe"
#define MyAppYear "2025"

[Setup]
; ---- Basic Application Information ----
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/support
AppUpdatesURL={#MyAppURL}/updates
AppCopyright=Copyright © {#MyAppYear} {#MyAppPublisher}

; ---- Installation Directories ----
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=installer_output
OutputBaseFilename=GoogleAccountAutomationTool_v{#MyAppVersion}_Setup
; SetupIconFile=setup_icon.ico (commented out - file doesn't exist)

; ---- Advanced Compression ----
Compression=lzma2/ultra64
LZMAUseSeparateProcess=yes
LZMADictionarySize=1048576
SolidCompression=yes
LZMANumBlockThreads=2

; ---- Modern UI and Features ----
WizardStyle=modern
; WizardImageFile=wizard_image.bmp (commented out - file doesn't exist)
; WizardSmallImageFile=wizard_small.bmp (commented out - file doesn't exist)
ShowLanguageDialog=auto
AllowNoIcons=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
AllowRootDirectory=no
DisableDirPage=no
DisableReadyPage=no

; ---- System Requirements ----
MinVersion=6.1sp1
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

; ---- Uninstaller ----
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
CreateUninstallRegKey=yes
UninstallLogMode=append

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"

[Types]
Name: "full"; Description: "Full Installation (Recommended)"
Name: "minimal"; Description: "Minimal Installation"
Name: "custom"; Description: "Custom Installation"; Flags: iscustom

[Components]
Name: "core"; Description: "Core Application Files"; Types: full minimal custom; Flags: fixed
Name: "templates"; Description: "CSV Templates and Examples"; Types: full custom
Name: "shortcuts"; Description: "Desktop and Quick Launch Shortcuts"; Types: full custom
Name: "documentation"; Description: "User Manual and Documentation"; Types: full custom

[Files]
; ---- Core Application ----
Source: "gui_executable\GoogleAccountAutomationGUI.exe"; DestDir: "{app}"; Flags: ignoreversion; Components: core
Source: "README.md"; DestDir: "{app}"; DestName: "ReadMe.txt"; Flags: ignoreversion; Components: documentation

; ---- Templates and Examples ----
Source: "accounts.csv"; DestDir: "{app}\templates"; DestName: "accounts_template.csv"; Flags: onlyifdoesntexist; Components: templates

; ---- Documentation ----
Source: "LICENSE"; DestDir: "{app}"; DestName: "License.txt"; Flags: ignoreversion; Components: documentation

[Dirs]
Name: "{app}\templates"; Components: templates
Name: "{app}\logs"; Permissions: users-modify
Name: "{app}\profiles"; Permissions: users-modify

[Icons]
; ---- Start Menu Icons ----
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autoprograms}\{#MyAppName} (Templates)"; Filename: "{app}\templates"; Components: templates
Name: "{autoprograms}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

; ---- Desktop Icons ----
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon; Components: shortcuts

; ---- Quick Launch ----
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: quicklaunchicon; Components: shortcuts

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; Components: shortcuts
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; OnlyBelowVersion: 6.1; Components: shortcuts
Name: "associatefiles"; Description: "Associate .csv files with {#MyAppName}"; GroupDescription: "File Associations:"; Flags: unchecked

[Registry]
; ---- Application Registration ----
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppName}"; ValueType: string; ValueName: "DisplayVersion"; ValueData: "{#MyAppVersion}"
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppName}"; ValueType: string; ValueName: "Publisher"; ValueData: "{#MyAppPublisher}"
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\{#MyAppName}"; ValueType: string; ValueName: "URLInfoAbout"; ValueData: "{#MyAppURL}"

; ---- File Associations ----
Root: HKCR; Subkey: ".csv"; ValueType: string; ValueName: ""; ValueData: "CSVFile"; Flags: uninsdeletevalue; Tasks: associatefiles
Root: HKCR; Subkey: "CSVFile"; ValueType: string; ValueName: ""; ValueData: "CSV Data File"; Flags: uninsdeletekey; Tasks: associatefiles
Root: HKCR; Subkey: "CSVFile\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName},0"; Tasks: associatefiles
Root: HKCR; Subkey: "CSVFile\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""; Tasks: associatefiles

[Run]
; ---- Post-Installation Actions ----
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
Filename: "{app}\ReadMe.txt"; Description: "View ReadMe file"; Flags: postinstall shellexec skipifsilent unchecked; Components: documentation

[UninstallRun]
; ---- Pre-Uninstall Cleanup ----
Filename: "{cmd}"; Parameters: "/c taskkill /f /im GoogleAccountAutomationGUI.exe"; Flags: runhidden; RunOnceId: "KillApp"

[UninstallDelete]
; ---- Cleanup Files ----
Type: files; Name: "{app}\*.log"
Type: files; Name: "{app}\*.tmp"
Type: files; Name: "{app}\profiles\*"
Type: dirifempty; Name: "{app}\profiles"
Type: dirifempty; Name: "{app}\logs"
Type: dirifempty; Name: "{app}\templates"

[Code]
// ---- Custom Installation Logic ----
function IsWin64: Boolean;
begin
  Result := ProcessorArchitecture = paX64;
end;

function InitializeSetup(): Boolean;
var
  Version: TWindowsVersion;
begin
  GetWindowsVersionEx(Version);
  
  // Check Windows version (Windows 7 SP1 or later)
  if (Version.Major < 6) or ((Version.Major = 6) and (Version.Minor < 1)) then
  begin
    MsgBox('This application requires Windows 7 SP1 or later.', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  
  // Check for .NET Framework (if needed)
  // Add additional system checks here
  
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Create initial configuration
    SaveStringToFile(ExpandConstant('{app}\config.ini'), 
      '[Settings]' + #13#10 + 
      'Version=' + '{#MyAppVersion}' + #13#10 +
      'InstallDate=' + GetDateTimeString('yyyy-mm-dd hh:nn:ss', #0, #0) + #13#10 +
      'FirstRun=true' + #13#10, False);
  end;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  // Skip license page if running silently
  if (PageID = wpLicense) and WizardSilent then
    Result := True
  else
    Result := False;
end;

[Messages]
; ---- Custom Messages ----
WelcomeLabel2=This will install {#MyAppName} version {#MyAppVersion} on your computer.%n%nThis professional tool automates Google Account 2FA setup with enterprise-grade security features and licensing system.%n%nIt is recommended that you close all other applications before continuing.
FinishedLabelNoIcons=Setup has finished installing {#MyAppName} on your computer.%n%nThe application is now ready to use with your license key.
ClickFinish=Click Finish to exit Setup and launch {#MyAppName}.

[CustomMessages]
; ---- Localized Custom Messages ----
english.ComponentsCore=Core application files (required)
english.ComponentsTemplates=CSV templates and examples
english.ComponentsShortcuts=Desktop and quick launch shortcuts
english.ComponentsDocumentation=User manual and help files
english.AssociateFiles=Associate CSV files with {#MyAppName}
english.LaunchAfterInstall=Launch {#MyAppName} after installation

; =====================
; COMPANY BRANDING
; =====================
; Publisher = Algolizen Solutions
; Website = https://algolizen.com
; Support = https://algolizen.com/support
; Copyright = © 2025 Algolizen Solutions
; To add your logo and branding images:
; 1. Place your installer icon as setup_icon.ico in this folder
; 2. Place your wizard side image as wizard_image.bmp (164x314px, 24-bit BMP)
; 3. Place your wizard header image as wizard_small.bmp (55x58px, 24-bit BMP)
; 4. Uncomment the lines below to enable custom branding images
; SetupIconFile=setup_icon.ico
; WizardImageFile=wizard_image.bmp
; WizardSmallImageFile=wizard_small.bmp
LicenseFile=LICENSE
