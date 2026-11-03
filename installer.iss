; Inno Setup script for Wirescope (formerly BACnet Inspector)  (needs Inno Setup 6.3 or newer: https://jrsoftware.org/isdl.php)
; Build order: 1) run build_windows.bat  2) run build_installer.bat  ->  installer\Wirescope-Setup-<version>.exe
; The version comes from version.txt; build_installer.bat passes it in as /DAppVersion=...

#define AppName "Wirescope"
#ifndef AppVersion
  #error Build this with build_installer.bat (it reads the version from version.txt)
#endif
#define AppExe "Wirescope.exe"

[Setup]
; Keep this AppId: it is what lets an installed copy (also one still called BACnet Inspector) upgrade in place.
AppId={{366CA448-BB27-4033-B85B-8D844CA0A856}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=Wirescope
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#AppExe}
OutputDir=installer
OutputBaseFilename=Wirescope-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=bacnet_inspector.ico
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Installs just for you without admin rights; the user can choose "all users" in a dialog.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
CloseApplications=yes
ChangesAssociations=yes
#ifdef SIGN
SignTool=signtool
SignedUninstaller=yes
#endif

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked
Name: "assoc"; Description: "Add Wirescope to the &Open with menu for .pcap and .pcapng files"; GroupDescription: "File types:"

[InstallDelete]
; Clear the previous version's program files so parts removed in an update do not linger (settings live elsewhere).
Type: filesandordirs; Name: "{app}\_internal"
; The app used to be called BACnet Inspector: remove its program file and shortcuts (an upgrade keeps the folder).
Type: files; Name: "{app}\BACnet Inspector.exe"
Type: files; Name: "{autoprograms}\BACnet Inspector.lnk"
Type: files; Name: "{autodesktop}\BACnet Inspector.lnk"

[Files]
Source: "dist\Wirescope\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
Root: HKA; Subkey: "Software\Classes\BACnetInspector.Capture"; ValueType: string; ValueData: "BACnet capture file"; Flags: uninsdeletekey; Tasks: assoc
Root: HKA; Subkey: "Software\Classes\BACnetInspector.Capture\DefaultIcon"; ValueType: string; ValueData: "{app}\{#AppExe},0"; Tasks: assoc
Root: HKA; Subkey: "Software\Classes\BACnetInspector.Capture\shell\open\command"; ValueType: string; ValueData: """{app}\{#AppExe}"" ""%1"""; Tasks: assoc
Root: HKA; Subkey: "Software\Classes\.pcap\OpenWithProgids"; ValueType: string; ValueName: "BACnetInspector.Capture"; ValueData: ""; Flags: uninsdeletevalue; Tasks: assoc
Root: HKA; Subkey: "Software\Classes\.pcapng\OpenWithProgids"; ValueType: string; ValueName: "BACnetInspector.Capture"; ValueData: ""; Flags: uninsdeletevalue; Tasks: assoc

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
; After an automatic update (a silent install) open the app again
Filename: "{app}\{#AppExe}"; Flags: nowait; Check: WizardSilent

[Code]
// Live capture uses Wireshark's capture engine. Offer to download it if it is missing.
function WiresharkMissing: Boolean;
begin
  Result := not (FileExists(ExpandConstant('{commonpf}\Wireshark\dumpcap.exe')) or
                 FileExists(ExpandConstant('{commonpf32}\Wireshark\dumpcap.exe')));
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ErrorCode: Integer;
begin
  if (CurStep = ssPostInstall) and WiresharkMissing and (not WizardSilent) then
    if MsgBox('Live packet capture needs Wireshark (it includes Npcap), which was not found on this PC.' + #13#10 +
              'Opening saved captures and MS/TP serial capture work without it.' + #13#10#13#10 +
              'Open the Wireshark download page now?', mbInformation, MB_YESNO) = IDYES then
      ShellExec('open', 'https://www.wireshark.org/download.html', '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode);
end;
