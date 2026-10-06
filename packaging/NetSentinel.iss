; NS-096: wrap the validated PyInstaller onedir; compile via build_installer.py.
#ifndef AppVersion
  #error AppVersion must come from build_installer.py
#endif
#ifndef PayloadDir
  #error PayloadDir is required
#endif
#ifndef OutputDir
  #error OutputDir is required
#endif
#ifndef InventoryFile
  #error InventoryFile is required
#endif

[Setup]
AppId={{62E3BFC6-ACAD-4FC3-94D8-46927D015096}
AppName=NetSentinel
AppVersion={#AppVersion}
VersionInfoVersion={#AppVersion}
AppVerName=NetSentinel {#AppVersion} (unsigned pilot)
DefaultDirName={localappdata}\Programs\NetSentinel
DefaultGroupName=NetSentinel
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
AppMutex=Global\NetSentinel.Desktop,Global\NetSentinel.Maintenance
SetupMutex=Global\NetSentinel.Setup
CloseApplications=no
RestartApplications=no
UsePreviousAppDir=yes
UninstallLogMode=append
UninstallDisplayIcon={app}\NetSentinel.exe
SetupIconFile=..\src\netsentinel\assets\netsentinel.ico
InfoBeforeFile=INSTALLER_POLICY.md
OutputDir={#OutputDir}
OutputBaseFilename=NetSentinel-{#AppVersion}-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
AllowNetworkDrive=no
AllowUNCPath=no
AllowRootDirectory=no
DisableProgramGroupPage=yes

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{#PayloadDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#InventoryFile}"; DestDir: "{app}"; DestName: "payload-files.txt"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\NetSentinel\NetSentinel"; Filename: "{app}\NetSentinel.exe"
Name: "{userdesktop}\NetSentinel"; Filename: "{app}\NetSentinel.exe"; Tasks: desktopicon

[Code]
var
  DeleteLocalData: Boolean;
  PreviousFiles: TArrayOfString;

function GetFileAttributesW(lpFileName: string): LongWord;
  external 'GetFileAttributesW@kernel32.dll stdcall';

function ProgramDirectoryError(Destination: string): string;
var
  ProgramBase, CurrentPath: string;
  Attributes: LongWord;
begin
  Result := '';
  ProgramBase := AddBackslash(ExpandConstant('{localappdata}\Programs'));
  Destination := ExpandFileName(Destination);
  if (CompareText(Copy(Destination, 1, Length(ProgramBase)), ProgramBase) <> 0) or
     (Length(Destination) <= Length(ProgramBase)) then begin
    Result := 'Choose a dedicated NetSentinel folder under your LocalAppData\Programs directory.';
    Exit;
  end;
  CurrentPath := Destination;
  while Length(CurrentPath) > 3 do begin
    Attributes := GetFileAttributesW(CurrentPath);
    if (Attributes <> $FFFFFFFF) and ((Attributes and $400) <> 0) then begin
      Result := 'Installation through a link or reparse point is not supported.';
      Exit;
    end;
    CurrentPath := ExtractFileDir(CurrentPath);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): string;
begin
  Result := ProgramDirectoryError(WizardDirValue);
  if Result <> '' then Exit;
  if CheckForMutexes('Global\NetSentinel.Desktop,Global\NetSentinel.Maintenance') then
    Result := 'Quit all NetSentinel instances using File or tray Quit before installation.';
end;

function SafeOwnedFile(RelativeName: string): Boolean;
var
  FullName, CurrentPath: string;
  Attributes: LongWord;
begin
  Result := False;
  StringChangeEx(RelativeName, '/', '\', True);
  if RelativeName = '' then Exit;
  if (Pos('..', RelativeName) > 0) or
     (Pos(':', RelativeName) > 0) or (RelativeName[1] = '\') then Exit;
  if not ((Pos('_internal\', RelativeName) = 1) or
          (Pos('licenses\', RelativeName) = 1) or
          (RelativeName = 'NetSentinel.exe') or
          (RelativeName = 'THIRD_PARTY_NOTICES.md') or
          (RelativeName = 'INSTALLER_POLICY.md')) then Exit;
  FullName := ExpandConstant('{app}\') + RelativeName;
  CurrentPath := FullName;
  while Length(CurrentPath) >= Length(ExpandConstant('{app}')) do begin
    Attributes := GetFileAttributesW(CurrentPath);
    if (Attributes <> $FFFFFFFF) and ((Attributes and $400) <> 0) then Exit;
    CurrentPath := ExtractFileDir(CurrentPath);
  end;
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  CurrentFiles: TArrayOfString;
  I, J: Integer;
  Retained: Boolean;
  RelativeName: string;
begin
  if CurStep = ssInstall then
    LoadStringsFromFile(ExpandConstant('{app}\payload-files.txt'), PreviousFiles);
  if CurStep = ssPostInstall then begin
    if not LoadStringsFromFile(ExpandConstant('{app}\payload-files.txt'), CurrentFiles) then
      RaiseException('Installed payload inventory is unavailable. User data was preserved.');
    for I := 0 to GetArrayLength(PreviousFiles) - 1 do begin
      RelativeName := PreviousFiles[I];
      Retained := False;
      for J := 0 to GetArrayLength(CurrentFiles) - 1 do
        if CompareText(RelativeName, CurrentFiles[J]) = 0 then Retained := True;
      if not Retained then begin
        if not SafeOwnedFile(RelativeName) then
          RaiseException('Unsafe old payload inventory. User data was preserved.');
        StringChangeEx(RelativeName, '/', '\', True);
        if FileExists(ExpandConstant('{app}\') + RelativeName) then
          if not DeleteFile(ExpandConstant('{app}\') + RelativeName) then
            RaiseException('Could not remove an obsolete owned payload file. Quit NetSentinel and repair.');
      end;
    end;
  end;
end;

function InitializeUninstall(): Boolean;
var
  Choice, I: Integer;
  Inventory: TArrayOfString;
  PathError: string;
begin
  Result := False;
  DeleteLocalData := False;
  PathError := ProgramDirectoryError(ExpandConstant('{app}'));
  if PathError <> '' then begin
    SuppressibleMsgBox(PathError + ' Uninstall cancelled; no data deletion.', mbError, MB_OK, IDOK);
    Exit;
  end;
  if not LoadStringsFromFile(ExpandConstant('{app}\payload-files.txt'), Inventory) then begin
    SuppressibleMsgBox('Owned payload inventory missing. Repair the installation before uninstalling.', mbError, MB_OK, IDOK);
    Exit;
  end;
  for I := 0 to GetArrayLength(Inventory) - 1 do begin
    if not SafeOwnedFile(Inventory[I]) then begin
      SuppressibleMsgBox('Unsafe payload path or link. Uninstall cancelled; repair the installation before retrying.', mbError, MB_OK, IDOK);
      Exit;
    end;
  end;
  if CheckForMutexes('Global\NetSentinel.Setup') then begin
    SuppressibleMsgBox('Another NetSentinel installer is active. Close it before uninstalling.', mbError, MB_OK, IDOK);
    Exit;
  end;
  if CheckForMutexes('Global\NetSentinel.Desktop,Global\NetSentinel.Maintenance') then begin
    SuppressibleMsgBox('Quit NetSentinel using File or tray Quit, then retry uninstall. Hidden tray applications are still running.', mbError, MB_OK, IDOK);
    Exit;
  end;
  CreateMutex('Global\NetSentinel.Setup');  // Prevent app startup until uninstaller exits.
  if UninstallSilent then begin
    Result := True;  // Silent uninstall always KEEP, no deletion switch.
    Exit;
  end;
  Choice := MsgBox('Uninstall NetSentinel. KEEP local data is the default.' + #13#10 +
    'Delete my local NetSentinel data instead?' + #13#10 +
    'Includes monitoring history, alerts/incidents, config/preferences, profiles/trust, reputation cache and local logs.' + #13#10 +
    'Yes = DELETE; No = KEEP; Cancel = cancel uninstall.', mbConfirmation, MB_YESNOCANCEL or MB_DEFBUTTON2);
  if Choice = IDCANCEL then Exit;
  if Choice = IDYES then begin
    Choice := MsgBox('Permanently delete local NetSentinel data? NetSentinel cannot restore it. Secure erasure is not guaranteed. Exports outside the owned data folder are preserved.', mbConfirmation, MB_OKCANCEL or MB_DEFBUTTON2);
    if Choice <> IDOK then Exit;
    DeleteLocalData := True;
  end;
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then begin
    if CheckForMutexes('Global\NetSentinel.Desktop,Global\NetSentinel.Maintenance') then begin
      SuppressibleMsgBox('NetSentinel is running. Quit and retry; uninstall cancelled.', mbError, MB_OK, IDOK);
      Abort;
    end;
    if DeleteLocalData then begin
      if not Exec(ExpandConstant('{app}\NetSentinel.exe'), '--uninstall-delete-local-data-confirmed',
          ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) then begin
        MsgBox('Data deletion could not start. Uninstall cancelled. Repair the application before retrying or choose KEEP.', mbError, MB_OK);
        Abort;
      end;
      if ResultCode <> 0 then begin
        MsgBox('Data deletion was refused or incomplete. Uninstall cancelled. Check paths/permissions and quit all NetSentinel processes, or choose KEEP. Already deleted files cannot be restored.', mbError, MB_OK);
        Abort;
      end;
    end;
  end;
end;
