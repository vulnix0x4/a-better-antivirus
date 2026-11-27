; ABA-Setup.exe: the "Next, Next, Finish" way to install A Better Antivirus.
;
; This is a front end for ABA's own installer, not a second one. It asks the
; questions of the terminal setup's "Recommended" path (phone alerts, the
; clipper and miner traps, updates), then runs
;
;     aba.exe install --yes --keep-settings ...
;
; from the copy it carries. ABA does everything itself: it copies itself to
; Program Files, creates the service, plants the baits, and adds its own entry
; to Windows' "Installed apps" list and the Start menu. So this program
; installs no files and registers no uninstaller: uninstalling is always
; `aba uninstall`, whichever way ABA was installed.
;
; Build it with `go run ./installer/build` (see installer/README.md), which
; passes these:
;
;   /DAppVersion=v1.2.3         the version of the aba.exe inside
;   /DAppVersionNumeric=1.2.3   the same as numbers, for the file properties
;   /DBinDir=<folder>           holds aba-amd64.exe and aba-arm64.exe
;   /DOutDir=<folder>           where ABA-Setup.exe goes
;   /DPreview                   a look-only build: it carries no aba.exe and
;                               can't install anything (see README.md)

#ifndef AppVersion
  #error AppVersion is not set. Build with: go run ./installer/build
#endif
#ifndef AppVersionNumeric
  #define AppVersionNumeric "0.0.0"
#endif
#ifndef OutDir
  #define OutDir "."
#endif
#ifndef Preview
  #ifndef BinDir
    #error BinDir is not set. Build with: go run ./installer/build
  #endif
  #if !FileExists(AddBackslash(BinDir) + "aba-amd64.exe") || !FileExists(AddBackslash(BinDir) + "aba-arm64.exe")
    #error BinDir must hold aba-amd64.exe and aba-arm64.exe
  #endif
#endif

; The miner trap's list of mining pools: plain data, installed next to aba.exe
; (internal/minertrap/pools.go says why it isn't inside the program).
#define PoolsFile "..\internal\minertrap\miner-pools.txt"
#ifndef Preview
  #if !FileExists(AddBackslash(SourcePath) + PoolsFile)
    #error internal\minertrap\miner-pools.txt is missing
  #endif
#endif

#define AppName "A Better Antivirus"
#define AppURL "https://github.com/vulnix0x4/a-better-antivirus"
; Where ABA puts itself (internal/paths). Low-profile names, on purpose.
#define ProgramDir "{commonpf}\File Access Monitor"
#define InstalledExe ProgramDir + "\aba.exe"
#define DataDir "{commonappdata}\FileAccessMonitor"

[Setup]
AppId=ABA-Setup
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=A Better Antivirus contributors
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
VersionInfoVersion={#AppVersionNumeric}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} Setup
VersionInfoProductTextVersion={#AppVersion}

OutputDir={#OutDir}
#ifdef Preview
OutputBaseFilename=ABA-Setup-preview
PrivilegesRequired=lowest
#else
OutputBaseFilename=ABA-Setup
PrivilegesRequired=admin
#endif

; ABA is built for 64-bit Windows 10 and 11, x64 and Arm64. Setup itself is a
; 32-bit program that runs on both; "64-bit install mode" makes {commonpf} the
; real Program Files folder.
MinVersion=10.0
ArchitecturesAllowed=x64os or arm64
ArchitecturesInstallIn64BitMode=x64os or arm64

; ABA installs and uninstalls itself. Nothing for Inno Setup to put on disk,
; nothing for it to undo.
CreateAppDir=no
Uninstallable=no
CreateUninstallRegKey=no
CloseApplications=no
RestartApplications=no

WizardStyle=modern dynamic
DisableWelcomePage=no
DisableReadyPage=no
ShowLanguageDialog=no
SetupMutex=ABA-Setup-Running,Global\ABA-Setup-Running
Compression=lzma2/max
; Each aba.exe is compressed on its own: only one of them is ever unpacked.
SolidCompression=no

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Messages]
SetupAppTitle={#AppName} Setup
SetupWindowTitle={#AppName} Setup
WelcomeLabel1=Set up [name]
ReadyLabel1=Setup is ready. This is what it will do:
ReadyLabel2a=Click Install to go ahead, or Back to change your answers.
ReadyLabel2b=Click Install to go ahead.
WizardPreparing=Setup didn't finish
PreparingDesc=[name] could not be set up on this PC.
CannotContinue=Click Cancel to close Setup.
WizardInstalling=Finishing
InstallingLabel=Almost done.
FinishedHeadingLabel=You're protected
FinishedLabelNoIcons=[name] is installed and running.
FinishedLabel=[name] is installed and running.
ClickFinish=Click Finish to close Setup.
ExitSetupMessage=Setup isn't finished. If you close it now, [name] won't be set up.%n%nClose Setup?

#ifndef Preview
[Files]
; Byte for byte the aba_<version>_windows_<arch>.exe files of the same release.
Source: "{#AddBackslash(BinDir)}aba-amd64.exe"; Flags: dontcopy
Source: "{#AddBackslash(BinDir)}aba-arm64.exe"; Flags: dontcopy
; aba install puts it in place, from next to the aba.exe it runs.
Source: "{#PoolsFile}"; Flags: dontcopy

[Run]
; Offered on the last page. --elevated-pause keeps the test's window open at
; the end so the result can be read. The test needs administrator rights, which
; Setup already has; the dashboard doesn't, so it opens as the person signed in.
Filename: "{#InstalledExe}"; Parameters: "test --elevated-pause"; Description: "Run the safe test: watch ABA catch a harmless fake stealer"; Flags: postinstall nowait skipifsilent runascurrentuser
Filename: "{#InstalledExe}"; Description: "Open the dashboard"; Flags: postinstall nowait skipifsilent unchecked
#else
[Run]
; Look-only build: the same two boxes, wired to nothing.
Filename: "{sys}\cmd.exe"; Parameters: "/c rem"; Description: "Run the safe test: watch ABA catch a harmless fake stealer"; Flags: postinstall nowait skipifsilent runhidden
Filename: "{sys}\cmd.exe"; Parameters: "/c rem"; Description: "Open the dashboard"; Flags: postinstall nowait skipifsilent runhidden unchecked
#endif

[Code]
const
  BundledVersion = '{#AppVersion}';
  // The letters ABA's own setup makes ntfy topics from (no 0/o or 1/l).
  TopicLetters = 'abcdefghijkmnpqrstuvwxyz23456789';

var
  // What's on this PC already (worked out once, in InitializeSetup).
  Existing: Boolean;        // ABA is set up here: keep its settings, ask nothing
  ExistingVersion: String;  // '' if there is no aba.exe, '?' if it wouldn't say
  IsUpgrade: Boolean;       // the installed version is older than this one

  ChangesPage: TOutputMsgMemoWizardPage;
  PhonePage: TWizardPage;
  PhoneOffRadio, PhoneNtfyRadio: TNewRadioButton;
  PhoneSteps, TopicLabel, TopicHint: TNewStaticText;
  TopicEdit: TNewEdit;
  TrapsPage: TWizardPage;
  ClippersCheck, MinersCheck: TNewCheckBox;
  UpdatesPage: TInputOptionWizardPage;
  ProgressPage: TOutputProgressWizardPage;

  // Filled in while aba.exe install runs.
  StepsDone, StepsExpected: Integer;
  LastStepLine: String;  // the last "<mark> <step> <detail>" line
  Warnings: String;      // steps that didn't work but don't stop setup

function BCryptGenRandom(hAlgorithm: Cardinal; var Buffer: Cardinal; cbBuffer, dwFlags: Cardinal): Integer;
  external 'BCryptGenRandom@bcrypt.dll stdcall';

// ---- small helpers ----

function YesNo(B: Boolean): String;
begin
  if B then Result := 'yes' else Result := 'no';
end;

function Param(const Name, Default: String): String;
begin
  Result := Trim(ExpandConstant('{param:' + Name + '|' + Default + '}'));
end;

// OnlyChars reports whether S is 1 to MaxLen characters, all of them in Allowed.
// Every answer that ends up on aba.exe's command line goes through this, so
// nothing typed into Setup (or passed to it) can add or change an option.
function OnlyChars(const S, Allowed: String; MaxLen: Integer): Boolean;
var
  I: Integer;
begin
  Result := (Length(S) >= 1) and (Length(S) <= MaxLen);
  if Result then
    for I := 1 to Length(S) do
      if Pos(S[I], Allowed) = 0 then begin
        Result := False;
        Exit;
      end;
end;

function ValidTopic(const S: String): Boolean;
begin
  Result := OnlyChars(S, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_', 64);
end;

// RandomTopic makes a hard-to-guess ntfy topic like aba-k3v9xw2mfp, from the
// system's secure random numbers. '' if those aren't available: the box is
// then left empty to type one, rather than filled with something guessable.
function RandomTopic: String;
var
  R: Cardinal;
  I, J: Integer;
  Letters: String;
begin
  Letters := TopicLetters;
  Result := 'aba-';
  for I := 1 to 2 do begin
    R := 0;
    if BCryptGenRandom(0, R, 4, 2 { use the system's preferred generator }) <> 0 then begin
      Result := '';
      Exit;
    end;
    for J := 1 to 5 do begin
      Result := Result + Letters[(R and 31) + 1];
      R := R shr 5;
    end;
  end;
end;

// ParseVersion reads vX.Y.Z (the only form releases use). Anything else, like
// a development build, can't be compared.
function ParseVersion(S: String; var A, B, C: Integer): Boolean;
var
  P, I, N: Integer;
  Part: String;
  V: array[0..2] of Integer;
begin
  Result := False;
  S := Trim(S);
  if (Length(S) < 2) or (S[1] <> 'v') then
    Exit;
  Delete(S, 1, 1);
  for I := 0 to 2 do begin
    P := Pos('.', S);
    if I < 2 then begin
      if P = 0 then
        Exit;
      Part := Copy(S, 1, P - 1);
      Delete(S, 1, P);
    end else begin
      if P <> 0 then
        Exit;
      Part := S;
    end;
    if not OnlyChars(Part, '0123456789', 6) then
      Exit;
    N := StrToIntDef(Part, -1);
    if N < 0 then
      Exit;
    V[I] := N;
  end;
  A := V[0];
  B := V[1];
  C := V[2];
  Result := True;
end;

// CompareVersions: -1 if X is older than Y, 0 if the same, 1 if newer.
// Comparable is False if either isn't a release version.
function CompareVersions(const X, Y: String; var Comparable: Boolean): Integer;
var
  A1, B1, C1, A2, B2, C2: Integer;
begin
  Result := 0;
  Comparable := ParseVersion(X, A1, B1, C1) and ParseVersion(Y, A2, B2, C2);
  if not Comparable then
    Exit;
  if A1 <> A2 then begin
    if A1 < A2 then Result := -1 else Result := 1;
  end else if B1 <> B2 then begin
    if B1 < B2 then Result := -1 else Result := 1;
  end else if C1 <> C2 then begin
    if C1 < C2 then Result := -1 else Result := 1;
  end;
end;

function ProgramDir: String;
begin
  Result := ExpandConstant('{#ProgramDir}');
end;

// InstalledVersion asks the installed aba.exe for its version ("A Better
// Antivirus v1.2.3"). It lives in Program Files, which only administrators can
// change, and --version needs no rights and changes nothing.
function InstalledVersion: String;
var
  Exe, Line: String;
  Code: Integer;
  Output: TExecOutput;
begin
  Result := '';
  Exe := ExpandConstant('{#InstalledExe}');
  if not FileExists(Exe) then
    Exit;
  Result := '?';
  try
    if ExecAndCaptureOutput(Exe, '--version', '', SW_SHOWNORMAL, ewWaitUntilTerminated, Code, Output) and
       (Code = 0) and (GetArrayLength(Output.StdOut) > 0) then begin
      Line := Trim(Output.StdOut[0]);
      if RPos(' ', Line) > 0 then
        Result := Copy(Line, RPos(' ', Line) + 1, Length(Line));
    end;
  except
    Log('Could not ask the installed aba.exe for its version: ' + GetExceptionMessage);
  end;
end;

// ---- what is on this PC already ----

function InitializeSetup: Boolean;
var
  Comparable: Boolean;
  Order: Integer;
#ifdef Preview
  State: String;
#endif
begin
  Result := True;
  Existing := False;
  IsUpgrade := False;

#ifdef Preview
  // Look-only build: pretend, as told by /PREVIEWSTATE=fresh|upgrade|repair|newer|unknown.
  State := Lowercase(Param('PREVIEWSTATE', 'fresh'));
  ExistingVersion := '';
  if State = 'upgrade' then ExistingVersion := 'v0.0.1';
  if State = 'repair' then ExistingVersion := BundledVersion;
  if State = 'newer' then ExistingVersion := 'v999.0.0';
  if State = 'unknown' then ExistingVersion := 'dev';
  Existing := ExistingVersion <> '';
#else
  // ABA counts as set up when its settings file exists (the same test ABA
  // itself uses). `aba uninstall` removes that file.
  Existing := FileExists(ExpandConstant('{#DataDir}\config.json'));
  ExistingVersion := InstalledVersion;
#endif
  Log('Already set up: ' + YesNo(Existing) + '. Installed version: "' + ExistingVersion + '". This installer: ' + BundledVersion + '.');

  if ExistingVersion = '' then
    Exit; // no aba.exe on this PC: nothing to compare with

  Order := CompareVersions(ExistingVersion, BundledVersion, Comparable);
  if Comparable and (Order > 0) then begin
    // Never replace a newer version with an older one.
    SuppressibleMsgBox(
      'A newer version of {#AppName} is already on this PC.' + #13#10#13#10 +
      'Installed: ' + ExistingVersion + #13#10 +
      'This installer: ' + BundledVersion + #13#10#13#10 +
      'Setup won''t replace it with an older one. Nothing was changed.' + #13#10#13#10 +
      'To change your settings, open a terminal and run: aba configure',
      mbInformation, MB_OK, IDOK);
    Log('Stopping: the installed version is newer.');
    Result := False;
    Exit;
  end;
  if not Comparable and (ExistingVersion <> BundledVersion) then begin
    // A development build on one side or the other. Don't guess: ask. With
    // message boxes switched off (a silent install) the answer is No.
    if SuppressibleMsgBox(
         '{#AppName} is already on this PC, in a version Setup can''t compare with its own.' + #13#10#13#10 +
         'Installed: ' + ExistingVersion + #13#10 +
         'This installer: ' + BundledVersion + #13#10#13#10 +
         'Replace the installed version with this one? Your settings are kept.',
         mbConfirmation, MB_YESNO or MB_DEFBUTTON2, IDNO) <> IDYES then begin
      Log('Stopping: the versions can''t be compared and replacing was not confirmed.');
      Result := False;
      Exit;
    end;
  end;
  IsUpgrade := Comparable and (Order < 0);
end;

// ---- the answers ----

function WantNtfy: Boolean;
begin
  Result := PhoneNtfyRadio.Checked;
end;

function Topic: String;
begin
  Result := Trim(TopicEdit.Text);
end;

function WantAutoUpdate: Boolean;
begin
  Result := UpdatesPage.SelectedValueIndex = 0;
end;

// The two traps. On a silent install nobody sees the page, so a trap is on
// only when asked for (/CLIPPERS=1, /MINERS=1): Setup never switches one on
// by itself.
function TrapParamGiven(const Name: String): Boolean;
begin
  Result := Param(Name, '') <> '';
end;

function WantTrap(const Name: String; Box: TNewCheckBox): Boolean;
begin
  if WizardSilent then
    Result := Param(Name, '') = '1'
  else
    Result := Box.Checked;
end;

function WantClippers: Boolean;
begin
  Result := WantTrap('CLIPPERS', ClippersCheck);
end;

function WantMiners: Boolean;
begin
  Result := WantTrap('MINERS', MinersCheck);
end;

function TrapArgument(const Flag, Name: String; Want: Boolean): String;
begin
  Result := '';
  if WizardSilent and not TrapParamGiven(Name) then
    Exit; // not asked for: left as it is (off on a first install)
  if Want then
    Result := ' --' + Flag + '=true'
  else
    Result := ' --' + Flag + '=false';
end;

// These are for silent installs (/VERYSILENT), where nobody can pick them in
// the window. '' means "not given": ABA's default applies.
function ParamPreset: String;
begin
  Result := Lowercase(Param('PRESET', 'balanced'));
end;

function ParamLearning: String;
begin
  // The terminal setup's Recommended path starts without a learning period
  // (it only matters with the strict preset).
  Result := Param('LEARNING', '0');
end;

// AbaArguments is the command line for aba.exe install. --keep-settings is
// always there: if ABA turns out to be set up already, it keeps what it has
// and the rest is ignored, so Setup can never reset anyone's settings.
function AbaArguments: String;
begin
  Result := 'install --yes --keep-settings --preset ' + ParamPreset + ' --learning ' + ParamLearning;
  if WantAutoUpdate then
    Result := Result + ' --auto-update=true'
  else
    Result := Result + ' --auto-update=false';
  if WantNtfy then
    Result := Result + ' --ntfy-topic ' + Topic;
  Result := Result + TrapArgument('clippers', 'CLIPPERS', WantClippers) + TrapArgument('miners', 'MINERS', WantMiners);
  if Param('CANARYEMAIL', '') <> '' then
    Result := Result + ' --canary-email ' + Param('CANARYEMAIL', '');
  if Param('BAITS', '') <> '' then
    Result := Result + ' --baits ' + Param('BAITS', '');
end;

// CheckParameters refuses anything on Setup's command line that isn't plainly
// a preset name, a number, an email address or a list of bait names.
function CheckParameters: String;
var
  P: String;
begin
  Result := '';
  P := ParamPreset;
  if (P <> 'alert') and (P <> 'balanced') and (P <> 'strict') then
    Result := '/PRESET must be alert, balanced or strict.';
  if not OnlyChars(ParamLearning, '0123456789', 3) then
    Result := '/LEARNING must be a number of days, like 0 or 3.';
  P := Param('AUTOUPDATE', '1');
  if (P <> '0') and (P <> '1') then
    Result := '/AUTOUPDATE must be 1 (on) or 0 (off).';
  P := Param('CLIPPERS', '');
  if (P <> '') and (P <> '0') and (P <> '1') then
    Result := '/CLIPPERS must be 1 (detect clippers) or 0 (don''t).';
  P := Param('MINERS', '');
  if (P <> '') and (P <> '0') and (P <> '1') then
    Result := '/MINERS must be 1 (detect hidden miners) or 0 (don''t).';
  P := Param('NTFYTOPIC', '');
  if (P <> '') and not ValidTopic(P) then
    Result := '/NTFYTOPIC may only have letters, digits, - and _ in it (64 at most).';
  P := Param('CANARYEMAIL', '');
  if (P <> '') and (not OnlyChars(P, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._+-', 254) or (Pos('@', P) < 2) or (P[1] = '-')) then
    Result := '/CANARYEMAIL must be an email address.';
  P := Param('BAITS', '');
  if (P <> '') and (not OnlyChars(P, 'abcdefghijklmnopqrstuvwxyz0123456789-,', 2000) or (P[1] = '-')) then
    Result := '/BAITS must be bait names separated by commas (see: aba bait catalog).';
end;

// ---- the pages ----

function AddText(Page: TWizardPage; Left, Top: Integer; const S: String): TNewStaticText;
begin
  Result := TNewStaticText.Create(Page);
  Result.Parent := Page.Surface;
  Result.AutoSize := False;
  Result.WordWrap := True;
  Result.Left := Left;
  Result.Top := Top;
  Result.Width := Page.SurfaceWidth - Left;
  Result.Caption := S;
  Result.AdjustHeight;
end;

function AddRadio(Page: TWizardPage; Top: Integer; const S: String): TNewRadioButton;
begin
  Result := TNewRadioButton.Create(Page);
  Result.Parent := Page.Surface;
  Result.Left := 0;
  Result.Top := Top;
  Result.Width := Page.SurfaceWidth;
  Result.Height := ScaleY(21);
  Result.Caption := S;
end;

procedure PhoneChoiceChanged(Sender: TObject);
var
  On: Boolean;
begin
  On := PhoneNtfyRadio.Checked;
  PhoneSteps.Enabled := On;
  TopicLabel.Enabled := On;
  TopicEdit.Enabled := On;
  TopicHint.Enabled := On;
end;

function RtfText(const S: String): String;
begin
  Result := S;
  StringChangeEx(Result, '\', '\\', True);
  StringChangeEx(Result, '{', '\{', True);
  StringChangeEx(Result, '}', '\}', True);
end;

// One "what changes" entry: a bold heading and a sentence or two under it.
function RtfItem(const Heading, Body: String): String;
begin
  Result := '\b ' + RtfText(Heading) + '\b0\par ' + RtfText(Body) + '\par\par ';
end;

// ChangesText is the README's "What gets changed on your PC" table in sentences.
function ChangesText: String;
begin
  Result := '{\rtf1\ansi ' +
    RtfText('Setup changes the things below. Uninstalling puts every one of them back.') + '\par\par ' +
    RtfItem('Program',
      'Copied to ' + ProgramDir + '. The folder and the service are called "File Access Monitor" on purpose, so they don''t tell malware what they are.') +
    RtfItem('Background service',
      '"File Access Monitor" starts with Windows and watches the baits. It uses no processor time while nothing happens.') +
    RtfItem('Baits',
      'Fake passwords, wallets and app data are placed in your Desktop, Documents and home folders, and in the data folders of apps you don''t have. They are harmless. Don''t open them yourself: that counts as a read.') +
    RtfItem('A Windows setting',
      'File auditing ("Audit File System") is switched on. That is how Windows tells ABA who opened a bait. Uninstalling sets it back to what it was.') +
    RtfItem('Settings, alerts and logs',
      'Kept in ' + ExpandConstant('{#DataDir}') + '. Only administrators can read that folder.') +
    RtfItem('Start menu, Installed apps and PATH',
      '"{#AppName}" is added to the Start menu and to Windows'' list of installed apps. The program folder is added to PATH, so the aba command works in a terminal.') +
    RtfItem('Firewall',
      'Nothing is blocked now. Only when ABA stops a threat does it add a Windows firewall rule that cuts that one program off from the internet.') +
    RtfItem('Mining pools, if you choose to detect miners',
      'A Windows name rule points the names of known crypto-mining pools at a fake pool on this PC. No other name changes. Turning the miner trap off, or uninstalling, removes the rule.') +
    RtfItem('Internet',
      'ABA sends nothing about you anywhere. It uses the internet only for phone alerts and update checks, and only if you turn them on in the next steps.') +
    RtfText('Keep Windows Defender, or the antivirus you have, switched on. ABA works next to it.') + '\par }';
end;

procedure InitializeWizard;
var
  Y: Integer;
  T: TNewStaticText;
  Given: String;
begin
  // ---- welcome ----
  if not Existing then
    WizardForm.WelcomeLabel2.Caption :=
      'ABA puts fake passwords, wallets and app data around your PC. Nothing normal ever reads them. ' +
      'When something does, ABA freezes it, cuts its internet and tells you, before your real data leaves.' + #13#10#13#10 +
      'Setup takes about a minute and asks a few questions.' + #13#10#13#10 +
      'Keep Windows Defender on. ABA works next to your antivirus. It doesn''t replace it.' + #13#10#13#10 +
      'This is version ' + BundledVersion + '. Click Next to continue.'
  else begin
    if IsUpgrade then begin
      WizardForm.WelcomeLabel1.Caption := 'Update {#AppName}';
      WizardForm.WelcomeLabel2.Caption :=
        'Version ' + ExistingVersion + ' is set up on this PC. Setup will update it to ' + BundledVersion + '.';
    end else begin
      WizardForm.WelcomeLabel1.Caption := 'Repair {#AppName}';
      WizardForm.WelcomeLabel2.Caption :=
        '{#AppName} is already set up on this PC. Setup will put its program files back and check the service, the Windows setting and your baits.';
    end;
    WizardForm.WelcomeLabel2.Caption := WizardForm.WelcomeLabel2.Caption + #13#10#13#10 +
      'Nothing you chose is changed: your baits, your response, phone alerts, updates, trusted programs and alert history all stay.' + #13#10#13#10 +
      'To change settings, open a terminal and run: aba configure' + #13#10#13#10 +
      'Click Next to continue.';
  end;

  // ---- what changes ----
  ChangesPage := CreateOutputMsgMemoPage(wpWelcome,
    'What Setup changes on your PC', 'Please read this before you continue.',
    'When you''re ready, click Next.', ChangesText);

  // ---- phone alerts ----
  PhonePage := CreateCustomPage(ChangesPage.ID,
    'Phone alerts', 'Get alerts on your phone too?');
  T := AddText(PhonePage, 0, 0,
    'They reach you when you''re away from this PC. They still get out when ABA has cut the PC off from the network.');
  Y := T.Top + T.Height + ScaleY(10);
  PhoneOffRadio := AddRadio(PhonePage, Y, 'Not now');
  Y := Y + PhoneOffRadio.Height + ScaleY(2);
  PhoneNtfyRadio := AddRadio(PhonePage, Y, 'Yes, with ntfy (a free app, no account needed)');
  Y := Y + PhoneNtfyRadio.Height + ScaleY(6);
  PhoneSteps := AddText(PhonePage, ScaleX(18), Y,
    '1.  Install the free ntfy app from the App Store or Google Play.' + #13#10 +
    '2.  In the app, tap + and subscribe to the topic below.' + #13#10 +
    '3.  That''s it. Setup ends by sending a test, so you''ll know it works.');
  Y := PhoneSteps.Top + PhoneSteps.Height + ScaleY(10);
  TopicLabel := AddText(PhonePage, ScaleX(18), Y + ScaleY(3), 'Topic:');
  TopicLabel.WordWrap := False;
  TopicLabel.AutoSize := True;
  TopicEdit := TNewEdit.Create(PhonePage);
  TopicEdit.Parent := PhonePage.Surface;
  TopicEdit.Left := ScaleX(70);
  TopicEdit.Top := Y;
  TopicEdit.Width := ScaleX(240);
  TopicEdit.MaxLength := 64;
  TopicLabel.FocusControl := TopicEdit;
  Y := Y + TopicEdit.Height + ScaleY(6);
  TopicHint := AddText(PhonePage, ScaleX(18), Y,
    'Anyone who knows the topic can read your alerts, so keep it hard to guess.');
  Y := TopicHint.Top + TopicHint.Height + ScaleY(14);
  AddText(PhonePage, 0, Y,
    'Discord, Pushover, email or your own ntfy server can be set up afterwards: open a terminal and run aba configure.');

  Given := Param('NTFYTOPIC', '');
  if Given <> '' then begin
    TopicEdit.Text := Given;
    PhoneNtfyRadio.Checked := True;
  end else begin
    TopicEdit.Text := RandomTopic;
    PhoneOffRadio.Checked := True;
  end;
  PhoneOffRadio.OnClick := @PhoneChoiceChanged;
  PhoneNtfyRadio.OnClick := @PhoneChoiceChanged;
  PhoneChoiceChanged(nil);

  // ---- clippers and miners (the terminal setup's words) ----
  TrapsPage := CreateCustomPage(PhonePage.ID,
    'Clippers and miners', 'Detect two more kinds of malware?');
  T := AddText(TrapsPage, 0, 0,
    'Two traps for malware that doesn''t go after your files. Both are recommended.');
  Y := T.Top + T.Height + ScaleY(12);
  ClippersCheck := TNewCheckBox.Create(TrapsPage);
  ClippersCheck.Parent := TrapsPage.Surface;
  ClippersCheck.Top := Y;
  ClippersCheck.Width := TrapsPage.SurfaceWidth;
  ClippersCheck.Height := ScaleY(21);
  ClippersCheck.Caption := 'Detect clippers (recommended)';
  Y := Y + ClippersCheck.Height + ScaleY(2);
  T := AddText(TrapsPage, ScaleX(18), Y,
    'Clippers swap a crypto wallet address you copy for the attacker''s. When you''re away from your PC, ABA puts a fake address on the clipboard and freezes any program that swaps it. Your clipboard is put back.');
  Y := T.Top + T.Height + ScaleY(14);
  MinersCheck := TNewCheckBox.Create(TrapsPage);
  MinersCheck.Parent := TrapsPage.Surface;
  MinersCheck.Top := Y;
  MinersCheck.Width := TrapsPage.SurfaceWidth;
  MinersCheck.Height := ScaleY(21);
  MinersCheck.Caption := 'Detect hidden crypto miners (recommended, unless you mine yourself)';
  Y := Y + MinersCheck.Height + ScaleY(2);
  T := AddText(TrapsPage, ScaleX(18), Y,
    'Hidden crypto miners use your PC to make money for someone else. ABA points the known mining pools at a fake one on this PC and freezes any program that tries to mine there. Turn it off if you mine crypto on this PC on purpose.');
  Y := T.Top + T.Height + ScaleY(14);
  AddText(TrapsPage, 0, Y,
    'Change either later in a terminal: aba clipboard on|off, aba miners on|off.');
  ClippersCheck.Checked := Param('CLIPPERS', '1') <> '0';
  MinersCheck.Checked := Param('MINERS', '1') <> '0';

  // ---- automatic updates ----
  UpdatesPage := CreateInputOptionPage(TrapsPage.ID,
    'Automatic updates', 'Keep {#AppName} up to date automatically?',
    'Once a day ABA checks GitHub for a new version. It installs one only if the release is signed with ABA''s release key and the download matches its signed checksum.',
    True, False);
  UpdatesPage.Add('Yes, automatically (recommended)');
  UpdatesPage.Add('No, I''ll update it myself');
  if Param('AUTOUPDATE', '1') = '0' then
    UpdatesPage.SelectedValueIndex := 1
  else
    UpdatesPage.SelectedValueIndex := 0;

  // ---- progress, shown while aba.exe works ----
  ProgressPage := CreateOutputProgressPage('Setting up {#AppName}', 'This takes about a minute. Please wait.');
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  // Already set up: nothing new changes on the PC, and nothing is asked.
  Result := Existing and ((PageID = ChangesPage.ID) or (PageID = PhonePage.ID) or (PageID = TrapsPage.ID) or (PageID = UpdatesPage.ID));
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Problem: String;
begin
  Result := True;
  if CurPageID = wpWelcome then begin
    // (Also reached on a silent install, before anything is done.)
    Problem := CheckParameters;
    if Problem <> '' then begin
      SuppressibleMsgBox('Setup was started with an option it can''t use.' + #13#10#13#10 + Problem + #13#10#13#10 + 'Nothing was changed.', mbError, MB_OK, IDOK);
      Log('Stopping: ' + Problem);
      Result := False;
    end;
  end;
  if (CurPageID = PhonePage.ID) and WantNtfy and not ValidTopic(Topic) then begin
    if Topic = '' then
      Problem := 'Type a topic for your phone alerts, or choose "Not now".'
    else
      Problem := 'A topic may only have letters, digits, - and _ in it, without spaces.';
    SuppressibleMsgBox(Problem, mbError, MB_OK, IDOK);
    Result := False;
  end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  if Existing then begin
    if IsUpgrade then
      Result := 'Update:' + NewLine + Space + 'from version ' + ExistingVersion + ' to ' + BundledVersion + NewLine
    else
      Result := 'Repair:' + NewLine + Space + 'program files, the background service, the Windows setting and your baits' + NewLine;
    Result := Result + NewLine +
      'Your settings:' + NewLine + Space + 'kept as they are' + NewLine + NewLine +
      'Protection:' + NewLine + Space + 'pauses for a few seconds while the service restarts';
    Exit;
  end;
  Result :=
    'Install:' + NewLine + Space + '{#AppName} ' + BundledVersion + NewLine + Space + 'in ' + ProgramDir + NewLine + NewLine +
    'Baits:' + NewLine + Space + 'the recommended set of fake files and app data' + NewLine + NewLine +
    'When something takes a bait:' + NewLine;
  if ParamPreset = 'alert' then
    Result := Result + Space + 'you get an alert, and nothing else happens' + NewLine
  else if ParamPreset = 'strict' then
    Result := Result + Space + 'it is frozen, and this PC is cut off from the network until you say so' + NewLine
  else
    Result := Result + Space + 'it is frozen and cut off from the internet, and you get an alert' + NewLine;
  Result := Result + NewLine + 'Phone alerts:' + NewLine;
  if WantNtfy then
    Result := Result + Space + 'ntfy, topic ' + Topic + NewLine + Space + 'a test is sent at the end' + NewLine
  else
    Result := Result + Space + 'off (turn on later with: aba configure)' + NewLine;
  Result := Result + NewLine + 'Clippers:' + NewLine;
  if WantClippers then
    Result := Result + Space + 'detected: a fake wallet address when you''re away from your PC' + NewLine
  else
    Result := Result + Space + 'not watched (turn on later with: aba clipboard on)' + NewLine;
  Result := Result + NewLine + 'Hidden crypto miners:' + NewLine;
  if WantMiners then
    Result := Result + Space + 'detected: a fake mining pool on this PC' + NewLine
  else
    Result := Result + Space + 'not watched (turn on later with: aba miners on)' + NewLine;
  Result := Result + NewLine + 'Updates:' + NewLine;
  if WantAutoUpdate then
    Result := Result + Space + 'automatic, signed releases only'
  else
    Result := Result + Space + 'you update it yourself (with: aba update)';
end;

// ---- running aba.exe install ----

// StepLine picks ABA's step lines out of its output. Each step prints one line
// when it's done: a mark, a space, then the step and what it did:
//     <ok> Planting baits 14 in place
//     ! Sending a test to your phone: couldn't reach ...
//     <bad> Starting the background service: ...
// The marks aren't plain ASCII except "!", so they're recognised by position
// (one to three characters at the very start of the line, not a letter or
// digit) rather than by value. Everything else ABA prints is indented or
// starts with a word.
function StepLine(const S: String; var Mark, Rest: String): Boolean;
var
  P: Integer;
  C: Char;
begin
  Result := False;
  P := Pos(' ', S);
  if (P < 2) or (P > 4) or (Length(S) <= P) or (S[P + 1] = ' ') then
    Exit;
  C := S[1];
  if ((C >= 'a') and (C <= 'z')) or ((C >= 'A') and (C <= 'Z')) or ((C >= '0') and (C <= '9')) then
    Exit;
  Mark := Copy(S, 1, P - 1);
  Rest := Trim(Copy(S, P + 1, Length(S)));
  Result := True;
end;

procedure ShowStep(const Rest: String);
begin
  StepsDone := StepsDone + 1;
  if StepsDone > StepsExpected then
    StepsExpected := StepsDone;
  ProgressPage.SetText('Done so far:', Rest);
  ProgressPage.SetProgress(StepsDone, StepsExpected + 1);
end;

procedure OnAbaOutput(const S: String; const Error, FirstLine: Boolean);
var
  Mark, Rest: String;
begin
  Log('aba: ' + S);
  if Error or not StepLine(S, Mark, Rest) then
    Exit;
  LastStepLine := Rest;
  if Mark = '!' then begin
    if Warnings <> '' then
      Warnings := Warnings + #13#10;
    Warnings := Warnings + Rest;
  end;
  ShowStep(Rest);
end;

#ifdef Preview
// Look-only build: play back what a real run prints. Nothing is executed.
// /PREVIEWRESULT=ok|warn|fail picks the ending.
function RunAba(var Problem: String): Boolean;
var
  Lines: TArrayOfString;
  I: Integer;
  Ending, Ok, Bad: String;
begin
  Ending := Lowercase(Param('PREVIEWRESULT', 'ok'));
  Log('A real build would run: aba.exe ' + AbaArguments);
  SetArrayLength(Lines, 8);
  // The marks ABA prints: a tick and a cross.
  Ok := #$2713;
  Bad := #$2717;
  Lines[0] := 'Setting up A Better Antivirus';
  Lines[1] := Ok + ' Checking this PC protecting PC\you';
  Lines[2] := Ok + ' Installing program files ' + ProgramDir;
  Lines[3] := Ok + ' Saving your settings Balanced (recommended), 14 baits, automatic updates, clipper and miner traps on';
  Lines[4] := Ok + ' Turning on Windows file auditing how ABA sees who opens a bait';
  Lines[5] := Ok + ' Planting baits 14 in place';
  if Ending = 'fail' then
    Lines[6] := Bad + ' Starting the background service: the service did not start (preview)'
  else
    Lines[6] := Ok + ' Starting the background service "File Access Monitor", starts with Windows';
  if Ending = 'warn' then
    Lines[7] := '! Sending a test to your phone: couldn''t reach ntfy (preview)'
  else
    Lines[7] := Ok + ' Adding ABA to Installed apps and the Start menu listed as "A Better Antivirus"';
  for I := 0 to GetArrayLength(Lines) - 1 do begin
    Sleep(350);
    OnAbaOutput(Lines[I], False, I = 0);
    if (Ending = 'fail') and (I = 6) then
      Break;
  end;
  Result := Ending <> 'fail';
  if not Result then
    Problem := LastStepLine;
end;
#else
function RunAba(var Problem: String): Boolean;
var
  Name, Exe: String;
  Code: Integer;
begin
  Result := False;
  // The copy built for this PC's processor. Setup's temporary folder can only
  // be written by administrators, so nothing running as you can swap the file
  // before it is started.
  if IsArm64 then
    Name := 'aba-arm64.exe'
  else
    Name := 'aba-amd64.exe';
  try
    ExtractTemporaryFile(Name);
    ExtractTemporaryFile('miner-pools.txt');
  except
    Problem := 'Setup couldn''t unpack its files: ' + GetExceptionMessage;
    Exit;
  end;
  Exe := ExpandConstant('{tmp}\') + Name;
  Log('Running ' + Name + ' install (already set up: ' + YesNo(Existing) + ')');
  try
    if not ExecAndLogOutput(Exe, AbaArguments, ExpandConstant('{tmp}'), SW_SHOWNORMAL, ewWaitUntilTerminated, Code, @OnAbaOutput) then begin
      Problem := 'Setup couldn''t start ABA''s installer: ' + SysErrorMessage(Code);
      Exit;
    end;
  except
    Problem := 'Setup couldn''t start ABA''s installer: ' + GetExceptionMessage;
    Exit;
  end;
  Log('aba install ended with exit code ' + IntToStr(Code));
  if Code <> 0 then begin
    // On a failure the last step line is the step that failed, and why.
    if LastStepLine <> '' then
      Problem := LastStepLine
    else
      Problem := 'ABA''s installer stopped with exit code ' + IntToStr(Code) + '.';
    Exit;
  end;
  Result := True;
end;
#endif

// Setup calls this after Install is clicked (and on a silent install). A text
// result stops Setup on a page showing it, with exit code 7.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Problem, Next: String;
begin
  Result := '';
  StepsDone := 0;
  LastStepLine := '';
  Warnings := '';
  Problem := '';
  // About how many steps ABA will report, for the bar (it grows if there are more).
  StepsExpected := 11;
  if not Existing and WantNtfy then
    StepsExpected := StepsExpected + 1;
  if not Existing and (Param('CANARYEMAIL', '') <> '') then
    StepsExpected := StepsExpected + 1;

  ProgressPage.SetText('Getting ready...', '');
  ProgressPage.SetProgress(0, StepsExpected + 1);
  ProgressPage.Show;
  try
    if not RunAba(Problem) then begin
      if WizardSilent then
        Next := 'run this installer again.'
      else
        Next := 'click Back and then Install to try again.';
      Result :=
        'Setup stopped at this step:' + #13#10#13#10 +
        Problem + #13#10#13#10 +
        'What to do next: ' + Next + ' If it stops at the same step, please report it at {#AppURL}/issues and include the text above.';
    end;
    if Result = '' then
      ProgressPage.SetProgress(StepsExpected + 1, StepsExpected + 1);
  finally
    ProgressPage.Hide;
  end;
  if Result <> '' then
    Log('Setup did not finish: ' + Problem);
end;

// ---- the last page ----

procedure CurPageChanged(CurPageID: Integer);
var
  Text: String;
  Bottom: Integer;
begin
  if CurPageID <> wpFinished then
    Exit;
  if not Existing then
    Text :=
      '{#AppName} is installed and running. It starts with Windows.' + #13#10#13#10 +
      'You''ll find it in the Start menu. In a terminal, the command is aba.' + #13#10#13#10 +
      'Don''t open the bait files yourself: that counts as a read.'
  else begin
    WizardForm.FinishedHeadingLabel.Caption := 'All set';
    if IsUpgrade then
      Text := '{#AppName} was updated to ' + BundledVersion + ' and is running. Your settings were kept.'
    else
      Text := '{#AppName} was checked and repaired, and is running. Your settings were kept.';
  end;
  if Warnings <> '' then
    Text := Text + #13#10#13#10 + 'One thing didn''t work:' + #13#10 + Warnings
  else if not Existing and WantNtfy then
    Text := Text + #13#10#13#10 + 'A test alert was sent to your phone. Check that it arrived.';
  WizardForm.FinishedLabel.Caption := Text;

  // The text is longer than the one Setup laid the page out for: move the
  // list of check boxes down to make room.
  Bottom := WizardForm.RunList.Top + WizardForm.RunList.Height;
  WizardForm.AdjustLabelHeight(WizardForm.FinishedLabel);
  WizardForm.RunList.Top := WizardForm.FinishedLabel.Top + WizardForm.FinishedLabel.Height + ScaleY(14);
  if Bottom - WizardForm.RunList.Top >= ScaleY(44) then
    WizardForm.RunList.Height := Bottom - WizardForm.RunList.Top;
end;
