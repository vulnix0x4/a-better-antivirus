<#
.SYNOPSIS
  Installs ABA with ABA-Setup.exe on a throwaway Windows machine, checks it,
  and uninstalls it again.

.DESCRIPTION
  The real thing, end to end: a silent install, then the service, `aba doctor`,
  the "Installed apps" entry, the Start menu shortcut, a second run (settings
  must survive), an older installer (must be refused), and an uninstall through
  the command Windows itself would run, after which nothing may be left.

  DO NOT run this on a PC you care about: it installs ABA, plants baits and
  removes ABA again, including an install that was already there. It is meant
  for CI runners (elevated, UAC off) and refuses to run anywhere else.
#>
param(
    # ABA-Setup.exe as GoReleaser built it.
    [Parameter(Mandatory)][string]$Setup,
    # The same installer compiled to say it holds v0.0.0, to prove an older one is refused.
    [Parameter(Mandatory)][string]$OldSetup,
    # The release's SHA256SUMS.txt.
    [Parameter(Mandatory)][string]$Sums,
    # amd64 or arm64: the aba.exe this machine must end up with.
    [Parameter(Mandatory)][ValidateSet('amd64', 'arm64')][string]$Arch,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -and -not $Force) {
    throw 'This installs and uninstalls ABA for real. It only runs on a CI runner (or with -Force, on a machine you can throw away).'
}
[Console]::OutputEncoding = [Text.UTF8Encoding]::new()

$Setup = (Resolve-Path $Setup).Path
$OldSetup = (Resolve-Path $OldSetup).Path
$installDir = Join-Path $env:ProgramFiles 'File Access Monitor'
$aba = Join-Path $installDir 'aba.exe'
$data = Join-Path $env:ProgramData 'FileAccessMonitor'
$appKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FileAccessMonitor'
$shortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\A Better Antivirus.lnk'
$logDir = Join-Path ([IO.Path]::GetTempPath()) 'aba-setup-test'
New-Item -ItemType Directory -Force $logDir | Out-Null

function Step($n) { Write-Host "`n=== $n ===" -ForegroundColor Cyan }
function Ok($m) { Write-Host "  ok    $m" -ForegroundColor Green }
function Fail($m) {
    Write-Host "  FAIL  $m" -ForegroundColor Red
    foreach ($f in Get-ChildItem $logDir -Filter *.log -ErrorAction SilentlyContinue) { Write-Host "--- $($f.Name) ---"; Get-Content $f.FullName -Tail 60 }
    if (Test-Path "$data\service.log") { Write-Host '--- service.log (tail) ---'; Get-Content "$data\service.log" -Tail 60 }
    exit 1
}
function Check($cond, $m) { if ($cond) { Ok $m } else { Fail $m } }
function WaitFor([scriptblock]$cond, [int]$seconds = 30) {
    $t = Get-Date
    while (((Get-Date) - $t).TotalSeconds -lt $seconds) { if (& $cond) { return $true }; Start-Sleep -Milliseconds 500 }
    return $false
}
function Sha([string]$p) { (Get-FileHash $p -Algorithm SHA256).Hash.ToLower() }

# Run-Setup runs an installer without showing anything and returns its exit code.
function Run-Setup([string]$exe, [string]$name, [string[]]$more = @()) {
    $log = Join-Path $logDir "$name.log"
    $argv = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=`"$log`"") + $more
    $p = Start-Process -FilePath $exe -ArgumentList $argv -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit(300000)) { $p.Kill(); Fail "${name}: the installer was still running after 5 minutes" }
    Write-Host "  $name $($more -join ' ') -> exit code $($p.ExitCode)"
    return $p.ExitCode
}
function SetupLog([string]$name) { Get-Content (Join-Path $logDir "$name.log") -Raw }
function Config { Get-Content "$data\config.json" -Raw | ConvertFrom-Json }
function BaitCount { @((Get-Content "$data\state.json" -Raw | ConvertFrom-Json).baits.PSObject.Properties).Count }
# Everything in Windows' lists of installed programs that looks like ABA or its installer.
function AppEntries {
    foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall') {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem $root | Where-Object {
            $_.PSChildName -match 'FileAccessMonitor|ABA-Setup' -or "$($_.GetValue('DisplayName'))" -match 'Better Antivirus|File Access Monitor'
        }
    }
}
function MachinePath { [Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' }

# What this release says the aba.exe for this machine is.
$expected = $null
foreach ($line in Get-Content $Sums) {
    $f = $line -split '\s+', 2
    if ($f.Count -eq 2 -and $f[1].Trim() -match "^aba_v?[^_]+_windows_$Arch\.exe$") { $expected = $f[0].ToLower() }
}
if (-not $expected) { throw "No aba_<tag>_windows_$Arch.exe in $Sums" }

# ---------------------------------------------------------------- a clean machine
Step 'Before: ABA is not on this machine'
$native = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').PROCESSOR_ARCHITECTURE
Check (($native -eq 'ARM64') -eq ($Arch -eq 'arm64')) "this machine's processor is $native, testing the $Arch build"
Check (-not (Get-Service FileAccessMonitor -ErrorAction SilentlyContinue)) 'no service'
Check (-not (Test-Path $installDir)) 'no program folder'
Check (-not @(AppEntries).Count) 'nothing in Installed apps'

# ---------------------------------------------------------------- options that can't be used
Step 'An option that tries to smuggle in more is refused'
$code = Run-Setup $Setup 'bad-option' @('/NTFYTOPIC="x --purge"')
Check ($code -ne 0) "the installer stopped (exit code $code)"
Check (-not (Test-Path $installDir) -and -not (Get-Service FileAccessMonitor -ErrorAction SilentlyContinue)) 'and installed nothing'

# ---------------------------------------------------------------- install
Step 'Silent install, with phone alerts on and automatic updates off'
$topic = 'aba-ci-' + [guid]::NewGuid().ToString('N').Substring(0, 16)
$code = Run-Setup $Setup 'install' @("/NTFYTOPIC=$topic", '/AUTOUPDATE=0')
Check ($code -eq 0) 'the installer reported success (exit code 0)'

Step 'ABA is installed and healthy'
Check (Test-Path $aba) "aba.exe is in $installDir"
Check ((Sha $aba) -eq $expected) "it is the $Arch build, byte for byte the aba_<tag>_windows_$Arch.exe of this release"
Check ((Sha (Join-Path $installDir 'famsvc.exe')) -eq $expected) 'and so is the copy the service runs'
$svc = Get-Service FileAccessMonitor -ErrorAction SilentlyContinue
Check ($svc -and $svc.Status -eq 'Running') 'the service is running'
Check ($svc.StartType -eq 'Automatic') 'and starts with Windows'
$version = ((& $aba --version) -split ' ')[-1]
Check ($version -match '^v\d') "aba --version says $version"
$doctor = (& $aba doctor 2>&1 | Out-String)
Write-Host $doctor
Check ($LASTEXITCODE -eq 0 -and $doctor -match 'Installed' -and -not $doctor.Contains([string][char]0x2717)) 'aba doctor finds no problem'
$cfg = Config
Check ($cfg.autoUpdate -eq $false) 'automatic updates are off, as asked'
Check ($cfg.preset -eq 'balanced') 'the response is Balanced'
$baits = BaitCount
Check ($baits -ge 10) "$baits baits planted"
Check ((SetupLog 'install') -match 'Sending a test to your phone') 'a phone test was sent (the ntfy topic reached ABA)'
Check ((MachinePath) -contains $installDir) 'the program folder is on PATH'

Step 'Installed apps and the Start menu'
Check (Test-Path $appKey) 'ABA has an entry in Installed apps'
$app = Get-ItemProperty $appKey
Check ($app.DisplayName -eq 'A Better Antivirus') "it is called '$($app.DisplayName)'"
Check ("v$($app.DisplayVersion)" -eq $version) "it shows version $($app.DisplayVersion)"
Check ($app.UninstallString -eq "`"$aba`" uninstall --elevated-pause") "Uninstall runs: $($app.UninstallString)"
Check ($app.QuietUninstallString -eq "`"$aba`" uninstall --yes") "the quiet form is: $($app.QuietUninstallString)"
$entries = @(AppEntries)
Check ($entries.Count -eq 1) "it is the only entry: the installer registered no uninstaller of its own ($($entries.PSChildName -join ', '))"
Check (Test-Path $shortcut) 'the Start menu has an A Better Antivirus shortcut'
$target = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcut).TargetPath
Check ($target -eq $aba) "it opens $target"

# ---------------------------------------------------------------- run it again
Step 'Running the installer again keeps every setting'
$code = Run-Setup $Setup 'again' @('/AUTOUPDATE=1', '/PRESET=strict')
Check ($code -eq 0) 'the installer reported success (exit code 0)'
Check ((SetupLog 'again') -match 'Already set up: yes') 'it saw that ABA was already set up'
$cfg = Config
Check ($cfg.autoUpdate -eq $false) 'automatic updates are still off'
Check ($cfg.preset -eq 'balanced') 'the response is still Balanced'
Check ((BaitCount) -eq $baits) "still $baits baits"
Check ((Get-Service FileAccessMonitor).Status -eq 'Running') 'the service is running again'
Check (@(AppEntries).Count -eq 1) 'still one entry in Installed apps'

# ---------------------------------------------------------------- no downgrade
Step 'An installer with an older version is refused'
Check ($version -ne 'v0.0.0') "the installed version ($version) is newer than v0.0.0"
$code = Run-Setup $OldSetup 'older'
Check ($code -ne 0) "the older installer stopped (exit code $code)"
Check ((SetupLog 'older') -match 'the installed version is newer') 'because the installed version is newer'
Check ((Sha $aba) -eq $expected) 'aba.exe was not replaced'
Check ((Get-Service FileAccessMonitor).Status -eq 'Running') 'the service is still running'

# ---------------------------------------------------------------- uninstall
Step 'Uninstall, the way Windows does it from Installed apps'
$quiet = (Get-ItemProperty $appKey).QuietUninstallString
$p = Start-Process -FilePath $env:ComSpec -ArgumentList "/d /s /c `"$quiet`"" -PassThru -NoNewWindow
$null = $p.Handle
if (-not $p.WaitForExit(300000)) { $p.Kill(); Fail 'aba uninstall was still running after 5 minutes' }
Check ($p.ExitCode -eq 0) "ran $quiet (exit code $($p.ExitCode))"

Step 'Nothing is left'
Check (-not (Get-Service FileAccessMonitor -ErrorAction SilentlyContinue)) 'the service is gone'
Check (-not @(AppEntries).Count) 'the Installed apps entry is gone'
Check (-not (Test-Path $shortcut)) 'the Start menu shortcut is gone'
Check (-not ((MachinePath) -contains $installDir)) 'the program folder is off PATH'
Check (-not (Test-Path "$data\config.json")) 'the settings are gone'
# aba.exe can't delete its own folder while it runs; a helper does it right after.
Check (WaitFor { -not (Test-Path $installDir) } 60) 'the program folder is gone'

Write-Host "`nABA-Setup.exe installs, repairs, refuses to downgrade and uninstalls cleanly ($Arch)." -ForegroundColor Green
