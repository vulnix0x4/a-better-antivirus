<#
.SYNOPSIS
  Full end-to-end test of A Better Antivirus on a disposable Windows machine.

.DESCRIPTION
  Installs ABA, runs fake stealers against it and checks every response:
  freeze, per-program block, kill, resume + ignore, release, strict-mode
  isolation (with a phone alert sent *while* isolated), bait repair, decoy
  retirement, custom baits, the autopsy of a stealer that read a real key
  before the bait (one that sent nothing, one that sent something after) and
  of one that didn't, and a complete uninstall.

  DO NOT run this on a PC you care about: it isolates the network for a few
  seconds and changes system settings. It's meant for CI runners.
#>
param(
    [string]$Aba = (Join-Path $PSScriptRoot '..\dist\aba.exe'),
    [string]$Medium = (Join-Path $PSScriptRoot '..\dist\medium.exe'),
    [string]$Ghost = (Join-Path $PSScriptRoot '..\dist\ghost.exe')
)

$ErrorActionPreference = 'Stop'
$Aba  = (Resolve-Path $Aba).Path
$Medium = (Resolve-Path $Medium).Path
$Ghost = (Resolve-Path $Ghost).Path
$data = Join-Path $env:ProgramData 'FileAccessMonitor'
$installDir = Join-Path $env:ProgramFiles 'File Access Monitor'
$fsGuid = '{0CCE921D-69AE-11D9-BED3-505054503030}'
$topic = 'aba-ci-' + [guid]::NewGuid().ToString('N').Substring(0, 16)
$started = Get-Date
$script:failures = 0

# Live progress outside the machine: if the runner becomes unreachable (it has,
# twice, with no log), the last steps and service log lines are still readable
# at https://ntfy.sh/<progress topic>. Test output only; nothing secret.
$progress = if ($env:GITHUB_RUN_ID) { "aba-ci-progress-$($env:GITHUB_RUN_ID)" } else { $null }
function Report([string]$m) {
    if (-not $progress) { return }
    try { Invoke-RestMethod -Method Post -Uri "https://ntfy.sh/$progress" -Body $m -TimeoutSec 5 | Out-Null } catch {}
}
if ($progress) {
    Write-Host "Live progress: https://ntfy.sh/$progress"
    # Background reporter: ships new service.log lines every 10 s.
    Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -ArgumentList '-NoProfile', '-Command', @"
`$seen = 0
while (`$true) {
  Start-Sleep 10
  `$f = '$data\service.log'
  if (Test-Path `$f) {
    `$lines = @(Get-Content `$f)
    if (`$lines.Count -gt `$seen) {
      `$new = (`$lines[`$seen..(`$lines.Count - 1)] | Where-Object { `$_ -notmatch 'woke at once' }) -join "`n"
      try { Invoke-RestMethod -Method Post -Uri 'https://ntfy.sh/$progress' -Body ('LOG ' + `$new) -TimeoutSec 5 | Out-Null; `$seen = `$lines.Count } catch {}
    }
  }
}
"@ | Out-Null
}

function Step($n) { Write-Host "`n=== $n ===" -ForegroundColor Cyan; Report "=== $n" }
# (Passed checks aren't reported: ntfy.sh limits requests per address, and the
# phone-alert checks below need that allowance.)
function Ok($m)   { Write-Host "  ok  $m" -ForegroundColor Green }
# Processes a step started that must not outlive a failed check (a browser
# and what started it): ended, with what they started, before Fail exits.
$script:leftovers = @()
function EndLeftovers {
    foreach ($p in $script:leftovers) { if ($p) { & taskkill.exe /T /F /PID $p 2>&1 | Out-Null } }
    $script:leftovers = @()
}
function Fail($m) {
    Write-Host "  FAIL $m" -ForegroundColor Red
    Report "FAIL $m"
    EndLeftovers
    # Never leave the runner isolated or anything frozen: it would go offline
    # and GitHub could neither cancel the job nor show its log.
    $r = Start-Process -FilePath $Aba -ArgumentList 'release' -NoNewWindow -PassThru
    if (-not $r.WaitForExit(60000)) { $r.Kill() }
    if (Test-Path "$data\service.log") { Write-Host '--- service.log (tail) ---'; Get-Content "$data\service.log" -Tail 120 }
    if (Test-Path "$data\crash.log") {
        # Every service start adds a "--- service ... started" line; anything after
        # one is that instance crashing. The reason is in a crash's first lines
        # (the rest is one stack per goroutine), so print how each crash begins.
        Write-Host '--- crash.log ---'
        $lines = @(Get-Content "$data\crash.log")
        $starts = @(for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -like '--- service * started *') { $i } })
        for ($i = 0; $i -lt $starts.Count; $i++) {
            $from = $starts[$i]
            $to = if ($i + 1 -lt $starts.Count) { $starts[$i + 1] - 1 } else { $lines.Count - 1 }
            if ($to -gt $from) {
                Write-Host "--- a crash ($($to - $from) lines; the first 80 follow) ---"
                $lines[$from..([Math]::Min($to, $from + 80))]
            }
        }
    }
    exit 1
}

# Safety net while the machine is isolated: a separate process that runs
# `aba release` after $seconds even if this script dies or hangs.
function ReleaseWatchdog([int]$seconds) {
    $topicArg = if ($progress) { $progress } else { '' }
    $script = @"
Start-Sleep $seconds
function Say(`$m) { if ('$topicArg') { try { Invoke-RestMethod -Method Post -Uri 'https://ntfy.sh/$topicArg' -Body ('WATCHDOG ' + `$m) -TimeoutSec 5 | Out-Null } catch {} } }
for (`$i = 1; `$i -le 4; `$i++) {
  `$out = & '$Aba' release 2>&1 | Out-String
  & curl.exe -s -o NUL --max-time 8 https://www.microsoft.com
  if (`$LASTEXITCODE -eq 0) { Say "release attempt `$i restored the network: `$out"; exit }
  if (`$i -eq 2) { sc.exe stop FileAccessMonitor | Out-Null; Start-Sleep 5 }
  Start-Sleep 10
}
Say 'could not restore the network'
"@
    Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -ArgumentList '-NoProfile', '-Command', $script -PassThru
}
function Check($cond, $m) { if ($cond) { Ok $m } else { Fail $m } }
# Every aba call gets a deadline: a hang fails fast with the service log.
function Aba {
    $argline = ($args | ForEach-Object { if ("$_" -match '\s') { '"' + $_ + '"' } else { "$_" } }) -join ' '
    $p = Start-Process -FilePath $Aba -ArgumentList $argline -NoNewWindow -PassThru
    $null = $p.Handle
    if (-not $p.WaitForExit(120000)) {
        Write-Host "  aba $argline is still running after 2 minutes; frozen processes:" -ForegroundColor Red
        if (Test-Path "$data\state.json") { (Get-Content "$data\state.json" -Raw | ConvertFrom-Json).frozen | Format-Table | Out-Host }
        $p.Kill()
        Fail "aba $argline hung"
    }
    if ($p.ExitCode) { Fail "aba $argline exited $($p.ExitCode)" }
}

function Alerts { if (Test-Path "$data\alerts") { Get-ChildItem "$data\alerts\*.json" | Sort-Object Name | ForEach-Object { Get-Content $_ -Raw | ConvertFrom-Json } } }
function WaitFor([scriptblock]$cond, [int]$seconds = 20) {
    $t = Get-Date
    while (((Get-Date) - $t).TotalSeconds -lt $seconds) {
        $r = & $cond
        if ($r) { return $r }
        Start-Sleep -Milliseconds 300
    }
    return $null
}
# Windows hands out the ID of a program that has exited to the next one soon
# after, so an alert from an earlier test program can carry the ID of the one
# under test. Snap (called just before a test program starts) notes the alerts
# so far; Fresh is the alerts made since, which are the only ones about it.
$script:known = @{}
function Snap { $script:known = @{}; foreach ($x in @(Alerts)) { $script:known[$x.id] = $true } }
function Fresh { Alerts | Where-Object { -not $script:known.ContainsKey($_.id) } }
function AlertFor([int]$procId, [int]$seconds = 20) { WaitFor { Fresh | Where-Object { $_.process.pid -eq $procId } | Select-Object -Last 1 } $seconds }
function State { Get-Content "$data\state.json" -Raw | ConvertFrom-Json }
# A command that changes settings tells the service to re-read them and returns
# at once; the service takes them in a moment later (about a second here). A
# step that depends on the new settings waits for that, or it races the service:
#   $reloads = Reloads; Aba trust ...; WaitReloaded $reloads
function Reloads { @(Select-String -Path "$data\service.log" -Pattern 'configuration reloaded' -ErrorAction SilentlyContinue).Count }
function WaitReloaded([int]$since) {
    if (-not (WaitFor { (Reloads) -gt $since } 15)) { Fail 'the service did not take in the new settings within 15 s' }
}
function Did($alert, $action) { [bool]($alert.actions | Where-Object { $_.action -eq $action -and $_.ok }) }

# A fake stealer: a copy of aba.exe in Temp (unsigned, user-writable -> critical)
# that reads a bait and then waits around.
# Like real stealers it runs as the normal user at medium integrity (not admin;
# scripts/medium does that from the elevated runner), and a few random bytes
# make its hash differ from ABA's, so it isn't recognised as ABA itself.
function Stealer([string]$name, [string]$bait, [switch]$Again) {
    $exe = Join-Path $env:TEMP "$name.exe"
    if (-not $Again) {   # -Again: run the same file again (same fingerprint)
        # A previous copy may still be exiting (Stop-Process doesn't wait).
        for ($i = 0; ; $i++) {
            try { Copy-Item $Aba $exe -Force -ErrorAction Stop; break }
            catch { if ($i -ge 30) { throw }; Start-Sleep -Milliseconds 300 }
        }
        [IO.File]::AppendAllText($exe, [guid]::NewGuid().ToString())
    }
    Snap
    $procId = & $Medium $exe test-reader $bait
    if ($LASTEXITCODE -or -not $procId) { Fail "fake stealer $name didn't start" }
    $p = Get-Process -Id ([int]$procId) -ErrorAction SilentlyContinue
    if (-not $p) { Fail "fake stealer $name exited immediately" }
    return $p
}
function IsSuspended([int]$procId) {
    $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if (-not $p) { return $false }
    foreach ($t in $p.Threads) {
        try { if ($t.ThreadState -ne 'Wait' -or $t.WaitReason -ne 'Suspended') { return $false } } catch { return $false }
    }
    return $true
}
function Online {
    foreach ($u in "https://www.microsoft.com", "https://github.com") { & curl.exe -s -o NUL --max-time 8 $u; if ($LASTEXITCODE -eq 0) { return $true } }
    return $false
}
# The miner trap's name rules (NRPT), and where a name leads.
function TrapRules {
    foreach ($k in 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig') {
        Get-ChildItem $k -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like '{ABA0A0A0-*' }
    }
}
function Resolves([string]$name) {
    Clear-DnsClientCache
    @(Resolve-DnsName $name -Type A -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.IP4Address } | ForEach-Object { $_.IP4Address })
}
$trapIP = '127.97.98.97'
function WfpRules {
    $f = Join-Path $env:TEMP 'wfp.xml'
    netsh wfp show filters file="$f" | Out-Null
    (Select-String -Path $f -Pattern '<name>ABA: ' -AllMatches).Matches.Count
}
# ntfy returns one JSON object per line; read the raw text (Invoke-RestMethod
# would auto-parse a single line into an object).
# Spaced out and forgiving: ntfy.sh limits requests per address, and a refused
# poll means "ask again later", not a failed test.
function NtfyMessages {
    Start-Sleep -Seconds 2
    try { $raw = (Invoke-WebRequest "https://ntfy.sh/$topic/json?poll=1&since=all" -UseBasicParsing -TimeoutSec 15).Content }
    catch { Write-Host "  (ntfy poll refused, trying again)" -ForegroundColor DarkGray; Start-Sleep -Seconds 6; return }
    if ($raw -is [byte[]]) { $raw = [Text.Encoding]::UTF8.GetString($raw) }
    $raw -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object event -eq 'message'
}
function AuditFS { (auditpol /get /subcategory:"$fsGuid" /r | ConvertFrom-Csv).'Inclusion Setting' }

# ---------------------------------------------------------------------------
Step 'Baseline'
$auditBefore = AuditFS
Ok "audit policy before install: $auditBefore"
Check (WaitFor { Online } 45) 'machine is online'
# A real-looking secret for the flight recorder to watch: a private key of
# this user's, there since before the install (fake, made for this test).
$sshDir = Join-Path $env:USERPROFILE '.ssh'
$realKey = Join-Path $sshDir 'id_e2e_real'
New-Item -ItemType Directory -Force $sshDir | Out-Null
if (Test-Path $realKey) { Fail "$realKey exists already" }
Set-Content -Path $realKey -Value "-----BEGIN OPENSSH PRIVATE KEY-----`nnot a real key: ABA end-to-end test`n-----END OPENSSH PRIVATE KEY-----" -NoNewline
# The flight recorder's audit rule: read data, by Everyone, inherited by the
# files directly in the folder only. (See winsec.SetRecorderAudit.)
# Compared as numbers and by SID, not by name: "read data" and "list folder"
# are the same bit, and which of the two names .NET prints isn't fixed.
# (Inheritance 2 is "the files in it"; propagation 3 is "only those, and not
# the folder itself".)
function RecorderRule([string]$dir) {
    @((Get-Acl -Audit $dir).GetAuditRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | Where-Object {
        $_.IdentityReference.Value -eq 'S-1-1-0' -and [int]$_.FileSystemRights -eq 1 -and
        ([int]$_.AuditFlags -band 1) -and [int]$_.InheritanceFlags -eq 2 -and [int]$_.PropagationFlags -eq 3 })
}
# What to print when a check on the rule fails.
function RecorderRuleReport([string]$dir) {
    "  audit rules on ${dir}:" | Out-Host
    (Get-Acl -Audit $dir).GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
        "    $($_.IdentityReference.Value) rights=$([int]$_.FileSystemRights) ($($_.FileSystemRights)) audit=$($_.AuditFlags) inherit=$($_.InheritanceFlags) propagate=$($_.PropagationFlags) inherited=$($_.IsInherited)" } | Out-Host
    "  recorder folders on record: $(((State).recorderDirs) -join '; ')" | Out-Host
}
Check ((RecorderRule $sshDir).Count -eq 0) 'no audit rule of ABA''s on the .ssh folder before the install'
# A browser that has been used, so that ABA plants its fake profile inside it:
# the runner has Chrome and Edge installed, but its user has never run them
# (no "User Data\Local State"). Run the first one found once, headless, on its
# default data folder; if it still left no Local State, write a minimal one.
$browsers = @(
    @{ id = 'chrome-profile'; name = 'Chrome'; exe = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"; ud = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
    @{ id = 'chrome-profile'; name = 'Chrome'; exe = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"; ud = "$env:LOCALAPPDATA\Google\Chrome\User Data" },
    @{ id = 'edge-profile'; name = 'Edge'; exe = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"; ud = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" },
    @{ id = 'edge-profile'; name = 'Edge'; exe = "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"; ud = "$env:LOCALAPPDATA\Microsoft\Edge\User Data" }
) | Where-Object { $_.exe -and (Test-Path $_.exe) }
$hostBrowser = $browsers | Select-Object -First 1
if ($hostBrowser) {
    $ls = Join-Path $hostBrowser.ud 'Local State'
    if (-not (Test-Path $ls)) {
        $hb = Start-Process -FilePath $hostBrowser.exe -PassThru -WindowStyle Hidden -ArgumentList '--headless=new', '--no-first-run', '--no-default-browser-check', '--disable-gpu', "--user-data-dir=`"$($hostBrowser.ud)`"", '--dump-dom', 'about:blank'
        if (-not $hb.WaitForExit(45000)) { & taskkill.exe /T /F /PID $hb.Id | Out-Null }
        Start-Sleep -Seconds 2
    }
    if (-not (Test-Path $ls)) {
        New-Item -ItemType Directory -Force $hostBrowser.ud | Out-Null
        Set-Content -Path $ls -Value '{"profile":{"info_cache":{"Default":{"name":"Person 1"}}}}' -NoNewline
        Ok "$($hostBrowser.name) left no Local State after a headless run: wrote a minimal one"
    }
    Ok "$($hostBrowser.name) has been used on this machine ($ls)"
} else {
    Ok 'no Chrome or Edge here: the fake-profile-inside-a-browser steps will be skipped'
}

Step 'Install (balanced, no learning, ntfy phone alerts)'
Aba install --yes --preset balanced --learning 0 --ntfy-topic $topic
Check ((Get-Service FileAccessMonitor).Status -eq 'Running') 'service running'
$st = State
$desktopBait = ($st.baits.'desktop-passwords'.files | Select-Object -First 1).path
Check (Test-Path $desktopBait) "desktop bait planted: $desktopBait"
Check (@($st.baits.PSObject.Properties).Count -ge 10) "$(@($st.baits.PSObject.Properties).Count) baits planted"
Check ((AuditFS) -match 'Success') 'file auditing on'
$cfg = Get-Content (Join-Path $data 'config.json') -Raw | ConvertFrom-Json
Check ($cfg.autoUpdate -eq $true) 'auto-update on by default'
Check (-not $cfg.clipboardBait -and -not $cfg.minerTrap) 'a silent install leaves both traps off'
Check ($cfg.version -ge 2) 'config is version 2'
Aba update --check
Aba doctor
Aba phone test

Step 'A program without admin rights can''t read where the baits are'
# state.json lists every bait, config.json every program you trusted: reading
# them was the cheapest way around ABA. -lua: no administrator membership.
$peek = Join-Path $env:TEMP 'aba-peek.txt'
foreach ($f in 'state.json', 'config.json', 'service.log') {
    Remove-Item $peek -ErrorAction SilentlyContinue
    & $Medium -lua -raw "$env:SystemRoot\System32\cmd.exe" "cmd /c type '$data\$f' > '$peek' 2>&1" | Out-Null
    Check (WaitFor { Test-Path $peek } 10) "tried to read $f without admin rights"
    Start-Sleep -Milliseconds 500
    Check (-not (Select-String -Path $peek -Pattern 'passwords|baits|watching' -Quiet)) "$f can't be read without admin rights"
}
# (The service publishes it at the end of its first health check.)
Check (WaitFor {
    Remove-Item $peek -ErrorAction SilentlyContinue
    & $Medium -lua -raw "$env:SystemRoot\System32\cmd.exe" "cmd /c type '$data\public\status.json' > '$peek' 2>&1" | Out-Null
    Start-Sleep -Milliseconds 800
    (Test-Path $peek) -and (Select-String -Path $peek -Pattern 'heartbeat' -Quiet)
} 70) 'the public status (no bait names or paths) can'
Check (-not (Select-String -Path $peek -Pattern ([regex]::Escape($env:USERPROFILE)) -Quiet)) 'and it names no path in your profile'
Check (-not (Select-String -Path $peek -Pattern 'preset|responses|balanced|learning' -Quiet)) 'nor how ABA is set to respond'
# Windows lets every signed-in user send a service custom commands; one of
# ABA's starts a full health check. Only administrators may send them now.
Remove-Item $peek -ErrorAction SilentlyContinue
& $Medium -lua -raw "$env:SystemRoot\System32\cmd.exe" "cmd /c sc.exe control FileAccessMonitor 128 > '$peek' 2>&1" | Out-Null
Check (WaitFor { (Test-Path $peek) -and (Select-String -Path $peek -Pattern 'FAILED 5|denied' -Quiet) } 10) "a program without admin rights can't send the service commands"
Check (-not ((sc.exe qdescription FileAccessMonitor | Out-String) -match 'decoy|Antivirus')) "the service's description doesn't say what it's for"
& $Aba status --once | Out-Null
Check (WaitFor { NtfyMessages | Where-Object title -match 'test alert' } 60) 'phone test alert arrived on ntfy'

Step 'Built-in safe test'
Aba test

Step 'Clipboard bait: a fake clipper is caught, and the clipboard put back'
$reloads = Reloads
Aba clipboard on
WaitReloaded $reloads
Check (WaitFor { Select-String -Path "$data\service.log" -Pattern 'clipboard bait: guarding session' -Quiet } 90) 'a clipboard guard runs in the desktop session'
$copied = $null
# clip.exe hands the text over as it copies it. (Set-Clipboard only promises
# it, to be handed over when asked, and this script is too busy to answer.)
cmd /c 'echo text the test copied| clip'
if ($LASTEXITCODE -eq 0) { $copied = 'text the test copied' } else { Write-Host '  (no clipboard here)' }
Snap
Aba clipboard test
$clip = Fresh | Where-Object { $_.test -and $_.baits -and $_.baits[0].access -eq 'swap' } | Select-Object -Last 1
Check $clip 'the fake clipper was caught swapping the fake wallet address'
if ($copied) {
    Check (WaitFor { "$(Get-Clipboard)".Trim() -eq $copied } 15) 'the clipboard was put back afterwards'
}
$reloads = Reloads
Aba clipboard off
WaitReloaded $reloads
Start-Sleep -Seconds 3   # let the guard go, and everything settle, before the next fake stealer

Step 'Miner trap: pool names lead to a fake pool, a fake miner is caught, nothing else changes'
$poolBefore = Resolves 'pool.supportxmr.com'
Check (-not ($poolBefore -contains $trapIP)) "trap off: a pool's name resolves normally ($($poolBefore -join ', '))"
Check (-not @(TrapRules).Count) 'trap off: no name rules'
$reloads = Reloads
Aba miners on
WaitReloaded $reloads
Check (WaitFor { @(TrapRules).Count -gt 0 } 60) "the name rules are in place ($(@(TrapRules).Count))"
Check (WaitFor { (Resolves 'pool.supportxmr.com') -contains $trapIP } 60) 'pool.supportxmr.com leads to the trap'
Check ((Resolves 'pool.hashvault.pro') -contains $trapIP) 'so does pool.hashvault.pro'
Check ((Resolves 'xmr-eu1.nanopool.org') -contains $trapIP) 'and a name under another pool'
foreach ($n in 'www.microsoft.com', 'github.com', 'f2pool.com', 'ntfy.sh') {
    $ips = Resolves $n
    Check ($ips.Count -gt 0 -and -not ($ips -contains $trapIP)) "$n still resolves normally ($($ips -join ', '))"
}
Check (Online) 'the internet still works'
Snap
Aba miners test
$mine = Fresh | Where-Object { $_.test -and $_.baits -and $_.baits[0].access -eq 'mine' } | Select-Object -Last 1
Check $mine "the fake miner was caught logging in at the fake pool ($($mine.title))"
Check (Did $mine 'freeze') 'it was frozen'
Check (($mine.verdict.reasons -join ' ') -match 'ABA-TEST-not-a-real-wallet') 'the alert names the wallet it mines for'
# A browser opening a pool's website gets a page saying why, and isn't caught.
# (Over HTTPS: port 80 can be held by Windows' own web server, as on CI
# runners, and the trap then does without it. -k: the trap's certificate is
# its own, which a browser warns about first.)
Snap
$page = (& curl.exe -sk --max-time 10 https://supportxmr.com/) -join "`n"
Check ($page -match 'miner trap') 'a pool''s website explains why it doesn''t open'
Start-Sleep -Seconds 2
Check (-not @(Fresh | Where-Object { $_.baits -and $_.baits[0].access -eq 'mine' }).Count) 'and opening it isn''t taken for mining'
$reloads = Reloads
Aba miners off
WaitReloaded $reloads
Check (-not @(TrapRules).Count) 'off: no name rules are left'
Check (WaitFor { $r = Resolves 'pool.supportxmr.com'; $r.Count -gt 0 -and -not ($r -contains $trapIP) } 30) 'off: pool names resolve normally again'
Start-Sleep -Seconds 3   # let everything settle before the next fake stealer

Step 'Real stealer: frozen, blocked, then killed'
$s1 = Stealer 'stealer1' $desktopBait
$a1 = AlertFor $s1.Id
Check ($a1) "alert raised ($($a1.id))"
Check ($a1.tier -eq 'critical') "tier critical: $($a1.summary)"
Check (Did $a1 'freeze') "froze it ($($a1.latencyMs) ms after the read, delivery $($a1.deliveryMs) ms)"
Check (Did $a1 'block-program') 'blocked its internet'
Check (WaitFor { IsSuspended $s1.Id } 5) 'process really is suspended'
Check ((WfpRules) -gt 0) 'WFP block rules present'
Check ((State).frozen.pid -contains $s1.Id) 'state lists it as frozen'
$sess = (Get-Process -Id $s1.Id -ErrorAction SilentlyContinue).SessionId
Ok "stealer ran in session $sess as a normal (medium-integrity) process"
if ($sess -eq 0) {
    Ok 'instant freeze deliberately skips session 0 (services); caught via the event log instead'
} else {
    Check ($a1.instant -eq $true) "instant freeze: caught the moment it opened the bait (frozen $($a1.latencyMs) ms after the open)"
}
$tree = @($s1.Id) + @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($s1.Id)" | ForEach-Object ProcessId)
# Only processes that still exist count (the `aba test` reader is killed by design).
$innocent = @((State).frozen | Where-Object { $tree -notcontains $_.pid -and (Get-Process -Id $_.pid -ErrorAction SilentlyContinue) })
Check ($innocent.Count -eq 0) "no innocent process frozen (frozen: $(((State).frozen.image) -join ', '))"
Select-String -Path "$data\service.log" -Pattern 'instant' | ForEach-Object { "  log: " + $_.Line } | Out-Host
Aba alerts show $a1.id
Aba kill $a1.id
Check (WaitFor { -not (Get-Process -Id $s1.Id -ErrorAction SilentlyContinue) } 10) 'killed'
Check (WaitFor { NtfyMessages | Where-Object { $_.message -match $a1.id } } 60) 'critical alert reached the phone (ntfy)'

Step 'Stealer running as administrator: frozen the moment it opens the bait'
# Real stealers (Umbral, Blank Grabber) make themselves administrator first,
# with the admin prompt or a way around it. Instant freeze used to let every
# program running as administrator through, so they were only caught by the
# event log, a second later. This one keeps the runner's admin token.
$exe = Join-Path $env:TEMP 'stealer-admin.exe'
Copy-Item $Aba $exe -Force
[IO.File]::AppendAllText($exe, [guid]::NewGuid().ToString())
Snap
$sa = Start-Process -FilePath $exe -ArgumentList 'test-reader', "`"$desktopBait`"" -PassThru -WindowStyle Hidden
$aa = AlertFor $sa.Id
Check ($aa -and $aa.tier -eq 'critical' -and (Did $aa 'freeze')) "caught and frozen ($($aa.id), $($aa.latencyMs) ms)"
if ($sess -eq 0) {
    Ok 'instant freeze deliberately skips session 0 (services); caught via the event log instead'
} else {
    Check ($aa.instant -eq $true) "running as administrator, still caught the moment it opened the bait (frozen $($aa.latencyMs) ms after the open)"
}
Select-String -Path "$data\service.log" -Pattern "pid $($sa.Id)\b" | ForEach-Object { "  log: " + $_.Line } | Out-Host
if ($aa) { Aba kill $aa.id }
Check (WaitFor { -not (Get-Process -Id $sa.Id -ErrorAction SilentlyContinue) } 10) 'killed'
Start-Sleep -Seconds 2

Step 'Autopsy: a stealer that read a real key before the bait'
# The answer has to be "it read your real SSH keys", with the evidence saved,
# the bot token in its memory found, and a shareable file with nothing of yours.
if (-not (WaitFor { (RecorderRule $sshDir).Count -eq 1 } 30)) { RecorderRuleReport $sshDir }
Check ((RecorderRule $sshDir).Count -eq 1) 'the flight recorder''s audit rule is on the .ssh folder'
$token = '7134567890:AAHk3n2Lq9xZr8Yv6Tt5Ww4Uu3Ss2Rr1Qq0'
# Readers: copies of aba.exe (unsigned, in Temp) running test-reader, which
# reads each file it's given in turn, then waits to be frozen.
function Reader([string]$name, [string[]]$files, [string]$beacon, [string]$do, [string]$send) {
    $exe = Join-Path $env:TEMP "$name.exe"
    Copy-Item $Aba $exe -Force
    [IO.File]::AppendAllText($exe, [guid]::NewGuid().ToString())
    Snap
    $readerArgs = @($exe, 'test-reader')
    if ($beacon) { $readerArgs += @('--beacon', $beacon) }
    if ($do) { $readerArgs += @('--do', $do) }   # overwrite | delete, instead of reading
    if ($send) { $readerArgs += @('--send', $send) }   # sends to it after the first file
    $procId = & $Medium @readerArgs @files
    if ($LASTEXITCODE -or -not $procId) { Fail "fake stealer $name didn't start" }
    return [int]$procId
}
function Autopsied([string]$id, [int]$seconds = 40) {
    WaitFor { Alerts | Where-Object { $_.id -eq $id -and $_.autopsy -and -not "$($_.autopsy.finished)".StartsWith('0001') } | Select-Object -Last 1 } $seconds
}
$pa = Reader 'stealer-a' @($realKey, $desktopBait) "https://api.telegram.org/bot$token/sendDocument"
$aa = AlertFor $pa
Check ($aa -and $aa.tier -eq 'critical' -and (Did $aa 'freeze')) "the stealer that read a real key first is caught and frozen ($($aa.id))"
$aa = Autopsied $aa.id
Check ($aa) 'its autopsy finished'
Check ($aa.autopsy.answer -eq 'read') "the autopsy says it read real data: $($aa.autopsy.headline) $($aa.autopsy.unsure -join ' ')"
Check (@($aa.autopsy.reads | Where-Object { $_.path -match 'id_e2e_real' }).Count -ge 1) "the real key is among what it read: $(($aa.autopsy.reads.path) -join ', ')"
# It sent nothing: the network record proves nothing left, so there's nothing to change.
Check ($aa.autopsy.sent -eq 'nothing') "nothing left the PC (answer 1): $($aa.autopsy.headline) | $($aa.autopsy.sentWhy -join ' | ') | sends: $(($aa.autopsy.sends | ForEach-Object { "$($_.pid) $($_.name) $($_.to)" }) -join ', ')"
Check ($aa.autopsy.headline -match 'nothing left this' -and -not $aa.autopsy.steps) "so it says there's nothing to change: $($aa.autopsy.headline)"
Check (@($aa.autopsy.addresses | Where-Object { $_.kind -eq 'telegram-bot' -and $_.value -eq $token }).Count -eq 1) "the bot token in its memory was found ($($aa.autopsy.memoryScanned) bytes looked through) $($aa.autopsy.notes -join ' ')"
$ev = Join-Path $data "evidence\$($aa.id)"
Check ((Test-Path "$ev\README.txt") -and (Test-Path "$ev\autopsy.json") -and @(Get-ChildItem "$ev\program\*.sample").Count -eq 1) "evidence saved to $ev"
Aba autopsy $aa.id
$ioc = Join-Path $env:TEMP 'aba-ioc.json'
Aba export-ioc $aa.id -o $ioc
$iocText = Get-Content $ioc -Raw
$iocJson = $iocText | ConvertFrom-Json
Check ($iocJson.file.sha256.Length -eq 64 -and $iocJson.sendingTo.value -contains $token) 'export-ioc: the fingerprint and the bot token'
Check (-not $iocText.Contains($env:USERPROFILE) -and -not $iocText.Contains($env:USERPROFILE.Replace('\', '\\')) -and -not $iocText.Contains('BEGIN OPENSSH')) 'and nothing of yours'
Aba kill $aa.id
Check (Test-Path "$ev\autopsy.json") 'the evidence outlives aba kill'

Step 'Autopsy: a stealer that sent something after reading a real key'
# It reads the real key, posts to example.com, then opens the bait: answer 2,
# where it sent and what to do.
$pc = Reader 'stealer-c' @($realKey, $desktopBait) '' '' 'http://example.com/'
$ac = AlertFor $pc
Check ($ac -and (Did $ac 'freeze')) "caught and frozen ($($ac.id))"
$ac = Autopsied $ac.id
Check ($ac) 'its autopsy finished'
Check ($ac.autopsy.answer -eq 'read' -and $ac.autopsy.sent -eq 'sent') "it read real data and sent something (answer 2): $($ac.autopsy.headline) | $($ac.autopsy.sentWhy -join ' | ')"
Check (@($ac.autopsy.sends | Where-Object { $_.after -and $_.to -match ':80$' }).Count -ge 1) "the send to example.com is listed: $(($ac.autopsy.sends | ForEach-Object { "$($_.name) $($_.to) $($_.bytesAfter) B" }) -join ', ')"
Check ($ac.autopsy.headline -match 'connected to' -and $ac.autopsy.headline -match 'Act on it now') "the headline says where it connected: $($ac.autopsy.headline)"
Check ($ac.autopsy.steps[0] -match 'SSH') "the first thing to do is about the SSH keys: $($ac.autopsy.steps[0])"
Aba autopsy $ac.id

Step 'The full report opens as a page, once, and leaves no copy behind'
# `aba report` hands the page to the browser from 127.0.0.1, once, at a random
# address; --no-browser prints the address instead (this runner has no one at
# its screen). The report names bait files, so no copy may be left anywhere
# a program running as the user could read it.
$tempDirs = @($env:TEMP, (Join-Path $env:LOCALAPPDATA 'Temp'), (Join-Path $env:SystemRoot 'Temp')) | Select-Object -Unique
function PageFiles { foreach ($d in $tempDirs) { Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '^\.(html?|mht)$' } | ForEach-Object FullName } }
function ReportPage([string[]]$cmd) {
    $out = Join-Path $env:TEMP ("aba-report-out-" + [guid]::NewGuid().ToString('N') + '.txt')
    $p = Start-Process -FilePath $Aba -ArgumentList (($cmd + '--no-browser') -join ' ') -RedirectStandardOutput $out -NoNewWindow -PassThru
    $null = $p.Handle
    $url = WaitFor { if (Test-Path $out) { (Get-Content $out -ErrorAction SilentlyContinue | Where-Object { $_ -match '^http://127\.0\.0\.1:\d+/[0-9a-f]{32}$' } | Select-Object -First 1) } } 30
    if (-not $url) { Get-Content $out -ErrorAction SilentlyContinue | Out-Host; $p.Kill(); Fail "aba $($cmd -join ' ') printed no address" }
    $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 20
    $again = $null
    try { $again = (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10).StatusCode } catch { $again = 'gone' }
    $ended = $p.WaitForExit(20000)
    if (-not $ended) { $p.Kill() }
    $page = [System.Net.WebUtility]::HtmlDecode($r.Content)
    Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue
    return [pscustomobject]@{ Url = $url; Status = $r.StatusCode; Page = $page; Raw = $r.Content; CacheControl = "$($r.Headers['Cache-Control'])"; Again = $again; Ended = $ended; ExitCode = $p.ExitCode }
}
$pagesBefore = @(PageFiles)
$rp = ReportPage @('report', $ac.id)
Check ($rp.Status -eq 200 -and $rp.Page.Contains($ac.autopsy.headline)) "aba report $($ac.id): the page has the headline ($($rp.Url))"
Check ($rp.Page.Contains('What it sent over the network') -and $rp.Page.Contains("aba kill $(($ac.id -split '-')[-1])")) 'and the rest of the report: where it sent, and how to end it'
Check (-not ($rp.Raw -match '<script|https?://(?!127\.0\.0\.1)[^"\s<]+\.(js|css|woff2?|png|svg)')) 'the page runs no script and loads nothing from anywhere'
Check ($rp.CacheControl -match 'no-store') 'the browser is told not to keep a copy (no-store)'
Check ($rp.Again -ne 200) "the address works once: a second load gets nothing ($($rp.Again))"
Check ($rp.Ended -and $rp.ExitCode -eq 0) 'aba report ends once the page was loaded'
$ri = ReportPage @('reports')
Check ($ri.Status -eq 200 -and $ri.Page.Contains($ac.id) -and $ri.Page.Contains($aa.id)) 'aba reports lists the reports (this one and the first stealer''s)'
Check ($ri.Again -ne 200 -and $ri.Ended) 'and works once too'
$leftover = @(PageFiles | Where-Object { $pagesBefore -notcontains $_ })
Check ($leftover.Count -eq 0) "no copy of a report page left in a temp folder $($leftover -join ', ')"
$nowAt = Get-Date
$lasting = @(foreach ($d in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('MyDocuments'), (Join-Path $env:USERPROFILE 'Downloads'))) {
    # (Names and dates only: nothing here is opened, the baits are among them.)
    Get-ChildItem -LiteralPath $d -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt $nowAt.AddMinutes(-3) -and $_.Extension -match '^\.(html?|mht)$' } | ForEach-Object FullName
})
Check ($lasting.Count -eq 0) "nor on the Desktop, in Documents or Downloads $($lasting -join ', ')"
Aba kill $ac.id

Step 'Autopsy: a stealer that only touched the bait'
$pb = Reader 'stealer-b' @($desktopBait) ''
$ab = AlertFor $pb
Check ($ab -and (Did $ab 'freeze')) "caught and frozen ($($ab.id))"
$ab = Autopsied $ab.id
Check ($ab) 'its autopsy finished'
Check ($ab.autopsy.answer -ne 'read') "it isn't said to have read anything real: $($ab.autopsy.headline)"
Check (@($ab.autopsy.watched | Where-Object { $_.store -eq 'ssh' -and $_.watched }).Count -eq 1) "the SSH keys were watched the whole time it ran"
if ($ab.autopsy.answer -eq 'no-sign') {
    Ok $ab.autopsy.headline
} else {
    # Browsers on this runner may update in the background and make a new
    # folder, which ABA only watches from its next check: then "can't tell"
    # is the honest answer, as long as it isn't about what was watched.
    Check ($ab.autopsy.answer -eq 'cannot-tell' -and -not (($ab.autopsy.unsure -join ' ') -match 'SSH')) "can't tell, for reasons that aren't the SSH keys: $($ab.autopsy.unsure -join ' | ')"
}
Aba kill $ab.id

Step 'Ransomware: a program that goes to overwrite a bait is stopped'
# It opens the bait only to write to it: nothing to steal that way, and what
# ransomware does to every file. A bait in Documents, where it would walk.
$docBait = @((State).baits.PSObject.Properties.Value | ForEach-Object { $_.files.path } | Where-Object { $_ -like "$env:USERPROFILE\Documents\*" }) | Select-Object -First 1
if (-not $docBait) { Fail 'no bait in Documents to try this on' }
$pw = Reader 'locker-a' @($docBait) '' 'overwrite'
$aw = AlertFor $pw
Check ($aw -and $aw.tier -eq 'critical' -and (Did $aw 'freeze')) "caught and frozen ($($aw.id)): $($aw.title)"
# Windows doesn't always say what an open asked for; then it's caught as an
# open, and the alert says what it did once the event log does.
$aw = WaitFor { Alerts | Where-Object { $_.id -eq $aw.id -and $_.kind -eq 'write' } } 20
Check ($aw) "the alert says it overwrote the bait: $($aw.title)"
Aba kill $aw.id
Aba doctor --fix

Step 'Wiper: a program that deletes a bait is stopped, and the bait put back'
Check (WaitFor { Test-Path $docBait } 10) 'the bait is there'
$pd = Reader 'wiper-a' @($docBait) '' 'delete'
$ad = AlertFor $pd
Check ($ad -and $ad.tier -eq 'critical' -and (Did $ad 'freeze')) "caught and frozen ($($ad.id)): $($ad.title)"
$ad = WaitFor { Alerts | Where-Object { $_.id -eq $ad.id -and $_.kind -eq 'delete' } } 20
Check ($ad) "the alert says it deleted the bait: $($ad.title)"
Aba kill $ad.id
Aba doctor --fix
Check (WaitFor { Test-Path $docBait } 30) 'the deleted bait was put back'

Step 'A signed, legit program reading a bait is let through'
$legit = Join-Path $env:TEMP 'legit-curl.exe'   # Microsoft-signed (catalog), so "warn": notify only
Copy-Item "$env:SystemRoot\System32\curl.exe" $legit -Force
$legitOut = Join-Path $env:TEMP 'legit-out.txt'
$sw = [Diagnostics.Stopwatch]::StartNew()
# Bait names differ per install and can contain a space ("my passwords.txt").
# Start-Process doesn't quote arguments, so an unquoted URL reached curl as two.
$legitUrl = 'file:///' + (($desktopBait -replace '\\', '/') -replace ' ', '%20')
Snap
$c = Start-Process -FilePath $legit -ArgumentList '-sS', '-o', "`"$legitOut`"", "`"$legitUrl`"" -NoNewWindow -PassThru
$null = $c.Handle
if (-not $c.WaitForExit(20000)) {
    $verdict = Fresh | Where-Object { $_.process.pid -eq $c.Id } | Select-Object -Last 1
    Fail "signed curl was still stuck after 20 s; ABA's verdict: $($verdict.tier) / $($verdict.process.signature | ConvertTo-Json -Compress) / $($verdict.summary)"
}
$sw.Stop()
$legitGot = if (Test-Path $legitOut) { (Get-Item $legitOut).Length } else { 0 }
Check ($c.ExitCode -eq 0 -and $legitGot -gt 0) "it got the file ($legitGot bytes, curl exit code $($c.ExitCode), paused $($sw.ElapsedMilliseconds) ms in total)"
Check (-not ((State).frozen | Where-Object { $_.image -like '*legit-curl*' })) 'it was not frozen'

Step 'False positive: resume + ignore'
$s2 = Stealer 'mytool' $desktopBait
$a2 = AlertFor $s2.Id
Check ($a2 -and (Did $a2 'freeze')) 'second reader frozen'
$reloads = Reloads
Aba resume $a2.id --ignore
WaitReloaded $reloads
Check (WaitFor { -not (IsSuspended $s2.Id) } 5) 'resumed'
Check ((& $Aba ignore list | Out-String) -match 'mytool') 'ignore rule added'
Stop-Process -Id $s2.Id -Force -ErrorAction SilentlyContinue
$before = @(Alerts).Count
$s2b = Stealer 'mytool' $desktopBait -Again
Start-Sleep -Seconds 6
Check (@(Alerts).Count -eq $before) 'ignored program no longer alerts'
Check (-not (IsSuspended $s2b.Id)) 'ignored program not frozen'
Stop-Process -Id $s2b.Id -Force -ErrorAction SilentlyContinue
# It's unsigned, so the rule is pinned to that exact file: anything else
# dropped at the same path later is still caught.
$s2c = Stealer 'mytool' $desktopBait
$a2c = AlertFor $s2c.Id
Check ($a2c -and $a2c.tier -eq 'critical' -and (Did $a2c 'freeze')) 'a different file at the trusted path is still caught'
Aba kill $a2c.id
Aba ignore remove 1

Step 'Learning mode still stops critical; one-click trust (the popup''s "It''s mine")'
Aba install --yes --preset balanced --learning 3 --ntfy-topic $topic
$s5 = Stealer 'devtool' $desktopBait
$a5 = AlertFor $s5.Id
Check ($a5 -and (Did $a5 'freeze')) 'critical reader frozen during learning mode'
$reloads = Reloads
Aba trust $a5.id
WaitReloaded $reloads
Check (WaitFor { -not (IsSuspended $s5.Id) } 5) 'trust unfroze it'
Check ((& $Aba ignore list | Out-String) -match 'devtool') 'trust added an ignore rule'
Stop-Process -Id $s5.Id -Force -ErrorAction SilentlyContinue
$before = @(Alerts).Count
$s5b = Stealer 'devtool' $desktopBait -Again
Start-Sleep -Seconds 6
Check (@(Alerts).Count -eq $before) 'trusted program no longer alerts'
Stop-Process -Id $s5b.Id -Force -ErrorAction SilentlyContinue
# Trust covers only the bait it was seen reading.
$discordBait = ($st.baits.discord.files | Where-Object audit | Select-Object -First 1).path
$s5c = Stealer 'devtool' $discordBait -Again
$a5c = AlertFor $s5c.Id
Check ($a5c -and (Did $a5c 'freeze')) 'the trusted program going after a different bait is still frozen'
Aba kill $a5c.id
Aba ignore remove 1
$starts = @(Select-String -Path "$data\service.log" -Pattern 'watching Security log for bait access' -ErrorAction SilentlyContinue).Count
Aba install --yes --preset balanced --learning 0 --ntfy-topic $topic
# The reinstall restarted the service. A sweep is judged from the Security
# log too, and reads made before its watcher has subscribed are never seen:
# wait for the new service to say it's watching, and a moment more.
if (-not (WaitFor { @(Select-String -Path "$data\service.log" -Pattern 'watching Security log for bait access' -ErrorAction SilentlyContinue).Count -gt $starts } 30)) { Fail 'the service did not come back after the reinstall' }
Start-Sleep -Seconds 3

Step 'A Windows program going through several apps'' data is stopped (how an injected stealer looks)'
# find.exe is part of Windows and signed by Microsoft: one bait read by it is
# only "suspicious". Reading your files, Discord and a browser in a row is a sweep.
$sweepBaits = @($desktopBait, $discordBait, ($st.baits.brave.files | Where-Object audit | Select-Object -First 1).path)
$findExe = "$env:SystemRoot\System32\find.exe"
Snap
$fp = & $Medium -raw $findExe ("'$findExe' 'zz-not-there' " + (($sweepBaits | ForEach-Object { "'$_'" }) -join ' '))
if ($LASTEXITCODE -or -not $fp) { Fail "find.exe didn't start" }
$a6 = WaitFor { Fresh | Where-Object { $_.process.pid -eq [int]$fp -and $_.tier -eq 'critical' } | Select-Object -Last 1 } 20
Check ($a6) "find.exe sweeping 3 apps' baits is critical: $($a6.summary)"
Check (@($a6.verdict.swept).Count -ge 3) "swept: $($a6.verdict.swept -join ', ')"
if ((Get-Process -Id ([int]$fp) -ErrorAction SilentlyContinue).SessionId -gt 0) {
    Check ((Did $a6 'freeze') -and (WaitFor { IsSuspended ([int]$fp) } 5)) 'frozen before it could read the third'
    Aba kill $a6.id
}
Check (Did $a6 'block-program') 'its internet is cut'

Step 'A browser a stealer starts suspended is frozen with the stealer; the browser you use is left running, cut off'
# What cookie stealers do to get past a browser's own encryption: start the
# genuine browser suspended, put code into it, and have it open every profile
# from inside the browser. ghost does the observable part (see scripts/ghost).
$hostBait = $null
if ($hostBrowser) {
    $hostBait = ((State).baits.($hostBrowser.id).files | Where-Object { $_.audit -and $_.path -like '*Login Data' } | Select-Object -First 1).path
}
if (-not $hostBait) {
    Ok 'skipped: no fake profile was planted inside a real browser on this machine'
} else {
    $bexe = $hostBrowser.exe
    $bname = $hostBrowser.name
    # ghost writes its progress to a status file it creates itself: until it
    # has, there's nothing to read (never an error).
    function GhostSays([string]$file, [string]$pattern) {
        if (-not (Test-Path -LiteralPath $file)) { return $null }
        $m = Select-String -LiteralPath $file -Pattern $pattern -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($m) { return [int]$m.Matches[0].Groups[1].Value }
        return $null
    }
    function ShowGhost([string]$file) {
        if (Test-Path -LiteralPath $file) { Get-Content -LiteralPath $file -ErrorAction SilentlyContinue | ForEach-Object { "  ghost: $_" } | Out-Host }
    }
    Start-Sleep -Seconds 2   # the guard on the bait is back after the step before
    $status = Join-Path $env:TEMP 'ghost-browser-suspended.txt'
    Remove-Item -LiteralPath $status -ErrorAction SilentlyContinue
    Snap
    $gp = & $Medium $Ghost browser-suspended $bexe $hostBait $status
    if ($LASTEXITCODE -or -not "$gp".Trim()) { Fail "ghost browser-suspended didn't start" }
    $gp = [int]"$gp".Trim()
    $script:leftovers = @($gp)
    $bp = WaitFor { GhostSays $status 'browser pid (\d+)' } 15
    if ($bp) { $script:leftovers += $bp }
    ShowGhost $status
    Check ($bp) "ghost (pid $gp) started $bname suspended (pid $bp)"
    $ah = WaitFor { Fresh | Where-Object { $_.verdict.host -and $_.tier -eq 'critical' } | Select-Object -Last 1 } 25
    ShowGhost $status
    if (Test-Path "$data\service.log") {
        Select-String -Path "$data\service.log" -Pattern 'instant|window check|joins the alert' | Select-Object -Last 10 | ForEach-Object { "  log: " + $_.Line } | Out-Host
    }
    Check ($ah) "critical alert about the $bname a stealer started: $($ah.summary)"
    Check (-not $ah.verdict.keepRunning) 'not taken for the browser you use'
    Check (Did $ah 'freeze') "froze it: $(($ah.actions | Where-Object action -eq 'freeze').detail)"
    Check (WaitFor { IsSuspended $bp } 5) "the $bname it started is suspended"
    Check (WaitFor { IsSuspended $gp } 5) 'and so is ghost, which started it'
    $blockedNow = @((State).blocked | ForEach-Object { $_.path })
    Check (-not ($blockedNow | Where-Object { $_ -eq $bexe })) "$bname's own program isn't blocked (your own windows of it keep their internet)"
    Check ($blockedNow | Where-Object { $_ -eq $Ghost }) 'ghost''s internet is cut'
    Aba kill $ah.id
    Check (WaitFor { -not (Get-Process -Id $bp -ErrorAction SilentlyContinue) -and -not (Get-Process -Id $gp -ErrorAction SilentlyContinue) } 10) "aba kill ended that $bname and ghost"
    $script:leftovers = @()

    # The browser you're using: only on a machine with a desktop someone is
    # signed in to (its windows have to be on a screen to count).
    if (-not (Get-Process explorer -ErrorAction SilentlyContinue | Where-Object SessionId -gt 0)) {
        Ok 'skipped the browser-you-use half: no desktop session on this machine'
    } else {
        # ghost is started exactly the way the browser was (the desktop's own
        # token, or else this script's at medium integrity): otherwise it may
        # not be allowed to open the browser at all.
        $how = @('-shell')
        $vp = & $Medium -shell $bexe --no-first-run --no-default-browser-check --new-window about:blank
        if ($LASTEXITCODE -or -not "$vp".Trim()) {
            $how = @()
            $vp = & $Medium $bexe --no-first-run --no-default-browser-check --new-window about:blank
        }
        $vp = if ("$vp".Trim() -match '^\d+$') { [int]"$vp".Trim() } else { 0 }
        $script:leftovers = @($vp)
        $shown = if ($vp) { WaitFor { $p = Get-Process -Id $vp -ErrorAction SilentlyContinue; $p -and $p.MainWindowHandle -ne 0 } 30 } else { $null }
        if (-not $shown) {
            Ok "skipped the browser-you-use half: $bname (pid $vp) showed no window here"
        } else {
            Start-Sleep -Seconds 3
            $rulesBefore = WfpRules
            # (In Public: ghost may run as the desktop's user, who can write there.)
            $status = Join-Path $env:PUBLIC 'ghost-browser-inject.txt'
            Remove-Item -LiteralPath $status -ErrorAction SilentlyContinue
            Snap
            $ip = & $Medium @how $Ghost browser-inject $vp $hostBait $status
            if ($LASTEXITCODE -or -not "$ip".Trim()) { Fail "ghost browser-inject didn't start (medium $($how -join ' '))" }
            $script:leftovers += [int]"$ip".Trim()
            # What ghost says it did: read the fake profile from inside the
            # browser, or which call failed (with Windows' error number).
            $said = WaitFor {
                if (Test-Path -LiteralPath $status) {
                    $l = Get-Content -LiteralPath $status -ErrorAction SilentlyContinue | Where-Object { $_ -match '^(its thread read|failed:)' } | Select-Object -First 1
                    if ($l) { return $l }
                }
                if (-not (Get-Process -Id ([int]"$ip".Trim()) -ErrorAction SilentlyContinue)) { return 'failed: ghost exited without saying why' }
                $null
            } 20
            ShowGhost $status
            if ($said -match '^failed: OpenProcess.*\(Win32 error 5\)') {
                Ok "skipped the browser-you-use half: this machine doesn't let ghost into the $bname it started ($said)"
            } else {
                if (-not $said) { Fail 'ghost browser-inject said nothing within 20 s' }
                if ($said -like 'failed:*') { Fail "ghost browser-inject: $said" }
                $ak = WaitFor { Fresh | Where-Object { $_.verdict.keepRunning } | Select-Object -Last 1 } 30
                if (Test-Path "$data\service.log") {
                    Select-String -Path "$data\service.log" -Pattern 'window check|instant' | Select-Object -Last 6 | ForEach-Object { "  log: " + $_.Line } | Out-Host
                }
                Check ($ak -and $ak.tier -eq 'critical') "critical alert, left running: $($ak.summary)"
                Check (-not (Did $ak 'freeze')) 'not frozen'
                Check (-not (IsSuspended $vp)) "your $bname is still running"
                Check (Did $ak 'block-program') "its internet is cut instead"
                Check ((State).blocked | Where-Object { $_.path -eq $bexe }) "$bname's program is on the blocked list"
                Check ((WfpRules) -gt $rulesBefore) 'a WFP rule for it is in place'
                Aba resume $ak.id
                Check (-not ((State).blocked | Where-Object { $_.path -eq $bexe })) 'aba resume gave it its internet back'
                Check ((WfpRules) -eq $rulesBefore) 'and its WFP rule is gone'
            }
        }
        EndLeftovers
    }
}

Step 'Release everything'
Aba release
$st = State
Check ((-not $st.frozen) -and (-not $st.blocked)) "nothing frozen or blocked (frozen=$($st.frozen | ConvertTo-Json -Compress) blocked=$($st.blocked | ConvertTo-Json -Compress))"
Check ((WfpRules) -eq 0) 'all WFP rules gone'

Step 'Strict mode: isolation, with the phone alert sent while isolated'
Aba install --yes --preset strict --learning 0 --ntfy-topic $topic
$watchdog = ReleaseWatchdog 90   # network comes back even if this script dies
$s3 = Stealer 'stealer3' $desktopBait
$a3 = AlertFor $s3.Id
Check ($a3 -and (Did $a3 'isolate')) 'PC isolated'
Check ((State).isolation) 'state shows isolation'
Check (-not (Online)) 'other programs are offline'
Start-Sleep -Seconds 4   # let the service push the phone alert through the isolation
Aba release
Check (WaitFor { Online } 60) 'back online after release'
Stop-Process -Id $watchdog.Id -Force -ErrorAction SilentlyContinue
Check (WaitFor { NtfyMessages | Where-Object { $_.message -match $a3.id } } 90) 'phone alert got out while isolated'
Stop-Process -Id $s3.Id -Force -ErrorAction SilentlyContinue

Step 'Back to balanced; deleted bait gets repaired'
Aba install --yes --preset balanced --learning 0 --ntfy-topic $topic
Remove-Item $desktopBait -Force
Check (WaitFor { Alerts | Where-Object { $_.kind -eq 'delete' -and $_.baits.path -contains $desktopBait } } 20) 'deletion alerted'
Aba doctor --fix
Check (WaitFor { Test-Path $desktopBait } 30) 'bait recreated'

Step 'Evasion: tricks for reading a bait unseen are caught, and count against the reader'
# An unsigned program in Program Files reading one bait is only "suspicious"
# (not frozen on balanced). The same program using a trick to dodge detection
# is critical: frozen, and marked as evading.
$toolDir = Join-Path $env:ProgramFiles 'AbaE2E'
New-Item -ItemType Directory -Force $toolDir | Out-Null
$tool = Join-Path $toolDir 'tool.exe'
Copy-Item $Ghost $tool -Force
function Evader([string]$mode, [string]$bait) {
    # The reader before this one has only just let go of the bait (or been
    # killed): give the service a moment to put its guard back on it.
    Start-Sleep -Seconds 2
    Snap
    $procId = & $Medium $tool $mode $bait
    if ($LASTEXITCODE -or -not $procId) { Fail "evasion helper ($mode) didn't start" }
    return [int]$procId
}
$e0 = Evader 'plain' $discordBait
$a0 = AlertFor $e0
Check ($a0 -and $a0.tier -eq 'warn' -and -not (Did $a0 'freeze')) "read normally, it's only a warning: $($a0.summary)"
Stop-Process -Id $e0 -Force -ErrorAction SilentlyContinue
foreach ($mode in 'ghost', 'map') {
    $e = Evader $mode $discordBait
    $a = WaitFor { Fresh | Where-Object { $_.process.pid -eq $e -and $_.tier -eq 'critical' } | Select-Object -Last 1 } 20
    Check ($a) "${mode}: critical: $($a.summary)"
    Check ($a.verdict.evasion -eq $true) "${mode}: recognised as evasion"
    Check ((Did $a 'freeze') -and (WaitFor { IsSuspended $e } 5)) "${mode}: frozen"
    # What a stealer's second process would do: un-suspend it. One call
    # undoes a plain suspension; what ABA froze is also held by the service.
    & $Medium $Ghost resume $e | Out-Null
    Start-Sleep -Seconds 2
    Check (IsSuspended $e) "${mode}: another program can't un-freeze it"
    Aba kill $a.id
}
foreach ($mode in 'link', 'linkgone') {
    $e = Evader $mode $discordBait
    $a = WaitFor { Fresh | Where-Object { $_.process.pid -eq $e } | Select-Object -Last 1 } 20
    if (-not $a -and $mode -eq 'linkgone') {
        # With the link deleted again there's no file left to identify: this one
        # relies on instant freeze having singled the reader out, which it
        # declines to do when several programs wake at the same instant.
        Ok "${mode}: not attributed on this run (instant freeze couldn't single the reader out)"
        Stop-Process -Id $e -Force -ErrorAction SilentlyContinue
        continue
    }
    Check ($a) "${mode}: a read through a hard link is noticed: $($a.summary)"
    if ($a.tier -eq 'critical') {
        Check ($a.verdict.evasion -eq $true) "${mode}: recognised as evasion"
        Aba kill $a.id
    } else {
        Ok "${mode}: Windows logged the bait's own name, so it was handled as an ordinary read ($($a.tier))"
        Stop-Process -Id $e -Force -ErrorAction SilentlyContinue
    }
}
Get-ChildItem $env:TEMP -Filter 'cache-*.dat' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
Remove-Item $toolDir -Recurse -Force -ErrorAction SilentlyContinue
Aba release

Step 'A fake "app installed" marker doesn''t get a decoy retired'
# Most of these apps install into your own profile, so anything running as you
# can create "Vivaldi\Application\vivaldi.exe". An unsigned file there used to
# make ABA remove its decoy by itself; now it's reported and the decoy stays.
$st = State
$decoy = @('vivaldi', 'yandex', 'opera', 'exodus') | Where-Object { $st.baits.$_ -and $st.baits.$_.status -eq 'ok' } | Select-Object -First 1
if ($decoy) {
    $markers = @{
        vivaldi = "$env:LOCALAPPDATA\Vivaldi\Application\vivaldi.exe"
        yandex  = "$env:LOCALAPPDATA\Yandex\YandexBrowser\Application\browser.exe"
        opera   = "$env:LOCALAPPDATA\Programs\Opera\opera.exe"
        exodus  = "$env:LOCALAPPDATA\exodus\Exodus.exe"
    }
    $m = $markers[$decoy]
    New-Item -ItemType Directory -Force (Split-Path $m) | Out-Null
    Set-Content $m 'pretend app' -Encoding ascii
    Aba doctor --fix
    Check (WaitFor { Alerts | Where-Object { $_.kind -eq 'tamper' -and $_.summary -match [regex]::Escape((Split-Path $m -Leaf)) } } 30) 'the fake app is reported as an attempt to switch a bait off'
    Check ((State).baits.$decoy.status -eq 'ok') "$decoy decoy kept"
    $first = ((State).baits.$decoy.files | Select-Object -First 1).path
    Check (Test-Path $first) 'its fake files are still there'
    Remove-Item (Split-Path $m) -Recurse -Force
} else { Ok 'no decoy available on this runner (skipped)' }

Step 'Custom bait'
$custom = Join-Path $env:USERPROFILE 'Documents\bank logins.txt'
$reloads = Reloads
Aba bait add $custom
WaitReloaded $reloads # or the stealer below may read it before the service watches it
Check (Test-Path $custom) 'custom bait created'
$cid = ((State).baits.PSObject.Properties | Where-Object { $_.Value.files[0].path -eq $custom }).Name
Check ($cid) "registered as $cid"
if ($decoy) { Check ((State).baits.$decoy.status -eq 'ok') "$decoy decoy still there after changing baits" }
$s4 = Stealer 'stealer4' $custom
Check (AlertFor $s4.Id) 'reading the custom bait alerts'
Aba release
Stop-Process -Id $s4.Id -Force -ErrorAction SilentlyContinue
# What ABA has on record about the file (it only deletes what's unchanged).
$rec = (State).baits.$cid.files | Select-Object -First 1
$fi = Get-Item $custom -ErrorAction SilentlyContinue
Write-Host "  on record: created=$($rec.created) size=$($rec.size) modTime=$($rec.modTime); on disk: size=$($fi.Length) written=$($fi.LastWriteTimeUtc.ToString('o'))"
Aba bait remove $cid
# The file's name stays visible until every handle on it is closed. The service
# lets go of its guard when it next re-reads its settings, which can take a few
# seconds when it is busy; `aba bait remove` itself only waits one.
$gone = WaitFor { -not (Test-Path $custom) } 15
if (-not $gone) {
    # Still there: deleted but held open by something, or never deleted?
    Write-Host (& $Ghost holders $custom | Out-String)
    Write-Host "stealer4 (pid $($s4.Id)) still running: $([bool](Get-Process -Id $s4.Id -ErrorAction SilentlyContinue))"
}
Check $gone 'custom bait removed'

Step 'Read-only commands'
$before = @(Alerts).Count
Aba bait show desktop-passwords
Start-Sleep -Seconds 3
Check (@(Alerts).Count -eq $before) '`bait show` prints the bait without tripping it'
Aba bait list
Aba bait catalog
Aba alerts
Aba status --once
Aba learn --stop
Aba doctor

Step 'Turn auto-update off, and the miner trap on, unattended'
Aba install --yes --preset balanced --learning 0 --auto-update=false --miners
$cfg = Get-Content (Join-Path $data 'config.json') -Raw | ConvertFrom-Json
Check ($cfg.autoUpdate -eq $false) '--auto-update=false turns it off'
Check ($cfg.minerTrap -eq $true -and -not $cfg.clipboardBait) '--miners turns the miner trap on, and nothing else'
Check (WaitFor { (Resolves 'pool.supportxmr.com') -contains $trapIP } 60) 'pool names lead to the trap'
Aba install --yes --keep-settings
Check ((Get-Content (Join-Path $data 'config.json') -Raw | ConvertFrom-Json).minerTrap -eq $true) '--keep-settings keeps it'
# (Here, not earlier: doctor opens every bait to check it, which lifts instant
# freeze off each for a moment, and no fake stealer follows from here on.)
$doc = (& $Aba doctor 2>&1 | Out-String)
Check ($doc -match 'Miner trap\s+on: \d+ mining pools') "aba doctor shows the miner trap on: $(($doc -split "`n" | Select-String 'Miner trap') -join '')"

Step 'What the flight recorder cost'
# Informational, for deciding between audit rules and other ways of watching:
# how many Security log entries ABA's recorder folders produced during this
# run, and how much CPU the service used in all.
$recDirs = @((State).recorderDirs)
$recEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663; StartTime = $started } -ErrorAction SilentlyContinue |
    Where-Object { $obj = $_.Properties[6].Value; $recDirs | Where-Object { $obj -like "$_\*" } })
$minutes = [math]::Max(1, ((Get-Date) - $started).TotalMinutes)
Ok "flight recorder folders: $($recDirs.Count); their Security log entries: $($recEvents.Count) in $([int]$minutes) min ($([int]($recEvents.Count * 60 / $minutes)) an hour)"
$svc = Get-Process famsvc -ErrorAction SilentlyContinue
if ($svc) { Ok "service CPU time so far: $([math]::Round($svc.TotalProcessorTime.TotalSeconds, 1)) s" }
$log = Get-WinEvent -ListLog Security
Ok "Security log: $([int]($log.FileSize / 1MB)) of $([int]($log.MaximumSizeInBytes / 1MB)) MB used"

Step 'Uninstall'
Aba uninstall --yes --purge
Check (-not (Get-Service FileAccessMonitor -ErrorAction SilentlyContinue)) 'service removed'
Check (-not (Test-Path $desktopBait)) 'baits removed'
Check (-not (Test-Path "$env:APPDATA\Opera Software")) 'fake app folders removed'
Check (-not (Test-Path $data)) 'data folder purged'
Check (-not (Test-Path $installDir) -or @(Get-ChildItem $installDir -Recurse -File).Count -eq 0) 'program files removed'
Check ((WfpRules) -eq 0) 'no WFP rules left'
Check (-not @(TrapRules).Count) 'no miner trap name rules left'
Check (WaitFor { $r = Resolves 'pool.supportxmr.com'; $r.Count -gt 0 -and -not ($r -contains $trapIP) } 30) 'mining pools'' names resolve normally again'
Check ((AuditFS) -eq $auditBefore) "audit policy restored ($auditBefore)"
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Check (-not ($machinePath -split ';' | Where-Object { $_ -eq $installDir })) 'removed from PATH'
Check (Online) 'still online'
Check ((RecorderRule $sshDir).Count -eq 0) 'the flight recorder''s audit rule is gone from the .ssh folder'
Check ((Get-Content $realKey -Raw) -match 'not a real key') 'the real-looking key was left as it was'
Remove-Item $realKey -Force

Write-Host "`nALL END-TO-END CHECKS PASSED in $([int]((Get-Date) - $started).TotalSeconds)s" -ForegroundColor Green
