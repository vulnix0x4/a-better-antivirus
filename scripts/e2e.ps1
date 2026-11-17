<#
.SYNOPSIS
  Full end-to-end test of A Better Antivirus on a disposable Windows machine.

.DESCRIPTION
  Installs ABA, runs fake stealers against it and checks every response:
  freeze, per-program block, kill, resume + ignore, release, strict-mode
  isolation (with a phone alert sent *while* isolated), bait repair, decoy
  retirement, custom baits, and a complete uninstall.

  DO NOT run this on a PC you care about: it isolates the network for a few
  seconds and changes system settings. It's meant for CI runners.
#>
param([string]$Aba = (Join-Path $PSScriptRoot '..\dist\aba.exe'))

$ErrorActionPreference = 'Stop'
$Aba  = (Resolve-Path $Aba).Path
$data = Join-Path $env:ProgramData 'FileAccessMonitor'
$installDir = Join-Path $env:ProgramFiles 'File Access Monitor'
$fsGuid = '{0CCE921D-69AE-11D9-BED3-505054503030}'
$topic = 'aba-ci-' + [guid]::NewGuid().ToString('N').Substring(0, 16)
$started = Get-Date
$script:failures = 0

function Step($n) { Write-Host "`n=== $n ===" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  ok  $m" -ForegroundColor Green }
function Fail($m) {
    Write-Host "  FAIL $m" -ForegroundColor Red
    if (Test-Path "$data\service.log") { Write-Host '--- service.log (tail) ---'; Get-Content "$data\service.log" -Tail 80 }
    exit 1
}
function Check($cond, $m) { if ($cond) { Ok $m } else { Fail $m } }
function Aba { & $Aba @args 2>&1 | Out-Host; if ($LASTEXITCODE) { Fail "aba $($args -join ' ') exited $LASTEXITCODE" } }

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
function AlertFor([int]$procId, [int]$seconds = 20) { WaitFor { Alerts | Where-Object { $_.process.pid -eq $procId } | Select-Object -Last 1 } $seconds }
function State { Get-Content "$data\state.json" -Raw | ConvertFrom-Json }
function Did($alert, $action) { [bool]($alert.actions | Where-Object { $_.action -eq $action -and $_.ok }) }

# A fake stealer: a copy of aba.exe in Temp (unsigned, user-writable -> critical)
# that reads a bait and then waits around.
function Stealer([string]$name, [string]$bait) {
    $exe = Join-Path $env:TEMP "$name.exe"
    Copy-Item $Aba $exe -Force
    $p = Start-Process -FilePath $exe -ArgumentList 'test-reader', "`"$bait`"" -PassThru -WindowStyle Hidden
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
function Online { & curl.exe -s -o NUL --max-time 8 https://www.microsoft.com; return ($LASTEXITCODE -eq 0) }
function WfpRules {
    $f = Join-Path $env:TEMP 'wfp.xml'
    netsh wfp show filters file="$f" | Out-Null
    (Select-String -Path $f -Pattern '<name>ABA: ' -AllMatches).Matches.Count
}
# ntfy returns one JSON object per line; read the raw text (Invoke-RestMethod
# would auto-parse a single line into an object).
function NtfyMessages {
    $raw = (Invoke-WebRequest "https://ntfy.sh/$topic/json?poll=1&since=all" -UseBasicParsing).Content
    if ($raw -is [byte[]]) { $raw = [Text.Encoding]::UTF8.GetString($raw) }
    $raw -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object event -eq 'message'
}
function AuditFS { (auditpol /get /subcategory:"$fsGuid" /r | ConvertFrom-Csv).'Inclusion Setting' }

# ---------------------------------------------------------------------------
Step 'Baseline'
$auditBefore = AuditFS
Ok "audit policy before install: $auditBefore"
Check (Online) 'machine is online'

Step 'Install (balanced, no learning, ntfy phone alerts)'
Aba install --yes --preset balanced --learning 0 --ntfy-topic $topic
Check ((Get-Service FileAccessMonitor).Status -eq 'Running') 'service running'
$st = State
$desktopBait = ($st.baits.'desktop-passwords'.files | Select-Object -First 1).path
Check (Test-Path $desktopBait) "desktop bait planted: $desktopBait"
Check (@($st.baits.PSObject.Properties).Count -ge 10) "$(@($st.baits.PSObject.Properties).Count) baits planted"
Check ((AuditFS) -match 'Success') 'file auditing on'
Aba doctor
Aba phone test
Check (WaitFor { NtfyMessages | Where-Object title -match 'test alert' } 20) 'phone test alert arrived on ntfy'

Step 'Built-in safe test'
Aba test

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
Aba alerts show $a1.id
Aba kill $a1.id
Check (WaitFor { -not (Get-Process -Id $s1.Id -ErrorAction SilentlyContinue) } 10) 'killed'
Check (WaitFor { NtfyMessages | Where-Object { $_.message -match $a1.id } } 30) 'critical alert reached the phone (ntfy)'

Step 'False positive: resume + ignore'
$s2 = Stealer 'mytool' $desktopBait
$a2 = AlertFor $s2.Id
Check ($a2 -and (Did $a2 'freeze')) 'second reader frozen'
Aba resume $a2.id --ignore
Check (WaitFor { -not (IsSuspended $s2.Id) } 5) 'resumed'
Check ((& $Aba ignore list | Out-String) -match 'mytool') 'ignore rule added'
Stop-Process -Id $s2.Id -Force -ErrorAction SilentlyContinue
$before = @(Alerts).Count
$s2b = Stealer 'mytool' $desktopBait
Start-Sleep -Seconds 6
Check (@(Alerts).Count -eq $before) 'ignored program no longer alerts'
Check (-not (IsSuspended $s2b.Id)) 'ignored program not frozen'
Stop-Process -Id $s2b.Id -Force -ErrorAction SilentlyContinue
Aba ignore remove 1

Step 'Release everything'
Aba release
$st = State
Check (@($st.frozen).Count -eq 0 -and @($st.blocked).Count -eq 0) 'nothing frozen or blocked'
Check ((WfpRules) -eq 0) 'all WFP rules gone'

Step 'Strict mode: isolation, with the phone alert sent while isolated'
Aba install --yes --preset strict --learning 0 --ntfy-topic $topic
$s3 = Stealer 'stealer3' $desktopBait
$a3 = AlertFor $s3.Id
Check ($a3 -and (Did $a3 'isolate')) 'PC isolated'
Check ((State).isolation) 'state shows isolation'
Check (-not (Online)) 'other programs are offline'
Start-Sleep -Seconds 4   # let the service push the phone alert through the isolation
Aba release
Check (WaitFor { Online } 20) 'back online after release'
Check (WaitFor { NtfyMessages | Where-Object { $_.message -match $a3.id } } 30) 'phone alert got out while isolated'
Stop-Process -Id $s3.Id -Force -ErrorAction SilentlyContinue

Step 'Back to balanced; deleted bait gets repaired'
Aba install --yes --preset balanced --learning 0 --ntfy-topic $topic
Remove-Item $desktopBait -Force
Check (WaitFor { Alerts | Where-Object { $_.kind -eq 'delete' -and $_.baits.path -contains $desktopBait } } 20) 'deletion alerted'
Aba doctor --fix
Check (WaitFor { Test-Path $desktopBait } 30) 'bait recreated'

Step 'Decoy retires when the real app shows up'
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
    Check (WaitFor { (State).baits.$decoy.status -eq 'retired' } 30) "$decoy decoy retired"
    $first = ((State).baits.$decoy.files | Select-Object -First 1).path
    Check (-not (Test-Path $first)) 'its fake files are gone'
    Remove-Item (Split-Path $m) -Recurse -Force
} else { Ok 'no decoy available to retire on this runner (skipped)' }

Step 'Custom bait'
$custom = Join-Path $env:USERPROFILE 'Documents\bank logins.txt'
Aba bait add $custom
Check (Test-Path $custom) 'custom bait created'
$cid = ((State).baits.PSObject.Properties | Where-Object { $_.Value.files[0].path -eq $custom }).Name
Check ($cid) "registered as $cid"
$s4 = Stealer 'stealer4' $custom
Check (AlertFor $s4.Id) 'reading the custom bait alerts'
Aba release
Stop-Process -Id $s4.Id -Force -ErrorAction SilentlyContinue
Aba bait remove $cid
Check (-not (Test-Path $custom)) 'custom bait removed'

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

Step 'Uninstall'
Aba uninstall --yes --purge
Check (-not (Get-Service FileAccessMonitor -ErrorAction SilentlyContinue)) 'service removed'
Check (-not (Test-Path $desktopBait)) 'baits removed'
Check (-not (Test-Path "$env:APPDATA\Opera Software")) 'fake app folders removed'
Check (-not (Test-Path $data)) 'data folder purged'
Check (-not (Test-Path $installDir) -or @(Get-ChildItem $installDir -Recurse -File).Count -eq 0) 'program files removed'
Check ((WfpRules) -eq 0) 'no WFP rules left'
Check ((AuditFS) -eq $auditBefore) "audit policy restored ($auditBefore)"
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
Check (-not ($machinePath -split ';' | Where-Object { $_ -eq $installDir })) 'removed from PATH'
Check (Online) 'still online'

Write-Host "`nALL END-TO-END CHECKS PASSED in $([int]((Get-Date) - $started).TotalSeconds)s" -ForegroundColor Green
