# A Better Antivirus installer.
#
#   irm https://raw.githubusercontent.com/vulnix0x4/a-better-antivirus/main/install.ps1 | iex
#
# Downloads the latest release for this PC, checks it against the release's
# SHA256SUMS.txt, and runs `aba install` (which asks for admin and continues
# in its own window). Afterwards `aba` works in this window too.
# Pass other arguments with $env:ABA_ARGS, e.g. for a test VM:
#   $env:ABA_ARGS = 'install --yes --preset strict --learning 0'

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue' # Windows PowerShell's progress bar makes downloads crawl
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Built from code points so the script reads the same in any encoding.
    $ok = [string][char]0x2713; $arrow = [string][char]0x203A; $no = [string][char]0x2717
    $dim = 'DarkGray'
    function Say([string]$mark, [string]$text, [string]$color = 'Green', [string]$note = '') {
        Write-Host ' ' -NoNewline
        Write-Host $mark -ForegroundColor $color -NoNewline
        Write-Host " $text" -NoNewline
        if ($note) { Write-Host "  $note" -ForegroundColor $dim } else { Write-Host '' }
    }
    # Stop-Install explains what went wrong and ends the installer without a
    # PowerShell error dump (and without closing the user's window).
    function Stop-Install([string]$why, [string]$hint = '') {
        Write-Host ''
        Say $no $why 'Red'
        if ($hint) { Write-Host "   $hint" -ForegroundColor $dim }
        Write-Host ''
        throw 'aba-install-stopped'
    }

    Write-Host ''
    Write-Host ' A Better Antivirus' -NoNewline
    Write-Host "   it's not an antivirus. it's a better one." -ForegroundColor $dim
    Write-Host ''

    $dir = $null
    try {
        if ([Environment]::OSVersion.Version.Major -lt 10) {
            Stop-Install 'A Better Antivirus needs Windows 10 or 11.'
        }

        $repo = 'vulnix0x4/a-better-antivirus'
        $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { 'arm64' } else { 'amd64' }
        try {
            $rel = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -Headers @{ 'User-Agent' = 'aba-installer' } -TimeoutSec 30
        } catch {
            $status = $null
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -eq 403 -or $status -eq 429) {
                Stop-Install 'GitHub is rate-limiting this network right now.' 'Wait a few minutes and run the command again.'
            }
            Stop-Install "Couldn't reach GitHub to find the latest release." 'Check your internet connection and run the command again.'
        }
        $tag = $rel.tag_name
        $name = "aba_${tag}_windows_$arch.exe"
        $asset = $rel.assets | Where-Object name -eq $name
        $sums = $rel.assets | Where-Object name -eq 'SHA256SUMS.txt'
        if (-not $asset -or -not $sums) { Stop-Install "Release $tag has no build for this PC ($arch)." }

        # A fresh folder each time, so a half-finished earlier download is never reused.
        $dir = Join-Path $env:TEMP ('aba-install-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force $dir | Out-Null
        $exe = Join-Path $dir 'aba.exe'
        $sumFile = Join-Path $dir 'SHA256SUMS.txt'
        try {
            Invoke-WebRequest $asset.browser_download_url -OutFile $exe -UseBasicParsing -TimeoutSec 300
            Invoke-WebRequest $sums.browser_download_url -OutFile $sumFile -UseBasicParsing -TimeoutSec 60
        } catch {
            Stop-Install "The download didn't finish." 'Check your internet connection and run the command again.'
        }
        Say $ok "Downloaded $tag" 'Green' ('{0:N1} MB, {1}' -f ($asset.size / 1MB), $arch)

        $line = Get-Content $sumFile | Where-Object { $_ -match ([regex]::Escape($name) + '$') }
        $expected = ($line -split '\s+')[0]
        $actual = (Get-FileHash $exe -Algorithm SHA256).Hash
        if (-not $expected -or $actual -ne $expected.ToUpper()) {
            Stop-Install "The download doesn't match the release's checksum, so it was not run." 'Run the command again. If it keeps happening, please open an issue on GitHub.'
        }
        Say $ok 'Checksum matches the release' 'Green' 'SHA-256'

        $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $admin -and -not $env:ABA_ARGS) {
            Say $arrow 'Starting setup' 'Green' 'Windows asks for permission, then setup opens in its own window'
        }
        $argv = if ($env:ABA_ARGS) { $env:ABA_ARGS -split '\s+' } else { @('install') }
        & $exe $argv
        $code = $LASTEXITCODE

        # Pick up the PATH change, so `aba` works in this window right away.
        $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
        $installed = Test-Path (Join-Path $env:ProgramFiles 'File Access Monitor\aba.exe')
        Write-Host ''
        if ($code -eq 0 -and $installed) {
            Say $ok 'A Better Antivirus is installed.'
            Write-Host '   Type ' -NoNewline -ForegroundColor $dim
            Write-Host 'aba' -NoNewline -ForegroundColor Green
            Write-Host ' for the dashboard, or ' -NoNewline -ForegroundColor $dim
            Write-Host 'aba test' -NoNewline -ForegroundColor Green
            Write-Host ' to watch it catch a fake stealer.' -ForegroundColor $dim
        } elseif ($code -ne 0) {
            Say $no "Setup didn't finish (exit code $code)." 'Red' 'Run the command again to retry.'
        }
        Write-Host ''
    } catch {
        if ("$_" -ne 'aba-install-stopped') {
            Write-Host ''
            Say $no "Something went wrong: $_" 'Red'
            Write-Host ''
        }
    } finally {
        # aba.exe copied itself into Program Files; the download isn't needed any more.
        if ($dir) { Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue }
    }
}
