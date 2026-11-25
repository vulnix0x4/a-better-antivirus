# A Better Antivirus installer.
#
#   irm https://raw.githubusercontent.com/vulnix0x4/a-better-antivirus/main/install.ps1 | iex
#
# Downloads the latest release for this PC, checks that the release's
# SHA256SUMS.txt carries a valid signature from ABA's release key (the same
# key the automatic updates check, its public half written out below), checks
# the download against that list, and runs `aba install` (which asks for admin
# and continues in its own window). Afterwards `aba` works in this window too.
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

    # ABA's release key (ed25519, base64): the same one the automatic updates
    # check (internal/update) and install.sh carries.
    $releaseKey = 'VLEZ7MWwcu4LFSYPzA71J9M0WWbqQryOGki0GSvuihU='

    # >>> ed25519
    # Test-Ed25519 checks an ed25519 signature (RFC 8032) with the same
    # equation as Go's crypto/ed25519, which made it (and is stricter about a
    # key that isn't written the one canonical way). Windows PowerShell has no
    # ed25519 of its own, so the curve arithmetic is done here with BigInteger.
    # It only verifies: nothing secret passes through it, so it needn't run in
    # constant time.
    # (PowerShell names are case-insensitive: no $p next to $P in here.)
    function Test-Ed25519([byte[]]$Key, [byte[]]$Message, [byte[]]$Signature) {
        if ($null -eq $Key -or $null -eq $Signature -or $Key.Length -ne 32 -or $Signature.Length -ne 64) { return $false }
        if ($null -eq $Message) { $Message = New-Object byte[] 0 }
        $big = [System.Numerics.BigInteger]
        $zero = $big::Zero; $one = $big::One; $two = $big::Parse('2')
        $fp = $big::Pow($two, 255) - $big::Parse('19')   # the field's prime
        $ord = $big::Parse('7237005577332262213973186563042994240857116359379907606001950938285454250989')   # the group's order
        $cd = $big::Parse('37095705934669439343138083508754565189542113879843219016388785533085940283555')   # the curve's d
        $cd2 = ($cd * $two) % $fp
        $sqrtM1 = $big::ModPow($two, ($fp - $one) / $big::Parse('4'), $fp)

        # Little-endian bytes to a number and back (32 bytes).
        function LeInt([byte[]]$bytes) { New-Object System.Numerics.BigInteger (, ([byte[]]($bytes + 0))) }
        function LeBytes($n) {
            $out = New-Object byte[] 32
            $raw = $n.ToByteArray()
            [Array]::Copy($raw, $out, [Math]::Min($raw.Length, 32))
            , $out
        }
        # A point is (X, Y, Z, T) with x = X/Z, y = Y/Z, xy = T/Z.
        function PtAdd($pt1, $pt2) {
            $ta = (($pt1[1] + $fp - $pt1[0]) * ($pt2[1] + $fp - $pt2[0])) % $fp
            $tb = (($pt1[1] + $pt1[0]) * ($pt2[1] + $pt2[0])) % $fp
            $tc = ((($pt1[3] * $cd2) % $fp) * $pt2[3]) % $fp
            $td = ((($pt1[2] * $two) % $fp) * $pt2[2]) % $fp
            $te = ($tb + $fp - $ta) % $fp
            $tf = ($td + $fp - $tc) % $fp
            $tg = ($td + $tc) % $fp
            $th = ($tb + $ta) % $fp
            , @((($te * $tf) % $fp), (($tg * $th) % $fp), (($tf * $tg) % $fp), (($te * $th) % $fp))
        }
        function PtMul([byte[]]$scalar, $pt) {
            $acc = @($zero, $one, $one, $zero)
            for ($bit = 255; $bit -ge 0; $bit--) {
                $acc = PtAdd $acc $acc
                if (($scalar[$bit -shr 3] -shr ($bit -band 7)) -band 1) { $acc = PtAdd $acc $pt }
            }
            , $acc
        }
        # The point 32 bytes stand for, or $null when they stand for none.
        function PtDecode([byte[]]$bytes) {
            $yb = [byte[]]$bytes.Clone()
            $odd = ($yb[31] -shr 7) -eq 1
            $yb[31] = $yb[31] -band 0x7f
            $y = LeInt $yb
            if ($y -ge $fp) { return $null }
            $y2 = ($y * $y) % $fp
            $u = ($y2 + $fp - $one) % $fp
            $v = ($cd * $y2 + $one) % $fp
            $v3 = ((($v * $v) % $fp) * $v) % $fp
            $v7 = ((($v3 * $v3) % $fp) * $v) % $fp
            $x = ((($u * $v3) % $fp) * $big::ModPow(($u * $v7) % $fp, ($fp - $big::Parse('5')) / $big::Parse('8'), $fp)) % $fp
            $vx2 = ((($v * $x) % $fp) * $x) % $fp
            if ($vx2 -ne $u) {
                if ($vx2 -ne (($fp - $u) % $fp)) { return $null }
                $x = ($x * $sqrtM1) % $fp
            }
            if ($x.IsZero -and $odd) { return $null }
            if ((-not $x.IsEven) -ne $odd) { $x = $fp - $x }
            , @($x, $y, $one, (($x * $y) % $fp))
        }

        $sigR = [byte[]]$Signature[0..31]
        $sigS = [byte[]]$Signature[32..63]
        if ((LeInt $sigS) -ge $ord) { return $false }
        $pub = PtDecode $Key
        if ($null -eq $pub) { return $false }
        $sha = [System.Security.Cryptography.SHA512]::Create()
        try { $digest = $sha.ComputeHash([byte[]]($sigR + $Key + $Message)) } finally { $sha.Dispose() }
        $challenge = LeBytes ((LeInt $digest) % $ord)

        # R' = [s]B - [h]A must come out as the signature's R, byte for byte.
        $bx = $big::Parse('15112221349535400772501151409588531511454012693041857206046113283949847762202')
        $by = $big::Parse('46316835694926478169428394003475163141307993866256225615783033603165251855960')
        $basePt = @($bx, $by, $one, (($bx * $by) % $fp))
        $negPub = @((($fp - $pub[0]) % $fp), $pub[1], $one, (($fp - $pub[3]) % $fp))
        $sum = PtAdd (PtMul $sigS $basePt) (PtMul $challenge $negPub)
        $zInv = $big::ModPow($sum[2], $fp - $two, $fp)
        $x = ($sum[0] * $zInv) % $fp
        $enc = LeBytes (($sum[1] * $zInv) % $fp)
        if (-not $x.IsEven) { $enc[31] = $enc[31] -bor 0x80 }
        for ($at = 0; $at -lt 32; $at++) { if ($enc[$at] -ne $sigR[$at]) { return $false } }
        return $true
    }
    # <<< ed25519

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
        $sig = $rel.assets | Where-Object name -eq 'SHA256SUMS.txt.sig'
        if (-not $asset -or -not $sums) { Stop-Install "Release $tag has no build for this PC ($arch)." }
        if (-not $sig) { Stop-Install "Release $tag has no signature, so nothing was downloaded." 'Please open an issue on GitHub.' }

        # A fresh folder each time, so a half-finished earlier download is never reused.
        $dir = Join-Path $env:TEMP ('aba-install-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force $dir | Out-Null
        $exe = Join-Path $dir 'aba.exe'
        $sumFile = Join-Path $dir 'SHA256SUMS.txt'
        $sigFile = Join-Path $dir 'SHA256SUMS.txt.sig'
        try {
            Invoke-WebRequest $asset.browser_download_url -OutFile $exe -UseBasicParsing -TimeoutSec 300
            Invoke-WebRequest $sums.browser_download_url -OutFile $sumFile -UseBasicParsing -TimeoutSec 60
            Invoke-WebRequest $sig.browser_download_url -OutFile $sigFile -UseBasicParsing -TimeoutSec 60
        } catch {
            Stop-Install "The download didn't finish." 'Check your internet connection and run the command again.'
        }
        Say $ok "Downloaded $tag" 'Green' ('{0:N1} MB, {1}' -f ($asset.size / 1MB), $arch)

        # The checksum list must be signed with ABA's release key: whoever can
        # change a release's files can change its checksum list too, but can't
        # sign it.
        $sumBytes = [IO.File]::ReadAllBytes($sumFile)
        $signed = $false
        try {
            $sigBytes = [Convert]::FromBase64String([IO.File]::ReadAllText($sigFile).Trim())
            $verdict = Test-Ed25519 ([Convert]::FromBase64String($releaseKey)) $sumBytes $sigBytes
            $signed = ($verdict -is [bool]) -and $verdict
        } catch { $signed = $false }
        if (-not $signed) {
            Stop-Install "The release's checksum list isn't signed with ABA's key, so nothing was run." 'Run the command again. If it keeps happening, please open an issue on GitHub.'
        }
        Say $ok "Signed with ABA's release key" 'Green' 'ed25519'

        # The download's line in the list that was just verified (those bytes,
        # not the file read again): "<sha256>  <name>".
        $expected = $null
        foreach ($line in ([Text.Encoding]::UTF8.GetString($sumBytes) -split "`n")) {
            $parts = $line.Trim() -split '\s+'
            if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -ceq $name) { $expected = $parts[0]; break }
        }
        $actual = (Get-FileHash $exe -Algorithm SHA256).Hash
        if (-not $expected -or $actual -ne $expected.ToUpper()) {
            Stop-Install "The download doesn't match the release's signed checksum, so it was not run." 'Run the command again. If it keeps happening, please open an issue on GitHub.'
        }
        Say $ok 'Checksum matches the signed list' 'Green' 'SHA-256'

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
