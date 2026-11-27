<#
.SYNOPSIS
  Checks what a GoReleaser run left in dist\ before (or after) it is published.

.DESCRIPTION
  The promises a release makes about ABA-Setup.exe:

  - SHA256SUMS.txt lists ABA-Setup.exe, with the hash of the file that is uploaded.
  - The two aba.exe files compiled into ABA-Setup.exe are byte for byte the
    aba_<tag>_windows_<arch>.exe downloads of the same release.
  - The files the auto-updater in installed copies looks for are all still
    there under their usual names.

  With -Signed (when the release job code-signs, see
  scripts/setup-windows-signing.ps1), also that every Windows program
  published carries a valid, timestamped Authenticode signature, checked with
  `signtool verify /pa` (ABA_SIGNTOOL) and Get-AuthenticodeSignature: both
  aba_<tag>_windows_<arch>.exe files, the aba.exe in each zip, ABA-Setup.exe
  and the two aba.exe files inside it.

  Exits with an error if any of them doesn't hold.
#>
param([string]$Dist = 'dist', [switch]$Signed)

$ErrorActionPreference = 'Stop'
$script:bad = 0
function Ok([string]$m) { Write-Host "  ok    $m" -ForegroundColor Green }
function Bad([string]$m) { Write-Host "  FAIL  $m" -ForegroundColor Red; $script:bad++ }
function Sha([string]$p) { (Get-FileHash $p -Algorithm SHA256).Hash.ToLower() }

$sumsFile = Join-Path $Dist 'SHA256SUMS.txt'
if (-not (Test-Path $sumsFile)) { throw "$sumsFile is missing: run GoReleaser first." }
$sums = @{}
foreach ($line in Get-Content $sumsFile) {
    $f = $line -split '\s+', 2
    if ($f.Count -eq 2 -and $f[0].Length -eq 64) { $sums[$f[1].Trim().TrimStart('*')] = $f[0].ToLower() }
}
Write-Host "SHA256SUMS.txt lists: $(($sums.Keys | Sort-Object) -join ', ')"

# The installer itself.
$setup = Join-Path $Dist 'installer\ABA-Setup.exe'
if (-not (Test-Path $setup)) { throw "$setup is missing: the installer was not built." }
if ($sums['ABA-Setup.exe'] -eq (Sha $setup)) { Ok 'ABA-Setup.exe is in SHA256SUMS.txt with the hash of the built file' }
else { Bad "ABA-Setup.exe: SHA256SUMS.txt says '$($sums['ABA-Setup.exe'])', the built file is $(Sha $setup)" }

# What went into it against what is published next to it.
foreach ($arch in 'amd64', 'arm64') {
    $names = @($sums.Keys | Where-Object { $_ -match "^aba_v?[^_]+_windows_$arch\.exe$" })
    if ($names.Count -ne 1) { Bad "expected one aba_<tag>_windows_$arch.exe in SHA256SUMS.txt, found $($names.Count)"; continue }
    $inside = Join-Path $Dist "installer\bin\aba-$arch.exe"
    if (-not (Test-Path $inside)) { Bad "$inside is missing"; continue }
    if ($sums[$names[0]] -eq (Sha $inside)) { Ok "the $arch aba.exe inside ABA-Setup.exe is $($names[0]), byte for byte" }
    else { Bad "the $arch aba.exe inside ABA-Setup.exe differs from $($names[0])" }

    if (@($sums.Keys | Where-Object { $_ -match "^aba_v?[^_]+_windows_$arch\.zip$" }).Count -eq 1) { Ok "aba_<tag>_windows_$arch.zip is still published" }
    else { Bad "aba_<tag>_windows_$arch.zip is missing from SHA256SUMS.txt" }
}

if ($Signed) {
    if (-not $env:ABA_SIGNTOOL -or -not (Test-Path $env:ABA_SIGNTOOL)) { throw '-Signed needs ABA_SIGNTOOL, the path of signtool.exe (scripts/setup-windows-signing.ps1 sets it).' }
    $unzipped = Join-Path ([IO.Path]::GetTempPath()) ('aba-verify-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $programs = @($setup) + @(Get-ChildItem (Join-Path $Dist 'installer\bin') -Filter 'aba-*.exe' | ForEach-Object FullName)
    foreach ($name in @($sums.Keys | Sort-Object)) {
        if ($name -like '*.exe' -and $name -ne 'ABA-Setup.exe') { $programs += (Join-Path $Dist $name) }
        if ($name -like '*.zip') {
            $to = Join-Path $unzipped ([IO.Path]::GetFileNameWithoutExtension($name))
            Expand-Archive -Path (Join-Path $Dist $name) -DestinationPath $to
            $programs += @(Get-ChildItem $to -Recurse -Filter '*.exe' | ForEach-Object FullName)
        }
    }
    foreach ($p in $programs) {
        $label = $p.Replace($unzipped, '<zip>')
        & $env:ABA_SIGNTOOL verify /pa /q $p | Out-Null
        $sig = Get-AuthenticodeSignature $p
        if ($LASTEXITCODE -ne 0) { Bad "${label}: signtool verify /pa says the signature isn't valid ($($sig.Status))"; continue }
        if ($sig.Status -ne 'Valid') { Bad "${label}: the signature is $($sig.Status): $($sig.StatusMessage)"; continue }
        if (-not $sig.TimeStamperCertificate) { Bad "${label}: the signature has no timestamp, so it would stop being valid when the certificate expires"; continue }
        Ok "$label is signed by '$($sig.SignerCertificate.Subject)', timestamped"
    }
    if ($programs.Count -ne 7) { Bad "expected 7 Windows programs to check (2 downloads, 2 in the zips, ABA-Setup.exe and the 2 inside it), found $($programs.Count)" }
    Remove-Item -Recurse -Force $unzipped -ErrorAction SilentlyContinue
}

# Nothing else slipped in.
if ($sums.Count -eq 5) { Ok 'five files in all: the four there always were, and ABA-Setup.exe' }
else { Bad "expected 5 files in SHA256SUMS.txt, found $($sums.Count)" }

if ($script:bad) { Write-Host "`n$($script:bad) check(s) failed." -ForegroundColor Red; exit 1 }
Write-Host "`nThe installer matches the release." -ForegroundColor Green
