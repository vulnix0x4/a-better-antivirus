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

  Exits with an error if any of them doesn't hold.
#>
param([string]$Dist = 'dist')

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

# Nothing else slipped in.
if ($sums.Count -eq 5) { Ok 'five files in all: the four there always were, and ABA-Setup.exe' }
else { Bad "expected 5 files in SHA256SUMS.txt, found $($sums.Count)" }

if ($script:bad) { Write-Host "`n$($script:bad) check(s) failed." -ForegroundColor Red; exit 1 }
Write-Host "`nThe installer matches the release." -ForegroundColor Green
