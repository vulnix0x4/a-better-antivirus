<#
.SYNOPSIS
  Code-signs Windows programs (Authenticode) in place, then checks the signature.

.DESCRIPTION
  installer/build runs this on each aba.exe GoReleaser has just built, before
  the file is copied into ABA-Setup.exe, zipped or listed in SHA256SUMS.txt,
  and then on ABA-Setup.exe itself. So every Windows program a release
  publishes is signed, and the checksums are of the signed files.

  It does nothing unless scripts/setup-windows-signing.ps1 has set things up
  (installer/build only calls it when ABA_WINDOWS_SIGNING is set). How:

    ABA_WINDOWS_SIGNING=artifact-signing   Microsoft's Artifact Signing service,
                                           the real release signature. Needs
                                           ABA_SIGN_DLIB and ABA_SIGN_METADATA.
    ABA_WINDOWS_SIGNING=test               a throwaway certificate in the
                                           current user's store (CI only), its
                                           thumbprint in ABA_SIGN_TEST_CERT.

  Both need ABA_SIGNTOOL (the path of signtool.exe). Every signature is
  timestamped (ABA_SIGN_TIMESTAMP, Microsoft's timestamp server by default),
  so it stays valid after the certificate behind it expires: Artifact Signing
  certificates only last three days.

  A file that already carries a valid signature is left as it is, so running
  this twice on the same file changes nothing.
#>
param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Path)

$ErrorActionPreference = 'Stop'

function Need([string]$name) {
    $v = [Environment]::GetEnvironmentVariable($name)
    if (-not $v) { throw "ABA_WINDOWS_SIGNING is '$env:ABA_WINDOWS_SIGNING' but $name is not set: run scripts/setup-windows-signing.ps1 first." }
    return $v
}

$signtool = Need 'ABA_SIGNTOOL'
if (-not (Test-Path $signtool)) { throw "ABA_SIGNTOOL is $signtool, which doesn't exist." }
$timestamp = if ($env:ABA_SIGN_TIMESTAMP) { $env:ABA_SIGN_TIMESTAMP } else { 'http://timestamp.acs.microsoft.com' }

switch ($env:ABA_WINDOWS_SIGNING) {
    'artifact-signing' { $how = @('/dlib', (Need 'ABA_SIGN_DLIB'), '/dmdf', (Need 'ABA_SIGN_METADATA')) }
    'test' { $how = @('/sha1', (Need 'ABA_SIGN_TEST_CERT'), '/s', 'My') }
    default { throw "ABA_WINDOWS_SIGNING is '$env:ABA_WINDOWS_SIGNING'; expected artifact-signing or test." }
}

foreach ($p in $Path) {
    $file = (Resolve-Path $p).Path
    if ((Get-AuthenticodeSignature $file).Status -eq 'Valid') {
        Write-Host "sign: $file is already signed"
        continue
    }
    # The signing service is a network call: give a passing hiccup two more tries.
    for ($try = 1; ; $try++) {
        & $signtool sign /v /fd SHA256 /tr $timestamp /td SHA256 @how $file
        if ($LASTEXITCODE -eq 0) { break }
        if ($try -ge 3) { throw "signtool could not sign $file (exit code $LASTEXITCODE)." }
        Write-Host "sign: try $try failed (exit code $LASTEXITCODE); trying again in $(15 * $try) s"
        Start-Sleep -Seconds (15 * $try)
    }
    # The same check Windows makes: a chain to a trusted root, for code signing.
    & $signtool verify /pa /v $file
    if ($LASTEXITCODE) { throw "$file was signed but its signature doesn't verify (signtool verify /pa, exit code $LASTEXITCODE)." }
    $sig = Get-AuthenticodeSignature $file
    if ($sig.Status -ne 'Valid') { throw "${file}: the signature is '$($sig.Status)': $($sig.StatusMessage)" }
    if (-not $sig.TimeStamperCertificate) { throw "${file}: the signature has no timestamp." }
    Write-Host "sign: signed $file for '$($sig.SignerCertificate.Subject)'"
}
