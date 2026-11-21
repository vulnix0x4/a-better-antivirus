<#
.SYNOPSIS
  Gets the Inno Setup compiler that ABA-Setup.exe is built with.

.DESCRIPTION
  Downloads one fixed version of Inno Setup, checks the download against the
  SHA-256 written below, and unpacks it into a folder. Nothing is installed
  system-wide: Inno Setup's own installer has a portable mode that needs no
  administrator rights and writes no registry entries or shortcuts.

  The version is fixed so that a release is built with a compiler somebody
  chose, not with whatever the build machine happens to have. To move to a
  newer Inno Setup, change the three values below in one commit.

  Prints the path of ISCC.exe. On GitHub Actions it also sets the ISCC
  environment variable for the following steps (installer/build reads it).

.EXAMPLE
  $env:ISCC = ./installer/get-inno.ps1
  go run ./installer/build -preview
#>
param(
    # Where to unpack. A folder that only this script uses.
    [string]$Dir = (Join-Path ([IO.Path]::GetTempPath()) 'aba-inno-setup')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$version = '6.7.4'
$url = 'https://github.com/jrsoftware/issrc/releases/download/is-6_7_4/innosetup-6.7.4.exe'
$sha256 = 'a549929319f9120716677c685535ca4671e4b937b5fdc87e2585f32d8eb30e8c'

$iscc = Join-Path $Dir 'ISCC.exe'
$marker = Join-Path $Dir 'aba-inno-version.txt'

# Already unpacked by an earlier run of this script, in this version?
$have = (Test-Path $iscc) -and (Test-Path $marker) -and ((Get-Content $marker -Raw).Trim() -eq $sha256)
if (-not $have) {
    $download = Join-Path ([IO.Path]::GetTempPath()) ("innosetup-$version-" + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.exe')
    try {
        Invoke-WebRequest $url -OutFile $download -UseBasicParsing -TimeoutSec 300
        $actual = (Get-FileHash $download -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $sha256) {
            throw "The Inno Setup download doesn't match its expected SHA-256, so it was not run.`n  expected $sha256`n  got      $actual"
        }
        if (Test-Path $Dir) { Remove-Item -Recurse -Force $Dir }
        $p = Start-Process -FilePath $download -Wait -PassThru -ArgumentList @(
            '/PORTABLE=1', '/CURRENTUSER', '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/DIR=`"$Dir`"")
        if ($p.ExitCode -ne 0 -or -not (Test-Path $iscc)) {
            throw "Unpacking Inno Setup $version into $Dir failed (exit code $($p.ExitCode))."
        }
        Set-Content -Path $marker -Value $sha256 -Encoding ascii
    } finally {
        Remove-Item -Force $download -ErrorAction SilentlyContinue
    }
}

if ($env:GITHUB_ENV) {
    Add-Content -Path $env:GITHUB_ENV -Value "ISCC=$iscc" -Encoding utf8
}
$iscc
