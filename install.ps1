# A Better Antivirus installer.
#
#   irm https://raw.githubusercontent.com/vulnix0x4/a-better-antivirus/main/install.ps1 | iex
#
# Downloads the latest release for this PC, checks it against the release's
# SHA256SUMS.txt, and runs `aba install` (which asks for admin).
# Pass other arguments with $env:ABA_ARGS, e.g. for a test VM:
#   $env:ABA_ARGS = 'install --yes --preset strict --learning 0'

& {
    $ErrorActionPreference = 'Stop'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $repo = 'vulnix0x4/a-better-antivirus'
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
    $rel = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -Headers @{ 'User-Agent' = 'aba-installer' }
    $tag = $rel.tag_name
    $name = "aba_${tag}_windows_$arch.exe"
    $asset = $rel.assets | Where-Object name -eq $name
    $sums = $rel.assets | Where-Object name -eq 'SHA256SUMS.txt'
    if (-not $asset -or -not $sums) { throw "release $tag has no $name" }

    $dir = Join-Path $env:TEMP 'aba-install'
    New-Item -ItemType Directory -Force $dir | Out-Null
    $exe = Join-Path $dir 'aba.exe'
    $sumFile = Join-Path $dir 'SHA256SUMS.txt'

    Write-Host "Downloading A Better Antivirus $tag ($arch)..."
    Invoke-WebRequest $asset.browser_download_url -OutFile $exe -UseBasicParsing
    Invoke-WebRequest $sums.browser_download_url -OutFile $sumFile -UseBasicParsing

    $line = Get-Content $sumFile | Where-Object { $_ -match [regex]::Escape($name) + '$' }
    $expected = ($line -split '\s+')[0]
    $actual = (Get-FileHash $exe -Algorithm SHA256).Hash
    if (-not $expected -or $actual -ne $expected.ToUpper()) {
        Remove-Item $exe -Force
        throw "Checksum mismatch for $name. The download was not run."
    }
    Write-Host "Checksum OK." -ForegroundColor Green

    $argv = if ($env:ABA_ARGS) { $env:ABA_ARGS -split '\s+' } else { @('install') }
    & $exe $argv
}
