<#
.SYNOPSIS
  Gets the tools for code-signing ABA's Windows programs and turns signing on
  for the following steps of a GitHub Actions job.

.DESCRIPTION
  Downloads fixed versions of signtool.exe (Microsoft.Windows.SDK.BuildTools)
  and, for the real signature, Microsoft's Artifact Signing client
  (Microsoft.ArtifactSigning.Client), each checked against the SHA-256 written
  below. Nothing is installed system-wide. Then it writes ABA_WINDOWS_SIGNING
  and the paths scripts/sign-windows.ps1 needs to $GITHUB_ENV, so that the
  GoReleaser step after it signs every Windows program it builds.

  -Mode artifact-signing   the release signature. The workflow must have signed
                           in to Azure first (azure/login, with OIDC: no
                           password or key is stored anywhere), and set
                           ARTIFACT_SIGNING_ENDPOINT, ARTIFACT_SIGNING_ACCOUNT
                           and ARTIFACT_SIGNING_PROFILE. The Artifact Signing
                           client needs the .NET 10 runtime (actions/setup-dotnet).
  -Mode test               a throwaway certificate made here and trusted on
                           this machine only, so CI can prove the signing steps
                           work before the real signature exists. It refuses to
                           run outside GitHub Actions: it adds a trusted root.

  To move to newer versions, change the version and SHA-256 together.
#>
param([Parameter(Mandatory)][ValidateSet('artifact-signing', 'test')][string]$Mode)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not $env:GITHUB_ENV) { throw 'This sets up signing for a GitHub Actions job ($GITHUB_ENV is not set).' }
$root = Join-Path ([IO.Path]::GetTempPath()) 'aba-signing'
New-Item -ItemType Directory -Force $root | Out-Null

# Get-Package downloads one NuGet package, checks it and unpacks it.
function Get-Package([string]$id, [string]$version, [string]$sha256) {
    $dir = Join-Path $root "$id.$version"
    $nupkg = "$dir.nupkg"
    Invoke-WebRequest "https://api.nuget.org/v3-flatcontainer/$($id.ToLower())/$version/$($id.ToLower()).$version.nupkg" -OutFile $nupkg -UseBasicParsing -TimeoutSec 300
    $actual = (Get-FileHash $nupkg -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $sha256) { throw "The $id $version download doesn't match its expected SHA-256, so it was not used.`n  expected $sha256`n  got      $actual" }
    if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
    Expand-Archive -Path $nupkg -DestinationPath $dir
    Remove-Item -Force $nupkg
    return $dir
}

function Must([string]$p) { if (-not (Test-Path $p)) { throw "$p is missing from the package." }; return $p }

$env_ = [ordered]@{ ABA_WINDOWS_SIGNING = $Mode }

$sdk = Get-Package 'Microsoft.Windows.SDK.BuildTools' '10.0.28000.2957' 'b7163fc6f636172726d0985963e4f7f11c41afe1c7fdfe78f8051877360ed696'
$env_.ABA_SIGNTOOL = Must (Join-Path $sdk 'bin\10.0.28000.0\x64\signtool.exe')

if ($Mode -eq 'artifact-signing') {
    $client = Get-Package 'Microsoft.ArtifactSigning.Client' '1.0.151' '35375a4bc4e1102da729fc3d8d9925f774c3baae6b8b7ff6398d948ca9ab0d8a'
    $env_.ABA_SIGN_DLIB = Must (Join-Path $client 'bin\x64\Azure.CodeSigning.Dlib.dll')

    foreach ($v in 'ARTIFACT_SIGNING_ENDPOINT', 'ARTIFACT_SIGNING_ACCOUNT', 'ARTIFACT_SIGNING_PROFILE') {
        if (-not [Environment]::GetEnvironmentVariable($v)) { throw "$v is not set." }
    }
    # Only the Azure CLI sign-in that azure/login made: no other way of
    # signing in is tried, so none can pick up something unexpected.
    $metadata = Join-Path $root 'metadata.json'
    [ordered]@{
        Endpoint               = $env:ARTIFACT_SIGNING_ENDPOINT.Trim()
        CodeSigningAccountName = $env:ARTIFACT_SIGNING_ACCOUNT.Trim()
        CertificateProfileName = $env:ARTIFACT_SIGNING_PROFILE.Trim()
        CorrelationId          = "$env:GITHUB_REPOSITORY $env:GITHUB_REF_NAME run $env:GITHUB_RUN_ID"
        ExcludeCredentials     = @(
            'EnvironmentCredential', 'WorkloadIdentityCredential', 'ManagedIdentityCredential',
            'SharedTokenCacheCredential', 'VisualStudioCredential', 'VisualStudioCodeCredential',
            'AzurePowerShellCredential', 'AzureDeveloperCliCredential', 'InteractiveBrowserCredential')
    } | ConvertTo-Json | Set-Content -Path $metadata -Encoding utf8
    $env_.ABA_SIGN_METADATA = $metadata

    # GitHub's sign-in token for Azure is short-lived, and the build takes a
    # few minutes before the first file is signed. Asking for the signing
    # service's access token now makes the Azure CLI keep one (good for about
    # an hour) that signtool's requests then use.
    az account get-access-token --resource https://codesigning.azure.net --query expiresOn --output tsv
    if ($LASTEXITCODE) { throw 'Could not get an access token for Artifact Signing: did azure/login run, and does its app have the "Artifact Signing Certificate Profile Signer" role?' }
} else {
    if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Test signing trusts a throwaway certificate machine-wide: it only runs on a CI runner.' }
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=ABA CI test signature (not a real one)' `
        -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddDays(2)
    $cer = Join-Path $root 'test-signing.cer'
    Export-Certificate -Cert $cert -FilePath $cer | Out-Null
    # Trusted on this runner only, so `signtool verify /pa` and Windows itself
    # treat the test signature the way they will treat the real one.
    foreach ($store in 'Root', 'TrustedPublisher') { Import-Certificate -FilePath $cer -CertStoreLocation "Cert:\LocalMachine\$store" | Out-Null }
    $env_.ABA_SIGN_TEST_CERT = $cert.Thumbprint
}

foreach ($k in $env_.Keys) {
    Add-Content -Path $env:GITHUB_ENV -Value "$k=$($env_[$k])" -Encoding utf8
    Write-Host "$k=$($env_[$k])"
}
