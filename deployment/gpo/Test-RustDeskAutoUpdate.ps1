# Local updater regression checks. No real tasks, AD, network or MSI execution.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'DeploymentSettings.ps1')
. (Join-Path $PSScriptRoot 'RustDeskUpdates.ps1')
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('rd-autoupdate-'+[guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $testRoot
try {
    $config = Join-Path $testRoot 'settings.psd1'
    $state = Join-Path $testRoot 'state'
    $null = New-Item -ItemType Directory -Path $state
    $fixture = Join-Path $testRoot 'fixture.data'
    [IO.File]::WriteAllText($fixture,'updater test data, not an MSI')
    $digest = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
    $releaseFixture = [pscustomobject]@{
        tag_name='1.5.2';draft=$false;prerelease=$false
        assets=@([pscustomobject]@{name='rustdesk-1.5.2-x86_64.msi';size=(Get-Item $fixture).Length;
            digest=('sha256:'+$digest);browser_download_url='https://github.com/rustdesk/rustdesk/releases/download/1.5.2/rustdesk-1.5.2-x86_64.msi'})
    }
    $original = @'
# Keep this company comment.
@{
    Domain = 'corp.example.com'
    OwnerDomain = 'EXAMPLE'
    IdServer = 'rd.corp.example.com'
    PublicKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
    WantVersion = '1.5.1'
    MsiPath = '\\corp.example.com\NETLOGON\RustDesk\rustdesk-1.5.1-x86_64.msi'
    MsiSha256 = ''
    ReaderAccounts = @('svc-console')
    PreviousComputerNames = @{ 'NEW-PC' = 'OLD-PC' }
}
'@
    Set-Content -LiteralPath $config -Value $original -Encoding UTF8
    $signatureValid = $true; $signatureSubject = 'TEST PUBLISHER'; $downloads = 0; $editDuringDownload = $false
    function Invoke-RestMethod { param($Uri,$Headers,$TimeoutSec) return $releaseFixture }
    function Get-AuthenticodeSignature {
        param($LiteralPath)
        [pscustomobject]@{Status=$(if ($signatureValid) { 'Valid' } else { 'NotSigned' });SignerCertificate=[pscustomobject]@{Subject=$signatureSubject}}
    }
    function Save-RustDeskReleaseAsset {
        param($Asset,$Destination)
        $script:downloads++
        Copy-Item -LiteralPath $fixture -Destination $Destination
        if ($editDuringDownload) { Add-Content -LiteralPath $config -Value '# administrator edited while downloading' }
    }
    $asset = Get-RustDeskStableMsi -Release $releaseFixture
    if ($asset.Version -ne '1.5.2' -or $asset.Sha256 -ne $digest) { throw 'Stable MSI parsing failed.' }
    foreach ($change in @(@{prerelease=$true},@{draft=$true},@{tag_name='nightly'})) {
        $copy = $releaseFixture | ConvertTo-Json -Depth 6 | ConvertFrom-Json
        foreach ($key in $change.Keys) { $copy.$key = $change[$key] }
        $rejected=$false
        try { Get-RustDeskStableMsi -Release $copy | Out-Null } catch { $rejected=$true }
        if (-not $rejected) { throw 'Unstable release accepted.' }
    }
    foreach ($change in @(@{digest=''},@{browser_download_url='http://github.com/rustdesk/rustdesk/releases/download/1.5.2/rustdesk-1.5.2-x86_64.msi'},@{size=129MB})) {
        $copy = $releaseFixture | ConvertTo-Json -Depth 6 | ConvertFrom-Json
        foreach ($key in $change.Keys) { $copy.assets[0].$key = $change[$key] }
        $rejected=$false
        try { Get-RustDeskStableMsi -Release $copy | Out-Null } catch { $rejected=$true }
        if (-not $rejected) { throw 'Invalid release asset accepted.' }
    }
    $before = [IO.File]::ReadAllText($config)
    $result = Invoke-RustDeskStagingUpdate -ConfigPath $config -StateDir $state -AllowedSignerSubject 'TEST PUBLISHER' -CheckOnly
    if ($downloads -ne 0 -or $result.Status -ne 'check only' -or [IO.File]::ReadAllText($config) -cne $before) { throw 'CheckOnly changed deployment.' }
    foreach ($case in @('unsigned','wrong publisher','wrong hash')) {
        $signatureValid = $case -ne 'unsigned'
        $signatureSubject = if ($case -eq 'wrong publisher') { 'OTHER PUBLISHER' } else { 'TEST PUBLISHER' }
        if ($case -eq 'wrong hash') { $releaseFixture.assets[0].digest = 'sha256:'+('0'*64) }
        $rejected=$false
        try { Invoke-RustDeskStagingUpdate -ConfigPath $config -StateDir $state -AllowedSignerSubject 'TEST PUBLISHER' | Out-Null } catch { $rejected=$true }
        if (-not $rejected -or [IO.File]::ReadAllText($config) -cne $before) { throw 'Verification failure changed settings.' }
    }
    $releaseFixture.assets[0].digest = 'sha256:'+$digest
    $signatureValid = $true; $signatureSubject = 'TEST PUBLISHER'
    $result = Invoke-RustDeskStagingUpdate -ConfigPath $config -StateDir $state -AllowedSignerSubject 'TEST PUBLISHER'
    if ($result.Status -ne 'staged') { throw 'Verified release was not staged.' }
    $settings = Get-RustDeskDeploymentSettings -ConfigPath $config
    if ($settings.WantVersion -ne '1.5.2' -or $settings.MsiSha256 -ne $digest -or $settings.MsiPath -notlike '*rustdesk-1.5.2-x86_64.msi') { throw 'Version/path/hash did not publish together.' }
    if ($settings.IdServer -ne 'rd.corp.example.com' -or $settings.OwnerDomain -ne 'EXAMPLE' -or $settings.ReaderAccounts[0] -ne 'svc-console' -or
        $settings.PreviousComputerNames['NEW-PC'] -ne 'OLD-PC' -or [IO.File]::ReadAllText($config) -notmatch '# Keep this company comment\.') { throw 'Company settings or comments were changed.' }
    if (-not (Test-Path -LiteralPath $result.Backup)) { throw 'Original settings were not backed up.' }
    $result = Invoke-RustDeskStagingUpdate -ConfigPath $config -StateDir $state -AllowedSignerSubject 'TEST PUBLISHER'
    if ($result.Status -ne 'already current') { throw 'Repeated update is not idempotent.' }
    $higher = [IO.File]::ReadAllText($config).Replace("WantVersion = '1.5.2'","WantVersion = '1.6.0'")
    Set-Content -LiteralPath $config -Value $higher -Encoding UTF8
    $result = Invoke-RustDeskStagingUpdate -ConfigPath $config -StateDir $state -AllowedSignerSubject 'TEST PUBLISHER'
    if ($result.Status -ne 'newer version already configured') { throw 'Updater attempted a downgrade.' }
    # Concurrent administrator edits must survive a new download.
    Set-Content -LiteralPath $config -Value $original -Encoding UTF8
    Remove-Item -LiteralPath (Join-Path $testRoot 'rustdesk-1.5.2-x86_64.msi') -Force
    $editDuringDownload=$true; $rejected=$false
    try { Invoke-RustDeskStagingUpdate -ConfigPath $config -StateDir $state -AllowedSignerSubject 'TEST PUBLISHER' | Out-Null } catch { $rejected=$true }
    if (-not $rejected -or [IO.File]::ReadAllText($config) -notmatch '# administrator edited while downloading' -or
        (Get-RustDeskDeploymentSettings -ConfigPath $config).WantVersion -ne '1.5.1') { throw 'Concurrent settings edit was overwritten.' }
    # Inserting absent update fields must preserve nested rename data.
    $sparse = "@{ Domain='corp.example.com'; PreviousComputerNames=@{ 'NEW-PC'='OLD-PC' } }"
    $updated = Get-RustDeskUpdatedSettingsText -Text $sparse -Version '1.5.2' -MsiPath '\\corp.example.com\NETLOGON\RustDesk\rustdesk-1.5.2-x86_64.msi' -Sha256 $digest
    Set-Content -LiteralPath $config -Value $updated -Encoding UTF8
    if ((Import-PowerShellDataFile -LiteralPath $config).PreviousComputerNames['NEW-PC'] -ne 'OLD-PC') { throw 'Insertion corrupted nested company settings.' }
    Write-Host 'PASS: stable-only MSI selection; official digest and publisher checks; atomic settings/backups; no downgrades; idempotency; CheckOnly; company data and concurrent edits preserved.'
} finally {
    $resolved=[IO.Path]::GetFullPath($testRoot)
    $temporaryRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if ($resolved.StartsWith($temporaryRoot,[StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf) -like 'rd-autoupdate-*') { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
