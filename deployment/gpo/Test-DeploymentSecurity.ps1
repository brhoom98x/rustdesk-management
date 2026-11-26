# Local security regression checks. No AD/GPO/service/installer changes.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'DeploymentSettings.ps1')
$key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
foreach ($unsafe in @(@{PublicKey=($key+"`n")}, @{StageDir="\\corp.example.com\NETLOGON\bad`"path"}, @{ApiServer='http://api.example.com'}, @{ApiServer='https://user:secret@api.example.com'}, @{Path='C:\'}, @{MsiSha256='not-a-digest'})) {
    $rejected=$false
    try { Get-RustDeskDeploymentSettings -Overrides (@{Domain='corp.example.com';OwnerDomain='EXAMPLE';IdServer='rd.corp.example.com';PublicKey=$key} + $unsafe) -Required @('IdServer','PublicKey') | Out-Null }
    catch { $rejected=$true }
    if (-not $rejected) { throw ('Unsafe configuration was accepted: '+(($unsafe.Keys) -join ', ')) }
}
$rejected=$false
try { & (Join-Path $PSScriptRoot 'Get-RustDeskPassword.ps1') -ComputerName '..\OTHER-PC' -OwnerDomain EXAMPLE -VaultPath '\\localhost\fixture' }
catch { $rejected=$true }
if (-not $rejected) { throw 'Traversal computer name was accepted.' }

$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('rd-security-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $tokens=$null; $errors=$null
    $ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Deploy-RustDesk.ps1'),[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw 'Deployment syntax errors.' }
    foreach ($name in @('Get-StoredRecord','Install-RustDesk')) {
        $function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$false)
        . ([scriptblock]::Create($function.Extent.Text))
    }
    $messages=New-Object System.Collections.Generic.List[string]
    function Write-Log { param($Message,$Level) $messages.Add([string]$Message) }
    $OwnerDomain='EXAMPLE'
    $testOwner="EXAMPLE\$env:COMPUTERNAME`$"
    function Get-Acl { param($LiteralPath) [pscustomobject]@{Owner=$testOwner} }
    $record=Join-Path $testRoot ($env:COMPUTERNAME+'.json')
    @{rustdesk=$true;host=$env:COMPUTERNAME;id='100000001';password='security-test-sentinel'} | ConvertTo-Json | Set-Content -LiteralPath $record -Encoding UTF8
    if (-not (Get-StoredRecord -Path $record)) { throw 'Valid own record was rejected.' }
    $testOwner='EXAMPLE\OTHER-PC$'
    if (Get-StoredRecord -Path $record) { throw 'Wrong-owner record was reused.' }
    $testOwner="EXAMPLE\$env:COMPUTERNAME`$"
    Set-Content -LiteralPath $record -Value '{"password":"security-test-sentinel",' -Encoding UTF8
    if (Get-StoredRecord -Path $record) { throw 'Malformed record was reused.' }
    if (($messages -join "`n") -like '*security-test-sentinel*') { throw 'Parse error logged password content.' }

    $MsiPath=Join-Path $testRoot 'fixture.msi'
    Set-Content -LiteralPath $MsiPath -Value 'test fixture, not an executable installer'
    $MsiSha256='0'*64
    $LogDir=$testRoot
    $installerStarted=$false
    function Start-Process { $script:installerStarted=$true; throw 'Test must never start an installer' }
    if (Install-RustDesk) { throw 'Checksum mismatch was accepted.' }
    if ($installerStarted) { throw 'Installer started despite mismatched checksum.' }
    Write-Host 'PASS: unsafe configuration/path traversal rejected; owner checked; malformed-record logs contain no password; bad MSI hash blocks execution.'
} finally {
    $resolved=[IO.Path]::GetFullPath($testRoot)
    $tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if ($resolved.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf) -like 'rd-security-*') { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
