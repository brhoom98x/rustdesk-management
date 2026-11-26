# Regression checks use temporary records and mock ownership. No real service,
# task, AD or unattended password is changed.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'DeploymentSettings.ps1')
$valid = @{Domain='corp.example.com';OwnerDomain='EXAMPLE';PreviousComputerNames=@{'NEW-PC'='OLD-PC'}}
$parsed = Get-RustDeskDeploymentSettings -Overrides $valid
if ($parsed.PreviousComputerNames['NEW-PC'] -ne 'OLD-PC') { throw 'Rename settings were not preserved.' }
foreach ($bad in @('not-a-map', @{'NEW-PC'='..\OTHER'}, @{'NEW-PC'='NEW-PC'})) {
    $rejected = $false
    try { Get-RustDeskDeploymentSettings -Overrides @{Domain='corp.example.com';PreviousComputerNames=$bad} | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'Invalid rename settings were accepted.' }
}
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('rd-identity-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    # Exercise the real Windows PowerShell -File startup entry point. Path
    # defaults must be resolved in the script body, after PSScriptRoot exists.
    foreach ($filename in @('Deploy-RustDesk.ps1','DeploymentSettings.ps1','Set-RustDeskUserConfig.ps1')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $filename) -Destination (Join-Path $testRoot $filename)
    }
    $fixture = "@{ Domain='corp.example.com'; OwnerDomain='EXAMPLE'; IdServer='rd.corp.example.com'; PublicKey='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='; PreviousComputerNames=@{ 'NEW-PC'='OLD-PC' } }"
    Set-Content -LiteralPath (Join-Path $testRoot 'settings.psd1') -Value $fixture -Encoding UTF8
    foreach ($filename in @('Deploy-RustDesk.ps1','Set-RustDeskUserConfig.ps1')) {
        & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $testRoot $filename) -CheckConfig
        if ($LASTEXITCODE -ne 0) { throw 'Startup entry point could not load its adjacent settings.' }
    }
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Deploy-RustDesk.ps1'), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'Deployment syntax errors.' }
    foreach ($name in @('Get-StoredRecord','Get-RenamedRecord','Get-PreviousDeploymentHost','Save-DeploymentIdentity','Set-StoredRecord','Invoke-RustDeskCli')) {
        $function = $ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name}, $false)
        if (-not $function) { throw "Missing function $name" }
        . ([scriptblock]::Create($function.Extent.Text))
    }
    $messages = New-Object System.Collections.Generic.List[string]
    function Write-Log { param($Message,$Level) $messages.Add([string]$Message) }
    $OwnerDomain = 'EXAMPLE'
    $LogDir = $testRoot
    $testOwner = "EXAMPLE\$env:COMPUTERNAME`$"
    function Get-Acl { param($LiteralPath) [pscustomobject]@{Owner=$testOwner} }
    $sentinel = 'rename-regression-password-only'
    $old = Join-Path $testRoot 'OLD-PC.json'
    @{rustdesk=$true;host='OLD-PC';id='45316545';password=$sentinel} |
        ConvertTo-Json -Compress | Set-Content -LiteralPath $old -Encoding UTF8
    $record = Get-RenamedRecord -Vault $testRoot -PreviousHost OLD-PC -Id '45316545'
    if (-not $record -or $record.password -ne $sentinel) { throw 'Same-account rename lost its original password.' }
    if (Get-RenamedRecord -Vault $testRoot -PreviousHost OLD-PC -Id '99999999') { throw 'Different RustDesk ID was accepted.' }
    $testOwner = 'EXAMPLE\OTHER-PC$'
    if (Get-RenamedRecord -Vault $testRoot -PreviousHost OLD-PC -Id '45316545') { throw 'Another computer account was accepted.' }
    $destination = Join-Path $testRoot ($env:COMPUTERNAME + '.json')
    Set-Content -LiteralPath $destination -Value 'leave this file unchanged'
    if (Set-StoredRecord -Path $destination -Id '45316545' -Password $sentinel) { throw 'Wrong-owner destination was overwritten.' }
    if ((Get-Content -LiteralPath $destination -Raw).Trim() -ne 'leave this file unchanged') { throw 'Rejected destination changed.' }
    $testOwner = "EXAMPLE\$env:COMPUTERNAME`$"
    if (-not (Set-StoredRecord -Path $destination -Id '45316545' -Password $record.password)) { throw 'Canonical record could not be published.' }
    $published = Get-StoredRecord -Path $destination
    if ($published.host -ne $env:COMPUTERNAME -or $published.id -ne '45316545' -or $published.password -ne $sentinel) { throw 'Canonical record changed the password or ID.' }
    @{host='OLD-PC';id='45316545';version=1} | ConvertTo-Json -Compress |
        Set-Content -LiteralPath (Join-Path $LogDir 'identity.json') -Encoding UTF8
    if ((Get-PreviousDeploymentHost) -ne 'OLD-PC') { throw 'Previous machine identity was lost.' }
    Save-DeploymentIdentity -Id '45316545'
    if ((Get-PreviousDeploymentHost) -ne $env:COMPUTERNAME) { throw 'Completed rename was not marked as consumed.' }
    $tracking = Get-Content -LiteralPath (Join-Path $LogDir 'identity.json') -Raw
    if ($tracking -like ('*' + $sentinel + '*') -or $tracking -match 'password') { throw 'Identity tracking contains a password.' }
    if (($messages -join "`n") -like ('*' + $sentinel + '*')) { throw 'Password leaked into repair diagnostics.' }
    $cliExit = 1; $cliReady = $true
    function Start-Process {
        param($FilePath,$ArgumentList,[switch]$PassThru,$WindowStyle,$RedirectStandardOutput)
        $process = [pscustomobject]@{ExitCode=$cliExit}
        $process | Add-Member ScriptMethod WaitForExit { param($milliseconds) return $cliReady }
        $process | Add-Member ScriptMethod Kill { }
        return $process
    }
    $rejected = $false
    try { Invoke-RustDeskCli -Arguments @('--password',$sentinel) -RequireSuccess | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Failed password command was reported as successful.' }
    $cliExit = 0
    Invoke-RustDeskCli -Arguments @('--password',$sentinel) -RequireSuccess | Out-Null
    $cliReady = $false; $rejected = $false
    try { Invoke-RustDeskCli -Arguments @('--password',$sentinel) -RequireSuccess | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Timed-out password command was reported as successful.' }
    Write-Host 'PASS: rename preserves password; current owner and ID required; foreign destination blocked; tracking contains no password and consumes recovery.'
} finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if ($resolved.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf) -like 'rd-identity-*') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
