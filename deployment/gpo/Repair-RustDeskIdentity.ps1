<#
.SYNOPSIS
    Preserves a renamed computer's original unattended password and vault identity.
.DESCRIPTION
    Run on the DC as an administrator with -ComputerName and -PreviousComputerName.
    The one-time task runs on that workstation as SYSTEM, verifies the previous
    file is owned by its CURRENT computer account and carries its current RustDesk
    ID, then republishes it under the new name. No installation, reboot, service
    restart, old-record deletion, or relaxed console owner checks are performed.
    Stage this helper, Deploy-RustDesk.ps1, DeploymentSettings.ps1 and settings.psd1
    together in the protected NETLOGON deployment folder first.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = '',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,14}$')]
    [Parameter(Mandatory)][string]$PreviousComputerName,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,14}$')][string]$ComputerName,
    [string]$DeployScript = '',
    [string]$OwnerDomain = '',
    [string]$VaultPath = '',
    [string]$VaultPointer = '',
    [string]$LogDir = "$env:ProgramData\RustDeskDeploy"
)
$ErrorActionPreference = 'Stop'
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'settings.psd1' }
if (-not $DeployScript) { $DeployScript = Join-Path $PSScriptRoot 'Deploy-RustDesk.ps1' }
. (Join-Path $PSScriptRoot 'DeploymentSettings.ps1')
$settings = Get-RustDeskDeploymentSettings -ConfigPath $ConfigPath -Overrides $PSBoundParameters
foreach ($name in @('OwnerDomain','VaultPath','VaultPointer')) { Set-Variable -Name $name -Value $settings[$name] }
if (-not $OwnerDomain) { throw 'Configure the actual AD NetBIOS OwnerDomain before repairing a machine identity.' }

if ($ComputerName) {
    if (-not $settings.StageDir) { throw 'Configure the NETLOGON StageDir first.' }
    $helper = Join-Path $settings.StageDir 'Repair-RustDeskIdentity.ps1'
    if (-not (Test-Path -LiteralPath $helper)) { throw 'Stage the identity repair helper in NETLOGON first.' }
    if ($PSBoundParameters.ContainsKey('VaultPath') -or $PSBoundParameters.ContainsKey('VaultPointer')) {
        throw 'For remote repairs, stage the vault configuration in adjacent settings.psd1 or vault-path.txt.'
    }
    # schtasks has a short /TR limit. Adjacent settings/pointer supply the vault
    # location. Neither a password nor an embedded script goes in the task.
    $command = 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -PreviousComputerName {1} -OwnerDomain {2}' -f $helper, $PreviousComputerName, $OwnerDomain
    if ($command.Length -gt 260) { throw 'Task command exceeds the Windows limit; use a shorter staged path.' }
    & schtasks.exe /Create /S $ComputerName /TN '\RustDesk\Repair identity' /RU SYSTEM /RL HIGHEST `
        /SC ONCE /ST ((Get-Date).AddMinutes(2).ToString('HH:mm')) /TR $command /F
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create the remote repair task. Check that the PC is online and remote Task Scheduler access is allowed.' }
    & schtasks.exe /Run /S $ComputerName /TN '\RustDesk\Repair identity'
    if ($LASTEXITCODE -ne 0) { throw 'The repair task was created but could not be started.' }
    Write-Host "$ComputerName : identity repair started; check its deploy.log and the console."
    return
}

if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {
    throw 'Run the repair as SYSTEM, not as your administrator account. On the DC use -ComputerName to create its one-time SYSTEM task.'
}
if ($PreviousComputerName -eq $env:COMPUTERNAME) { throw 'PreviousComputerName must differ from the current computer name.' }
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($DeployScript, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Deployment script has syntax errors.' }
foreach ($name in @('Write-Log','Invoke-RustDeskCli','Get-RustDeskId','Get-StoredRecord','Get-RenamedRecord','Set-StoredRecord','Save-DeploymentIdentity','Register-SessionReporter')) {
    $function = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $false)
    if (-not $function) { throw 'Stage the current deployment script with the repair helper.' }
    . ([scriptblock]::Create($function.Extent.Text))
}
$script:LogFile = Join-Path $LogDir 'deploy.log'
if (-not $VaultPath) { $VaultPath = (Get-Content -LiteralPath $VaultPointer -TotalCount 1).Trim() }
if ($VaultPath -notmatch '^\\\\[^\\]+\\[^\\]+') { throw 'The vault pointer must contain a UNC share path.' }
$rid = Get-RustDeskId
$record = Get-RenamedRecord -Vault $VaultPath -PreviousHost $PreviousComputerName -Id $rid
if (-not $record) { throw 'Previous record failed current-computer ownership or RustDesk ID verification; nothing was changed.' }
$destination = Join-Path $VaultPath ($env:COMPUTERNAME + '.json')
if (-not (Set-StoredRecord -Path $destination -Id $rid -Password $record.password)) { throw 'Canonical vault write failed; local password was left unchanged.' }
Invoke-RustDeskCli -Arguments @('--password', $record.password) -RequireSuccess | Out-Null
Save-DeploymentIdentity -Id $rid
$SessionTaskPath = '\RustDesk\'
$SessionTaskName = 'Report logged-on user'
Register-SessionReporter -Vault $VaultPath
Write-Log "identity repaired: $PreviousComputerName -> $env:COMPUTERNAME; original password preserved (RustDesk ID $rid)"
Write-Host 'Identity repair completed. The original password was preserved and was not printed.'
