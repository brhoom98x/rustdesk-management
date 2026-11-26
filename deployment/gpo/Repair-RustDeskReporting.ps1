<#
.SYNOPSIS
    Repairs only the logged-on-user reporting task, locally or from the DC.
.DESCRIPTION
    Copy this helper and Deploy-RustDesk.ps1 to NETLOGON\RustDesk. On the DC,
    run elevated with -ComputerName. Remote tasks run as SYSTEM using each
    machine's own computer account to write the vault; no WinRM is required.
    Locally, run elevated or as SYSTEM. Does not execute the deployment main.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = '',
    [ValidatePattern('^[A-Za-z0-9-]+$')][string[]]$ComputerName,
    [string]$StagedHelper = '',
    [string]$DeployScript = '',
    [string]$VaultPath = '',
    [string]$VaultPointer = ''
)
$ErrorActionPreference = 'Stop'
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'settings.psd1' }
if (-not $DeployScript) { $DeployScript = Join-Path $PSScriptRoot 'Deploy-RustDesk.ps1' }
. (Join-Path $PSScriptRoot 'DeploymentSettings.ps1')
$settings = Get-RustDeskDeploymentSettings -ConfigPath $ConfigPath -Overrides $PSBoundParameters
foreach ($name in @('StagedHelper','VaultPath','VaultPointer')) { Set-Variable -Name $name -Value $settings[$name] }
if ($ComputerName) {
    if (-not $StagedHelper) { throw 'Set Domain/StageDir in settings.psd1 or pass -StagedHelper.' }
    if (-not (Test-Path -LiteralPath $StagedHelper)) { throw "Stage the helper in NETLOGON first: $StagedHelper" }
    if ($VaultPath) { throw 'For remote repairs, use the staged vault-path.txt pointer.' }
    $command = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $StagedHelper
    if ($command.Length -gt 260) { throw 'Remote task command is too long; use a shorter NETLOGON path.' }
    foreach ($computer in $ComputerName) {
        # Creation is idempotent. SYSTEM authenticates to NETLOGON and the vault
        # as COMPUTER$, so report owners remain verifiable by the console.
        & schtasks.exe /Create /S $computer /TN '\RustDesk\Repair reporting' /RU SYSTEM /RL HIGHEST `
            /SC ONCE /ST ((Get-Date).AddMinutes(2).ToString('HH:mm')) /TR $command /F
        if ($LASTEXITCODE -ne 0) { Write-Warning "$computer : task creation failed; check admin rights and remote Task Scheduler firewall access"; continue }
        & schtasks.exe /Run /S $computer /TN '\RustDesk\Repair reporting'
        if ($LASTEXITCODE -ne 0) { Write-Warning "$computer : could not start repair"; continue }
        Write-Host "$computer : repair started; check the console after one minute"
    }
    return
}
if (-not $VaultPath) { $VaultPath = (Get-Content -LiteralPath $VaultPointer -TotalCount 1).Trim() }
if ($VaultPath -notmatch '^\\\\[^\\]+\\[^\\]+') { throw 'VaultPath must be a UNC share.' }
# Import exactly the reporting function from the reviewed deployment script;
# dot-sourcing the whole file would also run installation/password changes.
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($DeployScript, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Deploy-RustDesk.ps1 has syntax errors.' }
$function = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Register-SessionReporter'
}, $false)
if (-not $function) { throw 'Register-SessionReporter is missing; stage the current Deploy-RustDesk.ps1.' }
$SessionTaskPath = '\RustDesk\'
$SessionTaskName = 'Report logged-on user'
. ([scriptblock]::Create($function.Extent.Text))
Register-SessionReporter -Vault $VaultPath
Write-Host 'Reporting task repaired and started. Check C:\ProgramData\RustDeskDeploy\reporter.log.'
