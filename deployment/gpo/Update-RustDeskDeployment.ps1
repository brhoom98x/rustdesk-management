<# Checks the official stable Windows x64 release; stages verified updates only.
   Run as SYSTEM through Register-RustDeskAutoUpdate.ps1. Never installs an MSI,
   changes a workstation password, wakes a PC, or requests a reboot. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [string]$StateDir = "$env:ProgramData\RustDeskDeploy\AutoUpdate",
    # Publisher from the official signed RustDesk 1.5.1 Windows x64 MSI.
    [string]$AllowedSignerSubject = 'CN=PURSLANE, O=PURSLANE, S=North West, C=SG, OID.2.5.4.15=Business Entity, OID.1.3.6.1.4.1.311.60.2.1.3=SG, SERIALNUMBER=53481265A',
    [switch]$CheckOnly
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'DeploymentSettings.ps1')
. (Join-Path $PSScriptRoot 'RustDeskUpdates.ps1')
if ($CheckOnly) {
    Invoke-RustDeskStagingUpdate -ConfigPath $ConfigPath -StateDir $StateDir -AllowedSignerSubject $AllowedSignerSubject -CheckOnly
    return
}
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'Install/run the SYSTEM scheduled task using Register-RustDeskAutoUpdate.ps1.' }
if (-not (Test-Path -LiteralPath $StateDir) -or (Get-Item -LiteralPath $StateDir).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Protected updater directory is missing or unsafe; reinstall the task.' }
$lock = $null
$log = Join-Path $StateDir 'updater.log'
try {
    $lock = [IO.File]::Open((Join-Path $StateDir 'updater.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    if ((Test-Path -LiteralPath $log) -and (Get-Item -LiteralPath $log).Length -gt 1MB) { Move-Item -LiteralPath $log -Destination ($log+'.1') -Force }
    $result = Invoke-RustDeskStagingUpdate -ConfigPath $ConfigPath -StateDir $StateDir -AllowedSignerSubject $AllowedSignerSubject
    Add-Content -LiteralPath $log -Encoding UTF8 -Value ('{0} {1}; version={2}' -f (Get-Date -Format s),$result.Status,$result.Version)
    $result | ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path $StateDir 'status.json') -Encoding UTF8
} catch {
    # Do not log signed download URLs, HTTP bodies or arbitrary remote errors.
    Add-Content -LiteralPath $log -Encoding UTF8 -Value ('{0} update failed; type={1}; previous settings retained unless staging completed' -f (Get-Date -Format s),$_.Exception.GetType().Name)
    throw
} finally { if ($lock) { $lock.Dispose() } }
