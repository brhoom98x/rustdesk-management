<# Run once, elevated, on the DC that hosts NETLOGON. Installs a local SYSTEM
   task that checks stable releases daily at 04:00 (DC local time). No credentials
   are stored. Existing client startup GPO applies staged MSIs at normal boot. #>
[CmdletBinding()]
param(
    [string]$ConfigPath = '',
    [ValidatePattern('\A(?:[01][0-9]|2[0-3]):[0-5][0-9]\z')][string]$At = '04:00',
    [string]$InstallDir = "$env:ProgramData\RustDeskDeploy\AutoUpdate",
    [string]$AllowedSignerSubject = 'CN=PURSLANE, O=PURSLANE, S=North West, C=SG, OID.2.5.4.15=Business Entity, OID.1.3.6.1.4.1.311.60.2.1.3=SG, SERIALNUMBER=53481265A',
    [switch]$NoInitialCheck
)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run PowerShell as Administrator on the DC hosting NETLOGON.' }
if (-not $ConfigPath) { $ConfigPath = Join-Path (Get-SmbShare -Name NETLOGON -ErrorAction Stop).Path 'RustDesk\settings.psd1' }
if (-not [IO.Path]::IsPathRooted($ConfigPath) -or $ConfigPath.StartsWith('\\') -or $ConfigPath -match '[\x00-\x1F"]') { throw 'ConfigPath must be the local NETLOGON settings file on this DC.' }
if (-not [IO.Path]::IsPathRooted($InstallDir) -or $InstallDir.StartsWith('\\') -or $InstallDir -match '[\x00-\x1F"]' -or
    [IO.Path]::GetFullPath($InstallDir).TrimEnd('\') -eq [IO.Path]::GetPathRoot($InstallDir).TrimEnd('\')) { throw 'Use a dedicated local updater directory.' }
if (-not $AllowedSignerSubject -or $AllowedSignerSubject -match '[\x00-\x1F"]') { throw 'Invalid approved signer subject.' }
. (Join-Path $PSScriptRoot 'DeploymentSettings.ps1')
$null = Get-RustDeskDeploymentSettings -ConfigPath $ConfigPath -Required @('StageDir','IdServer','PublicKey','MsiPath')
$sources = @('Update-RustDeskDeployment.ps1','RustDeskUpdates.ps1','DeploymentSettings.ps1')
foreach ($name in $sources) { if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $name))) { throw "Missing package file: $name" } }
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$trustedOwners = @($system.Value,$admins.Value,[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
if (Test-Path -LiteralPath $InstallDir) {
    if ((Get-Item -LiteralPath $InstallDir).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Updater directory must not be a reparse point.' }
    $existing = Get-Acl -LiteralPath $InstallDir
    if ($existing.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trustedOwners) { throw 'Existing updater directory has an untrusted owner; choose a new dedicated directory.' }
    $writeRights = [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach ($rule in $existing.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $writeRights) -and $rule.IdentityReference.Value -notin $trustedOwners) {
            throw 'Existing updater directory is writable by another account; choose a new dedicated directory.'
        }
    }
}
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
$acl.SetOwner($admins)
foreach ($sid in @($system,$admins)) { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')) }
if (Test-Path -LiteralPath $InstallDir) { Set-Acl -LiteralPath $InstallDir -AclObject $acl }
else {
    # The task is installed with Windows PowerShell 5.1/.NET Framework. Give
    # the new directory its private ACL at creation, before placing code in it.
    $null = [IO.Directory]::CreateDirectory($InstallDir,$acl)
}
foreach ($name in $sources) {
    $destination = Join-Path $InstallDir $name
    $source = Join-Path $PSScriptRoot $name
    if ((Test-Path -LiteralPath $destination) -and (Get-Item -LiteralPath $destination).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installed updater file is a reparse point.' }
    if ([IO.Path]::GetFullPath($source) -ieq [IO.Path]::GetFullPath($destination)) { throw 'Run registration from the extracted setup package, outside the installation directory.' }
    # Remove only this directory entry before copying. Never truncate a
    # pre-existing hard link while installing code for a SYSTEM task.
    if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Force }
    Copy-Item -LiteralPath $source -Destination $destination
    $fileAcl = New-Object Security.AccessControl.FileSecurity
    $fileAcl.SetAccessRuleProtection($true,$false); $fileAcl.SetOwner($admins)
    foreach ($sid in @($system,$admins)) { $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','Allow')) }
    Set-Acl -LiteralPath $destination -AclObject $fileAcl
}
$arguments = '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -ConfigPath "{1}" -StateDir "{2}" -AllowedSignerSubject "{3}"' -f (Join-Path $InstallDir 'Update-RustDeskDeployment.ps1'),$ConfigPath,$InstallDir,$AllowedSignerSubject
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments
$trigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.Add([TimeSpan]::Parse($At)))
$taskSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
$taskPrincipal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
$scheduler = New-Object -ComObject Schedule.Service
$scheduler.Connect()
try { $null = $scheduler.GetFolder('\RustDesk') }
catch { $null = $scheduler.GetFolder('\').CreateFolder('RustDesk') }
Register-ScheduledTask -TaskPath '\RustDesk\' -TaskName 'Update deployment' -Action $action -Trigger $trigger -Settings $taskSettings -Principal $taskPrincipal -Force | Out-Null
if (-not $NoInitialCheck) { Start-ScheduledTask -TaskPath '\RustDesk\' -TaskName 'Update deployment' }
Write-Host "Installed: \RustDesk\Update deployment; daily at $At (DC local time)."
Write-Host "Settings: $ConfigPath"
Write-Host "Log: $InstallDir\updater.log"
Write-Host 'Verified stable MSIs will be staged automatically; clients upgrade at their normal startup. Existing installers are retained.'
