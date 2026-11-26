<#
.SYNOPSIS
    Reads a machine's RustDesk ID and unattended-access password from the vault.

.EXAMPLE
    .\Get-RustDeskPassword.ps1 -ComputerName WORKSTATION-01

.EXAMPLE
    # everything recorded so far
    .\Get-RustDeskPassword.ps1 -All | Format-Table -AutoSize

.NOTES
    Needs admin rights on the vault share (Domain Admins by default).
    No RSAT needed - it only reads files.

    Each record is trusted only if its file is OWNED by that machine's own
    account (e.g. WORKSTATION-01$). A machine can create files it names
    itself, so a compromised PC could plant a fake <OTHER-PC>.json before the
    real one boots; the owner check catches that and the record is skipped.

    If a deployed machine shows nothing, it has not rebooted yet or could not
    reach the vault - check C:\ProgramData\RustDeskDeploy\deploy.log on it.
#>
[CmdletBinding(DefaultParameterSetName = 'One')]
param(
    [string]$ConfigPath = '',
    [Parameter(Mandatory, ParameterSetName = 'One', Position = 0)]
    [ValidatePattern('\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\z')][string]$ComputerName,

    [Parameter(Mandatory, ParameterSetName = 'All')]
    [switch]$All,

    [string]$VaultPath    = '',
    [string]$VaultPointer = '',
    [string]$OwnerDomain = ''
)

$ErrorActionPreference = 'Stop'
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'settings.psd1' }
. (Join-Path $PSScriptRoot 'DeploymentSettings.ps1')
$settings = Get-RustDeskDeploymentSettings -ConfigPath $ConfigPath -Overrides $PSBoundParameters -Required @('OwnerDomain')
foreach ($name in @('VaultPath','VaultPointer','OwnerDomain')) { Set-Variable -Name $name -Value $settings[$name] }

if (-not $VaultPath) { $VaultPath = (Get-Content -LiteralPath $VaultPointer -TotalCount 1).Trim() }

$files = if ($All) {
    Get-ChildItem -LiteralPath $VaultPath -Filter '*.json' -File
} else {
    $f = Join-Path $VaultPath "$ComputerName.json"
    if (-not (Test-Path -LiteralPath $f)) {
        Write-Warning "${ComputerName}: nothing recorded in $VaultPath"
        return
    }
    Get-Item -LiteralPath $f
}

foreach ($f in $files) {
    if ($f.Attributes -band [IO.FileAttributes]::ReparsePoint -or $f.Length -gt 16384) { Write-Warning 'Skipped non-regular or oversized vault record'; continue }
    $name  = $f.BaseName
    $owner = (Get-Acl -LiteralPath $f.FullName).Owner
    if (-not [string]::Equals($owner, "$OwnerDomain\$name`$", [StringComparison]::OrdinalIgnoreCase)) {
        Write-Warning "${name}: file owned by '$owner', not '$name`$' - ignored (possible spoof; delete it and reboot $name)"
        continue
    }
    try { $rec = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json }
    catch { Write-Warning "${name}: record is not valid JSON"; continue }
    if ($rec.rustdesk -ne $true -or $rec.host -ne $name -or $rec.id -notmatch '\A[0-9]{1,16}\z' -or $rec.password -isnot [string]) { Write-Warning "${name}: invalid machine record"; continue }

    [pscustomobject]@{
        Computer   = $name
        RustDeskId = $rec.id
        Password   = $rec.password
        SetAt      = $rec.set_at
    }
}
