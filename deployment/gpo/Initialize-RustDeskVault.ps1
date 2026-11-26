<#
.SYNOPSIS
    One-time preparation of the RustDesk password vault share on the DC.
    Replaces Initialize-RustDeskAD.ps1 (the 'info' attribute is base schema,
    systemFlags 0x10, and cannot be marked confidential).

.DESCRIPTION
    Run ONCE, ON THE DC THAT WILL HOST THE VAULT, as Domain Admin. It:

    1. Creates C:\RustDeskVault with a drop-box ACL:
         SYSTEM, Administrators   Full Control   (folder + files)
         Domain Computers         Create files   (this folder ONLY - cannot list,
                                                  read or delete anything)
         CREATOR OWNER            Modify         (files only)
         -ReaderAccounts          Read           (folder + files; default
                                                  svc-rdconsole, the RustDesk Console)
       So each machine can create its own <COMPUTERNAME>.json, read and update
       that one file, and see nothing else. Only admins and the reader accounts
       can read the whole vault.

    2. Shares it as RustDeskVault$ (hidden) with SMB encryption ON, so the
       passwords are never on the wire in clear text.

    3. Writes the vault's UNC path to NETLOGON\RustDesk\vault-path.txt. The
       deploy and lookup scripts read the path from there, so nothing needs
       editing when the DC name is known only here.

    Idempotent: safe to re-run; it re-applies the ACL and share settings.
    The ACL is REPLACED on every run, which is why the reader accounts are
    part of it: a grant added by hand would be silently removed.

.NOTES
    Include C:\RustDeskVault in the DC's backup - it is the only record of
    the per-machine passwords.

    To remove everything later:
        Remove-SmbShare -Name 'RustDeskVault$' -Force
        Remove-Item 'C:\RustDeskVault' -Recurse -Force
        Remove-Item '<NETLOGON-STAGE>\vault-path.txt'
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = '',
    [string]$Path      = 'C:\RustDeskVault',
    [string]$ShareName = 'RustDeskVault$',
    [string]$StageDir  = '',

    # Accounts or groups that may READ every record - the RustDesk Console's
    # service account by default. Pass @() to grant no reader at all.
    [string[]]$ReaderAccounts = @('svc-rdconsole')
)

$ErrorActionPreference = 'Stop'
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'settings.psd1' }
Import-Module ActiveDirectory

$domain = Get-ADDomain
. (Join-Path $PSScriptRoot 'DeploymentSettings.ps1')
$overrides = @{} + $PSBoundParameters
if (-not $overrides.ContainsKey('Domain')) { $overrides.Domain = $domain.DNSRoot }
$settings = Get-RustDeskDeploymentSettings -ConfigPath $ConfigPath -Overrides $overrides -Required @('StageDir')
foreach ($name in @('Path','ShareName','StageDir','ReaderAccounts')) { Set-Variable -Name $name -Value $settings[$name] }

# SIDs instead of names: works on any OS language.
$sidSystem       = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$sidAdmins       = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$sidCreatorOwner = New-Object System.Security.Principal.SecurityIdentifier('S-1-3-0')
$sidDomainComps  = New-Object System.Security.Principal.SecurityIdentifier("$($domain.DomainSID)-515")

# Reader accounts, resolved to SIDs through AD like the groups above, so the
# grant does not depend on spelling or OS language. A missing account is a
# warning, not a failure: on a fresh domain the vault should still be created.
$readers = @()
foreach ($a in $ReaderAccounts) {
    $sam = $a.Split('\')[-1].Replace("'", "''")
    $obj = Get-ADObject -Filter "sAMAccountName -eq '$sam'" -Properties objectSid, sAMAccountName
    if ($obj) {
        $readers += [pscustomobject]@{ Name = $obj.sAMAccountName; Sid = $obj.objectSid }
    } else {
        Write-Warning "reader '$a' not found in AD - skipped. Create it, then re-run this script."
    }
}

# ------------------------------------------------------------ 1. folder + ACL
$share = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
if ($share -and [IO.Path]::GetFullPath($share.Path).TrimEnd('\') -ne [IO.Path]::GetFullPath($Path).TrimEnd('\')) {
    throw 'Existing share points to a different directory; refusing to change its permissions or publish a misleading vault path.'
}
if ((Test-Path -LiteralPath $Path) -and ((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Vault directory must not be a reparse point.'
}
if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path | Out-Null
    Write-Host "created   : $Path"
}

$R = [System.Security.AccessControl.FileSystemAccessRule]
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)     # do not inherit Users:Read from C:\
$acl.AddAccessRule($R::new($sidSystem, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
$acl.AddAccessRule($R::new($sidAdmins, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
# This folder only: create a file, nothing else - no list, no read, no delete.
$acl.AddAccessRule($R::new($sidDomainComps, 'CreateFiles, ReadAttributes, Synchronize', 'None', 'None', 'Allow'))
# Files only: whoever created a file (the machine account) can read/update it.
$acl.AddAccessRule($R::new($sidCreatorOwner, 'Modify', 'ObjectInherit', 'InheritOnly', 'Allow'))
# Readers: list the folder and read every record (the RustDesk Console). Lives
# here, inside the ACL this script owns, because Set-Acl below REPLACES the
# whole ACL - a grant added by hand would vanish on the next run.
foreach ($rd in $readers) {
    $acl.AddAccessRule($R::new($rd.Sid, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
Set-Acl -LiteralPath $Path -AclObject $acl
Write-Host "ACL set   : SYSTEM/Administrators full, Domain Computers create-only, CREATOR OWNER modify"
if ($readers) { Write-Host ("readers   : {0} (read-only)" -f (($readers | ForEach-Object Name) -join ', ')) }
else          { Write-Host "readers   : none - the RustDesk Console will not be able to read the vault" }

# ------------------------------------------------------------------ 2. share
# Share permissions stay broad; NTFS above does the real gating.
$share = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
if (-not $share) {
    $adminAccount = $sidAdmins.Translate([System.Security.Principal.NTAccount]).Value
    $authenticatedAccount = ([System.Security.Principal.SecurityIdentifier]::new('S-1-5-11')).Translate([System.Security.Principal.NTAccount]).Value
    New-SmbShare -Name $ShareName -Path $Path `
        -FullAccess   $adminAccount `
        -ChangeAccess $authenticatedAccount `
        -EncryptData  $true | Out-Null
    Write-Host "shared    : $ShareName (SMB encryption on)"
} else {
    Set-SmbShare -Name $ShareName -EncryptData $true -Force
    Write-Host "share     : $ShareName already exists, SMB encryption enforced"
}

# ------------------------------------------------------ 3. publish the path
$fqdn = ("{0}.{1}" -f $env:COMPUTERNAME, $domain.DNSRoot).ToLower()
$unc  = "\\$fqdn\$ShareName"
if (-not (Test-Path -LiteralPath $StageDir)) { New-Item -ItemType Directory -Path $StageDir -Force | Out-Null }
Set-Content -LiteralPath (Join-Path $StageDir 'vault-path.txt') -Value $unc -Encoding ASCII
Write-Host "pointer   : $StageDir\vault-path.txt -> $unc"

Write-Host "`nDone. After a pilot machine reboots, check:"
Write-Host "  .\Get-RustDeskPassword.ps1 -All | Format-Table -AutoSize"
