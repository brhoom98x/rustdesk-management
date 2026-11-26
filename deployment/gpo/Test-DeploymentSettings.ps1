# Configuration regression tests. No AD/GPO/share/service changes are made.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'DeploymentSettings.ps1')
$key='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' # test-only public-key fixture
foreach ($company in @(@{Domain='north.example.com';OwnerDomain='NORTH'},@{Domain='south.example.net';OwnerDomain='SOUTH'})) {
    $settings=Get-RustDeskDeploymentSettings -Overrides (@{} + $company + @{IdServer=('rd.'+$company.Domain);PublicKey=$key}) -Required @('IdServer','PublicKey','MsiPath')
    if ($settings.StageDir -ne ('\\'+$company.Domain+'\NETLOGON\RustDesk')) { throw 'Domain stage derivation failed.' }
    if ($settings.OwnerDomain -ne $company.OwnerDomain) { throw 'Owner domain changed unexpectedly.' }
    if ($settings.MsiPath -notlike '*rustdesk-1.5.0-x86_64.msi') { throw 'Installer path failed.' }
}
if ((Get-RustDeskRendezvousAddress 'rd.example.com:22116') -ne 'rd.example.com:22116') { throw 'Explicit port was duplicated.' }
if ((Get-RustDeskRendezvousAddress 'rd.example.com') -ne 'rd.example.com:21116') { throw 'Default port failed.' }
$rejected=$false
try { Get-RustDeskDeploymentSettings -Overrides @{IdServer='rd.example.com';PublicKey='PLACEHOLDER'} -Required @('IdServer','PublicKey') | Out-Null } catch { $rejected=$true }
if (-not $rejected) { throw 'Placeholder key was accepted.' }
Write-Host 'PASS: two companies, automatic NETLOGON paths, owner domains, public-key validation and explicit server ports.'
