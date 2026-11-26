<# Creates public company settings; does not install software or change AD/GPO. #>
[CmdletBinding()]
param(
    [string]$Domain, [string]$OwnerDomain, [string]$IdServer,
    [string]$RelayServer, [string]$PublicKey, [string]$WantVersion='1.5.0',
    [string]$StageDir='', [string]$OutputPath='',
    [switch]$Force
)
$ErrorActionPreference='Stop'
if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot 'settings.psd1' }
foreach ($name in @('Domain','OwnerDomain','IdServer','PublicKey')) {
    if (-not (Get-Variable $name -ValueOnly)) { Set-Variable $name (Read-Host "Enter $name") }
}
if (-not $RelayServer) { $RelayServer=$IdServer }
. (Join-Path $PSScriptRoot 'DeploymentSettings.ps1')
$settings=Get-RustDeskDeploymentSettings -Overrides @{Domain=$Domain;OwnerDomain=$OwnerDomain;IdServer=$IdServer;RelayServer=$RelayServer;PublicKey=$PublicKey;WantVersion=$WantVersion;StageDir=$StageDir} -Required @('Domain','OwnerDomain','IdServer','PublicKey','StageDir')
if ((Test-Path -LiteralPath $OutputPath) -and -not $Force) { throw 'Output already exists; use -Force to replace it.' }
function Quote-Data([string]$Value) { "'" + $Value.Replace("'","''") + "'" }
$lines=@('@{')
foreach ($key in @('Domain','OwnerDomain','IdServer','RelayServer','PublicKey','WantVersion','StageDir')) {
    $lines += '    ' + $key + ' = ' + (Quote-Data $settings[$key])
}
$lines += "    ReaderAccounts = @('svc-rdconsole')"
$lines += '    PasswordLength = 16'
$lines += '}'
Set-Content -LiteralPath $OutputPath -Value $lines -Encoding UTF8
Write-Host "Created $OutputPath. No passwords are stored in this file."
Write-Host "Stage the scripts, this file as settings.psd1, and the matching MSI in $($settings.StageDir)."
