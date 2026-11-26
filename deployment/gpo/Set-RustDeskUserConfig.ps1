<#
.SYNOPSIS
    Points an already-existing user profile at the self-hosted RustDesk server.
    Intended as an Active Directory USER logon script.

.DESCRIPTION
    The computer startup script seeds the Default profile, which only affects
    profiles created AFTER it runs. Anyone who has already logged on to a machine
    keeps their own %APPDATA%\RustDesk\config\RustDesk2.toml, so this fills that
    gap. It needs no admin rights - it only writes inside the user's own profile.

    Safe to run at every logon: it merges the three server keys and leaves
    everything else in the file untouched, and exits quietly if RustDesk is not
    installed on this machine.
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = '',
    [string]$IdServer    = '',
    [string]$RelayServer = '',
    [string]$PublicKey   = '',
    [string]$ApiServer   = '',
    [switch]$CheckConfig
)

$ErrorActionPreference = 'Stop'
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'settings.psd1' }
. (Join-Path $PSScriptRoot 'DeploymentSettings.ps1')
$settings = Get-RustDeskDeploymentSettings -ConfigPath $ConfigPath -Overrides $PSBoundParameters -Required @('IdServer','PublicKey')
foreach ($name in @('IdServer','RelayServer','PublicKey','ApiServer')) { Set-Variable -Name $name -Value $settings[$name] }
if ($CheckConfig) { Write-Host "User configuration valid: server=$IdServer"; return }

$programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
if (-not (Test-Path (Join-Path $programFiles 'RustDesk\rustdesk.exe'))) { exit 0 }

$path = Join-Path $env:APPDATA 'RustDesk\config\RustDesk2.toml'

$options = [ordered]@{
    'custom-rendezvous-server' = $IdServer
    'relay-server'             = $RelayServer
    'key'                      = $PublicKey
}
if ($ApiServer) { $options['api-server'] = $ApiServer }

try {
    $dir = Split-Path $path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    if (Test-Path $path) {
        $lines = [System.Collections.Generic.List[string]](Get-Content -LiteralPath $path)
    } else {
        $lines = [System.Collections.Generic.List[string]]@(
            "rendezvous_server = '$(Get-RustDeskRendezvousAddress $IdServer)'", 'nat_type = 1', 'serial = 0', '', '[options]'
        )
    }
    if (-not ($lines -match '^\s*\[options\]')) { $lines.Add(''); $lines.Add('[options]') }

    # rendezvous_server sits OUTSIDE [options]. A machine that previously used
    # the public RustDesk server keeps a stale value here, so repoint it too.
    $topLine = "rendezvous_server = '$(Get-RustDeskRendezvousAddress $IdServer)'"
    $foundTop = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i].TrimStart().StartsWith('rendezvous_server')) {
            $lines[$i] = $topLine; $foundTop = $true; break
        }
    }
    if (-not $foundTop) { $lines.Insert(0, $topLine) }

    foreach ($k in $options.Keys) {
        $newLine = "$k = '$($options[$k])'"
        $pattern = '^\s*' + [regex]::Escape($k) + '\s*='
        $idx = -1
        for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match $pattern) { $idx = $i; break } }
        if ($idx -ge 0) { $lines[$idx] = $newLine }
        else {
            $opt = ($lines | Select-String -Pattern '^\s*\[options\]' | Select-Object -First 1).LineNumber
            if ($opt) { $lines.Insert($opt, $newLine) } else { $lines.Add($newLine) }
        }
    }

    $desired = ($lines -join "`r`n")
    $current = if (Test-Path $path) { [string](Get-Content -LiteralPath $path -Raw) } else { '' }
    if ($current.TrimEnd() -ne $desired.TrimEnd()) {
        Set-Content -LiteralPath $path -Value $desired -Encoding UTF8
    }
    exit 0
}
catch {
    # Never block a user's logon over a config file.
    exit 0
}
