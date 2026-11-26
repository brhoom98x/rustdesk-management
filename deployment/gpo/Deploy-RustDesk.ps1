<#
.SYNOPSIS
    Installs RustDesk and points it at the self-hosted server.
    Intended as an Active Directory COMPUTER startup script.

.DESCRIPTION
    Runs as SYSTEM at boot, so it needs no UAC prompt and no admin user logged on.
    This is why RustDesk must be deployed per COMPUTER, not per user: the install
    writes to Program Files and registers a service, which a standard domain user
    cannot do. A User Configuration policy would fail on every non-admin desktop.

    The script is idempotent - it can run at every boot. It only installs when the
    wanted version is missing, or when the RustDesk present was not installed by
    the domain MSI (an NTLite/custom image or a manual .exe install), which it
    replaces with the MSI. It MERGES the server settings into any existing
    RustDesk2.toml rather than overwriting it, so a machine's RustDesk ID, trusted
    devices and unlock PIN survive.

    Each machine gets its own random unattended-access password, recorded in
    the admin-only vault share as <COMPUTERNAME>.json (see
    Initialize-RustDeskVault.ps1). The record is written FIRST and the password
    is set locally only if that write succeeded, so a machine never ends up
    with a password nobody can look up.

    It also registers the scheduled task \RustDesk\Report logged-on user,
    which tells the RustDesk Console who is logged on (see
    Register-SessionReporter). Opt out with -NoSessionReport.

.NOTES
    Verified against RustDesk 1.4.9 and 1.5.0. Note: SERVICE_START_NAME is
    LocalSystem, but RustDesk keeps its service config under the LocalService
    profile - see Get-RustDeskConfigDirs.
    Log: C:\ProgramData\RustDeskDeploy\deploy.log
#>
[CmdletBinding()]
param(
    [string]$ConfigPath   = '',
    [string]$MsiPath      = '',
    [string]$MsiSha256    = '',
    [string]$OwnerDomain  = '',
    # Treated as a MINIMUM (see main): machines below it are upgraded, machines
    # already at or above it are left alone - never downgraded.
    [string]$WantVersion  = '1.5.0',
    [string]$IdServer     = '',
    [string]$RelayServer  = '',
    [string]$PublicKey    = '',

    # RustDesk OSS has no API server. Leave empty unless a separate compatible
    # API service is actually configured; the monitoring console is not one.
    [string]$ApiServer    = '',

    [string]$LogDir       = "$env:ProgramData\RustDeskDeploy",

    # Vault share for per-machine passwords. Leave empty to read the path that
    # Initialize-RustDeskVault.ps1 published to $VaultPointer.
    [string]$VaultPath    = '',
    [string]$VaultPointer = '',
    [int]$PasswordLength  = 16,
    [switch]$ForceNewPassword,
    # One-time recovery for a PC renamed before local identity tracking existed.
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9-]{0,14}$')]
    [string]$PreviousComputerName = '',

    # Do not report the logged-on user to the RustDesk Console (and remove the
    # reporting task if an earlier run created it).
    [switch]$NoSessionReport,

    # Leave a RustDesk the domain MSI did not install (NTLite/custom image or a
    # manual .exe install) in place instead of replacing it with the MSI.
    [switch]$KeepForeignInstall,
    [switch]$CheckConfig
)

$ErrorActionPreference = 'Stop'
if (-not $ConfigPath) { $ConfigPath = Join-Path $PSScriptRoot 'settings.psd1' }
. (Join-Path $PSScriptRoot 'DeploymentSettings.ps1')
$settings = Get-RustDeskDeploymentSettings -ConfigPath $ConfigPath -Overrides $PSBoundParameters -Required @('IdServer','PublicKey','MsiPath')
foreach ($name in @('MsiPath','MsiSha256','OwnerDomain','WantVersion','IdServer','RelayServer','PublicKey','ApiServer','VaultPath','VaultPointer','PasswordLength')) { Set-Variable -Name $name -Value $settings[$name] }
if ($CheckConfig) { Write-Host "Configuration valid: server=$IdServer minimum=$WantVersion installer=$MsiPath"; return }
$script:LogFile = Join-Path $LogDir 'deploy.log'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $script:LogFile -Value $line -Encoding UTF8
    Write-Host $line
}

function Get-InstalledVersion {
    $programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
    $exe = Join-Path $programFiles 'RustDesk\rustdesk.exe'
    if (Test-Path $exe) { return (Get-Item $exe).VersionInfo.FileVersion }
    return $null
}

function Install-RustDesk {
    if (-not (Test-Path $MsiPath)) {
        Write-Log "MSI not reachable at $MsiPath" 'ERROR'
        return $false
    }
    # Copy locally first: msiexec against a UNC path can fail under SYSTEM if the
    # machine account loses the share mid-install.
    # An unpredictable name avoids reusing a file planted before the SYSTEM run.
    $local = Join-Path $env:TEMP ('rustdesk-deploy-' + [guid]::NewGuid().ToString('N') + '.msi')
    Copy-Item $MsiPath $local -Force
    if ($MsiSha256 -and (Get-FileHash -LiteralPath $local -Algorithm SHA256).Hash -ne $MsiSha256) {
        Write-Log 'MSI checksum mismatch; refusing to execute the installer' 'ERROR'
        Remove-Item -LiteralPath $local -Force -ErrorAction SilentlyContinue
        return $false
    }
    Write-Log "Installing $([IO.Path]::GetFileName($MsiPath))"
    $log = Join-Path $LogDir 'msi.log'
    $p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
        '/i', "`"$local`"", '/qn', '/norestart',
        'CREATEDESKTOPSHORTCUTS=0', 'CREATESTARTMENUSHORTCUTS=1',
        '/l*v', "`"$log`""
    )
    Remove-Item $local -Force -ErrorAction SilentlyContinue
    # 3010 = success, reboot required
    if ($p.ExitCode -in 0, 3010) { Write-Log "Install OK (exit $($p.ExitCode))"; return $true }
    Write-Log "Install FAILED (exit $($p.ExitCode)) - see $log" 'ERROR'
    return $false
}

function Get-RustDeskInstalls {
    <#
        Machine-wide uninstall registrations for RustDesk, 64- and 32-bit views.
        The domain MSI registers a Windows Installer product (WindowsInstaller=1);
        the .exe installer - and so a copy baked into an NTLite or other custom
        image - registers a plain "RustDesk" entry with "RustDesk.exe --uninstall".
    #>
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if ($p -and [string]$p.DisplayName -like 'RustDesk*') {
                [pscustomobject]@{
                    Key = $key.PSChildName; Path = $key.PSPath; Version = [string]$p.DisplayVersion
                    Msi = ($p.WindowsInstaller -eq 1); Uninstall = [string]$p.UninstallString
                }
            }
        }
    }
}

function Test-ForeignRustDesk {
    <#
        True when RustDesk is on the machine but the domain MSI does not own it:
        an .exe-installer or image (NTLite) copy, or a bare unregistered copy.
        Such a copy defeats the deployment - the MSI cannot upgrade a product it
        did not install (it fails, and the run aborts before any server config),
        and a same-or-newer copy is skipped and keeps talking to the public servers.

        Any registered MSI RustDesk product means the domain install owns it, even
        if RustDesk also wrote its own non-MSI key, so a domain-installed machine is
        never classed as foreign and never reinstalled in a loop.
    #>
    param([object[]]$Installs, [bool]$ExePresent)
    if (@($Installs | Where-Object { $_.Msi }).Count) { return $false }
    return ($ExePresent -or @($Installs).Count -gt 0)
}

function Remove-ForeignRustDesk {
    <#
        Removes a non-domain RustDesk so the domain MSI can install cleanly - the
        same as uninstalling it by hand and rebooting, done by the startup script.
        Uses RustDesk's own "--uninstall" on the known Program Files binary (never
        a command line read from the registry), then removes anything it left:
        the service, the program folder and the non-MSI uninstall entries.
        The machine's RustDesk config, and so its ID, is not deleted here; the
        server settings are merged into it after the MSI install.
    #>
    param([object[]]$Installs)
    $programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
    $dir = Join-Path $programFiles 'RustDesk'
    $exe = Join-Path $dir 'rustdesk.exe'

    Stop-Service -Name 'RustDesk' -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $exe) {
        Invoke-RustDeskCli -Arguments @('--uninstall') -TimeoutSec 120 | Out-Null
        # RustDesk finishes its uninstall in a detached helper; give it time.
        for ($i = 0; $i -lt 30 -and (Test-Path -LiteralPath $exe); $i++) { Start-Sleep -Seconds 2 }
    }
    # Tray and session processes keep files open; stop whatever is still running.
    Get-Process -Name 'rustdesk' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    if (Get-Service -Name 'RustDesk' -ErrorAction SilentlyContinue) {
        Stop-Service -Name 'RustDesk' -Force -ErrorAction SilentlyContinue
        & sc.exe delete RustDesk | Out-Null
        Write-Log 'removed the leftover RustDesk service'
    }
    if (Test-Path -LiteralPath $dir) {
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }
    foreach ($i in @($Installs | Where-Object { -not $_.Msi })) {
        Remove-Item -LiteralPath $i.Path -Recurse -Force -ErrorAction SilentlyContinue
    }
    $gone = -not (Test-Path -LiteralPath $exe)
    if ($gone) { Write-Log 'non-domain RustDesk removed' }
    else       { Write-Log "non-domain RustDesk could not be fully removed ($exe still present)" 'ERROR' }
    return $gone
}

function Merge-RustDeskConfig {
    <#
        Writes the server settings into RustDesk2.toml without disturbing
        anything else in the file. Overwriting wholesale would discard
        trusted_devices, unlock_pin and other per-machine state.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $options = [ordered]@{
        'custom-rendezvous-server' = $IdServer
        'relay-server'             = $RelayServer
        'key'                      = $PublicKey
    }
    if ($ApiServer) { $options['api-server'] = $ApiServer }

    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    if (Test-Path $Path) {
        $lines = [System.Collections.Generic.List[string]](Get-Content -LiteralPath $Path)
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
        $v        = $options[$k]
        $pattern  = '^\s*' + [regex]::Escape($k) + '\s*='
        $newLine  = "$k = '$v'"
        $idx      = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match $pattern) { $idx = $i; break }
        }
        if ($idx -ge 0) {
            $lines[$idx] = $newLine
        } else {
            # append just after the [options] header so it lands in the right table
            $opt = ($lines | Select-String -Pattern '^\s*\[options\]' | Select-Object -First 1).LineNumber
            if ($opt) { $lines.Insert($opt, $newLine) } else { $lines.Add($newLine) }
        }
    }

    $desired = ($lines -join "`r`n")
    $current = if (Test-Path $Path) { [string](Get-Content -LiteralPath $Path -Raw) } else { '' }
    if ($current.TrimEnd() -eq $desired.TrimEnd()) { return $false }   # already correct
    Set-Content -LiteralPath $Path -Value $desired -Encoding UTF8
    return $true
}

function Invoke-RustDeskCli {
    <#
        rustdesk.exe is a GUI binary: some switches open a window and never
        return (--help does exactly that). Always run it with a timeout and a
        redirected stdout, or a startup script can hang a machine's boot.
    #>
    param([string[]]$Arguments, [int]$TimeoutSec = 30, [switch]$RequireSuccess)
    $programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
    $exe = Join-Path $programFiles 'RustDesk\rustdesk.exe'
    $out = Join-Path $env:TEMP ('rd-' + [guid]::NewGuid().ToString('N') + '.txt')
    try {
        $p = Start-Process -FilePath $exe -ArgumentList $Arguments -PassThru `
                           -WindowStyle Hidden -RedirectStandardOutput $out
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            try { $p.Kill() } catch { }
            if ($RequireSuccess) { throw 'RustDesk command timed out; verify the local password before relying on the vault record.' }
            Write-Log "rustdesk.exe $($Arguments[0]) timed out after $TimeoutSec s" 'WARN'
        }
        elseif ($RequireSuccess -and $p.ExitCode -ne 0) {
            throw 'RustDesk command failed; verify the local password before relying on the vault record.'
        }
        # [string] cast: -Raw on an empty file returns $null, and $null.Trim() throws
        $text = if (Test-Path $out) { [string](Get-Content -LiteralPath $out -Raw) } else { '' }
        return $text.Trim()
    }
    finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
}

function New-RustDeskPassword {
    # Letters and digits only. The password is passed on a command line, and
    # symbols invite quoting bugs across the cmd/PowerShell boundary.
    #
    # Get-Random is NOT used here: it is seeded System.Random, which is not
    # cryptographically secure and is predictable from observed output. The
    # RustDesk sample deployment script uses it; a fleet password should not.
    $set = [char[]]((48..57) + (65..90) + (97..122))
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $byte  = New-Object byte[] 1
        $chars = New-Object System.Collections.Generic.List[char]
        # 256 is not a multiple of 62, so plain modulo would favour the first
        # few characters. Discard the uneven tail instead.
        $limit = 256 - (256 % $set.Count)
        while ($chars.Count -lt $PasswordLength) {
            $rng.GetBytes($byte)
            if ($byte[0] -lt $limit) { $chars.Add($set[$byte[0] % $set.Count]) }
        }
        return (-join $chars)
    }
    finally { $rng.Dispose() }
}

function Get-RustDeskId {
    # Right after a service restart the ID can come back empty; retry briefly.
    for ($i = 1; $i -le 5; $i++) {
        $id = Invoke-RustDeskCli -Arguments @('--get-id')
        if ($id -match '\A[0-9]{6,16}\z') { return $id }
        Start-Sleep -Seconds 3
    }
    Write-Log 'could not read RustDesk ID' 'WARN'
    return ''
}

function Resolve-VaultPath {
    $p = $VaultPath
    if (-not $p) {
        try   { $p = (Get-Content -LiteralPath $VaultPointer -TotalCount 1 -ErrorAction Stop).Trim() }
        catch { Write-Log "vault pointer not readable at $VaultPointer" 'WARN'; return $null }
    }
    if (-not (Test-Path -LiteralPath $p)) { Write-Log "vault not reachable at $p" 'WARN'; return $null }
    return $p
}

function Get-StoredRecord {
    param([string]$Path, [string]$RecordHost = $env:COMPUTERNAME)
    try {
        if (Test-Path -LiteralPath $Path) {
            $item = Get-Item -LiteralPath $Path
            if (-not $OwnerDomain -or $item.Length -gt 16384 -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $null }
            $owner=(Get-Acl -LiteralPath $Path).Owner
            if (-not [string]::Equals($owner, "$OwnerDomain\$env:COMPUTERNAME`$", [StringComparison]::OrdinalIgnoreCase)) {
                Write-Log 'own vault record has an unexpected owner; refusing to reuse it' 'WARN'
                return $null
            }
            $rec = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
            if ($rec.rustdesk -eq $true -and $rec.host -eq $RecordHost -and
                $rec.id -is [string] -and $rec.id -match '\A[0-9]{6,16}\z' -and
                $rec.password -is [string] -and $rec.password.Length -ge 1 -and $rec.password.Length -le 1024) { return $rec }
        }
    }
    catch { Write-Log 'cannot read own record: unreadable or invalid record' 'WARN' }
    return $null
}

function Get-PreviousDeploymentHost {
    param([string]$Override = '')
    if ($Override) { return $Override.ToUpperInvariant() }
    try {
        $path = Join-Path $LogDir 'identity.json'
        if (Test-Path -LiteralPath $path) {
            $item = Get-Item -LiteralPath $path
            if ($item.Length -gt 1024 -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return '' }
            $identity = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            if ($identity.host -is [string] -and $identity.host -match '\A[A-Za-z0-9][A-Za-z0-9-]{0,14}\z') {
                return $identity.host.ToUpperInvariant()
            }
        }
    } catch { Write-Log 'previous deployment identity could not be read' 'WARN' }
    return ''
}

function Get-RenamedRecord {
    param([string]$Vault, [string]$PreviousHost, [string]$Id)
    if ($PreviousHost -notmatch '\A[A-Za-z0-9][A-Za-z0-9-]{0,14}\z' -or $Id -notmatch '\A[0-9]{6,16}\z') { return $null }
    # AD renames preserve the computer SID. Windows resolves the old file's
    # owner to CURRENT-NAME$, so Get-StoredRecord must still require that exact
    # current account. Only the historical record's host field may be old.
    $record = Get-StoredRecord -Path (Join-Path $Vault ($PreviousHost + '.json')) -RecordHost $PreviousHost
    if ($record -and $record.id -eq $Id) { return $record }
    Write-Log 'rename recovery failed owner or RustDesk ID verification; password left unchanged' 'WARN'
    return $null
}

function Save-DeploymentIdentity {
    param([string]$Id)
    # Non-secret pointer only. Passwords remain in the machine-owned vault;
    # this lets the next startup find that same record after a computer rename.
    try {
        if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        $path = Join-Path $LogDir 'identity.json'
        if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unsafe identity path' }
        @{ host = $env:COMPUTERNAME; id = $Id; version = 1 } | ConvertTo-Json -Compress |
            Set-Content -LiteralPath $path -Encoding UTF8
    } catch { Write-Log 'could not save non-secret deployment identity' 'WARN' }
}

function Set-StoredRecord {
    param([string]$Path, [string]$Id, [string]$Password)
    if (Test-Path -LiteralPath $Path) {
        try {
            $item = Get-Item -LiteralPath $Path
            $owner = (Get-Acl -LiteralPath $Path).Owner
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint -or -not $OwnerDomain -or
                -not [string]::Equals($owner, "$OwnerDomain\$env:COMPUTERNAME`$", [StringComparison]::OrdinalIgnoreCase)) {
                Write-Log 'refusing to overwrite an existing record with an unexpected owner' 'ERROR'
                return $false
            }
        } catch { Write-Log 'existing record owner could not be verified; record left unchanged' 'ERROR'; return $false }
    }
    $json = [ordered]@{
        rustdesk = $true
        host     = $env:COMPUTERNAME
        id       = $Id
        password = $Password
        set_at   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    } | ConvertTo-Json -Compress
    try {
        Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
        return $true
    }
    catch {
        # Access denied here usually means another machine already created a
        # file with this name - Get-RustDeskPassword.ps1 flags that as a spoof.
        Write-Log "FAILED writing $Path : $($_.Exception.Message)" 'ERROR'
        return $false
    }
}

function Register-SessionReporter {
    <#
        Registers a SYSTEM scheduled task that writes <COMPUTERNAME>.session to
        the vault - who is logged on, and when that was checked - at every logon
        and every 5 minutes. The RustDesk Console shows it next to the machine.

        Written by SYSTEM, so the file is created and owned by the computer
        account, exactly like the password record, and the console trusts it by
        the same owner check. The .session extension keeps it out of every
        *.json scan (Get-RustDeskPassword.ps1 -All, the console's reveal).

        The script is embedded in the task with -EncodedCommand rather than
        saved to disk: there is no file on the machine a user could edit to
        make SYSTEM run something else.
    #>
    param([Parameter(Mandatory)][string]$Vault)

    $reporter = @'
$ErrorActionPreference = 'Stop'
# Interactive sessions = whoever owns an explorer.exe: console, RDP, and
# switched-away users alike. Services and scheduled tasks have none.
$users = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object {
    # An explorer process can exit between enumeration and GetOwner. One race
    # must not prevent the entire workstation from sending its report.
    try {
        $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
        if ($o.ReturnValue -eq 0 -and $o.User) { '{0}\{1}' -f $o.Domain, $o.User }
    } catch { }
} | Sort-Object -Unique)
if (-not $users.Count) {
    $consoleUser = (Get-CimInstance Win32_ComputerSystem).UserName
    if ($consoleUser) { $users = @($consoleUser) }
}
# The exact OS release, which the network cannot see: 24H2/25H2/26H2 all report
# build 26100 over SMB, so only the machine itself knows its DisplayVersion.
# Guarded so a lookup failure never costs the logged-on-user report.
$os = ''; $build = ''
try {
    $cv  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $cap = (Get-CimInstance Win32_OperatingSystem).Caption
    if     ($cap -match 'Windows Server (\d{4}(?: R2)?)') { $os = 'Windows Server ' + $Matches[1] }
    elseif ($cap -match 'Windows (10|11)')                { $os = 'Windows ' + $Matches[1] + $(if ($cv.DisplayVersion) { ' ' + $cv.DisplayVersion }) }
    else                                                   { $os = ($cap -replace '^Microsoft ', '').Trim() }
    if ($cv.CurrentBuildNumber) { $build = '{0}.{1}' -f $cv.CurrentBuildNumber, [int]$cv.UBR }
} catch { }
$rec = [ordered]@{
    rustdesk_session = $true
    host             = $env:COMPUTERNAME
    users            = $users
    os               = $os
    os_build         = $build
    at               = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    reporter_version = '2'
}
$json = ConvertTo-Json -InputObject $rec -Compress
$logDir = Join-Path $env:ProgramData 'RustDeskDeploy'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$log = Join-Path $logDir 'reporter.log'
if ((Test-Path -LiteralPath $log) -and (Get-Item -LiteralPath $log).Length -gt 1MB) {
    Move-Item -LiteralPath $log -Destination ($log + '.1') -Force
}
for ($attempt = 1; $attempt -le 3; $attempt++) {
    try {
        # Publish a complete file, so scans never see a partially-written JSON.
        $temporary = Join-Path '__VAULT__' "$env:COMPUTERNAME.session.tmp"
        Set-Content -LiteralPath $temporary `
                    -Value $json -Encoding UTF8 -ErrorAction Stop
        Move-Item -LiteralPath $temporary -Destination (Join-Path '__VAULT__' "$env:COMPUTERNAME.session") -Force -ErrorAction Stop
        Add-Content -LiteralPath $log -Encoding UTF8 -Value (
            '{0} report written; users={1}; reporter=2' -f (Get-Date -Format s), $users.Count)
        exit 0
    } catch {
        Add-Content -LiteralPath $log -Encoding UTF8 -Value (
            '{0} report write failed; attempt={1}; error={2}' -f (Get-Date -Format s), $attempt, $_.Exception.GetType().Name)
        if ($attempt -lt 3) { Start-Sleep -Seconds 10 }
    }
}
exit 1
'@
    $reporter = $reporter.Replace('__VAULT__', $Vault.Replace("'", "''"))
    $encoded  = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($reporter))

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand ' + $encoded)
    # -Once with only a RepetitionInterval repeats indefinitely on Windows 10/11.
    $triggers = @(
        (New-ScheduledTaskTrigger -AtLogOn),
        (New-ScheduledTaskTrigger -AtStartup),
        (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5))
    )
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable -MultipleInstances IgnoreNew -Hidden `
                    -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskPath $SessionTaskPath -TaskName $SessionTaskName -Action $action `
        -Trigger $triggers -Settings $settings -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskPath $SessionTaskPath -TaskName $SessionTaskName
}

function Get-RustDeskConfigDirs {
    <#
        Where RustDesk keeps RustDesk2.toml (server config) and RustDesk.toml
        (password) for the SERVICE.

        RustDesk does NOT follow the service token's own %APPDATA%. Verified on a
        1.4.9 machine: SERVICE_START_NAME is LocalSystem, yet the live config -
        the file RustDesk actually reads and rewrites, carrying trusted_devices,
        unlock_pin and local-ip-addr - lives under the LocalService profile, not
        systemprofile. So the account tells us nothing reliable; writing to the
        profile it implies is what left machines stuck on the public servers.

        Write every service profile instead. RustDesk's real file is whichever
        one it maintains; the other copies are inert and harmless. LocalService
        is first because that is where RustDesk has actually been observed to
        keep it.
    #>
    $acct = $null
    try { $acct = (Get-CimInstance Win32_Service -Filter "Name='RustDesk'" -ErrorAction Stop).StartName } catch { }
    Write-Log "RustDesk service account: $(if ($acct) { $acct } else { 'unreadable' }) - writing all service profiles (RustDesk ignores the token's own profile)"
    @(
        "$env:windir\ServiceProfiles\LocalService"       # RustDesk's actual service config has been observed here
        "$env:windir\System32\config\systemprofile"      # LocalSystem profile, should a build use it
        "$env:windir\ServiceProfiles\NetworkService"
    ) | ForEach-Object { Join-Path $_ 'AppData\Roaming\RustDesk\config' }
}

$SessionTaskPath = '\RustDesk\'
$SessionTaskName = 'Report logged-on user'

# ----------------------------------------------------------------- main
try {
    Write-Log "=== start on $env:COMPUTERNAME ==="
    $have = Get-InstalledVersion
    if ($have) { Write-Log "RustDesk present: $have" } else { Write-Log 'RustDesk not installed' }

    # A copy the domain MSI did not install (an NTLite/custom image, or a manual
    # .exe install) is replaced, so every domain machine ends up on the MSI with
    # the server config - no manual uninstall and reboot needed.
    $installs = @(Get-RustDeskInstalls)
    if (Test-ForeignRustDesk -Installs $installs -ExePresent ([bool]$have)) {
        $what = ($installs | ForEach-Object { "$($_.Key) $($_.Version) msi=$($_.Msi)" }) -join '; '
        if ($KeepForeignInstall) {
            Write-Log "non-domain RustDesk found ($what) - kept (-KeepForeignInstall)" 'WARN'
        } else {
            Write-Log "non-domain RustDesk found ($(if ($what) { $what } else { 'unregistered copy' })) - replacing it with the domain MSI"
            if (-not (Remove-ForeignRustDesk -Installs $installs)) {
                Write-Log 'Aborting: the existing RustDesk could not be removed; will retry next boot' 'ERROR'
                exit 1
            }
            $have = $null          # forces the MSI install below
        }
    }

    # WantVersion is a MINIMUM, not an exact pin. RustDesk clients self-update,
    # and the version carries build metadata like "1.5.0+68", which [version]
    # cannot parse - so compare on the numeric part only. Installing an older
    # MSI over a newer build is a downgrade: MSI fails it with 1603, and because
    # a failed install aborts the
    # whole run, the password re-check and the session-report task never ran.
    # Only install when RustDesk is missing or genuinely older.
    $haveNum = if ($have) { ($have -split '\+')[0] } else { $null }
    $needInstall = $true
    if ($haveNum) {
        try   { $needInstall = [version]$haveNum -lt [version]$WantVersion }
        catch { $needInstall = $haveNum -notlike "$WantVersion*" }   # unparseable: literal fallback
    }
    if ($needInstall) {
        if (-not (Install-RustDesk)) { Write-Log 'Aborting: install failed' 'ERROR'; exit 1 }
        $have = Get-InstalledVersion
    } else {
        Write-Log "RustDesk $have meets the $WantVersion minimum - not reinstalling"
    }

    # Write the server config into the service's OWN profile (resolved from its
    # account), so the running service actually reads it, plus the Default
    # profile to seed future users. Existing users are handled by the logon script.
    $svcDirs = @(Get-RustDeskConfigDirs)
    $targets = @($svcDirs | ForEach-Object { Join-Path $_ 'RustDesk2.toml' })
    $targets += "$env:SystemDrive\Users\Default\AppData\Roaming\RustDesk\config\RustDesk2.toml"
    $targets = @($targets | Select-Object -Unique)

    # Stop the service BEFORE writing. RustDesk rewrites its config from memory
    # when it exits, so writing while it runs and then restarting lets it flush
    # the old server (the public one on a fresh install) back over ours.
    $svc = Get-Service -Name 'RustDesk' -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Stop-Service -Name 'RustDesk' -Force -ErrorAction SilentlyContinue
        try { (Get-Service -Name 'RustDesk').WaitForStatus('Stopped', '00:00:20') } catch { }
        Write-Log 'service stopped to write config'
    }

    foreach ($t in $targets) {
        if (Merge-RustDeskConfig -Path $t) { Write-Log "config written: $t" }
        else { Write-Log "config already correct: $t" }
    }

    if ($svc) {
        if ($svc.StartType -ne 'Automatic') {
            Set-Service -Name 'RustDesk' -StartupType Automatic
            Write-Log 'service set to Automatic'
        }
        Start-Service -Name 'RustDesk' -ErrorAction SilentlyContinue
        try { (Get-Service -Name 'RustDesk').WaitForStatus('Running', '00:00:20') } catch { }
        Write-Log 'service started on the deployed config'
    } else {
        Write-Log 'RustDesk service not found' 'WARN'
    }
    # ---- unattended access password -------------------------------------
    # Each machine gets its OWN random password, recorded in the admin-only
    # vault. Nothing secret lives in this script or on NETLOGON, and one
    # compromised workstation does not hand over the rest of the fleet.
    $vault = Resolve-VaultPath
    if (-not $vault) {
        Write-Log 'skipping password step: vault unavailable, will retry next boot' 'WARN'
    }
    else {
        $recordFile = Join-Path $vault "$env:COMPUTERNAME.json"
        $stored     = Get-StoredRecord -Path $recordFile

        # The password is in RustDesk.toml in the service's own profile - the
        # same dir(s) the server config went to, resolved from the service account.
        $pwTomls = @($svcDirs | ForEach-Object { Join-Path $_ 'RustDesk.toml' })
        $localHasPw = $false
        foreach ($pt in $pwTomls) {
            if ((Test-Path $pt) -and (Select-String -LiteralPath $pt -Pattern "^password = '.+'" -Quiet)) {
                $localHasPw = $true; break
            }
        }

        $rid = Get-RustDeskId
        $previousHost = Get-PreviousDeploymentHost -Override $PreviousComputerName
        # A one-time company mapping recovers PCs renamed before identity.json
        # existed. Once this host is tracked locally, the mapping is consumed.
        if (-not $previousHost -and $settings.PreviousComputerNames.ContainsKey($env:COMPUTERNAME)) {
            $previousHost = $settings.PreviousComputerNames[$env:COMPUTERNAME]
        }
        $renamed = $previousHost -and $previousHost -ne $env:COMPUTERNAME
        $recovered = $null
        $passwordReady = $false
        if ($renamed -and -not $ForceNewPassword) {
            $recovered = Get-RenamedRecord -Vault $vault -PreviousHost $previousHost -Id $rid
        }

        if ($renamed -and -not $ForceNewPassword -and -not $recovered) {
            # Never silently rotate a password just because the old record
            # cannot be recovered. An administrator can repair the record or
            # explicitly request -ForceNewPassword after reviewing the failure.
            Write-Log 'rename detected; password step deferred until the previous record is verified' 'WARN'
        }
        elseif ($recovered) {
            if (Set-StoredRecord -Path $recordFile -Id $rid -Password $recovered.password) {
                Invoke-RustDeskCli -Arguments @('--password', $recovered.password) -RequireSuccess | Out-Null
                $passwordReady = $true
                Write-Log "rename recovered: $previousHost -> $env:COMPUTERNAME; existing password preserved (RustDesk ID $rid)"
            }
        }
        elseif ($ForceNewPassword -or -not $stored -or -not $stored.password) {
            $pw = New-RustDeskPassword
            # Record FIRST: if the vault write fails, the local password is left
            # untouched rather than set to something nobody can look up.
            if (Set-StoredRecord -Path $recordFile -Id $rid -Password $pw) {
                Invoke-RustDeskCli -Arguments @('--password', $pw) -RequireSuccess | Out-Null
                $passwordReady = $true
                Start-Sleep -Seconds 2
                $pwVisible = $false
                foreach ($pt in $pwTomls) {
                    if ((Test-Path $pt) -and (Select-String -LiteralPath $pt -Pattern "^password = '.+'" -Quiet)) { $pwVisible = $true; break }
                }
                if ($pwVisible) {
                    Write-Log "unattended password set and recorded in vault (RustDesk ID $rid)"
                } else {
                    Write-Log 'password recorded but not visible in RustDesk.toml yet - will re-check next boot' 'WARN'
                }
            } else {
                Write-Log 'password NOT changed because the vault write failed' 'ERROR'
            }
        }
        elseif (-not $localHasPw) {
            # Restore the verified vault password instead of rotating it when
            # RustDesk's local config has been reset or moved between profiles.
            if (Set-StoredRecord -Path $recordFile -Id $rid -Password $stored.password) {
                Invoke-RustDeskCli -Arguments @('--password', $stored.password) -RequireSuccess | Out-Null
                $passwordReady = $true
                Write-Log "existing vault password restored (RustDesk ID $rid)"
            }
        }
        elseif ($rid -and $rid -ne $stored.id) {
            # Same password, but the recorded ID is missing or stale.
            if (Set-StoredRecord -Path $recordFile -Id $rid -Password $stored.password) {
                $passwordReady = $true
                Write-Log "record updated with RustDesk ID $rid (password unchanged)"
            }
        }
        else {
            $passwordReady = $true
            Write-Log "password already set and recorded (RustDesk ID $($stored.id))"
        }
        if ($passwordReady) { Save-DeploymentIdentity -Id $rid }
    }

    # ---- logged-on user report for the RustDesk Console -----------------
    # Re-registered every boot so a changed vault path or script takes effect.
    # A failure here is logged and ignored: it must never cost a machine its
    # RustDesk install or password.
    try {
        if ($NoSessionReport) {
            if (Get-ScheduledTask -TaskPath $SessionTaskPath -TaskName $SessionTaskName -ErrorAction SilentlyContinue) {
                Unregister-ScheduledTask -TaskPath $SessionTaskPath -TaskName $SessionTaskName -Confirm:$false
                Write-Log 'session report task removed (-NoSessionReport)'
            }
        }
        elseif ($vault) {
            Register-SessionReporter -Vault $vault
            Write-Log "session report task registered ($SessionTaskPath$SessionTaskName)"
        }
        else {
            Write-Log 'session report task not registered: vault unavailable, will retry next boot' 'WARN'
        }
    }
    catch { Write-Log "session report task failed: $($_.Exception.Message)" 'WARN' }

    Write-Log "=== done (version $have) ==="
    exit 0
}
catch {
    Write-Log "UNHANDLED: $($_.Exception.Message)" 'ERROR'
    exit 1
}
