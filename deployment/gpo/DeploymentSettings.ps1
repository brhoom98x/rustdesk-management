# Shared, non-secret settings. Import-PowerShellDataFile reads literal data;
# company settings never contain passwords or private keys.
function Get-RustDeskDeploymentSettings {
    [CmdletBinding()]
    param([string]$ConfigPath, [hashtable]$Overrides = @{}, [string[]]$Required = @())
    $settings = @{
        Domain=''; OwnerDomain=''; StageDir=''; IdServer=''; RelayServer=''; PublicKey=''; ApiServer=''
        WantVersion='1.5.0'; MsiPath=''; MsiSha256=''; VaultPath=''; VaultPointer=''
        Path='C:\RustDeskVault'; ShareName='RustDeskVault$'; ReaderAccounts=@('svc-rdconsole')
        PasswordLength=16; StagedHelper=''
        PreviousComputerNames=@{}
    }
    if ($ConfigPath -and (Test-Path -LiteralPath $ConfigPath)) {
        $data = Import-PowerShellDataFile -LiteralPath $ConfigPath
        foreach ($key in $data.Keys) {
            if (-not $settings.ContainsKey($key)) { throw "Unknown deployment setting '$key'. Passwords and private keys do not belong in this file." }
            $settings[$key] = $data[$key]
        }
    }
    foreach ($key in $Overrides.Keys) { if ($settings.ContainsKey($key)) { $settings[$key] = $Overrides[$key] } }
    if ($settings.PreviousComputerNames -isnot [hashtable]) { throw 'PreviousComputerNames must map current computer names to their previous names.' }
    foreach ($current in $settings.PreviousComputerNames.Keys) {
        $previous = $settings.PreviousComputerNames[$current]
        if ($current -isnot [string] -or $previous -isnot [string] -or
            $current -notmatch '\A[A-Za-z0-9][A-Za-z0-9-]{0,14}\z' -or
            $previous -notmatch '\A[A-Za-z0-9][A-Za-z0-9-]{0,14}\z' -or $current -eq $previous) {
            throw 'Each rename mapping must contain different, valid Windows computer names.'
        }
    }
    foreach ($key in @('Domain','OwnerDomain','StageDir','IdServer','RelayServer','PublicKey','ApiServer','WantVersion','MsiPath','MsiSha256','VaultPath','VaultPointer','Path','ShareName','StagedHelper')) {
        if ($settings[$key] -isnot [string] -or $settings[$key] -match '[\x00-\x1F"'']') { throw "$key must be a single-line value without quotes or control characters." }
    }
    if ($settings.MsiSha256 -and $settings.MsiSha256 -notmatch '\A[A-Fa-f0-9]{64}\z') { throw 'MsiSha256 must be a SHA-256 digest (64 hex characters).' }
    if (-not [IO.Path]::IsPathRooted($settings.Path) -or $settings.Path.StartsWith('\\')) { throw 'Vault Path must be an absolute local directory.' }
    $resolvedVaultPath = [IO.Path]::GetFullPath($settings.Path).TrimEnd('\')
    if ($resolvedVaultPath -eq [IO.Path]::GetPathRoot($resolvedVaultPath).TrimEnd('\')) { throw 'Refusing to replace permissions on a drive root.' }
    if ($settings.ApiServer) {
        $uri=$null
        if (-not [Uri]::TryCreate($settings.ApiServer,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -ne 'https' -or $uri.UserInfo) { throw 'ApiServer must use HTTPS without embedded credentials.' }
    }
    if (-not $settings.Domain) {
        try {
            $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            if ($computer.PartOfDomain) { $settings.Domain = $computer.Domain }
        } catch { }
    }
    if ($settings.Domain -and $settings.Domain -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') { throw 'Domain must be an AD DNS domain name.' }
    if ($settings.OwnerDomain -and $settings.OwnerDomain -notmatch '^[A-Za-z0-9_.-]{1,15}$') { throw 'OwnerDomain must be the actual AD NetBIOS domain (1 to 15 characters).' }
    if (-not $settings.StageDir -and $settings.Domain) { $settings.StageDir = '\\' + $settings.Domain + '\NETLOGON\RustDesk' }
    if (-not $settings.VaultPointer -and $settings.StageDir) { $settings.VaultPointer = Join-Path $settings.StageDir 'vault-path.txt' }
    if (-not $settings.MsiPath -and $settings.StageDir) { $settings.MsiPath = Join-Path $settings.StageDir ("rustdesk-{0}-x86_64.msi" -f $settings.WantVersion) }
    if (-not $settings.StagedHelper -and $settings.StageDir) { $settings.StagedHelper = Join-Path $settings.StageDir 'Repair-RustDeskReporting.ps1' }
    if (-not $settings.RelayServer) { $settings.RelayServer = $settings.IdServer }
    foreach ($key in @('IdServer','RelayServer')) {
        if ($settings[$key] -and $settings[$key] -notmatch '^(?:[A-Za-z0-9._-]+|\[[0-9a-fA-F:]+\])(?::[0-9]{1,5})?$') { throw "$key must be a host name or address with an optional port." }
        if ($settings[$key] -match ':(\d+)$' -and ([int]$Matches[1] -lt 1 -or [int]$Matches[1] -gt 65535)) { throw "$key port must be 1 to 65535." }
    }
    if ($settings.WantVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'WantVersion must be a version such as 1.5.0.' }
    if ([int]$settings.PasswordLength -lt 16 -or [int]$settings.PasswordLength -gt 128) { throw 'PasswordLength must be 16 to 128.' }
    foreach ($key in @('StageDir','VaultPath','VaultPointer','StagedHelper')) {
        if ($settings[$key] -and $settings[$key] -notmatch '^\\\\[^\\]+\\[^\\]+') { throw "$key must be a UNC path." }
    }
    foreach ($key in $Required) {
        if (-not $settings[$key]) { throw "Missing '$key'. Create settings.psd1 from config/examples/deployment.psd1.example or pass -$key." }
    }
    if ($Required -contains 'PublicKey') {
        if ($settings.PublicKey -notmatch '\A[A-Za-z0-9+/]{43}=\z') { throw 'PublicKey must be a single base64 public key.' }
        try { $bytes = [Convert]::FromBase64String($settings.PublicKey) }
        catch { throw 'PublicKey must be the base64 public key of your RustDesk server.' }
        if ($bytes.Length -ne 32) { throw 'RustDesk public key must decode to 32 bytes.' }
    }
    return $settings
}

function Get-RustDeskRendezvousAddress {
    param([Parameter(Mandatory)][string]$Server)
    if ($Server -match ':\d+$') { return $Server }
    return $Server + ':21116'
}
