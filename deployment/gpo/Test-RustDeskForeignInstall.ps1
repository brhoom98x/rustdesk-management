# Regression checks for replacing a RustDesk the domain MSI did not install
# (NTLite/custom image or manual .exe install). Uses a temporary fake
# Program Files tree and mocks; no real service, registry key or install changes.
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Deploy-RustDesk.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Deployment syntax errors.' }
foreach ($name in @('Get-RustDeskInstalls','Test-ForeignRustDesk','Remove-ForeignRustDesk')) {
    $function = $ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name}, $false)
    if (-not $function) { throw "Missing function $name" }
    . ([scriptblock]::Create($function.Extent.Text))
}
$messages = New-Object System.Collections.Generic.List[string]
function Write-Log { param($Message,$Level) $messages.Add([string]$Message) }

# --- classification -------------------------------------------------------
# Shapes match real registrations: the .exe installer writes key "RustDesk",
# WindowsInstaller unset, UninstallString '"...\RustDesk.exe" --uninstall'.
$exeEntry = [pscustomobject]@{ Key='RustDesk'; Path='x'; Version='1.5.3'; Msi=$false; Uninstall='"C:\Program Files\RustDesk\RustDesk.exe" --uninstall' }
$msiEntry = [pscustomobject]@{ Key='{11111111-2222-3333-4444-555555555555}'; Path='y'; Version='1.5.3'; Msi=$true; Uninstall='MsiExec.exe /X{11111111-2222-3333-4444-555555555555}' }
$cases = @(
    @{ Name='image/.exe install';             Installs=@($exeEntry);           Exe=$true;  Want=$true  }
    @{ Name='domain MSI install';             Installs=@($msiEntry);           Exe=$true;  Want=$false }
    @{ Name='MSI plus RustDesk''s own key';   Installs=@($msiEntry,$exeEntry); Exe=$true;  Want=$false }
    @{ Name='unregistered (portable) copy';   Installs=@();                    Exe=$true;  Want=$true  }
    @{ Name='nothing installed';              Installs=@();                    Exe=$false; Want=$false }
)
foreach ($c in $cases) {
    $got = Test-ForeignRustDesk -Installs $c.Installs -ExePresent $c.Exe
    if ($got -ne $c.Want) { throw "Classification wrong for '$($c.Name)': got $got, want $($c.Want)." }
}

# Live, read-only: the registry reader must return well-formed entries.
foreach ($i in @(Get-RustDeskInstalls)) {
    if (-not $i.Key -or $i.Msi -isnot [bool]) { throw 'Get-RustDeskInstalls returned a malformed entry.' }
}

# --- removal --------------------------------------------------------------
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('rd-foreign-' + [guid]::NewGuid().ToString('N'))
$savedPF = $env:ProgramW6432
try {
    $env:ProgramW6432 = $testRoot
    $dir = Join-Path $testRoot 'RustDesk'
    $cli = New-Object System.Collections.Generic.List[string]
    $uninstallWorks = $true
    function Invoke-RustDeskCli { param([string[]]$Arguments,[int]$TimeoutSec,[switch]$RequireSuccess)
        $cli.Add(($Arguments -join ' '))
        if ($uninstallWorks) { Remove-Item -LiteralPath $dir -Recurse -Force }
        return '' }
    function Stop-Service { param($Name,[switch]$Force,$ErrorAction) }
    function Get-Service  { param($Name,$ErrorAction) $null }
    function Get-Process  { param($Name,$ErrorAction) $null }
    function Start-Sleep  { param($Seconds) }

    function New-Fixture {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'rustdesk.exe') -Value 'fake'
        $exeKey = Join-Path $testRoot 'key-exe'; $msiKey = Join-Path $testRoot 'key-msi'
        Set-Content -LiteralPath $exeKey -Value 'exe'; Set-Content -LiteralPath $msiKey -Value 'msi'
        # A hostile UninstallString must never be executed: removal uses the
        # known binary's --uninstall, not the registry command line.
        @([pscustomobject]@{ Key='RustDesk'; Path=$exeKey; Version='1.5.3'; Msi=$false; Uninstall='cmd.exe /c evil.bat' },
          [pscustomobject]@{ Key='{GUID}';   Path=$msiKey; Version='1.5.3'; Msi=$true;  Uninstall='MsiExec.exe /X{GUID}' })
    }

    $installs = New-Fixture
    if (-not (Remove-ForeignRustDesk -Installs $installs)) { throw 'A removable copy was reported as not removed.' }
    if ($cli.Count -ne 1 -or $cli[0] -ne '--uninstall') { throw "Unexpected RustDesk commands: $($cli -join ', ')" }
    if (Test-Path -LiteralPath $installs[0].Path) { throw 'The non-MSI uninstall entry was left behind.' }
    if (-not (Test-Path -LiteralPath $installs[1].Path)) { throw 'An MSI registration was removed.' }

    # Uninstaller that leaves files behind: the folder is cleaned up directly.
    $cli.Clear(); $uninstallWorks = $false
    $installs = New-Fixture
    if (-not (Remove-ForeignRustDesk -Installs $installs)) { throw 'Leftover files were not cleaned up.' }
    if (Test-Path -LiteralPath $dir) { throw 'Program folder survived removal.' }

    # A file that cannot be deleted must be reported, so the run aborts and retries.
    $cli.Clear()
    $installs = New-Fixture
    $lock = [IO.File]::Open((Join-Path $dir 'rustdesk.exe'), 'Open', 'Read', 'None')
    try { if (Remove-ForeignRustDesk -Installs $installs) { throw 'A copy that is still present was reported as removed.' } }
    finally { $lock.Dispose() }

    Write-Host 'PASS: image/.exe copies detected, MSI-owned installs never replaced, removal uses only --uninstall on the known binary, leftovers cleaned, failures reported.'
} finally {
    $env:ProgramW6432 = $savedPF
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if ($resolved.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf) -like 'rd-foreign-*' -and (Test-Path -LiteralPath $resolved)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
