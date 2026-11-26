# Local regression check. Mocks scheduling; creates no real scheduled task.
$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('rdconsole-report-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    function New-ScheduledTaskAction { param($Execute, $Argument) [pscustomobject]@{ Execute=$Execute; Argument=$Argument } }
    function New-ScheduledTaskTrigger { param([switch]$AtLogOn, [switch]$AtStartup, [switch]$Once, $At, $RepetitionInterval) 'trigger' }
    function New-ScheduledTaskSettingsSet { param([switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries, [switch]$StartWhenAvailable, [switch]$Hidden, $MultipleInstances, $ExecutionTimeLimit) 'settings' }
    function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) 'principal' }
    function Register-ScheduledTask { param($TaskPath,$TaskName,$Action,$Trigger,$Settings,$Principal,[switch]$Force) $global:rdconsoleTestAction=$Action }
    function Start-ScheduledTask { param($TaskPath,$TaskName) }
    & (Join-Path $PSScriptRoot 'Repair-RustDeskReporting.ps1') -VaultPath '\\localhost\test-vault'
    $encoded = ($global:rdconsoleTestAction.Argument -split '-EncodedCommand ')[1]
    if (-not $encoded) { throw 'Scheduled action was not captured.' }
    $reporter = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
    $reporter = $reporter.Replace('\\localhost\test-vault', $testRoot.Replace("'", "''"))
    $reporter = $reporter.Replace('$env:ProgramData', "'" + $testRoot.Replace("'", "''") + "'")
    # Mock a disappearing explorer process, then a valid owner. This formerly
    # aborted the whole report. Keep actual serialization and file writes.
    $mocks = @'
function Get-CimInstance {
    param($ClassName, $Filter)
    if ($ClassName -eq 'Win32_Process') { [pscustomobject]@{TestId=1}; [pscustomobject]@{TestId=2} }
    elseif ($ClassName -eq 'Win32_OperatingSystem') { [pscustomobject]@{Caption='Microsoft Windows 11 Pro'} }
    else { [pscustomobject]@{UserName='TEST\fallback'} }
}
function Invoke-CimMethod {
    param($InputObject,$MethodName,$ErrorAction)
    if ($InputObject.TestId -eq 1) { throw 'process exited' }
    [pscustomobject]@{ReturnValue=0;Domain='TEST';User='alice'}
}
'@
    $runner = Join-Path $testRoot 'reporter-test.ps1'
    Set-Content -LiteralPath $runner -Value ($mocks + "`r`n" + $reporter) -Encoding UTF8
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $runner
    if ($LASTEXITCODE -ne 0) { throw 'Reporter test failed.' }
    $report = Get-Content -LiteralPath (Join-Path $testRoot "$env:COMPUTERNAME.session") -Raw | ConvertFrom-Json
    if ($report.users.Count -ne 1 -or $report.users[0] -ne 'TEST\alice' -or $report.reporter_version -ne '2') { throw 'Report contents failed validation.' }
    Write-Host 'PASS: repair function imports, scheduled action encodes, disappearing process is tolerated, UTF-8 session report is written.'
} finally {
    Remove-Variable rdconsoleTestAction -Scope Global -ErrorAction SilentlyContinue
    # The exact randomly-created directory is the only recursive delete target.
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if ($resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and (Split-Path $resolved -Leaf) -like 'rdconsole-report-*') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
