# Shared updater functions. Dot-sourcing this file performs no network or writes.
function Get-RustDeskStableMsi {
    param([Parameter(Mandatory)]$Release)
    if ($Release.draft -ne $false -or $Release.prerelease -ne $false -or
        $Release.tag_name -isnot [string] -or $Release.tag_name -notmatch '\Av?([0-9]+\.[0-9]+\.[0-9]+)\z') {
        throw 'The upstream response is not a stable versioned release.'
    }
    $version = $Matches[1]
    $null = [version]$version
    $name = 'rustdesk-' + $version + '-x86_64.msi'
    $assets = @($Release.assets | Where-Object { $_.name -ceq $name })
    if ($assets.Count -ne 1) { throw 'The stable release must contain exactly one Windows x64 MSI.' }
    $asset = $assets[0]
    $expectedUrl = 'https://github.com/rustdesk/rustdesk/releases/download/' + $Release.tag_name + '/' + $name
    if ($asset.browser_download_url -cne $expectedUrl -or $asset.digest -isnot [string] -or
        $asset.digest -notmatch '\Asha256:([A-Fa-f0-9]{64})\z') { throw 'The official asset URL or SHA-256 digest is missing or invalid.' }
    $hash = $Matches[1].ToLowerInvariant()
    $size = [long]$asset.size
    if ($size -lt 1 -or $size -gt 128MB) { throw 'The MSI exceeds the updater size limit.' }
    return [pscustomobject]@{Version=$version;Name=$name;Url=$expectedUrl;Sha256=$hash;Size=$size}
}

function Save-RustDeskReleaseAsset {
    param([Parameter(Mandatory)]$Asset, [Parameter(Mandatory)][string]$Destination)
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $handler.UseDefaultCredentials = $false
    $handler.CheckCertificateRevocationList = $true
    $client = New-Object Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromMinutes(5)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('RustDesk-Management-Updater/1.0')
    $cancel = New-Object Threading.CancellationTokenSource
    $cancel.CancelAfter([TimeSpan]::FromMinutes(5))
    $response = $null; $source = $null; $output = $null
    try {
        $uri = [uri]$Asset.Url
        for ($redirects = 0; $redirects -le 6; $redirects++) {
            if ($uri.Scheme -ne 'https' -or $uri.UserInfo -or
                ($uri.Host -ne 'github.com' -and -not $uri.Host.EndsWith('.githubusercontent.com'))) {
                throw 'Unexpected download redirect; only HTTPS GitHub asset hosts are allowed.'
            }
            $response = $client.GetAsync($uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancel.Token).GetAwaiter().GetResult()
            $code = [int]$response.StatusCode
            if ($code -in 301,302,303,307,308) {
                $location = $response.Headers.Location
                if (-not $location) { throw 'Download redirect has no destination.' }
                $uri = [uri]::new($uri, $location)
                $response.Dispose(); $response = $null
                continue
            }
            if ($code -ne 200) { throw 'GitHub asset download did not succeed.' }
            break
        }
        if (-not $response -or [int]$response.StatusCode -ne 200) { throw 'Too many download redirects.' }
        if ($response.Content.Headers.ContentLength -and $response.Content.Headers.ContentLength -ne $Asset.Size) { throw 'Unexpected download size.' }
        $source = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $output = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $buffer = New-Object byte[] 65536
        $total = [long]0
        while (($read = $source.ReadAsync($buffer, 0, $buffer.Length, $cancel.Token).GetAwaiter().GetResult()) -gt 0) {
            $total += $read
            if ($total -gt $Asset.Size) { throw 'Downloaded MSI exceeds its declared size.' }
            $output.Write($buffer, 0, $read)
        }
        if ($total -ne $Asset.Size) { throw 'Downloaded MSI is incomplete.' }
        $output.Flush($true)
    } finally {
        if ($output) { $output.Dispose() }
        if ($source) { $source.Dispose() }
        if ($response) { $response.Dispose() }
        $client.Dispose(); $handler.Dispose(); $cancel.Dispose()
    }
}

function Test-RustDeskReleaseMsi {
    param([string]$Path, $Asset, [string]$AllowedSignerSubject)
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint -or $item.Length -ne $Asset.Size) { throw 'Invalid MSI file or size.' }
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $Asset.Sha256) { throw 'MSI SHA-256 does not match the official release.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -cne $AllowedSignerSubject) { throw 'MSI signature or approved RustDesk publisher verification failed.' }
}

function Get-RustDeskUpdatedSettingsText {
    param([string]$Text, [string]$Version, [string]$MsiPath, [string]$Sha256)
    if ($Version -notmatch '\A[0-9]+\.[0-9]+\.[0-9]+\z' -or $Sha256 -notmatch '\A[A-Fa-f0-9]{64}\z' -or
        $MsiPath -match '[\x00-\x1F"'']' -or $MsiPath -notmatch '^\\\\[^\\]+\\[^\\]+') { throw 'Invalid replacement deployment values.' }
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'Deployment settings have syntax errors.' }
    $table = $ast.Find({param($node) $node -is [Management.Automation.Language.HashtableAst]}, $true)
    if (-not $table) { throw 'Deployment settings must contain a data hashtable.' }
    $values = @{WantVersion=$Version;MsiPath=$MsiPath;MsiSha256=$Sha256.ToLowerInvariant()}
    $found = @{}; $edits = @()
    foreach ($pair in $table.KeyValuePairs) {
        $key = $pair.Item1.SafeGetValue()
        if ($values.ContainsKey($key)) {
            if ($found.ContainsKey($key)) { throw 'Duplicate deployment setting.' }
            $found[$key] = $true
            $extent = $pair.Item2.Extent
            $edits += [pscustomobject]@{Start=$extent.StartOffset;Length=$extent.EndOffset-$extent.StartOffset;Value=("'"+$values[$key]+"'")}
        }
    }
    $missing = @($values.Keys | Where-Object { -not $found.ContainsKey($_) })
    if ($missing.Count) {
        $insert = "`r`n" + (($missing | Sort-Object | ForEach-Object { "    $_ = '"+$values[$_]+"'" }) -join "`r`n") + "`r`n"
        $edits += [pscustomobject]@{Start=$table.Extent.EndOffset-1;Length=0;Value=$insert}
    }
    foreach ($edit in ($edits | Sort-Object Start -Descending)) { $Text = $Text.Remove($edit.Start,$edit.Length).Insert($edit.Start,$edit.Value) }
    return $Text
}

function Invoke-RustDeskStagingUpdate {
    param([string]$ConfigPath, [string]$StateDir, [string]$AllowedSignerSubject, [switch]$CheckOnly)
    if (-not [IO.Path]::IsPathRooted($ConfigPath) -or $ConfigPath.StartsWith('\\')) { throw 'Use the DC local NETLOGON settings path, not a UNC path.' }
    $item = Get-Item -LiteralPath $ConfigPath -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Settings must be a regular local file.' }
    $original = [IO.File]::ReadAllBytes($ConfigPath)
    $text = [IO.File]::ReadAllText($ConfigPath)
    $settings = Get-RustDeskDeploymentSettings -ConfigPath $ConfigPath -Required @('StageDir','IdServer','PublicKey','MsiPath')
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/rustdesk/rustdesk/releases/latest' -Headers @{
        'User-Agent'='RustDesk-Management-Updater/1.0';Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28'
    } -TimeoutSec 30
    $asset = Get-RustDeskStableMsi -Release $release
    if ([version]$asset.Version -lt [version]$settings.WantVersion) { return [pscustomobject]@{Status='newer version already configured';Version=$settings.WantVersion} }
    if ($CheckOnly) { return [pscustomobject]@{Status='check only';ConfiguredVersion=$settings.WantVersion;LatestStable=$asset.Version;Sha256=$asset.Sha256} }
    $stage = Split-Path $ConfigPath -Parent
    $destination = Join-Path $stage $asset.Name
    $clientPath = Join-Path $settings.StageDir $asset.Name
    $download = Join-Path $StateDir ([guid]::NewGuid().ToString('N')+'.msi')
    $staged = Join-Path $stage ('.rustdesk-update-'+[guid]::NewGuid().ToString('N')+'.tmp')
    $candidate = Join-Path $stage ('.rustdesk-settings-'+[guid]::NewGuid().ToString('N')+'.tmp')
    try {
        if (Test-Path -LiteralPath $destination) {
            Test-RustDeskReleaseMsi -Path $destination -Asset $asset -AllowedSignerSubject $AllowedSignerSubject
        } else {
            Save-RustDeskReleaseAsset -Asset $asset -Destination $download
            Test-RustDeskReleaseMsi -Path $download -Asset $asset -AllowedSignerSubject $AllowedSignerSubject
            Copy-Item -LiteralPath $download -Destination $staged
            Test-RustDeskReleaseMsi -Path $staged -Asset $asset -AllowedSignerSubject $AllowedSignerSubject
            # The temporary file inherits NETLOGON read permissions. Publish
            # the verified MSI first, before any client can see new settings.
            [IO.File]::Move($staged,$destination)
        }
        if ($settings.WantVersion -eq $asset.Version -and $settings.MsiPath -eq $clientPath -and $settings.MsiSha256 -ieq $asset.Sha256) {
            return [pscustomobject]@{Status='already current';Version=$asset.Version}
        }
        $updated = Get-RustDeskUpdatedSettingsText -Text $text -Version $asset.Version -MsiPath $clientPath -Sha256 $asset.Sha256
        [IO.File]::WriteAllText($candidate,$updated,(New-Object Text.UTF8Encoding($true)))
        $validated = Get-RustDeskDeploymentSettings -ConfigPath $candidate -Required @('StageDir','IdServer','PublicKey','MsiPath')
        if ($validated.WantVersion -ne $asset.Version -or $validated.MsiPath -ne $clientPath -or $validated.MsiSha256 -ine $asset.Sha256) { throw 'Replacement settings failed validation.' }
        if ([Convert]::ToBase64String([IO.File]::ReadAllBytes($ConfigPath)) -cne [Convert]::ToBase64String($original)) { throw 'Settings changed during download; retry without overwriting administrator changes.' }
        $backup = Join-Path $StateDir ('settings-before-'+$asset.Version+'-'+[guid]::NewGuid().ToString('N')+'.psd1')
        # One filesystem replacement publishes version, path and checksum
        # together. Never rewrite server/key/vault/rename settings wholesale.
        # StateDir can be on a different volume from SYSVOL. Copy the exact
        # original bytes privately, then atomically replace on SYSVOL itself.
        [IO.File]::WriteAllBytes($backup,$original)
        [IO.File]::Replace($candidate,$ConfigPath,[NullString]::Value)
        return [pscustomobject]@{Status='staged';Version=$asset.Version;PreviousVersion=$settings.WantVersion;Backup=$backup}
    } finally {
        foreach ($temporary in @($download,$staged,$candidate)) {
            if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
        }
    }
}
