# Windows AD deployment

Use a company-managed Windows x64 MSI from the
[official RustDesk releases](https://github.com/rustdesk/rustdesk/releases).
The example minimum is 1.5.0; configure the version and filename you actually
stage. Installed newer versions are not downgraded.

Set `MsiSha256` in company settings to the independently verified hash of that
installer. The deployment checks the local copy before running it and stops on a
mismatch. A blank hash retains trust in the deployment share's administrators.

## 1. Generate the company settings

On the DC, elevated Windows PowerShell 5.1:

```powershell
Get-ADDomain | Select-Object DNSRoot,NetBIOSName
Set-Location .\deployment\gpo
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\New-RustDeskDeploymentConfig.ps1
```

The generator asks for domain, actual NetBIOS name, server and server **public**
key. Alternatively edit a copy of `config/examples/deployment.psd1.example` as
`settings.psd1`. No password or private key belongs in that file. The generator
does not write `MsiSha256`; add it to the generated file yourself.

Validate without installing or restarting anything:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Deploy-RustDesk.ps1 -CheckConfig
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Set-RustDeskUserConfig.ps1 -CheckConfig
```

Stage **all `.ps1` files**, `settings.psd1` and the selected MSI together in the
configured NETLOGON directory. Shared `DeploymentSettings.ps1` is required.
The scripts need computer/user read access; write access belongs to deployment
administrators. Stage configuration without private passwords. Stage before
creating the vault: `Initialize-RustDeskVault.ps1` writes `vault-path.txt` into
the stage directory. [Step-by-step](step-by-step.md) has the download, hash and
copy commands.

## 2. Prepare the encrypted vault (if using passwords/reporting)

Create a dedicated reader account, such as `svc-rdconsole`, with no admin role.
Supply its password privately through your AD account-management tools. Set
`ReaderAccounts` in company settings, then run on the DC hosting the vault:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Initialize-RustDeskVault.ps1
```

The script derives Domain Computers from the actual domain SID, applies create-only
folder access and CREATOR OWNER file modification, grants readers read-only access,
requires SMB encryption, and publishes `vault-path.txt` in the stage directory.
Re-running replaces the managed ACL, so include all intended readers in settings.

The vault is required for the default password/reporting deployment. If deliberately
omitting it, the installer still configures RustDesk but logs that vault password
storage/reporting is unavailable; no unknown unattended password is silently set.

## 3. Link policies to the actual workstation OU

Create a deployment GPO using GPMC, link it to the OU that holds the workstation
**computer** accounts (not a parent OU that also holds servers), and set:

- Computer startup: the staged `Deploy-RustDesk.ps1`, running as SYSTEM.
- User logon: the staged `Set-RustDeskUserConfig.ps1` for existing profiles.
- For a conventional startup script launch, use `powershell.exe` and
  `-NoProfile -ExecutionPolicy Bypass -File "\\<domain>\NETLOGON\RustDesk\Deploy-RustDesk.ps1"`.
- **Loopback processing in Merge mode** (Computer Configuration → Administrative
  Templates → System → Group Policy → Configure user Group Policy loopback
  processing mode). User accounts normally live in a different OU from the
  computers; without loopback, the logon script in a GPO linked to the computer
  OU never runs.
- **Always wait for the network at computer startup and logon** (Computer
  Configuration → Administrative Templates → System → Logon). By default Windows
  starts before the network is ready and skips startup scripts. A PC that has
  not yet received this setting may need two restarts the first time.

Both settings can also be set with `Set-GPRegistryValue`; see
[step-by-step](step-by-step.md#7-create-and-link-the-gpo).

The process execution-policy override cannot supersede a domain-enforced signing
policy. If signing is required, sign the scripts with the company's trusted
code-signing certificate. Do not alter domain-wide policy merely to run the examples.

Pilot one workstation. Verify merged server settings, connection to your server,
machine-owned vault records and reporting. Per-machine passwords use a secure RNG;
later runs preserve them unless `-ForceNewPassword` is explicitly requested.
The reporter runs at startup/logon and every five minutes, tolerates process races,
retries writes, and publishes complete files. See `reporter.log` under
`%ProgramData%\RustDeskDeploy`. Let machines reboot normally for startup deployment.
Use Restart rather than Shut down: with Fast Startup a shutdown is not a full
boot, and startup scripts do not run.

Managed PCs must reach the RustDesk server on 21115-21117/tcp and 21116/udp.
Open that path on any router or firewall between client networks and the server.

### Machines that already have RustDesk (NTLite or custom images)

A RustDesk baked into a deployment image (NTLite, MDT, a golden image) or
installed by hand with the `.exe` installer is not owned by the domain MSI. Left
alone it defeats the deployment: an older copy makes the MSI install fail (and the
run abort before any server settings are written), and a same-or-newer copy is
skipped and keeps using the public servers.

The startup script therefore replaces any RustDesk without a registered Windows
Installer product: it runs that copy's own `--uninstall`, removes anything left
(service, `Program Files\RustDesk`, the non-MSI uninstall entry), then installs the
domain MSI and merges the server settings - what used to be a manual uninstall and
reboot. The machine's RustDesk configuration, and so its ID, is kept. Machines
installed by the domain MSI are never reinstalled. The deploy log records it as
`non-domain RustDesk found (...) - replacing it with the domain MSI`.

To keep such a copy instead, pass `-KeepForeignInstall`. Better still, remove
RustDesk from the image and let the domain deployment install it.

## 4. Repair reporting without reinstalling

On the DC, adjust the domain and machine names:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '\\corp.example.com\NETLOGON\RustDesk\Repair-RustDeskReporting.ps1' -ComputerName 'WORKSTATION-01','WORKSTATION-02'"
```

Remote scheduling requires admin rights, online targets and remote Task Scheduler
network access. Failed requests are not queued. If blocked, run the helper locally
as administrator/SYSTEM or deploy it through a computer-side Group Policy
Preferences immediate task. It repairs reporting only.

The console verifies owners against `vault.owner_domain`. The Windows lookup
helper verifies the complete configured domain and `<HOST>$` owner before showing
a password. An owner mismatch is an investigation, never a reason to disable checks.

## 5. Renaming computers without changing their password

After a successful deployment, `%ProgramData%\RustDeskDeploy\identity.json` keeps
only the previous computer name and RustDesk ID, never a password. A subsequent
startup after an AD rename reuses the previous vault password only when that file
is still owned by the current computer account and contains the current RustDesk
ID. It republishes the record under the new hostname and updates local tracking.
If verification fails, password changes are deferred and logged. A reset local
RustDesk config also restores the verified vault password instead of generating
a replacement. `-ForceNewPassword` remains an explicit rotation request.

For a machine renamed before identity tracking was deployed, add a one-time
entry to company `settings.psd1`, stage the updated scripts and settings, and let
the existing computer startup GPO run at its next normal boot:

```powershell
PreviousComputerNames = @{ 'NEW-PC' = 'OLD-PC' }
```

This entry is a field inside the settings hashtable. It is used only if local
identity tracking is absent; a successful recovery records the current name so
future boots do not repeatedly restore a historical password. Retain the old
vault file until recovery succeeds. A machine that is offline cannot be repaired
immediately; staging files does not wake it or force a restart.

For an online machine, a DC administrator can instead run this targeted repair:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '\\corp.example.com\NETLOGON\RustDesk\Repair-RustDeskIdentity.ps1' -ComputerName NEW-PC -PreviousComputerName OLD-PC"
```

Stage the helper, deployment script, shared settings loader and actual company
settings together first. The repair runs as the machine's SYSTEM account,
reapplies its original password, republishes its correctly named vault record
and refreshes reporting. It performs no installation, reboot or service restart.
Existing owner checks remain enforced; neither ownership nor old records are
changed or deleted. If AD recreated the computer account with a different SID,
recovery fails safely and requires administrator investigation.

## 6. Automatic stable RustDesk MSI updates

**Availability:** these updater scripts are included in `v2.0.4` and later
release packages under `deployment/gpo/`. Use the four files from the same
release before following this section.

Run the setup once on the DC that hosts the existing NETLOGON deployment. Copy
these four files together to a temporary setup folder on that DC:

- `Register-RustDeskAutoUpdate.ps1`
- `Update-RustDeskDeployment.ps1`
- `RustDeskUpdates.ps1`
- `DeploymentSettings.ps1`

In elevated **Windows PowerShell 5.1**, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Register-RustDeskAutoUpdate.ps1
```

The setup discovers the local NETLOGON share path and its `RustDesk\settings.psd1`.
For a custom stage folder, supply its **local** configuration path with
`-ConfigPath 'D:\SYSVOL\domain\scripts\CustomStage\settings.psd1'`. Do not use
a UNC configuration path for the updater's own writes. Clients still receive
the configured UNC installer path from `StageDir`.

The task `\RustDesk\Update deployment` runs as SYSTEM daily at **04:00 DC local
time** and starts its first check immediately. Use `-At '02:30'` to choose
another time or `-NoInitialCheck` to defer its first check. No account password,
GitHub token or Windows credential is saved. The DC needs outbound HTTPS access
to the GitHub API, release asset hosts and Windows certificate validation services.

For each official `rustdesk/rustdesk` stable release, it:

1. Rejects drafts, previews/nightlies, unexpected asset URLs, missing publisher
   digests and oversized downloads. Selects only the Windows x64 MSI.
2. Verifies the exact file size, GitHub's official SHA-256 digest and a valid
   Authenticode signature from the approved RustDesk publisher.
3. Publishes the verified MSI before atomically changing only `WantVersion`,
   `MsiPath` and `MsiSha256` in company settings. Comments, server/public key,
   vault/reader options and rename mappings are preserved. Concurrent admin
   edits cause the updater to abort rather than overwrite those edits.
4. Keeps the original settings backup and all older installers. It never
   downgrades a version already configured by an administrator.

No MSI is executed by this task. The existing computer startup GPO upgrades
eligible clients at their next normal network-connected boot. There is no
forced reboot or wake-up, and the updater does not read or change unattended
passwords. This updates the Windows RustDesk deployment; the console and native
hbbs/hbbr services have their own release/install process.

Installed scripts, logs and settings backups are protected for SYSTEM and
Administrators under `%ProgramData%\RustDeskDeploy\AutoUpdate`. Read
`updater.log` and `status.json` there. Logs rotate at 1 MiB. Task Scheduler also
shows its last run and result. Download/verification failures retain the working
settings and retry at the next daily run. A newly downloaded MSI may remain
staged if a later settings check aborts, but clients continue using the old
settings until the complete replacement succeeds.

After installation, wait for the initial check to finish and verify its result:

```powershell
Get-ScheduledTaskInfo -TaskPath '\RustDesk\' -TaskName 'Update deployment' |
    Select-Object LastRunTime, LastTaskResult, NextRunTime
Get-Content "$env:ProgramData\RustDeskDeploy\AutoUpdate\updater.log" -Tail 10
```

`LastTaskResult` of `0` means the run completed successfully. The log should
report `staged; version=...` or `already current; version=...`. The setup's
installation confirmation alone does not prove its asynchronous first check
has finished. If the configured version is newer than upstream, the updater
reports that condition and keeps the administrator's version.

The approved signer subject is the one verified from the official signed
RustDesk 1.5.1 MSI. Certificate renewal with the same subject is supported. If
the vendor changes its signing identity, updates stop until an administrator
verifies the change and re-registers with `-AllowedSignerSubject`. Checks are
never disabled automatically. A checksum confirms the publisher's published
asset; it does not independently audit a new upstream RustDesk release.

For a read-only check, run the extracted updater with the local settings path:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Update-RustDeskDeployment.ps1 -ConfigPath 'C:\Windows\SYSVOL\sysvol\corp.example.com\scripts\RustDesk\settings.psd1' -CheckOnly
```

To stop future automatic staging:

```powershell
Disable-ScheduledTask -TaskPath '\RustDesk\' -TaskName 'Update deployment'
```
