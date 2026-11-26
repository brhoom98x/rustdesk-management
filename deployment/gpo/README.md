# RustDesk Management GPO deployment

Windows x64 AD startup/logon deployment, encrypted machine-owned password vault,
and logged-on-user/OS reporting for the console.

- [Windows deployment](../../docs/windows-deployment.md)
- [Company configuration](../../docs/configuration.md)
- [Migration](../../docs/migration.md)

Create adjacent `settings.psd1` using `New-RustDeskDeploymentConfig.ps1`, or a
copy of `config/examples/deployment.psd1.example`. Explicit script parameters
override company data. Stage shared `DeploymentSettings.ps1` with the scripts.

Entry points retain their names: `Deploy-RustDesk.ps1`,
`Set-RustDeskUserConfig.ps1`, `Initialize-RustDeskVault.ps1`,
`Get-RustDeskPassword.ps1` and `Repair-RustDeskReporting.ps1`.
`Repair-RustDeskIdentity.ps1` provides a targeted repair for renamed machines;
the startup deployment also preserves existing passwords across later renames.
`Register-RustDeskAutoUpdate.ps1` installs an optional daily SYSTEM task on the
DC to stage verified official stable Windows x64 MSIs automatically. See
[automatic updates](../../docs/windows-deployment.md#6-automatic-stable-rustdesk-msi-updates).

Run `Deploy-RustDesk.ps1 -CheckConfig` and
`Set-RustDeskUserConfig.ps1 -CheckConfig` before rollout. No credentials or private
keys belong in NETLOGON. MSI installers and actual company settings are not committed.
