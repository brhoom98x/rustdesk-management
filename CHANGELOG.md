# Release notes

## 2.0.4 — 2026-11-04

Connect launcher and dashboard controls fixes.

### Fixed

- Use the current `rustdesk://connect/<ID>` launcher action, verified with
  RustDesk 1.5.1 in Brave. Passwords are never included in launcher URLs.
- Restore theme, refresh, pause, CSV export and details sizing under the
  production Content Security Policy by binding handlers inside the authorized
  script instead of using blocked inline event attributes.
- Exercise the Connect handoff and dashboard controls with the actual server
  CSP in browser regression tests; keep the security policy unchanged.

### Upgrade notes

Update the console and reload the dashboard with **Ctrl + F5**. Existing company
configuration, accounts, certificates and vault credentials should be preserved.
The launcher requires a local RustDesk installation with its URL handler
registered. The optional Windows updater below requires one-time setup on the
DC; publishing this release does not enable it or reboot workstations.

### Added — 2026-11-04

- Optional daily SYSTEM task on the DC to stage official stable Windows x64
  RustDesk MSIs automatically, with one-time setup and a configurable schedule.
- Exact size, official SHA-256, approved Authenticode publisher and HTTPS asset
  checks before publication; settings backups, retained installers and no
  downgrades or forced workstation reboots.
- Atomic updates to installer version/path/hash that preserve company settings
  and comments, and refuse to overwrite concurrent administrator edits.
- Setup, first-run verification, logs, signer-change handling and disable
  instructions; isolated updater regression checks included in Windows CI.

## 2.0.3 — 2026-10-22

Full-width dashboard layout.

- Use the full browser width for the fleet cards, filters and machine table
  instead of keeping the dashboard centered in a narrow content area.
- Keep responsive edge spacing (14–24 pixels), the existing table height fit,
  and normal scrolling on phones.
- Preserve all monitoring, filtering, password reveal and account behavior.

### Upgrade notes

This is a dashboard stylesheet update. Existing company settings and Windows
deployment scripts do not need changes for this release. Reload the dashboard
after updating the console. Layout was checked at 2560, 1920, 1440 and 390 pixel
viewport widths, and the existing dashboard browser regression suite passed.

## 2.0.2 — 2026-10-22

Computer rename and presence fixes.

- Detect heartbeats from 6–16 digit RustDesk IDs, including older 8-digit IDs
  that previously appeared offline despite connecting to the server.
- Refresh cached NTFS owner names when duplicate ID claims are encountered
  after an AD rename. Distinct verified computers claiming one ID remain blocked.
- Preserve the original unattended password across computer renames using a
  non-secret local identity pointer, current-computer ownership and exact ID checks.
- Add `PreviousComputerNames` for one-time recovery of older deployments and
  `Repair-RustDeskIdentity.ps1` for targeted online repairs as SYSTEM.
- Restore the verified vault password after a local config reset instead of
  rotating it; report password-command failures and timeouts accurately.
- Refuse writes over an existing vault record owned by another account.
- Fix adjacent settings/script path defaults for Windows PowerShell 5.1 `-File`
  launches; add rename, ownership, CLI and startup regression checks to CI.

### Upgrade notes

Preserve existing Linux configuration, accounts, TLS files and vault credentials.
Stage the updated Windows scripts and shared `DeploymentSettings.ps1` together,
retaining company `settings.psd1`. Computers renamed before identity tracking
was deployed need an explicit recovery mapping or the targeted repair helper;
see [rename recovery](docs/windows-deployment.md#5-renaming-computers-without-changing-their-password).
Keep the old vault record until recovery succeeds. Workstations apply startup
changes at their next normal network-connected boot; publishing does not deploy
the update or force a reboot. File owners and vault access rules are not relaxed.

## 2.0.1 — 2026-10-15

Security update; existing installations should upgrade.

- Refuse plaintext login when TLS is unavailable; add browser security headers
  and cross-origin login protection.
- Block reveal on audit failure; sanitize/rotate audit logs and recheck revocation.
- Bound connection/session/auth/heartbeat resources and SMB discovery replies.
- Harden vault schema/owner/file checks and reject conflicting RustDesk IDs.
- Enforce password remasking during selections/page hiding; harden CSV export.
- Prevent sensitive JSON parse errors in GPO logs, verify record owners, add MSI
  hash verification, and validate deployment paths.
- Add security regression tests and automated GitHub security checks.

See [review and limitations](docs/security-review-2026-10-15.md). TLS is mandatory;
the no-config bind default is now loopback. Existing company INI values, account
data, credentials and TLS files should be preserved during migration.

## 2.0.0 — 2026-10-14

First combined, configurable RustDesk Management release. Version 2 marks the
configuration/layout migration from the separately released console.

- Console and Windows GPO toolkit combined in one repository.
- Private Linux INI and public Windows PSD1 company configuration replace
  company-specific source defaults; configuration validation and generation.
- Ubuntu/Debian installer with TLS, managed services, account preservation,
  optional encrypted read-only vault and dynamic service uid/gid.
- Existing dashboard features, reporting diagnostics, Admin/Operator/Viewer
  accounts, owner-verified password reveal, CSRF, auditing and rate limiting.
- Complete Linux/Windows source packages and SHA-256 checksums.
- Setup, configuration, security and migration documentation.

### Migration required

Existing installations must create their company INI/PSD1 before switching
to these scripts. Vault integration defaults to disabled. Stage
`DeploymentSettings.ps1` and `settings.psd1` with the GPO scripts. Follow
[migration](docs/migration.md); do not deploy generic scripts without settings.

### Verification

14 Python tests passed on Ubuntu, two browser regression suites passed, and
Windows PowerShell 5.1 configuration/reporting checks passed. Two independent
sample company configurations were validated without editing source code.

### Scope

Existing RustDesk OSS hbbs/hbbr is required. Console: Ubuntu/Debian with local
hbbs database/heartbeat visibility. GPO: Windows x64, AD and PowerShell 5.1.
Vault/session reporting needs the optional AD SMB integration. AD SSO and
automatic application upgrades are not implemented.
