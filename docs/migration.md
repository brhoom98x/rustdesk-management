# Migrating an existing installation

The console and GPO histories are combined under `console/` and `deployment/gpo/`.
The repository is generic; each company's runtime values live outside source.

## Console

1. Back up current application files, units, account database (SQLite backup API),
   and existing private configuration in an access-controlled backup location.
2. Build a private `console.ini` from the example using the current actual database,
   ports, share, credential-file path and NetBIOS owner domain. Set `vault.enabled=true`
   for an existing vault installation; otherwise the generic default disables it.
3. Validate with `console/install.py --check`. Standard runtime paths retain
   `/opt/rdmon`, `/etc/rdmon`, `/var/lib/rdmon` and the `rdmon-*` unit names.
4. Install the new component using the documented installer. Keep existing TLS
   files as a matching pair and existing account/credential files. Reconcile any
   existing fstab vault mount before replacing its mount-unit definition.
5. Verify HTTPS, accounts/roles, heartbeat updates, owner verification and reveal
   auditing. Existing account passwords and the legacy Admin bootstrap are preserved.

No private migration INI should be committed. Generic code does not retain a
fallback to a previous company's domain/IP/public key.

## GPO scripts

1. Create the company's `settings.psd1` with its current actual server public key,
   DNS domain, NetBIOS domain, installer version and existing stage/vault paths.
2. Run both `-CheckConfig` checks before rollout.
3. Stage the new scripts **and `DeploymentSettings.ps1` and `settings.psd1` together**.
   Existing startup/logon policy entry points keep the same script names.
4. Test a pilot before broader rollout. Existing RustDesk config is merged and
   passwords are preserved; configuration errors fail before deployment changes.
5. Existing encoded reporter tasks continue their old action until the deployment
   startup or reporting repair helper re-registers them with the new script.

Do not stage generic scripts without company settings: there is no hardcoded
server/key fallback. The original working copies are historical migration sources,
not templates to clone unchanged into another company.
