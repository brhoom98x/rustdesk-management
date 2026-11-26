# RustDesk Management Console

Independent Python monitoring console for an existing RustDesk OSS server.

- [Installation](../docs/console-installation.md)
- [Company configuration](../docs/configuration.md)
- [Security](../docs/security.md)
- [Migration](../docs/migration.md)

Configuration: `/etc/rdmon/console.ini` or `RDMON_CONFIG`. Vault integration is
disabled by default; no company domain, controller, IP or public key is embedded.
Users/roles, HTTPS, monitoring, filters/export and optional owner-verified reveal
remain available. `install.py --check` validates without changing the system.

Tests: `python3 -m unittest discover -s console/tests -v` from repository root.
