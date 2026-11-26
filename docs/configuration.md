# Company configuration

## Linux console: private INI

Copy `config/examples/console.ini.example` and edit it outside Git. The runtime
loads `/etc/rdmon/console.ini`; `RDMON_CONFIG` can select another file. An explicit
missing configuration path, unknown setting, invalid port, or incomplete enabled
vault fails validation. Without any configuration, defaults enable monitoring
only and disable vault reads.

Without company configuration, the bind address defaults to loopback (127.0.0.1).
Remote access requires an explicit bind setting and management-network firewall rules.

| Section | Settings |
|---|---|
| `console` | Bind host, HTTP/HTTPS ports, public HTTPS origin, state/static/TLS/account/audit paths, online window |
| `collector` | hbbs database path, interface, heartbeat port, aliases file |
| `vault` | Enabled flag, mount path, SMB share, credential-file path, actual NetBIOS owner domain, timeouts/cache paths |

The managed installer uses conventional runtime paths (`/opt/rdmon`,
`/etc/rdmon`, `/var/lib/rdmon`, `/var/log/rdmon`). Port, database, interface and
company network settings are configurable. Advanced custom runtime paths require
manual installation and corresponding systemd sandbox permissions; the installer
rejects those overrides rather than silently producing an unusable service.

`public_url` is an HTTPS origin without credentials, query or path. It sets the
HTTP redirect destination. Configure system DNS to resolve the actual AD domain
if using a vault; `console/deploy/resolved/company.conf.example` is an optional
systemd-resolved template. No domain controller or resolver is hardcoded in Python.

## Windows: public deployment data

All GPO scripts use the adjacent `settings.psd1` through
`DeploymentSettings.ps1`. `Import-PowerShellDataFile` imports literal data.
Explicit script parameters override the file. Domain-joined clients can derive
their DNS domain automatically; providing `Domain` makes staging reproducible.

| Setting | Purpose |
|---|---|
| Domain | AD DNS domain; default stage is `\\<domain>\NETLOGON\RustDesk` |
| OwnerDomain | Actual AD NetBIOS domain used to verify machine file owners |
| IdServer, RelayServer | DNS/IP endpoints, optionally with ports |
| PublicKey | Your server's public key, base64 encoding of 32 bytes |
| ApiServer | Blank for OSS; never point it at the monitoring console |
| WantVersion, MsiPath | Minimum supported client version and installer location |
| MsiSha256 | Optional independently verified SHA-256; mismatch blocks MSI execution |
| StageDir, VaultPointer | Optional overrides for the public deployment share/pointer |
| VaultPath | Optional explicit vault UNC instead of the pointer |
| Path, ShareName, ReaderAccounts | DC vault directory, share name and read-only reader accounts |
| PasswordLength | Per-machine random unattended password length, 16–128 |
| StagedHelper | Optional reporting repair helper location |

On the DC, discover the two different domain identifiers with:

```powershell
Get-ADDomain | Select-Object DNSRoot,NetBIOSName
```

These files contain public connection settings, not credentials. Unknown data
keys such as `Password` are rejected. Use the root-only/console-readable Linux
credential file for the SMB reader password, never NETLOGON or Git.
