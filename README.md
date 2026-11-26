# RustDesk Management

A configurable monitoring console and Windows Active Directory deployment
toolkit for a self-hosted RustDesk OSS server. Each company supplies its own
server, domain, installer and optional encrypted password-vault settings.

```text
rustdesk-management/
├── console/          Python HTTPS console, users/roles, collector and installer
├── deployment/
│   └── gpo/          Windows startup/logon deployment and reporting helpers
├── config/
│   └── examples/     Non-secret company configuration templates
└── docs/             Setup, security, configuration and migration
```

## Choose your deployment

| Component | Supported environment | Required company configuration |
|---|---|---|
| Console | Ubuntu/Debian Linux with local RustDesk OSS hbbs database and heartbeats | Database path, listener ports, TLS |
| GPO deployment | Windows x64 clients, AD, Windows PowerShell 5.1 | Domain, ID/relay server, server public key, MSI version/location |
| Password vault and logged-on users | Optional AD computer-account reporting plus encrypted SMB 3 share | Share, actual NetBIOS owner domain, dedicated read-only reader |

The console can run on its own without AD. Vault reveal and workstation session
reporting require the optional domain integration. This project does not install
hbbs/hbbr or deploy Linux/macOS clients through GPO, and is not RustDesk Server Pro.

## Quick start

### Get the released version

On a new Ubuntu/Debian server, install GitHub CLI and authenticate with an
account that can read this private repository. Authentication is interactive;
never put a GitHub token in the clone URL or shell command.

```bash
sudo apt update
sudo apt install git gh python3 tcpdump openssl
gh auth login --hostname github.com --git-protocol https
gh auth setup-git
gh repo clone brhoom98x/rustdesk-management -- --branch v2.0.4
cd rustdesk-management
```

This checks out the fixed `v2.0.4` release. Releases also include complete
`.tar.gz` and `.zip` packages with SHA-256 checksums. See
[console installation](docs/console-installation.md) for package downloads.

### Configure and install

1. Install and configure your own RustDesk OSS server.
2. Copy `config/examples/console.ini.example` to a private `console.ini` and
   configure your company's values. Leave `vault.enabled=false` for monitoring only.
3. On the Linux server:

   ```bash
   sudo apt install python3 tcpdump openssl
   python3 console/install.py --config /path/to/console.ini --check
   sudo python3 console/install.py --config /path/to/console.ini \
     --self-signed --hostname rustdesk.corp.example.com
   ```

   The installer creates a service account, prompts for the initial Admin
   password, installs services and TLS, and preserves existing account data.
   Use a company-issued certificate instead of `--self-signed` when available.
4. Open your configured HTTPS address and manage users under **Users**.
5. For Windows domain deployment, generate `deployment/gpo/settings.psd1` with
   `New-RustDeskDeploymentConfig.ps1` or edit a copy of its example. Follow
   [Windows deployment](docs/windows-deployment.md).

Never put a service-account password or a private key in company settings.
Actual configuration, vault records, account databases, installers, credentials
and runtime logs are excluded from Git.

## Automatic Windows client updates

An optional updater on the DC can keep the existing Windows GPO deployment
current without manually downloading each new MSI or editing company settings.
It runs as SYSTEM daily at **04:00 DC local time**, selects official stable
Windows x64 releases and verifies their size, SHA-256 and approved publisher
signature before staging them. PCs upgrade at their next normal startup on the
company network. Company server/key/vault settings and older installers are kept.

Run the one-time setup from an extracted folder containing the four updater
files listed in the [automatic update guide](docs/windows-deployment.md#6-automatic-stable-rustdesk-msi-updates):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Register-RustDeskAutoUpdate.ps1
```

Use elevated Windows PowerShell 5.1 on the DC hosting NETLOGON. The guide covers
custom schedules, logs, first-run verification, checks that refuse unverified
updates, and disabling the task. No account password or GitHub token is stored.

**Availability:** updater scripts are included in the `v2.0.4` release packages
under `deployment/gpo/`. Follow the one-time setup guide when adding them to an
existing deployment.

## Console capabilities

- RustDesk heartbeat presence, names and OS hints, optional domain session reports.
- Dark/light themes, search, online/offline/reporting filters, sort, column
  visibility, CSV export, refresh controls and RustDesk launcher links.
- Admin/Operator/Viewer accounts; account disabling, password changes and resets.
- Optional on-demand vault reveal with HTTPS, role checks, CSRF, rate limiting,
  no-store responses, NTFS machine-owner verification and auditing.
- Collector/vault health, report age/clock-skew diagnostics and bounded TLS handshakes.

| Role | Monitor/export | Connect launcher | Reveal vault passwords | Audit | Manage users |
|---|---|---|---|---|---|
| Admin | Yes | Yes | Yes | Yes | Yes |
| Operator | Yes | Yes | Yes | No | No |
| Viewer | Yes | No | No | No | No |

Console accounts are local application accounts; AD single sign-on is not
implemented. A Connect link launches the client's own RustDesk application and
does not grant a RustDesk session or embed a password.

## Documentation

- [Console installation](docs/console-installation.md)
- [Windows deployment](docs/windows-deployment.md)
- [Automatic Windows updates](docs/windows-deployment.md#6-automatic-stable-rustdesk-msi-updates)
- [Configuration](docs/configuration.md)
- [Security](docs/security.md)
- [Security review and test results](docs/security-review-2026-10-15.md)
- [Migration from the separate repositories](docs/migration.md)
- [Release notes](CHANGELOG.md)

## Verification

```bash
RDMON_CONFIG=config/examples/console.ini.example python3 -m unittest discover -s console/tests -v
```

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deployment\gpo\Test-DeploymentSettings.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File deployment\gpo\Test-RustDeskReporting.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File deployment\gpo\Test-RustDeskAutoUpdate.ps1
```

Browser regression checks use an optional Playwright install:
`node console/tests/test_dashboard.cjs` and `node console/tests/test_users.cjs`.
`RDMON_TEST_BROWSER` can select an installed Chromium-compatible browser.

Both original repositories' commit histories are included. Earlier layouts are
historical component snapshots; use this repository for generic installations.
