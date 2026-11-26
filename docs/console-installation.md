# Console installation

## Download a fixed release

This repository is public; no GitHub account is needed. On a new
Ubuntu/Debian server:

```bash
sudo apt update
sudo apt install git python3 tcpdump openssl
git clone --branch v2.0.4 https://github.com/brhoom98x/rustdesk-management.git
cd rustdesk-management
```

Alternatively, download the Linux release package into an empty directory:

```bash
base=https://github.com/brhoom98x/rustdesk-management/releases/download/v2.0.4
curl -fLO "$base/rustdesk-management-2.0.4.tar.gz"
curl -fLO "$base/SHA256SUMS"
sha256sum --check SHA256SUMS --ignore-missing
tar -xzf rustdesk-management-2.0.4.tar.gz
cd rustdesk-management-2.0.4
```

The package contains the console, installer, GPO scripts, examples and docs;
it contains no Git history or private company runtime files. It is a Python
source distribution, not an OS package, and does not install hbbs/hbbr.

## Prerequisites

- Ubuntu/Debian Linux with Python 3.10+, systemd, tcpdump and OpenSSL.
- An existing RustDesk OSS hbbs database and client heartbeat traffic visible
  to this server. Configure database path, interface and heartbeat port. The
  official `rustdesk-server` `.deb` packages keep the database at
  `/var/lib/rustdesk-server/db_v2.sqlite3`, not the example's `/opt/rustdesk`
  path. [Step-by-step](step-by-step.md#2-install-the-rustdesk-oss-server-hbbs-and-hbbr)
  covers installing them.
- Optional vault: `cifs-utils` and `smbclient`, network connectivity to the AD
  vault server (by DNS name, or by IP address in `share`), and a dedicated
  reader with read-only NTFS rights including ACL reads.

```bash
sudo apt install python3 tcpdump openssl
# Only for the optional encrypted SMB vault:
sudo apt install cifs-utils smbclient
```

For a fresh installation, copy the console INI example to your home directory,
replace the documentation domain with your own, and validate before installing:

```bash
install -m 600 config/examples/console.ini.example "$HOME/rustdesk-console.ini"
nano "$HOME/rustdesk-console.ini"
python3 console/install.py --config "$HOME/rustdesk-console.ini" --check
sudo python3 console/install.py --config "$HOME/rustdesk-console.ini" \
  --self-signed --hostname rustdesk.corp.example.com
```

Replace the certificate hostname with your actual server DNS name or IP; an IP
address becomes an `IP:` subject alternative name. Run the installer from the
repository folder. To change the name later, move the existing `cert.pem` and
`key.pem` out of the TLS directory first: the installer never replaces an
existing pair, and it keeps existing accounts when run again.

For an existing company certificate, place `cert.pem` and matching `key.pem` in
the configured TLS directory and omit `--self-signed`. The key is root-owned,
group-readable by the `rdmon` service, mode 640. Both TLS files must exist as a
pair; the installer will not replace a partially installed pair.

The first installation prompts privately for an Admin password (12+ characters).
Existing account databases and legacy login credentials are preserved. Runtime
units/copies retain `rdmon` names for upgrade compatibility.
Ports below 1024 (for example HTTPS 443) receive only `CAP_NET_BIND_SERVICE`;
the web service still runs as the unprivileged service account.

Open your configured HTTPS port from your administration networks. The installer
does not automatically open firewall ports to the whole network. For a UFW-based
server, adapt your actual management subnet and HTTPS port, for example:

```bash
sudo ufw allow from 192.0.2.0/24 to any port 8443 proto tcp
```

Only HTTPS should be used for login. The HTTP port redirects to the configured
public HTTPS origin. For a self-signed certificate, arrange trust on management
clients; company-issued certificates avoid per-client trust work.

## Optional vault

Prepare the AD share first using the Windows instructions. Set `vault.enabled=true`,
the exact share UNC in `//server/share` form and the actual AD NetBIOS owner domain.
The installer prompts privately for the SMB reader password when its credential
file does not exist. That file is root:rdmon 640 inside a 750 directory, so only
root and the web service can read it; the share account itself is read-only.
Enter the username without the domain; the installer adds `owner_domain`.

Test the share by hand before enabling it, so a wrong password or domain shows
up before the mount unit is created:

```bash
smbclient '//dc.corp.example.com/RustDeskVault$' -U 'EXAMPLE\svc-rdconsole' \
  -m SMB3 --client-protection=encrypt -c 'ls'
```

The installer creates a CIFS mount unit using `ro,vers=3.1.1,seal,sec=ntlmssp`,
the dynamically discovered service uid/gid, `file_mode=0400` and `dir_mode=0500`.
Encryption is also required by the DC share. No password enters mount options.

```bash
findmnt /mnt/rustdesk-vault
sudo systemctl status rdmon-web rdmon-collector
sudo journalctl -u rdmon-web -u rdmon-collector --since '10 minutes ago'
```

Verify the mount is read-only and encrypted before enabling reveal. If an existing
fstab entry already mounts that path, reconcile its source/options with the INI
before using a generated mount unit. Never mount a different company's vault at
the configured path.

## Users and troubleshooting

Admin: full console permissions. Operator: monitor/connect/reveal. Viewer:
monitor/export only. Open **Users** for account management or **Account** for
personal password changes. Disabling an account or changing its password/role
invalidates its sessions; the last active Admin cannot be disabled or demoted.

```bash
sudo rdmon-passwd --user admin --role admin  # hidden password prompt/recovery
```

Health details distinguish optional disabled reporting from actual mount/scan
failures. Missing/stale/invalid/owner-rejected reports remain distinguishable;
clock skew is shown separately. Passwords never appear in polling or CSV.

## Later upgrades

Releases pin installation to a known version; the console does not auto-update
running services when GitHub changes. For a Git checkout, fetch tags and select
the desired release with `git fetch origin --tags` and `git checkout <release-tag>`.
Read that release's migration notes, back up the existing installation, validate
your existing private INI and run the installer again. Do not replace working
company configuration with the example. See [migration](migration.md).
