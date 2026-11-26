# Step-by-step: from a blank server to managed Windows PCs

This guide walks through a complete installation in order: the Linux server,
the RustDesk OSS server, the console, and the Windows Active Directory rollout
with the encrypted password vault. The other documents explain each part in
depth; this one gives the exact commands in the order they are run.

Every value below is an example. Replace them with your own:

| Example value | Meaning |
|---|---|
| `192.0.2.20` | The new Linux server (RustDesk server and console) |
| `192.0.2.10` | The domain controller that hosts NETLOGON and the vault |
| `corp.example.com` | AD DNS domain |
| `EXAMPLE` | AD **NetBIOS** domain name (often not the first label of the DNS name) |
| `OU=Workstations,OU=Corp,DC=corp,DC=example,DC=com` | OU that holds the PCs to manage |
| `OU=Service Accounts,OU=Corp,DC=corp,DC=example,DC=com` | OU for the vault reader account |

The guide uses IP addresses for the server and the vault share, so no DNS
record is needed. DNS names work too; use them consistently in every step.

```text
Windows PCs ──21115-21117/tcp, 21116/udp──▶ hbbs/hbbr ┐
     │                                                 ├─ Linux server 192.0.2.20
     │ startup GPO: install + configure + vault record  │   console https://192.0.2.20:8443
     ▼                                                 │
Domain controller: NETLOGON\RustDesk  +  RustDeskVault$ ◀─ read-only, encrypted SMB
```

## 1. Prepare the Linux server

Create a VM or physical host running a current Ubuntu Server LTS (Debian also
works). 2 vCPU, 2 GB RAM and 32 GB disk are plenty for a few hundred PCs.

- Give it a **static IP** in a network the PCs can reach.
- On VMware Workstation, use a **Bridged** network adapter; NAT and host-only
  networks are not reachable from other PCs.
- Install the OpenSSH server during setup.

After the first boot:

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y open-vm-tools      # VMware; use qemu-guest-agent on Proxmox/KVM
sudo reboot
```

## 2. Install the RustDesk OSS server (hbbs and hbbr)

This repository does not include the RustDesk server. Install the official
packages from [rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server/releases):

| Program | Role | Ports |
|---|---|---|
| hbbs | ID/rendezvous server: clients register, send heartbeats and find each other | 21115/tcp, 21116/tcp+udp, 21118/tcp |
| hbbr | Relay for sessions that cannot connect directly | 21117/tcp, 21119/tcp |

```bash
V=1.1.16   # the latest release version
mkdir -p ~/rustdesk-pkgs && cd ~/rustdesk-pkgs
curl -fLO https://github.com/rustdesk/rustdesk-server/releases/download/$V/rustdesk-server-hbbs_${V}_amd64.deb
curl -fLO https://github.com/rustdesk/rustdesk-server/releases/download/$V/rustdesk-server-hbbr_${V}_amd64.deb
sudo apt install -y ./rustdesk-server-hbbs_${V}_amd64.deb ./rustdesk-server-hbbr_${V}_amd64.deb

systemctl status rustdesk-hbbs rustdesk-hbbr --no-pager
sudo ss -tulpn | grep -E '2111[5-9]'
```

The packages keep their data in `/var/lib/rustdesk-server/`: the peer database
`db_v2.sqlite3` and the server key pair. The private key is created
world-readable, so restrict it and take a backup:

```bash
sudo chmod 600 /var/lib/rustdesk-server/id_ed25519
sudo cat /var/lib/rustdesk-server/id_ed25519.pub      # the PUBLIC key, needed in step 5
sudo tar -czf ~/rustdesk-keys-backup.tar.gz -C /var/lib/rustdesk-server id_ed25519 id_ed25519.pub
```

Copy the backup off the server and delete the local copy. If the private key is
lost, every client must be reconfigured with a new public key.

## 3. Install the console (monitoring only)

```bash
sudo apt install -y git python3 tcpdump openssl
cd ~ && git clone --branch v2.0.4 https://github.com/brhoom98x/rustdesk-management.git
cd ~/rustdesk-management

install -m 600 config/examples/console.ini.example ~/rustdesk-console.ini
sed -i \
  -e 's|^public_url = .*|public_url = https://192.0.2.20:8443|' \
  -e 's|^database = .*|database = /var/lib/rustdesk-server/db_v2.sqlite3|' \
  ~/rustdesk-console.ini
```

The example `database` path is `/opt/rustdesk/db_v2.sqlite3`; the official
packages use `/var/lib/rustdesk-server/`. Keep `enabled = false` in `[vault]`
for now.

Run the installer from the repository folder. `--hostname` accepts a DNS name
or an IP address; the certificate gets a matching `DNS:` or `IP:` name.

```bash
cd ~/rustdesk-management
python3 console/install.py --config ~/rustdesk-console.ini --check
sudo python3 console/install.py --config ~/rustdesk-console.ini \
  --self-signed --hostname 192.0.2.20
sudo systemctl status rdmon-web rdmon-collector --no-pager
```

The first installation asks for the console `admin` password (12+ characters).
Open `https://192.0.2.20:8443` and accept the self-signed certificate. No PCs
appear until a client uses this server.

To change the certificate name later, move the existing pair aside and run the
installer again. It never replaces an existing certificate, and it keeps the
existing accounts:

```bash
sudo mkdir -p /root/rdmon-old-tls
sudo mv /etc/rdmon/tls/cert.pem /etc/rdmon/tls/key.pem /root/rdmon-old-tls/
sudo python3 console/install.py --config ~/rustdesk-console.ini --self-signed --hostname <new name or IP>
```

## 4. Open the network path from the PCs

Every network the managed PCs are on must reach the server on **21115-21117/tcp
and 21116/udp**. Add a rule to any router or firewall between them. The console
port (8443/tcp by default) only needs to be reachable from administrator networks.

If `ufw` is enabled on the server:

```bash
sudo ufw allow 21115:21117/tcp
sudo ufw allow 21116/udp
sudo ufw allow from <admin subnet> to any port 8443 proto tcp
```

## 5. Prepare the deployment on the domain controller

Use **elevated Windows PowerShell 5.1** on the DC that hosts NETLOGON.

Download the release package and verify it:

```powershell
$work = 'C:\RustDeskSetup'; New-Item -ItemType Directory -Force $work | Out-Null; Set-Location $work
$rel = 'https://github.com/brhoom98x/rustdesk-management/releases/download/v2.0.4'
Invoke-WebRequest "$rel/rustdesk-management-2.0.4.zip" -OutFile rdm.zip -UseBasicParsing
Invoke-WebRequest "$rel/SHA256SUMS" -OutFile SHA256SUMS -UseBasicParsing
(Get-FileHash rdm.zip -Algorithm SHA256).Hash.ToLower()
Select-String 'zip' SHA256SUMS          # must show the same hash
Expand-Archive rdm.zip -DestinationPath . -Force
```

Download the RustDesk client MSI and compare it with the digest GitHub publishes
for the official release:

```powershell
$ver = '1.5.3'   # the RustDesk client version to deploy
$msi = "rustdesk-$ver-x86_64.msi"
Invoke-WebRequest "https://github.com/rustdesk/rustdesk/releases/download/$ver/$msi" -OutFile $msi -UseBasicParsing
$hash = (Get-FileHash $msi -Algorithm SHA256).Hash.ToLower()
$published = ((Invoke-RestMethod "https://api.github.com/repos/rustdesk/rustdesk/releases/tags/$ver").assets |
    Where-Object name -eq $msi).digest
"$hash`n$published"                     # second line is sha256:<same hash>
```

Find the domain names, then create and check the company settings. The
generator does not write `MsiSha256`, so add it afterwards:

```powershell
Get-ADDomain | Select-Object DNSRoot, NetBIOSName
Set-Location "$work\rustdesk-management-2.0.4\deployment\gpo"
.\New-RustDeskDeploymentConfig.ps1 -Domain 'corp.example.com' -OwnerDomain 'EXAMPLE' `
  -IdServer '192.0.2.20' -RelayServer '192.0.2.20' `
  -PublicKey '<contents of id_ed25519.pub>' -WantVersion $ver
(Get-Content .\settings.psd1) -replace '^    PasswordLength = 16', "    PasswordLength = 16`r`n    MsiSha256 = '$hash'" |
    Set-Content .\settings.psd1 -Encoding UTF8
Get-Content .\settings.psd1

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Deploy-RustDesk.ps1 -CheckConfig
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Set-RustDeskUserConfig.ps1 -CheckConfig
```

## 6. Create the vault reader, stage the files, create the vault

The console reads the vault as a dedicated account without admin rights. Type
its password at the prompt and keep it in your password manager; it is entered
once more on the Linux server in step 9.

```powershell
$pw = Read-Host 'Password for svc-rdconsole' -AsSecureString
New-ADUser -Name 'svc-rdconsole' -SamAccountName 'svc-rdconsole' `
  -Path 'OU=Service Accounts,OU=Corp,DC=corp,DC=example,DC=com' `
  -Description 'RustDesk console - read-only vault reader' `
  -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true
Remove-Variable pw
```

Stage every `.ps1` file, `settings.psd1` and the MSI together. The vault script
in the next command writes `vault-path.txt` into this folder, so stage first:

```powershell
$stage = 'C:\Windows\SYSVOL\sysvol\corp.example.com\scripts\RustDesk'   # = \\corp.example.com\NETLOGON\RustDesk
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item .\*.ps1, .\settings.psd1 -Destination $stage -Force
Copy-Item "$work\$msi" -Destination $stage -Force
(Get-FileHash "$stage\$msi" -Algorithm SHA256).Hash.ToLower()          # must equal $hash

powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Initialize-RustDeskVault.ps1
Get-SmbShare -Name 'RustDeskVault$' | Select-Object Name, Path, EncryptData   # EncryptData must be True
Get-Content "$stage\vault-path.txt"
```

Add `C:\RustDeskVault` to the DC backup. It is the only copy of the per-PC
unattended passwords.

## 7. Create and link the GPO

Link the GPO to the OU that contains the **computer** accounts, not to a parent
OU that also contains servers.

```powershell
$name = 'RustDesk Deployment'
New-GPO -Name $name -Comment 'Installs RustDesk and points it at the company server' | Out-Null
# Always wait for the network at computer startup and logon
Set-GPRegistryValue -Name $name -Key 'HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon' `
  -ValueName 'SyncForegroundPolicy' -Type DWord -Value 1
# Loopback processing, Merge mode: apply this GPO's user settings to everyone who signs in on these PCs
Set-GPRegistryValue -Name $name -Key 'HKLM\Software\Policies\Microsoft\Windows\System' `
  -ValueName 'UserPolicyMode' -Type DWord -Value 1
New-GPLink -Name $name -Target 'OU=Workstations,OU=Corp,DC=corp,DC=example,DC=com' -LinkEnabled Yes
```

Why both settings matter:

- **Loopback (Merge).** User accounts normally live in a different OU from the
  computers. Without loopback, the user logon script in a GPO linked to the
  computer OU never runs.
- **Wait for the network.** By default Windows starts before the network is
  ready and skips startup scripts. With this setting, startup scripts run on
  every boot. A PC that has not yet received the setting may need **two
  reboots** the first time.

PowerShell cannot add GPO scripts cleanly, so add them in GPMC. Edit the GPO and
use the **Scripts** tab (not the PowerShell Scripts tab):

| Location | Script Name | Script Parameters |
|---|---|---|
| Computer Configuration → Policies → Windows Settings → Scripts → **Startup** | `powershell.exe` | `-NoProfile -ExecutionPolicy Bypass -File "\\corp.example.com\NETLOGON\RustDesk\Deploy-RustDesk.ps1"` |
| User Configuration → Policies → Windows Settings → Scripts → **Logon** | `powershell.exe` | `-NoProfile -ExecutionPolicy Bypass -File "\\corp.example.com\NETLOGON\RustDesk\Set-RustDeskUserConfig.ps1"` |

## 8. Pilot one PC

Put one computer account in the linked OU and **restart** it. Use Restart, not
Shut down: with Fast Startup a shutdown is not a full boot, and startup scripts
do not run. The PC must be on the network while it boots.

To check that the policy arrived without waiting, on the PC:

```powershell
gpupdate /force
gpresult /r /scope computer | Select-String 'RustDesk'
```

After the restart and sign-in:

```powershell
# On the PC
Get-ChildItem "$env:ProgramData\RustDeskDeploy"
Get-Content (Get-ChildItem "$env:ProgramData\RustDeskDeploy\*.log" | Sort-Object LastWriteTime | Select-Object -Last 1).FullName -Tail 25

# On the DC, from deployment\gpo: the PC must be listed (do not share the password)
.\Get-RustDeskPassword.ps1 -All | Format-Table -AutoSize
```

The console now shows the PC as **online** with its RustDesk ID and address.
Machine name, logged-on user and password stay empty until step 9.

## 9. Connect the console to the vault

On the Linux server, test the share by hand before enabling it:

```bash
sudo apt install -y cifs-utils smbclient
smbclient '//192.0.2.10/RustDeskVault$' -U 'EXAMPLE\svc-rdconsole' -m SMB3 --client-protection=encrypt -c 'ls'
```

The pilot PC's `<COMPUTERNAME>.json` must be listed. Then enable the vault and run
the installer again from the repository folder:

```bash
cd ~/rustdesk-management
sed -i \
  -e 's|^enabled = .*|enabled = true|' \
  -e 's|^share = .*|share = //192.0.2.10/RustDeskVault$|' \
  -e 's|^owner_domain = .*|owner_domain = EXAMPLE|' \
  ~/rustdesk-console.ini
python3 console/install.py --config ~/rustdesk-console.ini --check
sudo python3 console/install.py --config ~/rustdesk-console.ini
findmnt /mnt/rustdesk-vault        # options must include ro and seal
```

At the prompts, enter the username **without** the domain (`svc-rdconsole`) and
its password. `--self-signed` is not needed again. Reload the console: the PC now
shows its machine name, logged-on user and reporting state, and an Admin can
reveal its password (recorded under **Audit**).

## 10. Roll out and maintain

- **More PCs:** move their computer accounts into the linked OU. Each one
  installs at its next normal restart.
- **Client updates:** set up the [automatic stable MSI updater](windows-deployment.md#6-automatic-stable-rustdesk-msi-updates)
  on the DC, or stage a new MSI and update `WantVersion`, `MsiPath` and `MsiSha256` yourself.
- **Server updates:** install newer `rustdesk-server` `.deb` packages the same way
  as in step 2; the database and keys in `/var/lib/rustdesk-server/` are kept.
- **Moving the server:** install hbbs/hbbr on the new host and restore
  `id_ed25519` and `id_ed25519.pub`. If the new host keeps the same address,
  the PCs need no change.
- **Backups:** the server key pair, `C:\RustDeskVault` on the DC, and
  `/var/lib/rdmon/users.sqlite3` (console accounts).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `can't open file '.../console/install.py'` | Run the installer from the repository folder: `cd ~/rustdesk-management` |
| `Collector database does not exist` | `database` in the INI does not point at hbbs's `db_v2.sqlite3` |
| PC got no RustDesk after one restart | Normal the first time; restart once more. Check `gpresult /r /scope computer` lists the GPO |
| User settings never applied | Loopback processing (step 7) is missing, or the GPO is linked to the user OU instead of the computer OU |
| PC installed but never appears in the console | The PC's network cannot reach 21115-21117/tcp and 21116/udp on the server (step 4) |
| Console shows `unknown` machine and `vault disabled` | The console vault is not enabled yet (step 9) |
| `smbclient` returns `NT_STATUS_LOGON_FAILURE` | Wrong reader password, or the NetBIOS domain is wrong: check `Get-ADDomain` |
| Browser warns about the certificate | Expected with `--self-signed`; trust it on admin PCs or install a company certificate |
