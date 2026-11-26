#!/usr/bin/env python3
"""Install the console on Ubuntu/Debian using a company's private INI file."""
import argparse
import getpass
import ipaddress
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
from urllib.parse import urlparse

SOURCE = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE / "app"))


def run(*command):
    subprocess.run(command, check=True)


def write(path, text, mode=0o644, uid=0, gid=0):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Refusing to overwrite a symbolic link: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    # Restrict permissions before writing anything sensitive.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, mode)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Refusing a non-regular runtime file: " + str(path))
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
        os.ftruncate(fd, 0)
        with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as stream:
            stream.write(text)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="private company console.ini")
    parser.add_argument("--check", action="store_true", help="validate without changing the system")
    parser.add_argument("--self-signed", action="store_true", help="create a certificate if none exists")
    parser.add_argument("--hostname", help="DNS name or IP for the certificate")
    args = parser.parse_args()
    # Validate the explicitly supplied file, even when an existing service INI
    # is correctly unreadable to the user running a non-root --check.
    os.environ["RDMON_CONFIG"] = args.config
    from config import DEFAULTS, load_config
    settings = load_config(args.config, required=True)
    # The managed units use standard runtime paths. Advanced custom paths can
    # be installed manually with corresponding systemd sandbox changes.
    for key in ("state_file", "static_dir", "cert_file", "key_file", "users_db", "audit_log"):
        if settings["console"][key] != DEFAULTS["console"][key]:
            raise ValueError("Managed installer requires the standard console." + key + " path.")
    for key in ("mount_dir", "credentials_file", "collector_cache_dir", "web_cache_dir"):
        if settings["vault"][key] != DEFAULTS["vault"][key]:
            raise ValueError("Managed installer requires the standard vault." + key + " path.")
    if args.check:
        print("Configuration valid. Vault integration:", "enabled" if settings.getboolean("vault", "enabled") else "disabled")
        return
    if os.geteuid() != 0:
        raise ValueError("Run the installer as root, or use --check.")
    dependencies = ["tcpdump", "systemctl", "useradd", "openssl"]
    if settings.getboolean("vault", "enabled"):
        dependencies += ["smbcacls", "mount.cifs", "systemd-escape", "findmnt"]
    missing = [command for command in dependencies if not shutil.which(command)]
    if missing:
        raise ValueError("Install the documented prerequisites first: " + ", ".join(missing))
    if not Path(settings["collector"]["database"]).is_file():
        raise ValueError("Collector database does not exist; configure your hbbs database path.")
    try:
        service = pwd.getpwnam("rdmon")
    except KeyError:
        run("useradd", "--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", "rdmon")
        service = pwd.getpwnam("rdmon")
    for directory, mode, uid, gid in (("/opt/rdmon", 0o755, 0, 0), ("/opt/rdmon/static", 0o755, 0, 0),
                                     ("/etc/rdmon", 0o750, 0, service.pw_gid),
                                     ("/etc/rdmon/tls", 0o750, 0, service.pw_gid),
                                     ("/var/lib/rdmon", 0o700, service.pw_uid, service.pw_gid),
                                     ("/var/log/rdmon", 0o750, service.pw_uid, service.pw_gid),
                                     ("/var/cache/rdmon", 0o750, service.pw_uid, service.pw_gid)):
        path = Path(directory)
        if path.is_symlink():
            raise ValueError("Refusing a symbolic-link runtime directory.")
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, mode)
        os.chown(path, uid, gid)
    for file in (SOURCE / "app").glob("*.py"):
        write(Path("/opt/rdmon") / file.name, file.read_text())
    if (SOURCE.parent / "VERSION").is_file():
        write("/opt/rdmon/VERSION", (SOURCE.parent / "VERSION").read_text())
    for file in (SOURCE / "app" / "static").iterdir():
        if not file.is_file():
            continue
        target = Path("/opt/rdmon/static") / file.name
        shutil.copyfile(file, target)
        os.chmod(target, 0o644)
        os.chown(target, 0, 0)
    write("/usr/local/sbin/rdmon-passwd", (SOURCE / "bin" / "rdmon-passwd").read_text(), 0o755)
    write("/etc/rdmon/console.ini", Path(args.config).read_text(encoding="utf-8-sig"), 0o640, gid=service.pw_gid)
    cert, key = Path(settings["console"]["cert_file"]), Path(settings["console"]["key_file"])
    if not cert.is_file() or not key.is_file():
        if cert.exists() or key.exists():
            raise ValueError("Only one TLS file exists; install its matching certificate/key without replacing it.")
        if not args.self_signed:
            raise ValueError("Install TLS certificate/key first, or use --self-signed --hostname.")
        host = args.hostname or urlparse(settings["console"]["public_url"]).hostname
        if not host or not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
            raise ValueError("A valid TLS hostname or IP is required.")
        try:
            ipaddress.ip_address(host)
            san = "IP:" + host
        except ValueError:
            san = "DNS:" + host
        run("openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "365",
            "-keyout", str(key), "-out", str(cert), "-subj", "/CN=" + host, "-addext", "subjectAltName=" + san)
    os.chmod(key, 0o640)
    os.chown(key, 0, service.pw_gid)
    units = Path("/etc/systemd/system")
    for filename in ("rdmon-web.service", "rdmon-collector.service"):
        write(units / filename, (SOURCE / "deploy" / "systemd" / filename).read_text())
    dropins = units / "rdmon-web.service.d"
    write(dropins / "auth.conf", (SOURCE / "deploy" / "systemd" / "rdmon-web.service.d" / "auth.conf").read_text())
    capability = "CAP_NET_BIND_SERVICE" if min(settings.getint("console", "http_port"), settings.getint("console", "https_port")) < 1024 else ""
    write(dropins / "ports.conf", "[Service]\nAmbientCapabilities=" + capability + "\nCapabilityBoundingSet=" + capability + "\n")
    # This replaces only our managed vault drop-in. The collector continues
    # writing monitoring state independently of optional vault integration.
    extra = "[Unit]\nRequiresMountsFor=\n"
    if settings.getboolean("vault", "enabled"):
        credentials = Path(settings["vault"]["credentials_file"])
        if credentials.parent.is_symlink():
            raise ValueError("Credentials directory must not be a symbolic link.")
        credentials.parent.mkdir(parents=True, exist_ok=True)
        # root:rdmon directory traversal; credential file is 0640, never world-readable.
        os.chmod(credentials.parent, 0o750)  # nosec B103
        os.chown(credentials.parent, 0, service.pw_gid)
        if not credentials.exists():
            username = input("Read-only SMB service-account username: ").strip()
            password = getpass.getpass("SMB service-account password: ")
            if not username or not password or any(c in username + password for c in "\r\n"):
                raise ValueError("SMB credentials must be non-empty single-line values.")
            write(credentials, f"username={username}\npassword={password}\ndomain={settings['vault']['owner_domain']}\n", 0o640, gid=service.pw_gid)
            password = None
        if credentials.is_symlink():
            raise ValueError("Credentials file must not be a symbolic link.")
        os.chmod(credentials, 0o640)
        os.chown(credentials, 0, service.pw_gid)
        mount = settings["vault"]["mount_dir"]
        Path(mount).mkdir(parents=True, exist_ok=True)
        mount_unit = subprocess.check_output(["systemd-escape", "--path", "--suffix=mount", mount], text=True).strip()
        options = f"ro,vers=3.1.1,seal,sec=ntlmssp,credentials={credentials},uid={service.pw_uid},gid={service.pw_gid},file_mode=0400,dir_mode=0500,_netdev,noserverino"
        write(units / mount_unit, f"[Unit]\nDescription=RustDesk encrypted read-only vault\nWants=network-online.target\nAfter=network-online.target\n[Mount]\nWhat={settings['vault']['share']}\nWhere={mount}\nType=cifs\nOptions={options}\n[Install]\nWantedBy=remote-fs.target\n")
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "--now", mount_unit)
        actual = subprocess.check_output(["findmnt", "--noheadings", "--output", "SOURCE,FSTYPE,OPTIONS", "--target", mount], text=True).strip().split(None, 2)
        if len(actual) != 3 or actual[0].casefold() != settings["vault"]["share"].casefold() or actual[1] != "cifs" or not {"ro", "seal"}.issubset(set(actual[2].split(","))):
            raise ValueError("Existing vault mount does not match the configured encrypted, read-only CIFS share.")
        extra += "RequiresMountsFor=" + mount + "\n"
    extra += "[Service]\nLogsDirectory=rdmon\nLogsDirectoryMode=0750\nCacheDirectory=rdmon\nCacheDirectoryMode=0750\nEnvironment=HOME=/var/cache/rdmon\nEnvironment=RDMON_CONFIG=/etc/rdmon/console.ini\n"
    write(dropins / "vault.conf", extra)
    if not Path(settings["console"]["users_db"]).exists() and not Path("/etc/rdmon/auth.env").exists():
        run("/usr/local/sbin/rdmon-passwd", "--user", "admin", "--no-restart")
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "rdmon-web", "rdmon-collector")
    run("systemctl", "restart", "rdmon-collector", "rdmon-web")
    print("Installed. Configure your firewall to allow HTTPS from your administration networks.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        sys.exit("Installation stopped: " + str(error))
