"""Company settings, loaded from a private INI file outside the repository."""
import configparser
import os
import re
from pathlib import Path
from urllib.parse import urlparse

CONFIG_PATH = "/etc/rdmon/console.ini"
DEFAULTS = {
    "console": {
        "bind_host": "127.0.0.1", "http_port": "8080", "https_port": "8443",
        "state_file": "/opt/rdmon/state.json", "static_dir": "/opt/rdmon/static",
        "cert_file": "/etc/rdmon/tls/cert.pem", "key_file": "/etc/rdmon/tls/key.pem",
        "users_db": "/var/lib/rdmon/users.sqlite3", "audit_log": "/var/log/rdmon/reveal-audit.log",
        "online_window": "60", "public_url": "",
    },
    "collector": {
        "database": "/opt/rustdesk/db_v2.sqlite3", "interface": "any",
        "heartbeat_port": "21116", "aliases_file": "/etc/rdmon/aliases.conf",
    },
    "vault": {
        "enabled": "false", "mount_dir": "/mnt/rustdesk-vault", "share": "",
        "credentials_file": "/etc/rdconsole/vault.cred", "owner_domain": "",
        "owner_timeout": "8", "collector_cache_dir": "/var/cache/rdmon-collector",
        "web_cache_dir": "/var/cache/rdmon",
    },
}


def load_config(path=None, *, required=False):
    filename = path or os.environ.get("RDMON_CONFIG", CONFIG_PATH)
    settings = configparser.ConfigParser(interpolation=None)
    settings.read_dict(DEFAULTS)
    if Path(filename).is_file():
        supplied = configparser.ConfigParser(interpolation=None)
        with open(filename, encoding="utf-8-sig") as stream:
            supplied.read_file(stream)
        if supplied.defaults():
            raise ValueError("Use named configuration sections; DEFAULT is not supported.")
        for section in supplied.sections():
            if section not in DEFAULTS:
                raise ValueError(f"Unknown configuration section: {section}")
            for key in supplied[section]:
                if key not in DEFAULTS[section]:
                    raise ValueError(f"Unknown configuration setting: {section}.{key}")
                if any(ord(c) < 32 for c in supplied[section][key]):
                    raise ValueError(f"Configuration setting contains control characters: {section}.{key}")
                settings[section][key] = supplied[section][key].strip()
    elif required or path or os.environ.get("RDMON_CONFIG"):
        raise ValueError("Console configuration file is missing.")
    for section, key in (("console", "http_port"), ("console", "https_port"), ("collector", "heartbeat_port")):
        if not 1 <= settings.getint(section, key) <= 65535:
            raise ValueError(f"Invalid port: {section}.{key}")
    if settings.getint("console", "http_port") == settings.getint("console", "https_port"):
        raise ValueError("HTTP and HTTPS ports must differ.")
    if not 30 <= settings.getint("console", "online_window") <= 3600:
        raise ValueError("Online window must be 30 to 3600 seconds.")
    if not 1 <= settings.getint("vault", "owner_timeout") <= 60:
        raise ValueError("Owner timeout must be 1 to 60 seconds.")
    for section, key in (("console", "state_file"), ("console", "static_dir"), ("console", "cert_file"),
                         ("console", "key_file"), ("console", "users_db"), ("console", "audit_log"),
                         ("collector", "database"), ("collector", "aliases_file"), ("vault", "mount_dir"),
                         ("vault", "credentials_file"), ("vault", "collector_cache_dir"), ("vault", "web_cache_dir")):
        if not settings[section][key].startswith("/") or settings[section][key] == "/":
            raise ValueError(f"Expected an absolute Linux file path: {section}.{key}")
    public_url = settings["console"]["public_url"]
    if public_url:
        parsed = urlparse(public_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ValueError("Public URL must be an HTTPS origin without credentials or a path.")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("Public URL port must be 1 to 65535.")
    if settings.getboolean("vault", "enabled"):
        if not re.fullmatch(r"//[A-Za-z0-9._-]+/[A-Za-z0-9._$-]+", settings["vault"]["share"]):
            raise ValueError("Enabled vault requires a share such as //dc.corp.example.com/RustDeskVault$.")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", settings["vault"]["owner_domain"]):
            raise ValueError("Enabled vault requires its actual AD NetBIOS owner domain.")
        if "," in settings["vault"]["credentials_file"]:
            raise ValueError("Credentials path cannot contain commas.")
    return settings


SETTINGS = load_config()
