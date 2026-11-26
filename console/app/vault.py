#!/usr/bin/env python3
"""
Unattended-access password lookup for RustDesk Console.

Passwords are NOT stored here. Each domain workstation writes its own record to
a read-only SMB share on the DC, and this module reads the matching file at
request time only - never on the polling path, never cached, never logged.

Trust rule: a record counts only if the file's NTFS owner is that machine's own
computer account. A compromised PC can create <OTHER-PC>.json on the share, but
it cannot forge the owner, so the owner check is what makes the record credible.

The owner must come from smbcacls, which resolves SIDs against the DC.
getcifsacl was tried first because it needs no credentials, but this mount has
no idmap and it returns an unmapped synthetic SID (S-1-0x484...), which cannot
be compared to anything.
"""
import json, os, re, stat, subprocess, time
from config import SETTINGS

ENABLED     = SETTINGS.getboolean("vault", "enabled")
VAULT_DIR   = SETTINGS["vault"]["mount_dir"]
SHARE       = SETTINGS["vault"]["share"]
CREDENTIALS = SETTINGS["vault"]["credentials_file"]
NETBIOS     = SETTINGS["vault"]["owner_domain"].upper()
SMB_HOME    = SETTINGS["vault"]["web_cache_dir"]
SMB_TIMEOUT = SETTINGS.getint("vault", "owner_timeout")

# Statuses the UI renders verbatim.
OK          = "ok"
NO_RECORD   = "no record"
BAD_OWNER   = "owner mismatch"
UNREACHABLE = "vault unreachable"
ID_MISMATCH = "ID mismatch"
DISABLED    = "vault disabled"

_OWNER_RE = re.compile(r"^OWNER:(.+)$", re.MULTILINE)
_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.(?:json|session)", re.I)
MAX_RECORD = 16384
MAX_FILES = 10000
LOOKUP_BUDGET = 15


def _signature(filename):
    info = os.stat(os.path.join(VAULT_DIR, filename), follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise OSError("Vault entry must be a regular file")
    return info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _read_json(filename, limit):
    if not _SAFE_NAME.fullmatch(filename):
        return None
    try:
        if os.path.islink(os.path.join(VAULT_DIR, filename)):
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(os.path.join(VAULT_DIR, filename), flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                return None
            data = stream.read(limit + 1)
            if len(data) > limit:
                return None
        return json.loads(data.decode("utf-8-sig"))
    except (OSError, ValueError, UnicodeError, RecursionError):
        return None


def _read_record(filename):
    """Parse one vault file. Returns a dict or None."""
    rec = _read_json(filename, MAX_RECORD)
    if not isinstance(rec, dict) or rec.get("rustdesk") is not True:
        return None
    host, rid, password = rec.get("host"), rec.get("id"), rec.get("password")
    if not isinstance(host, str) or host.casefold() != filename[:-5].casefold():
        return None
    if not isinstance(rid, str) or (rid and not re.fullmatch(r"[0-9]{1,16}", rid)):
        return None
    if not isinstance(password, str) or not 1 <= len(password) <= 1024:
        return None
    if not isinstance(rec.get("set_at", ""), str) or len(rec.get("set_at", "")) > 64:
        return None
    return rec


def _owner_of(filename, home=SMB_HOME):
    """NTFS owner, in DOMAIN-backslash-NAME form, or None if undeterminable.

    home: smbclient's cache directory. The root collector passes its own, so it
    never leaves root-owned cache files where the unprivileged web server
    needs to write.
    """
    if not _SAFE_NAME.fullmatch(filename):
        return None
    env = dict(os.environ, HOME=home)
    try:
        out = subprocess.run(
            ["smbcacls", SHARE, filename, "-A", CREDENTIALS, "-m", "SMB3", "--client-protection=encrypt"],
            capture_output=True, text=True, timeout=SMB_TIMEOUT, env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    m = _OWNER_RE.search(out.stdout)
    return m.group(1).strip() if m else None


def _list_files():
    try:
        if not os.path.ismount(VAULT_DIR):
            return None
        found = []
        with os.scandir(VAULT_DIR) as entries:
            for entry in entries:
                if _SAFE_NAME.fullmatch(entry.name) and entry.name.lower().endswith(".json"):
                    found.append(entry.name)
                    if len(found) > MAX_FILES:
                        return None
        return found
    except OSError:
        return None          # distinct from "empty": the share is not readable


def lookup(rustdesk_id, hostname=None):
    """
    Resolve one peer to its password.

    Returns {status, password, host, id, set_at, owner}. password is non-empty
    only when status == OK. Caller must not log or cache the password.
    """
    blank = {"status": NO_RECORD, "password": None, "host": None,
             "id": None, "set_at": None, "owner": None}
    if not ENABLED:
        return dict(blank, status=DISABLED)

    expires = time.monotonic() + LOOKUP_BUDGET
    files = _list_files()
    if files is None:
        return dict(blank, status=UNREACHABLE)

    rustdesk_id = str(rustdesk_id or "").strip()

    # Match on id first, as the console already knows it and it is what the
    # machine itself reported. Check the hostname-named file first so the common
    # case costs one read instead of a full directory scan.
    ordered = files
    if hostname:
        preferred = hostname.strip().upper() + ".JSON"
        ordered = sorted(files, key=lambda f: f.upper() != preferred)

    by_host, matches = None, []
    for filename in ordered:
        if time.monotonic() >= expires:
            return dict(blank, status=UNREACHABLE)
        try:
            signature = _signature(filename)
        except OSError:
            continue
        rec = _read_record(filename)
        if not rec:
            continue
        stem = filename[:-5]
        if str(rec.get("id", "")).strip() == rustdesk_id and rustdesk_id:
            matches.append(_finalise(filename, stem, rec, signature))
        if hostname and stem.upper() == hostname.strip().upper():
            by_host = (filename, stem, rec, signature)

    accepted = [record for record in matches if record["status"] == OK]
    if len(accepted) > 1:
        return dict(blank, status=ID_MISMATCH)
    if accepted:
        return accepted[0]
    if matches:
        return matches[0]

    # A file named for this machine exists but carries a different RustDesk ID -
    # worth saying so explicitly rather than a blank "no record".
    if by_host:
        checked = _finalise(*by_host)
        if checked["status"] != OK:
            return checked
        return dict(blank, status=ID_MISMATCH, host=by_host[2].get("host"),
                    id=by_host[2].get("id"))
    return blank


def _finalise(filename, stem, rec, signature):
    """Apply the owner check to a matched record."""
    owner = _owner_of(filename)
    try:
        if _signature(filename) != signature:
            owner = None
    except OSError:
        owner = None
    expected = NETBIOS + chr(92) + stem.upper() + "$"   # chr(92) is a backslash
    if owner is None:
        # Cannot prove the record is genuine, so refuse to show it. Failing
        # closed here is the point of the whole check.
        return {"status": BAD_OWNER, "password": None, "host": rec.get("host"),
                "id": rec.get("id"), "set_at": rec.get("set_at"),
                "owner": "unverifiable"}
    if owner.upper() != expected:
        return {"status": BAD_OWNER, "password": None, "host": rec.get("host"),
                "id": rec.get("id"), "set_at": rec.get("set_at"), "owner": owner}
    return {"status": OK, "password": rec.get("password"), "host": rec.get("host"),
            "id": rec.get("id"), "set_at": rec.get("set_at"), "owner": owner}
