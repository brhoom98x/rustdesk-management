#!/usr/bin/env python3
"""
Non-secret facts from the vault, for the collector.

Two things, both keyed so the polling path never needs a password:

  1. RustDesk ID -> computer name, from <HOST>.json. Each deployed machine wrote
     its own ID there, so this names a peer by its ID, which survives NAT (two
     machines behind one gateway IP) where every IP-based lookup cannot.
     Only "id" is taken from the record; the password is never kept.

  2. Who is logged on, from <HOST>.session. Deploy-RustDesk.ps1 registers a
     SYSTEM scheduled task that rewrites it at every logon and every 5 minutes.

Both go through the same trust rule as reveal: a file counts only if its NTFS
owner is the machine's own computer account. A PC can create a file named for
another PC, but it cannot forge the owner. Owner cache entries are invalidated
when the file changes, and periodically rechecked even when it does not.
"""
import json, math, os, sys, time
import vault
from config import SETTINGS

HOME        = SETTINGS["vault"]["collector_cache_dir"]
OWNER_TTL   = 3600       # re-verify each file's owner hourly anyway
OWNER_RETRY = 120
MAX_SESSION = 4096       # a session record is a few hundred bytes

_owners = {}             # filename -> (owner or None, checked_at, file signature)
_last_rejected = []
_diagnostics = {"status": "starting", "session_errors": {}}


def diagnostics():
    return {"status": _diagnostics["status"],
            "session_errors": dict(_diagnostics["session_errors"])}


def _trusted(filename, *, refresh=False):
    """True if filename is owned by the computer account its name claims."""
    now = time.time()
    hit = _owners.get(filename)
    stem = filename.rsplit(".", 1)[0]
    expected = vault.NETBIOS + chr(92) + stem.upper() + "$"   # chr(92) is a backslash
    try:
        info = os.stat(os.path.join(vault.VAULT_DIR, filename))
        signature = (info.st_ino, info.st_ctime_ns)
    except OSError:
        _owners[filename] = (None, now, None)
        return False
    # Changed files are rechecked. Rejected/unverifiable owners retry sooner.
    good_owner = hit and hit[0] and hit[0].upper() == expected
    if refresh or not hit or len(hit) < 3 or hit[2] != signature or now - hit[1] > (OWNER_TTL if good_owner else OWNER_RETRY):
        hit = (vault._owner_of(filename, home=HOME), now, signature)
        _owners[filename] = hit
    return bool(hit[0]) and hit[0].upper() == expected


def _id_of(filename):
    """The RustDesk ID in a password record. The rest of the record, the
    password included, is dropped before this returns."""
    rec = vault._read_record(filename)
    if not rec:
        return None, None
    rid = str(rec.get("id") or "").strip()
    set_at = str(rec.get("set_at") or "")
    rec.clear()
    return (rid if rid.isdigit() else None), set_at


def _session(filename):
    rec = vault._read_json(filename, MAX_SESSION)
    if not isinstance(rec, dict) or not rec.get("rustdesk_session"):
        return None
    if str(rec.get("host") or "").upper() != filename[:-8].upper():
        return None
    users = rec.get("users")
    if not isinstance(users, list) or any(not isinstance(u, str) for u in users):
        return None
    try:
        at = float(rec.get("at"))
    except (TypeError, ValueError):
        return None
    if not math.isfinite(at) or at <= 0:
        return None
    out = {"users": [str(u)[:128] for u in users if u][:8], "at": at}
    # The machine's own OS, which beats the SMB build guess (24H2/25H2/26H2 are
    # the same build over the wire). Optional: older agents do not send it.
    os_label = str(rec.get("os") or "").strip()[:64]
    if os_label:
        out["os"] = os_label
        out["os_build"] = str(rec.get("os_build") or "").strip()[:32]
    return out


def scan():
    """
    Returns (names, sessions) or None if the vault is not readable.
      names:    {rustdesk_id: HOST}
      sessions: {HOST: {"users": [...], "at": epoch}}
    """
    if not vault.ENABLED:
        _diagnostics.update(status="disabled", session_errors={})
        return None
    os.makedirs(HOME, mode=0o700, exist_ok=True)
    # Unmounted, the mount point is an empty directory - an empty vault, as far
    # as listdir can tell. That must read as "unknown", not "no records".
    if not os.path.ismount(vault.VAULT_DIR):
        _diagnostics.update(status="unreachable", session_errors={})
        return None
    try:
        files = []
        with os.scandir(vault.VAULT_DIR) as entries:
            for entry in entries:
                if vault._SAFE_NAME.fullmatch(entry.name):
                    files.append(entry.name)
                    if len(files) > vault.MAX_FILES:
                        _diagnostics.update(status="file limit exceeded", session_errors={})
                        return None
    except OSError:
        _diagnostics.update(status="unreachable", session_errors={})
        return None

    names, sessions, rejected = {}, {}, []
    claims = {}
    session_errors = {}
    expires = time.monotonic() + 45
    for f in files:
        if time.monotonic() >= expires:
            _diagnostics.update(status="scan timeout", session_errors={})
            return None
        if not vault._SAFE_NAME.fullmatch(f):
            continue
        low = f.lower()
        if low.endswith(".json"):
            rid, set_at = _id_of(f)
            if not rid:
                continue
            if not _trusted(f):
                rejected.append(f)
                continue
            host = f[:-5].upper()
            claims.setdefault(rid, []).append((f, host))
        elif low.endswith(".session"):
            host = f[:-8].upper()
            if not _trusted(f):
                rejected.append(f)
                session_errors[host] = ("owner mismatch" if _owners[f][0]
                                        else "owner unverifiable")
                continue
            rec = _session(f)
            if not rec:
                session_errors[host] = "invalid report"
                continue
            sessions[host] = rec

    for rid, candidates in claims.items():
        if len(candidates) > 1:
            # An AD rename changes the resolved account name without changing
            # the file's owner SID or timestamps. An old cached account name
            # must not turn the old/new filenames into a false ID conflict.
            verified = []
            for filename, host in candidates:
                if time.monotonic() >= expires:
                    _diagnostics.update(status="scan timeout", session_errors={})
                    return None
                if _trusted(filename, refresh=True):
                    verified.append((filename, host))
                else:
                    rejected.append(filename)
            candidates = verified
        if len(candidates) == 1:
            names[rid] = candidates[0][1]
        elif len(candidates) > 1:
            # Distinct, genuinely owned computers claiming one ID are still
            # ambiguous. Never choose the newest claim or weaken owner checks.
            for _, host in candidates:
                session_errors[host] = "ID mismatch"

    gone = set(_owners) - set(files)
    for f in gone:
        del _owners[f]
    global _last_rejected
    rejected = sorted(rejected)
    if rejected and rejected != _last_rejected:        # say it once, not every pass
        print("[rdmon] vault files ignored, owner is not the machine itself: "
              + ", ".join(rejected), file=sys.stderr, flush=True)
    _last_rejected = rejected
    _diagnostics.update(status="ok", session_errors=session_errors)
    return names, sessions
