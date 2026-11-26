#!/usr/bin/env python3
"""
rdmon collector - the only component that needs root.

Two jobs, one output file:
  1. sniff UDP 21116 and record when each RustDesk ID last heartbeated
  2. periodically snapshot hbbs's peer table for registration metadata

Why sniff rather than read a socket table: RustDesk clients heartbeat over UDP,
which is connectionless, so `ss` shows only the listening socket and never the
peers. And why key on the ID from the packet payload rather than the source IP:
peers arrive NAT'd (several can share one gateway IP), so IP cannot tell them
apart. The heartbeat carries the ID in clear text, including older short IDs.
"""
import json, os, re, shutil, socket, sqlite3, struct, subprocess, sys, tempfile
import threading, time
import osdetect, vaultinfo
from config import SETTINGS

STATE_PATH = SETTINGS["console"]["state_file"]
DB_PATH    = SETTINGS["collector"]["database"]
IFACE      = SETTINGS["collector"]["interface"]
RDV_PORT   = SETTINGS.getint("collector", "heartbeat_port")
DB_POLL    = 15          # seconds between peer-table snapshots
FLUSH      = 3           # seconds between state.json writes
MAX_UNKNOWN_PEERS = 256
UNKNOWN_PEER_TTL = 300

# --- machine-name resolution -------------------------------------------------
# hbbs never learns the hostname: the RustDesk signal protocol carries only
# id/uuid/pk, and peer.info holds nothing but the IP. So the name has to be
# inferred from the network, best-effort, and the admin can always override it.
ALIAS_PATH    = SETTINGS["collector"]["aliases_file"]
NAME_POLL     = 30
NAME_TTL_OK   = 900      # re-check a resolved name every 15 min
NAME_TTL_FAIL = 180      # retry a failed one sooner, hosts come and go
NBT_TIMEOUT   = 1.5
VAULT_POLL    = 60       # seconds between vault scans (names + who is logged on)

_lock    = threading.Lock()
_vnames  = {}            # rustdesk id -> HOST, from the machine's own vault record
_vsess   = {}            # HOST -> {"users": [...], "at": epoch}
_vhealth = {"status": "starting", "last_attempt": None, "last_success": None,
            "session_errors": {}}
_names   = {}            # ip -> {"name": str|None, "src": str, "until": epoch}
_aliases = {}            # rustdesk id -> name (manual, wins over everything)
_osalias = {}            # rustdesk id -> OS string (manual, wins over everything)
_osinfo  = {}            # ip -> {"os": str|None, "detail": str, "src": str, "until": epoch}
_seen    = {}            # rustdesk_id -> {"last_seen": epoch, "ip": str, "port": int}
_registry= {}            # rustdesk_id -> {"registered_ip": str, "registered_at": str}
_started = time.time()

HDR_RE = re.compile(
    r"(?P<src>[0-9a-fA-F:.]+)\.(?P<sport>\d+)\s+>\s+"
    r"(?P<dst>[0-9a-fA-F:.]+)\.(?P<dport>\d+):\s+UDP,\s+length\s+(?P<len>\d+)"
)
TTL_RE = re.compile("ttl ([0-9]+)")
ID_RE = re.compile(r"(?<![0-9])([0-9]{6,16})(?![0-9])")


def _commit(pkt_hdr, payload):
    """Record a heartbeat if this packet was client -> rendezvous port."""
    if not pkt_hdr or int(pkt_hdr["dport"]) != RDV_PORT:
        return
    m = ID_RE.search(payload)
    if not m:
        return
    pid = m.group(1)
    with _lock:
        now = time.time()
        unknown = [key for key in _seen if key not in _registry]
        for key in unknown:
            if now - _seen[key]["last_seen"] > UNKNOWN_PEER_TTL:
                _seen.pop(key, None)
        if pid not in _registry and pid not in _seen and sum(key not in _registry for key in _seen) >= MAX_UNKNOWN_PEERS:
            return  # unregistered UDP identifiers cannot grow memory forever
        _seen[pid] = {
            "last_seen": now,
            "ip": pkt_hdr["src"].replace("::ffff:", ""),
            "port": int(pkt_hdr["sport"]),
            "ttl": pkt_hdr.get("ttl"),
        }


def sniff():
    # -v adds the "ttl N" line, which is the only OS hint available for a
    # peer with SMB closed. It moves the addresses onto their own line, which
    # is why HDR_RE no longer anchors on a leading "IP".
    cmd = ["tcpdump", "-nn", "-A", "-v", "-l", "-i", IFACE,
           f"udp port {RDV_PORT} and not host ::1"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, bufsize=0)
    hdr, buf, pending_ttl = None, [], None
    for raw in proc.stdout:
        line = raw.decode("utf-8", "replace")
        m_ttl = TTL_RE.search(line)
        if m_ttl:
            pending_ttl = int(m_ttl.group(1))   # verbose line precedes its addresses
        m = HDR_RE.search(line)
        if m:
            _commit(hdr, "".join(buf))     # flush the packet that just ended
            hdr, buf = m.groupdict(), []
            hdr["ttl"] = pending_ttl
            pending_ttl = None
        else:
            buf.append(line)
    _commit(hdr, "".join(buf))


def nbstat(ip, timeout=NBT_TIMEOUT):
    """NetBIOS node-status query (UDP 137) - asks a Windows host its own name.

    This works without DNS records, including networks without reverse DNS.
    Returns the unique workstation name, or None.
    """
    name = b"*" + bytes(15)
    enc = b"".join(bytes([0x41 + (b >> 4), 0x41 + (b & 0xF)]) for b in name)
    pkt = (struct.pack(">HHHHHH", 0x4242, 0x0000, 1, 0, 0, 0)
           + bytes([len(enc)]) + enc + bytes(1) + struct.pack(">HH", 0x0021, 0x0001))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (ip, 137))
        data, _ = sock.recvfrom(2048)
    except Exception:
        return None
    finally:
        sock.close()
    try:
        off = 12 + 1 + len(enc) + 1 + 4 + 4 + 2
        count = data[off]; off += 1
        for _ in range(count):
            nm = data[off:off + 15].decode("ascii", "replace").strip()
            suffix = data[off + 15]
            flags = data[off + 16] if off + 16 < len(data) else 0
            # suffix 0x00 = workstation service; group bit (0x80) excludes domains
            if suffix == 0x00 and not (flags & 0x80) and nm:
                return nm
            off += 18
    except Exception:
        pass
    return None


def ptr(ip):
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0]
    except Exception:
        return None


def load_aliases():
    """Reread the override file each pass so edits apply without a restart.

    Two kinds of line, both keyed on the RustDesk ID:
        <id> = <name>            a manual machine name
        os:<id> = <os string>    a manual OS, e.g. os:123456 = Windows 11 26H2
    Returns (names, os_overrides).
    """
    names, osov = {}, {}
    try:
        with open(ALIAS_PATH) as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if not k or not v:
                    continue
                if k.lower().startswith("os:"):
                    osov[k[3:].strip()] = v
                else:
                    names[k] = v
    except FileNotFoundError:
        pass
    except Exception as exc:
        print(f"[rdmon] alias file unreadable: {exc}", file=sys.stderr, flush=True)
    return names, osov


def resolve_names():
    while True:
        try:
            aliases, osaliases = load_aliases()
            with _lock:
                _aliases.clear()
                _aliases.update(aliases)
                _osalias.clear()
                _osalias.update(osaliases)
                # carry each peer's observed hop TTL along: it is the OS hint
                targets = {v.get("ip"): v.get("ttl")
                           for v in _seen.values() if v.get("ip")}
                for cache in (_names, _osinfo):
                    for address in set(cache) - set(targets):
                        cache.pop(address, None)
            now = time.time()
            for ip, hop_ttl in targets.items():
                with _lock:
                    ent = _names.get(ip)
                    oent = _osinfo.get(ip)
                need_name = not (ent and ent["until"] > now)
                need_os = not (oent and oent["until"] > now)
                # one SMB handshake serves both lookups
                probe = (osdetect.smb_probe(ip) or {}) if (need_name or need_os) else None
                if need_name:
                    # All three ask about the IP. The host's own answers come
                    # first; PTR last, as the DC has no reverse records.
                    #   NetBIOS - firewalled to the local subnet on Windows
                    #   SMB     - the computer name in the NTLM challenge;
                    #             works across subnets wherever 445 is open
                    nm, src = nbstat(ip), "netbios"
                    if not nm:
                        nm, src = probe.get("nb_computer"), "smb"
                    if not nm:
                        nm, src = ptr(ip), "dns"
                    keep = NAME_TTL_OK if nm else NAME_TTL_FAIL
                    with _lock:
                        _names[ip] = {"name": nm, "src": src if nm else "none",
                                      "until": time.time() + keep}
                        ent = _names[ip]
                if need_os:
                    label, detail, osrc = osdetect.describe(
                        ip, hop_ttl, bool(ent and ent.get("src") == "netbios"), probe)
                    keep = NAME_TTL_OK if label else NAME_TTL_FAIL
                    with _lock:
                        _osinfo[ip] = {"os": label, "detail": detail,
                                       "src": osrc, "until": time.time() + keep}
        except Exception as exc:
            print(f"[rdmon] name resolution failed: {exc}", file=sys.stderr, flush=True)
        time.sleep(NAME_POLL)


def poll_vault():
    """Names by RustDesk ID and logged-on users, from owner-verified vault files.
    A failed scan keeps the last good result: the share blinking for a moment
    should not blank every name in the table."""
    while True:
        try:
            with _lock:
                _vhealth["last_attempt"] = time.time()
            got = vaultinfo.scan()
            with _lock:
                _vhealth.update(vaultinfo.diagnostics())
                if got is not None:
                    _vhealth["last_success"] = time.time()
                    _vnames.clear(); _vnames.update(got[0])
                    _vsess.clear();  _vsess.update(got[1])
        except Exception as exc:
            with _lock:
                _vhealth["status"] = "scan failed"
            print(f"[rdmon] vault scan failed: {exc}", file=sys.stderr, flush=True)
        time.sleep(VAULT_POLL)


def poll_db():
    """Snapshot the peer table. Copied first: hbbs holds it open in WAL mode,
    and a read-only open would still need to write the -shm sidecar."""
    while True:
        try:
            tmp = tempfile.mkdtemp(prefix="rdmon-db-")
            try:
                for suffix in ("", "-wal", "-shm"):
                    src = DB_PATH + suffix
                    if os.path.exists(src):
                        shutil.copy2(src, os.path.join(tmp, os.path.basename(src)))
                con = sqlite3.connect(os.path.join(tmp, os.path.basename(DB_PATH)))
                rows = con.execute(
                    "select id, created_at, info from peer").fetchall()
                con.close()
                reg = {}
                for pid, created, info in rows:
                    try:
                        ip = json.loads(info).get("ip", "")
                    except Exception:
                        ip = ""
                    reg[str(pid)] = {
                        "registered_ip": ip.replace("::ffff:", ""),
                        "registered_at": str(created),
                    }
                with _lock:
                    _registry.clear()
                    _registry.update(reg)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        except Exception as exc:
            print(f"[rdmon] db poll failed: {exc}", file=sys.stderr, flush=True)
        time.sleep(DB_POLL)


def write_state():
    tmp = STATE_PATH + ".tmp"
    while True:
        with _lock:
            ids = set(_seen) | set(_registry)
            peers = {}
            for pid in sorted(ids):
                s = _seen.get(pid, {})
                r = _registry.get(pid, {})
                ip = s.get("ip") or r.get("registered_ip", "")
                # A manual alias is keyed on the RustDesk ID, which is stable,
                # and beats any lookup - it is the only thing that can name a
                # peer whose traffic arrives NAT'd behind a shared gateway IP.
                # After it, the vault: also keyed on the ID, and written by the
                # machine itself. Only then the lookups by IP.
                if pid in _aliases:
                    name, src = _aliases[pid], "alias"
                elif pid in _vnames:
                    name, src = _vnames[pid], "vault"
                else:
                    ent = _names.get(ip) or {}
                    name, src = ent.get("name"), ent.get("src", "none")
                # Display aliases must not disconnect reports from their real
                # computer name, which is mapped to this ID by the trusted vault.
                report_host = (_vnames.get(pid) or name or "").upper()
                sess = _vsess.get(report_host) or {}
                oent = _osinfo.get(ip) or {}
                # OS, same precedence as the name: a manual override by ID, then
                # the machine's own report (24H2/25H2/26H2 are one build over SMB,
                # so only the machine knows its release), then the network probe.
                if pid in _osalias:
                    os_label, os_detail, os_src = _osalias[pid], "manual override", "alias"
                elif sess.get("os"):
                    os_label = sess["os"]
                    os_detail = sess.get("os_build") or "reported by the machine"
                    os_src = "report"
                else:
                    os_label, os_detail, os_src = oent.get("os"), oent.get("detail"), oent.get("src", "none")
                peers[pid] = {
                    "last_seen":     s.get("last_seen"),
                    "ip":            ip,
                    "port":          s.get("port"),
                    "name":          name,
                    "name_source":   src if name else "none",
                    "os":            os_label,
                    "os_detail":     os_detail,
                    "os_source":     os_src if os_label else "none",
                    "registered_ip": r.get("registered_ip", ""),
                    "registered_at": r.get("registered_at", ""),
                    "registered":    pid in _registry,
                    # None = this machine has never reported; [] = reported,
                    # nobody logged on.
                    "users":         sess.get("users"),
                    "users_at":      sess.get("at"),
                    "report_host":   report_host or None,
                    "report_error":  _vhealth["session_errors"].get(report_host),
                }
            doc = {"updated": time.time(),
                   "collector_started": _started,
                   "vault_health": {k: v for k, v in _vhealth.items() if k != "session_errors"},
                   "report_issues": dict(_vhealth["session_errors"]),
                   "peers": peers}
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            fd = os.open(tmp, flags, 0o600)
            with os.fdopen(fd, "w") as fh:
                if hasattr(os, "fchmod"):
                    os.fchmod(fh.fileno(), 0o600)
                json.dump(doc, fh)
            if os.name == "posix" and os.geteuid() == 0:
                import grp
                os.chown(tmp, 0, grp.getgrnam("rdmon").gr_gid)
            os.chmod(tmp, 0o640)
            os.replace(tmp, STATE_PATH)      # atomic: readers never see a partial file
        except Exception as exc:
            print(f"[rdmon] state write failed: {exc}", file=sys.stderr, flush=True)
        time.sleep(FLUSH)


if __name__ == "__main__":
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    threading.Thread(target=poll_db, daemon=True).start()
    threading.Thread(target=resolve_names, daemon=True).start()
    threading.Thread(target=poll_vault, daemon=True).start()
    threading.Thread(target=write_state, daemon=True).start()
    sniff()
