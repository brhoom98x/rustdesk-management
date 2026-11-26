#!/usr/bin/env python3
"""
OS inference for RustDesk peers.

RustDesk never tells the server what a peer runs - the signal protocol carries
only id/uuid/pk - so the OS has to be inferred from the network. Two signals,
strongest first:

  1. SMB on 445. An SMB2 SESSION_SETUP carrying an NTLMSSP NEGOTIATE gets back a
     CHALLENGE whose Version field holds the exact Windows build, and it comes
     back BEFORE authentication, so no credentials are involved. The same reply
     carries the machine's own computer name, which the collector uses too.
  2. IP TTL of the heartbeat packets the collector already sees. Coarse, but it
     is the only signal that identifies a non-Windows peer when 445 is shut.

Kept apart from collector.py so the packet parser stays untouched.
"""
import socket, struct, time

# Build -> marketing name. Client and server SKUs share a build number, so the
# ambiguous ones say so rather than guessing a SKU we cannot actually observe.
BUILDS = {
    26300: ("Windows 11 26H2", None),
    26200: ("Windows 11 25H2", None),
    # 24H2, 25H2 and 26H2 are enablement packages on the same 26100 base, so the
    # pre-auth build the network sees stays 26100 whatever the display version -
    # they are indistinguishable over SMB. 24H2 is the best single guess; a
    # machine's own report (vault) overrides this when available.
    26100: ("Windows 11 24H2", "or 25H2/26H2, or Server 2025 - identical over SMB"),
    22631: ("Windows 11 23H2", None),
    22621: ("Windows 11 22H2", None),
    22000: ("Windows 11 21H2", None),
    20348: ("Windows Server 2022", None),
    19045: ("Windows 10 22H2", None),
    19044: ("Windows 10 21H2", None),
    17763: ("Windows 10 1809", "or Server 2019"),
    14393: ("Windows 10 1607", "or Server 2016"),
    10240: ("Windows 10 1507", None),
     9600: ("Windows 8.1", "or Server 2012 R2"),
     7601: ("Windows 7 SP1", "or Server 2008 R2"),
}


def _smb2_header(command, message_id):
    return (b"\xfeSMB" + struct.pack("<HH", 64, 0) + struct.pack("<I", 0)
            + struct.pack("<HH", command, 1) + struct.pack("<II", 0, 0)
            + struct.pack("<Q", message_id) + struct.pack("<I", 0)
            + struct.pack("<I", 0) + struct.pack("<Q", 0) + b"\x00" * 16)


def _txn(sock, payload):
    deadline = time.monotonic() + (sock.gettimeout() or 3.0)
    sock.sendall(b"\x00" + len(payload).to_bytes(3, "big") + payload)
    head = b""
    while len(head) < 4:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("SMB response deadline exceeded")
        sock.settimeout(remaining)
        chunk = sock.recv(4 - len(head))
        if not chunk:
            return b""
        head += chunk
    want = int.from_bytes(head[1:], "big")
    if head[0] != 0 or want > 65536:
        raise ValueError("Invalid or oversized SMB pre-auth response")
    buf = b""
    while len(buf) < want:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("SMB response deadline exceeded")
        sock.settimeout(remaining)
        chunk = sock.recv(want - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


# NTLM CHALLENGE TargetInfo AV_PAIR ids (MS-NLMP 2.2.2.1) worth keeping.
_AV_NAMES = {1: "nb_computer", 2: "nb_domain", 3: "dns_computer", 4: "dns_domain"}


def _target_info(msg):
    """AV pairs from an NTLM CHALLENGE message (msg starts at its signature)."""
    out = {}
    try:
        length, _, offset = struct.unpack("<HHI", msg[40:48])
        ti, i = msg[offset:offset + length], 0
        while i + 4 <= len(ti):
            av_id, av_len = struct.unpack("<HH", ti[i:i + 4])
            if av_id == 0:                       # MsvAvEOL
                break
            if av_id in _AV_NAMES:
                out[_AV_NAMES[av_id]] = ti[i + 4:i + 4 + av_len].decode("utf-16le", "replace")
            i += 4 + av_len
    except (struct.error, ValueError):
        pass
    return out


def smb_probe(ip, timeout=3.0):
    """
    One pre-auth SMB handshake, everything it gives away, or None.

    Returns {"version": "10.0.26100" | None, "nb_computer": ..., "nb_domain": ...,
    "dns_computer": ..., "dns_domain": ...}. The names come from the CHALLENGE's
    TargetInfo, which Windows fills with its own computer name. That makes it the
    one name source that works across subnets, where NetBIOS (UDP 137) is
    firewalled to the local subnet and the DC holds no PTR records.
    """
    sock = socket.socket()
    sock.settimeout(timeout)
    try:
        sock.connect((ip, 445))
        dialects = [0x0202, 0x0210, 0x0300, 0x0302]
        body = (struct.pack("<HHHH", 36, len(dialects), 1, 0)
                + struct.pack("<I", 0) + b"\x11" * 16 + struct.pack("<Q", 0)
                + b"".join(struct.pack("<H", d) for d in dialects))
        _txn(sock, _smb2_header(0x0000, 0) + body)

        flags = 0x00088207 | 0x02000000          # standard flags + NEGOTIATE_VERSION
        ntlm = (b"NTLMSSP\x00" + struct.pack("<I", 1) + struct.pack("<I", flags)
                + struct.pack("<HHI", 0, 0, 0) + struct.pack("<HHI", 0, 0, 0)
                + b"\x06\x01\xb1\x1d\x00\x00\x00\x0f")
        body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(ntlm), 0) + ntlm
        resp = _txn(sock, _smb2_header(0x0001, 1) + body)

        at = resp.find(b"NTLMSSP\x00\x02\x00\x00\x00")
        if at < 0 or len(resp) < at + 56:
            return None
        msg = resp[at:]
        out = _target_info(msg)
        major, minor = msg[48], msg[49]
        build = struct.unpack("<H", msg[50:52])[0]
        out["version"] = f"{major}.{minor}.{build}" if build else None
        return out
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def family_from_ttl(ttl):
    """Initial TTL is the give-away: Windows starts at 128, Linux/macOS at 64.

    Observed TTL has already been decremented once per hop, so round up to the
    nearest standard starting value rather than matching exactly.
    """
    if not ttl:
        return None
    for start, name in ((64, "Linux / Unix"), (128, "Windows"), (255, "Network device")):
        if 0 < ttl <= start and start - ttl <= 32:
            return name
    return None


def smb_version(ip, timeout=3.0):
    """Exact Windows version string from the pre-auth NTLM challenge, or None."""
    return (smb_probe(ip, timeout) or {}).get("version")


def describe(ip, ttl=None, netbios=False, probe=None):
    """Return (label, detail, source). Best signal wins.

    probe: a smb_probe() result the caller already has, so one handshake can
    serve both the name and the OS lookup. None means probe here.
    """
    if probe is None:
        probe = smb_probe(ip) or {}
    ver = probe.get("version")
    if ver:
        try:
            build = int(ver.split(".")[2])
        except (IndexError, ValueError):
            build = 0
        name, caveat = BUILDS.get(build, (None, None))
        if name:
            detail = f"{ver}{' - ' + caveat if caveat else ''}"
            return name, detail, "smb"
        return f"Windows (build {build})", ver, "smb"

    fam = family_from_ttl(ttl)
    if fam:
        return fam, f"inferred from IP TTL {ttl}", "ttl"
    if netbios:
        return "Windows", "NetBIOS responded; SMB unreachable", "netbios"
    return None, None, "none"
