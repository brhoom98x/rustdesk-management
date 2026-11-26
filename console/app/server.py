#!/usr/bin/env python3
"""
rdmon web - reads state.json and serves the dashboard.

Unprivileged: monitoring state and application files are read-only. Only console
account hashes and audit logs are writable. It never touches the RustDesk database.

Named accounts have Admin, Operator and Viewer roles. The old EnvironmentFile
credential is migrated once as an Admin. HTTP Basic supports authorized reads;
password reveals and account mutations require an HTTPS session plus CSRF.
"""
import base64, hashlib, hmac, html, json, os, re, secrets, ssl, stat, sys, threading, time
import urllib.parse
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import vault
import accounts
from config import SETTINGS

STATE_PATH    = SETTINGS["console"]["state_file"]
STATIC_DIR    = SETTINGS["console"]["static_dir"]
BIND          = (SETTINGS["console"]["bind_host"], SETTINGS.getint("console", "http_port"))
BIND_TLS      = (SETTINGS["console"]["bind_host"], SETTINGS.getint("console", "https_port"))
CERT_PATH     = SETTINGS["console"]["cert_file"]
KEY_PATH      = SETTINGS["console"]["key_file"]
ONLINE_WINDOW = SETTINGS.getint("console", "online_window")
TLS_HANDSHAKE_TIMEOUT = 5
HTTP_REQUEST_TIMEOUT = 30
COOKIE        = "rdmon_session"
SESSION_TTL   = 12 * 3600
LOCK_FAILS    = 10          # failed logins from one IP before a cooldown
LOCK_WINDOW   = 300
REVEAL_LIMIT  = 30          # password reveals per session per window
REVEAL_WINDOW = 60
AUDIT_LOG     = SETTINGS["console"]["audit_log"]
MAX_CONNECTIONS = 32
MAX_CONNECTIONS_PER_IP = 16
TOTAL_CONNECTION_TIMEOUT = 35
MAX_SESSIONS = 512
MAX_FAILURE_IPS = 4096
AUDIT_MAX_BYTES = 5 * 1024 * 1024
AUDIT_BACKUPS = 3
_audit_lock = threading.Lock()

AUTH_USER = os.environ.get("RDMON_USER", "")
AUTH_HASH = os.environ.get("RDMON_PASS_HASH", "")
USER_STORE = accounts.Store(os.environ.get("RDMON_USERS_DB", accounts.DB_PATH))

_sessions, _sess_lock = {}, threading.Lock()      # token -> {exp, csrf}
_fails,    _fail_lock = {}, threading.Lock()      # ip -> [failure timestamps]
_basic_cache, _basic_lock = {}, threading.Lock()
_reveals, _reveal_lock = {}, threading.Lock()     # session token -> [timestamps]
_BASIC_TTL = 300


def _check_password(user, password):
    return USER_STORE.authenticate(user, password)


def _check_basic(header):
    """HTTP Basic fallback, so scripts and monitors need no form."""
    if not header or not header.startswith("Basic "):
        return None
    now = time.time()
    key = hashlib.sha256(header.encode()).digest()
    with _basic_lock:
        cached = _basic_cache.get(key)
    if cached and cached["exp"] > now:
        user = USER_STORE.get(cached["username"])
        if user and user["enabled"] and user["version"] == cached["version"]:
            return user
    try:
        raw = base64.b64decode(header[6:], validate=True).decode("utf-8", "replace")
    except Exception:
        return None
    user, sep, password = raw.partition(":")
    identity = _check_password(user, password) if sep else None
    if not identity:
        return None
    # PBKDF2 is deliberately slow; re-deriving per poll would burn CPU for nothing.
    with _basic_lock:
        if len(_basic_cache) >= 64:
            for k in [k for k, v in _basic_cache.items() if v["exp"] <= now]:
                _basic_cache.pop(k, None)
            if len(_basic_cache) >= 64:
                _basic_cache.pop(next(iter(_basic_cache)))
        _basic_cache[key] = {"username": identity["username"], "version": identity["version"], "exp": now + _BASIC_TTL}
    return identity


def _new_session(user):
    tok  = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    with _sess_lock:
        now = time.time()
        for k in [k for k, v in _sessions.items() if v["exp"] <= now]:
            _sessions.pop(k, None)
        if len(_sessions) >= MAX_SESSIONS:
            _sessions.pop(next(iter(_sessions)))
        _sessions[tok] = {"exp": time.time() + SESSION_TTL, "csrf": csrf,
                          "username": user["username"], "version": user["version"]}
    return tok


def _session_user(tok):
    if not tok:
        return False
    with _sess_lock:
        ent = _sessions.get(tok)
        if not ent:
            return None
        if ent["exp"] <= time.time():
            del _sessions[tok]
            return None
        username, version = ent["username"], ent["version"]
    user = USER_STORE.get(username)
    if not user or not user["enabled"] or user["version"] != version:
        _drop_session(tok)
        return None
    return user


def _session_ok(tok):
    return bool(_session_user(tok))


def _session_csrf(tok):
    """Per-session CSRF token.

    SameSite=Strict already stops a cross-site form post, but the reveal
    endpoint hands out a password, so it gets a second explicit check rather
    than resting on one cookie attribute.
    """
    with _sess_lock:
        ent = _sessions.get(tok)
        return ent["csrf"] if ent else None


def _drop_session(tok):
    with _sess_lock:
        _sessions.pop(tok, None)
    with _reveal_lock:
        _reveals.pop(tok, None)


def _locked_out(ip):
    now = time.time()
    with _fail_lock:
        hits = [t for t in _fails.get(ip, []) if now - t < LOCK_WINDOW]
        if hits:
            _fails[ip] = hits
        else:
            _fails.pop(ip, None)
        return len(hits) >= LOCK_FAILS


def _record_fail(ip):
    with _fail_lock:
        if ip not in _fails and len(_fails) >= MAX_FAILURE_IPS:
            _fails.pop(next(iter(_fails)))
        _fails.setdefault(ip, []).append(time.time())
        _fails[ip] = _fails[ip][-LOCK_FAILS:]


def _clear_fails(ip):
    with _fail_lock:
        _fails.pop(ip, None)

def _reveal_allowed(token):
    """Rate limit reveals per session, separate from the login throttle."""
    now = time.time()
    with _reveal_lock:
        hits = [t for t in _reveals.get(token, []) if now - t < REVEAL_WINDOW]
        if len(hits) >= REVEAL_LIMIT:
            _reveals[token] = hits
            return False
        hits.append(now)
        _reveals[token] = hits
        if len(_reveals) > 512:
            stale = [k for k, v in _reveals.items()
                     if not v or now - v[-1] > REVEAL_WINDOW]
            for k in stale:
                _reveals.pop(k, None)
        return True


def audit(user, ip, machine, rustdesk_id, outcome):
    """One line per reveal attempt.

    The password is deliberately not a parameter of this function, so it cannot
    be logged by accident from any call site.
    """
    def safe(value):
        return json.dumps(str(value or "-")[:128], ensure_ascii=True)[1:-1].replace(" ", "\\u0020")
    # Even internal identity/address fields must not create forged log lines.
    line = "{0} user={1} ip={2} machine={3} id={4} outcome={5}".format(
        time.strftime("%Y-%m-%d %H:%M:%S"), safe(user), safe(ip),
        safe(machine), safe(rustdesk_id), safe(outcome))
    try:
        with _audit_lock:
            os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
            if os.path.islink(AUDIT_LOG):
                raise OSError("Audit path is a symbolic link")
            if os.path.exists(AUDIT_LOG) and os.path.getsize(AUDIT_LOG) >= AUDIT_MAX_BYTES:
                for n in range(AUDIT_BACKUPS, 0, -1):
                    source = AUDIT_LOG if n == 1 else AUDIT_LOG + "." + str(n - 1)
                    if os.path.exists(source):
                        os.replace(source, AUDIT_LOG + "." + str(n))
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            fd = os.open(AUDIT_LOG, flags, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise OSError("Audit path is not a regular file")
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8", closefd=False) as fh:
                    fh.write(line + "\n")
                    fh.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
        return True
    except OSError as exc:
        print("[rdmon] audit write failed: " + str(exc), file=sys.stderr, flush=True)
        return False


def report_status(peer, now, vault_status="ok"):
    if vault_status == "disabled":
        return "not configured"
    if peer.get("report_error"):
        return peer["report_error"]
    if vault_status != "ok":
        return "vault unavailable" if vault_status != "starting" else "checking"
    if peer.get("users") is None:
        return "missing report"
    age = now - (peer.get("users_at") or 0)
    if age < -300:
        return "clock skew"
    if age > 900:
        return "stale report"
    return "reported" if peer["users"] else "nobody logged on"


def build_payload():
    try:
        with open(STATE_PATH) as fh:
            state = json.load(fh)
    except FileNotFoundError:
        return {"error": "collector has not written state yet", "peers": []}
    except json.JSONDecodeError:
        return {"error": "state file unreadable", "peers": []}

    now, out = time.time(), []
    vault_health = state.get("vault_health", {})
    for pid, p in state.get("peers", {}).items():
        last = p.get("last_seen")
        age = (now - last) if last else None
        out.append({
            "id": pid,
            "online": age is not None and age <= ONLINE_WINDOW,
            "age_seconds": round(age, 1) if age is not None else None,
            "ip": p.get("ip", ""),
            "port": p.get("port"),
            "name": p.get("name"),
            "name_source": p.get("name_source", "none"),
            "os": p.get("os"),
            "os_detail": p.get("os_detail"),
            "os_source": p.get("os_source", "none"),
            "registered": p.get("registered", False),
            "registered_at": p.get("registered_at", ""),
            "registered_ip": p.get("registered_ip", ""),
            "users": p.get("users"),
            "users_age": (round(now - p["users_at"]) if p.get("users_at") else None),
            "report_status": report_status(p, now, vault_health.get("status", "ok")),
            "report_host": p.get("report_host") or p.get("name"),
        })
    # Stable order: online first, then by machine name, then ID. Sorting by
    # heartbeat age (as before) reshuffled every row on every 5s refresh, so a
    # machine never stayed in one place long enough to read or copy.
    out.sort(key=lambda r: (not r["online"],
                            not r["name"],
                            (r["name"] or "").upper(),
                            r["id"]))
    return {
        "peers": out,
        "online_count": sum(1 for r in out if r["online"]),
        "total_count": len(out),
        "online_window": ONLINE_WINDOW,
        "updated": state.get("updated"),
        "collector_started": state.get("collector_started"),
        "server_time": now,
        "vault_enabled": vault.ENABLED,
        "health": {
            "collector_age": max(0, round(now - state["updated"])) if state.get("updated") else None,
            "vault_status": vault_health.get("status", "unknown"),
            "vault_age": max(0, round(now - vault_health["last_success"])) if vault_health.get("last_success") else None,
            "report_issues": state.get("report_issues", {}),
            "report_counts": {status: sum(p["report_status"] == status for p in out)
                              for status in sorted({p["report_status"] for p in out})},
        },
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "rdmon"
    sys_version = ""

    def _send(self, code, body, ctype, extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        scripts = []
        if ctype.startswith("text/html"):
            document = body.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
            scripts = ["'sha256-" + base64.b64encode(hashlib.sha256(script.encode()).digest()).decode() + "'"
                       for script in re.findall(r"<script\b[^>]*>(.*?)</script\s*>", document, re.I | re.S)]
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self' " + " ".join(scripts) +
                         "; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
        if getattr(self.server, "is_tls", False):
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        # Close after each response: rejected or unread bodies must never be
        # interpreted as another authenticated request on the same connection.
        self.close_connection = True
        self.send_header("Connection", "close")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location, extra=None):
        self._send(303, b"", "text/plain", {**(extra or {}), "Location": location})

    def _static(self, name, code=200, extra=None):
        try:
            with open(os.path.join(STATIC_DIR, name), "rb") as fh:
                self._send(code, fh.read(), "text/html; charset=utf-8", extra)
        except FileNotFoundError:
            self._send(500, name + " missing", "text/plain")

    def _cookie_token(self):
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            jar = SimpleCookie()
            jar.load(raw)
            return jar[COOKIE].value if COOKIE in jar else None
        except Exception:
            return None

    def _client_ip(self):
        return self.client_address[0] if self.client_address else "?"

    def _authed(self):
        user = _session_user(self._cookie_token())
        if user:
            return user
        header = self.headers.get("Authorization")
        if not header or _locked_out(self._client_ip()):
            return None
        user = _check_basic(header)
        if user:
            _clear_fails(self._client_ip())
        else:
            _record_fail(self._client_ip())
        return user

    def _configured(self):
        USER_STORE.initialize(AUTH_USER, AUTH_HASH)
        if USER_STORE.list():
            return True
        # Fail closed: an unset credential must never mean "open to everyone".
        self._send(503, "auth not configured", "text/plain")
        return False

    def _json(self, status, payload):
        self._send(status, json.dumps(payload), "application/json")

    def _session_permission(self, permission):
        user = _session_user(self._cookie_token())
        if not user:
            self._json(401, {"error": "unauthorized"})
            return None
        if permission not in accounts.PERMISSIONS.get(user["role"], set()):
            self._json(403, {"error": "forbidden"})
            return None
        if not getattr(self.server, "is_tls", False):
            self._json(403, {"error": "HTTPS required"})
            return None
        want = _session_csrf(self._cookie_token()) or ""
        if not want or not hmac.compare_digest(self.headers.get("X-CSRF-Token", "").encode(), want.encode()):
            self._json(403, {"error": "csrf"})
            return None
        return user

    def _json_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= 16384:
                raise ValueError
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(body, dict):
                raise ValueError
            return body
        except (ValueError, UnicodeError, RecursionError):
            self._json(400, {"error": "bad request"})
            return None

    def _manage_users(self):
        user = self._session_permission("users")
        if not user:
            return
        body = self._json_body()
        if body is None:
            return
        with USER_STORE.lock:
            # Recheck after reading the body, without holding a global account
            # lock while waiting for a slow client to upload it.
            current = USER_STORE.get(user["username"])
            if not current or not current["enabled"] or current["version"] != user["version"]:
                self._json(401, {"error": "unauthorized"})
                return
            try:
                username = body.get("username", "")
                action = body.get("action")
                if action == "create":
                    result = USER_STORE.create(username, body.get("password"), body.get("role", "viewer"))
                elif action == "update":
                    result = USER_STORE.update(username, role=body.get("role"), enabled=body.get("enabled"), password=body.get("password"))
                else:
                    raise ValueError("Unknown action.")
            except (ValueError, TypeError) as exc:
                self._json(400, {"error": str(exc)})
                return
            audit(user["username"], self._client_ip(), result["username"], "-", "account-" + action)
            self._json(200, {"user": result})

    def _change_password(self):
        user = self._session_permission("monitor")
        if not user:
            return
        body = self._json_body()
        if body is None:
            return
        if not isinstance(body.get("password"), str) or not accounts.MIN_PASSWORD <= len(body["password"]) <= 1024:
            self._json(400, {"error": "Password must contain 12 to 1024 characters."})
            return
        ip = self._client_ip()
        if _locked_out(ip):
            self._json(429, {"error": "Too many attempts; try again later."})
            return
        if not _check_password(user["username"], body.get("current_password")):
            _record_fail(ip)
            self._json(400, {"error": "Current password is incorrect."})
            return
        try:
            USER_STORE.update(user["username"], password=body.get("password"), expected_version=user["version"])
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
            return
        audit(user["username"], ip, user["username"], "-", "account-password-change")
        _drop_session(self._cookie_token())
        self._send(200, json.dumps({"ok": True}), "application/json", {"Set-Cookie": self._expire_cookie()})

    def _secure_flag(self):
        return "; Secure"

    def _expire_cookie(self):
        return (COOKIE + "=; HttpOnly; SameSite=Strict; Path=/" +
                self._secure_flag() + "; Max-Age=0")

    def _reveal(self):
        """POST /api/reveal - the only path that can ever return a password.

        Session cookie only. A Basic-auth script has no CSRF token and no
        business pulling passwords; /api/clients stays open to it as before.
        """
        ip  = self._client_ip()
        tok = self._cookie_token()
        user = _session_user(tok)
        if not user:
            audit(None, ip, None, None, "denied-unauthenticated")
            self._send(401, json.dumps({"error": "unauthorized"}), "application/json")
            return

        if "reveal" not in accounts.PERMISSIONS.get(user["role"], set()):
            audit(user["username"], ip, None, None, "denied-role")
            self._json(403, {"error": "forbidden"})
            return
        if not getattr(self.server, "is_tls", False):
            self._json(403, {"error": "HTTPS required"})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > 4096:
            self._send(400, json.dumps({"error": "bad request"}), "application/json")
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8", "replace"))
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, RecursionError):
            self._send(400, json.dumps({"error": "bad request"}), "application/json")
            return

        rid, host = body.get("id"), body.get("host") or ""
        if not isinstance(rid, str) or not re.fullmatch(r"[0-9]{1,16}", rid) or not isinstance(host, str) or (host and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", host)):
            audit(user["username"], ip, None, None, "denied-invalid-request")
            self._json(400, {"error": "invalid machine ID or hostname"})
            return

        sent = self.headers.get("X-CSRF-Token", "")
        want = _session_csrf(tok) or ""
        if not want or not hmac.compare_digest(sent.encode(), want.encode()):
            audit(user["username"], ip, host, rid, "denied-csrf")
            self._send(403, json.dumps({"error": "csrf"}), "application/json")
            return

        if not _reveal_allowed(tok):
            audit(user["username"], ip, host, rid, "denied-rate-limit")
            self._send(429, json.dumps({"error": "rate limited"}), "application/json")
            return

        with USER_STORE.lock:
            current = _session_user(tok)
            if not current or "reveal" not in accounts.PERMISSIONS.get(current["role"], set()):
                self._json(401, {"error": "session changed; sign in again"})
                return
            res = vault.lookup(rid, host)
            if not audit(current["username"], ip, res.get("host") or host, rid, res["status"]):
                self._json(503, {"error": "Audit unavailable; reveal blocked"})
                return

        payload = {"status": res["status"], "host": res.get("host"),
                   "id": res.get("id"), "set_at": res.get("set_at")}
        if res["status"] == vault.OK:
            payload["password"] = res["password"]
        # _send() already stamps Cache-Control: no-store on every response.
        self._send(200, json.dumps(payload), "application/json")

    def _audit_page(self):
        try:
            with open(AUDIT_LOG, encoding="utf-8") as fh:
                lines = fh.readlines()[-300:]
        except OSError:
            lines = []
        rows = "".join(html.escape(x) for x in reversed(lines))
        body = (
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<script>(function(){var t=null;try{t=localStorage.getItem('rdconsole.theme')}catch(e){}if(t!=='light'&&t!=='dark')t=window.matchMedia&&matchMedia('(prefers-color-scheme: light)').matches?'light':'dark';document.documentElement.setAttribute('data-theme',t)})();</script>"
            "<title>Reveal audit</title>"
            "<link rel=\"icon\" href=\"/favicon.svg\" type=\"image/svg+xml\">"
            "<link rel=\"stylesheet\" href=\"/rdmon.css\"></head><body>"
            "<div class=\"bar\"><div class=\"brand\">RustDesk <span>Console</span>"
            "<span class=\"tag\">reveal audit</span></div>"
            "<div class=\"right\"><a class=\"ghost\" href=\"/\">Back</a></div></div>"
            "<div class=\"wrap\"><pre class=\"audit\">"
            + (rows or "no reveals recorded yet")
            + "</pre></div></body></html>")
        self._send(200, body, "text/html; charset=utf-8")

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/healthz":                      # open on purpose: reveals
            self._send(200, "ok", "text/plain")     # nothing, lets monitors probe
            return
        if not getattr(self.server, "is_tls", False):
            self._json(403, {"error": "HTTPS required"})
            return
        if path in ("/favicon.svg", "/favicon.ico"):
            # Unauthenticated: browsers fetch the icon for the sign-in page too,
            # before any session exists. Carries no data.
            name = path.lstrip("/")
            ctype = ("image/svg+xml" if name.endswith(".svg")
                     else "image/x-icon")
            try:
                with open(os.path.join(STATIC_DIR, name), "rb") as fh:
                    self._send(200, fh.read(), ctype)
            except FileNotFoundError:
                self._send(404, "not found", "text/plain")
            return
        if path == "/rdmon.css":
            # Unauthenticated: the sign-in page needs it before a session exists,
            # and it carries styling only, never peer data.
            try:
                with open(os.path.join(STATIC_DIR, "rdmon.css"), "rb") as fh:
                    self._send(200, fh.read(), "text/css; charset=utf-8")
            except FileNotFoundError:
                self._send(404, "not found", "text/plain")
            return
        if not self._configured():
            return

        if path == "/login":
            if self._authed():
                self._redirect("/")
            else:
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                self._static("login.html", 401 if q.get("e") else 200)
            return

        if path == "/logout":
            _drop_session(self._cookie_token())
            self._redirect("/login", {"Set-Cookie": self._expire_cookie()})
            return

        identity = self._authed()
        if not identity:
            # A browser gets sent to the form; a script gets a clean 401 rather
            # than an HTML page it would have to parse.
            if path.startswith("/api/"):
                self._send(401, json.dumps({"error": "unauthorized"}),
                           "application/json")
            else:
                self._redirect("/login")
            return

        if path == "/api/clients":
            payload = build_payload()
            # Not a secret, and the page needs it to call /api/reveal.
            payload["csrf"] = _session_csrf(self._cookie_token())
            user = identity
            payload["user"] = {"username": user["username"], "role": user["role"]}
            payload["permissions"] = sorted(accounts.PERMISSIONS.get(user["role"], set()))
            self._send(200, json.dumps(payload), "application/json")
        elif path in ("/api/me", "/api/users", "/users", "/account"):
            user = identity
            if path in ("/api/users", "/users") and "users" not in accounts.PERMISSIONS.get(user["role"], set()):
                self._json(403, {"error": "forbidden"})
            elif path == "/api/users":
                self._json(200, {"users": USER_STORE.list()})
            elif path == "/api/me":
                self._json(200, {"user": {"username": user["username"], "role": user["role"]},
                                 "permissions": sorted(accounts.PERMISSIONS.get(user["role"], set())),
                                 "csrf": _session_csrf(self._cookie_token())})
            else:
                self._static("users.html" if path == "/users" else "account.html")
        elif path == "/audit":
            if "audit" not in accounts.PERMISSIONS.get(identity["role"], set()):
                self._json(403, {"error": "forbidden"})
            else:
                self._audit_page()
        elif path in ("/", "/index.html"):
            self._static("index.html")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if not getattr(self.server, "is_tls", False) and path != "/api/reveal":
            self._json(403, {"error": "HTTPS required"})
            return
        if not self._configured():
            return

        if path == "/logout":
            _drop_session(self._cookie_token())
            self._redirect("/login", {"Set-Cookie": self._expire_cookie()})
            return

        if path == "/api/reveal":
            self._reveal()
            return
        if path == "/api/users":
            self._manage_users()
            return
        if path == "/api/password":
            self._change_password()
            return

        if path != "/login":
            self._send(404, "not found", "text/plain")
            return

        origin = self.headers.get("Origin")
        def origin_key(value):
            try:
                parsed = urllib.parse.urlsplit(value)
                if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
                    return None
                return parsed.scheme, parsed.hostname.lower(), parsed.port or 443
            except ValueError:
                return None
        expected = {origin_key("https://" + (self.headers.get("Host") or "")), origin_key(SETTINGS["console"]["public_url"])} - {None}
        if self.headers.get("Sec-Fetch-Site") == "cross-site" or (origin and (origin_key(origin) is None or origin_key(origin) not in expected)):
            self._json(403, {"error": "Cross-origin login rejected"})
            return

        ip = self._client_ip()
        if _locked_out(ip):
            self._redirect("/login?e=2")
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > 16384:
            self._redirect("/login?e=1")
            return
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        user = (form.get("username") or [""])[0]
        pw   = (form.get("password") or [""])[0]

        identity = _check_password(user, pw)
        if identity:
            _clear_fails(ip)
            USER_STORE.touch_login(identity["username"])
            # Secure is added only on the TLS listener; on plain HTTP the browser
            # would refuse to store the cookie and the login would never stick.
            cookie = (COOKIE + "=" + _new_session(identity) +
                      "; HttpOnly; SameSite=Strict; Path=/" + self._secure_flag() +
                      "; Max-Age=" + str(SESSION_TTL))
            self._redirect("/", {"Set-Cookie": cookie})
        else:
            _record_fail(ip)
            self._redirect("/login?e=1")

    def log_message(self, fmt, *args):
        pass        # journald already timestamps; avoid duplicating every poll


class Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64
    is_tls = False

    def __init__(self, *args, tls_context=None, **kwargs):
        self.tls_context = tls_context
        self.is_tls = tls_context is not None
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._connection_lock = threading.Lock()
        self._connection_counts = {}
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        ip = client_address[0]
        with self._connection_lock:
            if self._connection_counts.get(ip, 0) >= MAX_CONNECTIONS_PER_IP:
                self._slots.release()
                self.shutdown_request(request)
                return
            self._connection_counts[ip] = self._connection_counts.get(ip, 0) + 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._release_connection(ip)
            raise

    def _release_connection(self, ip):
        with self._connection_lock:
            self._connection_counts[ip] -= 1
            if not self._connection_counts[ip]:
                del self._connection_counts[ip]
        self._slots.release()

    def process_request_thread(self, request, client_address):
        # Accept plain sockets in the main loop. TLS negotiation belongs in
        # this worker: an idle/incomplete handshake must never block accept().
        deadline = threading.Timer(TOTAL_CONNECTION_TIMEOUT, lambda: self.shutdown_request(request))
        deadline.daemon = True
        deadline.start()
        try:
            if self.tls_context is not None:
                request.settimeout(TLS_HANDSHAKE_TIMEOUT)
                request = self.tls_context.wrap_socket(request, server_side=True)
            request.settimeout(HTTP_REQUEST_TIMEOUT)
            self.finish_request(request, client_address)
        except (ssl.SSLError, TimeoutError, ConnectionError):
            pass  # disconnected, idle, or non-TLS client; no request was served
        except Exception:
            self.handle_error(request, client_address)
        finally:
            deadline.cancel()
            try:
                self.shutdown_request(request)
            finally:
                self._release_connection(client_address[0])


class RedirectHandler(BaseHTTPRequestHandler):
    """Plain-HTTP listener that only bounces callers to HTTPS.

    308 rather than 301: it preserves the method and body, so a client that
    POSTs to the HTTP port still lands on the login form correctly instead of
    being silently downgraded to a GET.
    """
    protocol_version = "HTTP/1.1"
    server_version = "rdmon"
    sys_version = ""

    def _go(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        if not host:
            host = BIND_TLS[0]
        self.send_response(308)
        origin = SETTINGS["console"]["public_url"].rstrip("/") or f"https://{host}:{BIND_TLS[1]}"
        self.send_header("Location", origin + self.path)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_HEAD = do_POST = _go

    def log_message(self, fmt, *args):
        pass


def _tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT_PATH, KEY_PATH)
    return ctx


if __name__ == "__main__":
    USER_STORE.initialize(AUTH_USER, AUTH_HASH)
    if not USER_STORE.list():
        print("[rdmon] WARNING: RDMON_USER / RDMON_PASS_HASH unset - "
              "serving 503 until configured", file=sys.stderr, flush=True)

    have_tls = os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH)
    if not have_tls:
        sys.exit("[rdmon] TLS certificate/key missing; refusing plaintext login. Install TLS before starting the web service.")

    https = Server(BIND_TLS, Handler, tls_context=_tls_context())

    redirector = Server(BIND, RedirectHandler)
    redirector.daemon_threads = True
    threading.Thread(target=redirector.serve_forever, daemon=True).start()

    print(f"[rdmon] https on {BIND_TLS[1]}, redirecting http {BIND[1]} -> https",
          file=sys.stderr, flush=True)
    https.serve_forever()
