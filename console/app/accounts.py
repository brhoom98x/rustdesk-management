"""Console accounts only. This database never contains workstation passwords."""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from config import SETTINGS

DB_PATH = SETTINGS["console"]["users_db"]
ROLES = {"admin", "operator", "viewer"}
PERMISSIONS = {
    "admin": {"monitor", "connect", "reveal", "audit", "users"},
    "operator": {"monitor", "connect", "reveal"},
    "viewer": {"monitor"},
}
USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
ITERATIONS = 600_000
MIN_PASSWORD = 12


def hash_password(password):
    if not isinstance(password, str) or not MIN_PASSWORD <= len(password) <= 1024:
        raise ValueError("Password must contain 12 to 1024 characters.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password, encoded):
    try:
        algorithm, iterations, salt, digest = encoded.split("$")
        if algorithm != "pbkdf2_sha256" or not isinstance(password, str) or len(password) > 1024:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(actual, bytes.fromhex(digest))
    except (ValueError, TypeError):
        return False


def public(row):
    if row is None:
        return None
    return {key: row[key] for key in ("id", "username", "role", "enabled", "version", "created_at", "updated_at", "last_login")}


class Store:
    def __init__(self, path=DB_PATH):
        self.path = path
        self.lock = threading.RLock()
        self.ready = False
        self.dummy_hash = None

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize(self, legacy_user="", legacy_hash=""):
        if self.ready:
            return
        with self.lock:
            if self.ready:
                return
            os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
            with self.connect() as connection:
                connection.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE COLLATE NOCASE NOT NULL,
                    password_hash TEXT NOT NULL, role TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1, version INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL, updated_at REAL NOT NULL, last_login REAL)""")
                # One-time migration; an existing account database wins over
                # the old EnvironmentFile, including password rotations.
                if not connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] and legacy_user and legacy_hash:
                    if not USERNAME.fullmatch(legacy_user):
                        raise ValueError("Existing username is invalid for migration.")
                    now = time.time()
                    connection.execute("INSERT INTO users(username,password_hash,role,created_at,updated_at) VALUES(?,?,?,?,?)",
                                       (legacy_user, legacy_hash, "admin", now, now))
            os.chmod(self.path, 0o600)
            self.dummy_hash = hash_password(secrets.token_urlsafe(24))
            self.ready = True

    def list(self):
        with self.connect() as connection:
            return [public(row) for row in connection.execute("SELECT * FROM users ORDER BY username COLLATE NOCASE")]

    def get(self, username):
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            return None
        with self.connect() as connection:
            return public(connection.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone())

    def authenticate(self, username, password):
        row = None
        if isinstance(username, str) and USERNAME.fullmatch(username):
            with self.connect() as connection:
                row = connection.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        valid = verify_password(password, row["password_hash"] if row else self.dummy_hash)
        if valid and row and row["enabled"] and len(password) >= MIN_PASSWORD:
            iterations = int(row["password_hash"].split("$")[1])
            if iterations < ITERATIONS:
                # Upgrade legacy hashes after proof of the existing password.
                # A concurrent password reset must never be overwritten.
                encoded = hash_password(password)
                with self.lock, self.connect() as connection:
                    connection.execute("UPDATE users SET password_hash=? WHERE id=? AND password_hash=? AND version=?",
                                       (encoded, row["id"], row["password_hash"], row["version"]))
        return public(row) if valid and row and row["enabled"] else None

    def touch_login(self, username):
        with self.connect() as connection:
            connection.execute("UPDATE users SET last_login=? WHERE username=?", (time.time(), username))

    def create(self, username, password, role="viewer"):
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise ValueError("Username must be 1 to 64 letters, digits, dots, underscores, @ or hyphens.")
        if role not in ROLES:
            raise ValueError("Unknown role.")
        encoded, now = hash_password(password), time.time()
        with self.lock, self.connect() as connection:
            try:
                connection.execute("INSERT INTO users(username,password_hash,role,created_at,updated_at) VALUES(?,?,?,?,?)",
                                   (username, encoded, role, now, now))
            except sqlite3.IntegrityError:
                raise ValueError("Username already exists.") from None
        return self.get(username)

    def update(self, username, *, role=None, enabled=None, password=None, expected_version=None):
        if not isinstance(username, str) or not USERNAME.fullmatch(username):
            raise ValueError("Invalid username.")
        if role is not None and role not in ROLES:
            raise ValueError("Unknown role.")
        if enabled is not None and not isinstance(enabled, bool):
            raise ValueError("Enabled must be true or false.")
        encoded = hash_password(password) if password is not None else None
        with self.lock, self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if not row:
                raise ValueError("User not found.")
            if expected_version is not None and row["version"] != expected_version:
                raise ValueError("Account changed; sign in again.")
            new_role = row["role"] if role is None else role
            new_enabled = bool(row["enabled"]) if enabled is None else enabled
            if row["role"] == "admin" and row["enabled"] and (new_role != "admin" or not new_enabled):
                admins = connection.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1").fetchone()[0]
                if admins <= 1:
                    raise ValueError("The last active administrator cannot be disabled or demoted.")
            connection.execute("UPDATE users SET role=?,enabled=?,password_hash=?,version=version+1,updated_at=? WHERE id=?",
                               (new_role, int(new_enabled), encoded or row["password_hash"], time.time(), row["id"]))
        return self.get(username)
