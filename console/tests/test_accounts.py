import base64
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import accounts
import server

PASSWORD = "test-only-password-123"


class AccountsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.iterations = patch.object(accounts, "ITERATIONS", 1000)
        self.iterations.start()
        self.store = accounts.Store(str(Path(self.directory.name, "users.sqlite3")))
        self.store.initialize("admin", accounts.hash_password(PASSWORD))

    def tearDown(self):
        self.iterations.stop()
        self.directory.cleanup()

    def test_migration_and_persistence_do_not_override_changed_credentials(self):
        self.assertEqual(self.store.authenticate("ADMIN", PASSWORD)["role"], "admin")
        self.store.update("admin", password="replacement-test-password")
        reopened = accounts.Store(self.store.path)
        reopened.initialize("admin", accounts.hash_password(PASSWORD))
        self.assertIsNone(reopened.authenticate("admin", PASSWORD))
        self.assertIsNotNone(reopened.authenticate("admin", "replacement-test-password"))
        self.assertNotIn("password_hash", json.dumps(reopened.list()))

    def test_last_administrator_and_password_validation(self):
        for changes in ({"role": "viewer"}, {"enabled": False}):
            with self.assertRaisesRegex(ValueError, "last active administrator"):
                self.store.update("admin", **changes)
        self.store.create("second-admin", PASSWORD, "admin")
        self.store.update("admin", role="operator")
        self.assertEqual(self.store.get("admin")["role"], "operator")
        with self.assertRaises(ValueError):
            self.store.create("invalid\nname", PASSWORD)
        with self.assertRaises(ValueError):
            self.store.create("valid", "short")

    def test_legacy_hash_upgrades_after_verified_login(self):
        with patch.object(accounts, "ITERATIONS", 2000):
            self.assertEqual(self.store.authenticate("admin", PASSWORD)["role"], "admin")
            with self.store.connect() as connection:
                encoded = connection.execute("SELECT password_hash FROM users WHERE username='admin'").fetchone()[0]
            self.assertEqual(encoded.split("$")[1], "2000")

    def test_sessions_and_basic_auth_revoke_after_account_changes(self):
        user = self.store.create("operator", PASSWORD, "operator")
        with patch.object(server, "USER_STORE", self.store):
            token = server._new_session(user)
            header = "Basic " + base64.b64encode(("operator:" + PASSWORD).encode()).decode()
            self.assertTrue(server._session_ok(token))
            self.assertEqual(server._check_basic(header)["role"], "operator")
            self.store.update("operator", role="viewer")
            self.assertFalse(server._session_ok(token))
            self.assertEqual(server._check_basic(header)["role"], "viewer")
            self.store.update("operator", enabled=False)
            self.assertIsNone(server._check_basic(header))

    def test_role_endpoints_and_csrf(self):
        self.store.create("operator", PASSWORD, "operator")
        self.store.create("viewer", PASSWORD, "viewer")
        state = Path(self.directory.name, "state.json")
        state.write_text(json.dumps({"updated": time.time(), "peers": {}}))
        audit = Path(self.directory.name, "audit.log")
        with patch.object(server, "USER_STORE", self.store), \
             patch.object(server, "STATE_PATH", str(state)), \
             patch.object(server, "AUDIT_LOG", str(audit)), \
             patch.object(server, "STATIC_DIR", str(Path(__file__).resolve().parents[1] / "app" / "static")), \
             patch.object(server.vault, "lookup", return_value={"status": "ok", "password": "vault-test-only-secret", "id": "100000001", "host": "TEST-PC"}) as lookup:
            httpd = server.Server(("127.0.0.1", 0), server.Handler)
            httpd.is_tls = True  # transport flag for loopback authorization tests
            worker = threading.Thread(target=httpd.serve_forever, daemon=True)
            worker.start()
            def request(path, token=None, body=None, csrf=None):
                connection = http.client.HTTPConnection(*httpd.server_address, timeout=3)
                headers = {"Connection": "close"}
                if token:
                    headers["Cookie"] = server.COOKIE + "=" + token
                if csrf:
                    headers["X-CSRF-Token"] = csrf
                payload = json.dumps(body) if body is not None else None
                connection.request("POST" if body is not None else "GET", path, payload, headers)
                response = connection.getresponse()
                status, data, response_headers = response.status, response.read(), dict(response.getheaders())
                connection.close()
                return status, data, response_headers
            try:
                self.assertEqual(request("/api/users")[0], 401)
                self.assertEqual(request("/api/reveal", body={"id": "100000001"})[0], 401)
                for role in ("admin", "operator", "viewer"):
                    token = server._new_session(self.store.get(role))
                    csrf = server._session_csrf(token)
                    self.assertEqual(request("/api/clients", token)[0], 200)
                    self.assertEqual(request("/api/users", token)[0], 200 if role == "admin" else 403)
                    self.assertEqual(request("/audit", token)[0], 200 if role == "admin" else 403)
                    status, data, headers = request("/api/reveal", token, {"id": "100000001"}, csrf)
                    self.assertEqual(status, 403 if role == "viewer" else 200)
                    self.assertEqual(headers["Cache-Control"], "no-store")
                    if role == "viewer":
                        self.assertNotIn(b"vault-test-only-secret", data)
                    else:
                        self.assertIn(b"vault-test-only-secret", data)
                    self.assertEqual(request("/api/users", token, {"action": "create", "username": "blocked", "password": PASSWORD})[0], 403)
                admin_token = server._new_session(self.store.get("admin"))
                csrf = server._session_csrf(admin_token)
                self.assertEqual(request("/api/users", admin_token, {"action": "create", "username": "new-viewer", "password": PASSWORD}, csrf)[0], 200)
                self.assertEqual(request("/api/users", admin_token, {"action": "update", "username": "admin", "enabled": False}, csrf)[0], 400)
                viewer_token = server._new_session(self.store.get("viewer"))
                csrf = server._session_csrf(viewer_token)
                self.assertEqual(request("/api/password", viewer_token, {"current_password": PASSWORD, "password": "viewer-replacement-password"}, csrf)[0], 200)
                self.assertEqual(request("/api/me", viewer_token)[0], 401)
                httpd.is_tls = False
                self.assertEqual(request("/api/reveal", admin_token, {"id": "100000001"}, server._session_csrf(admin_token))[0], 403)
                self.assertEqual(request("/api/users", admin_token, {"action": "create", "username": "insecure", "password": PASSWORD}, server._session_csrf(admin_token))[0], 403)
                self.assertNotIn("vault-test-only-secret", audit.read_text())
                self.assertIn("user=operator", audit.read_text())
                self.assertEqual(lookup.call_count, 2)
            finally:
                httpd.shutdown()
                httpd.server_close()
                worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
