"""Security regression probes use temporary data and loopback, never live secrets."""
import base64
from contextlib import ExitStack
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import accounts
import collector
import osdetect
import server
import vault
import vaultinfo

PASSWORD = "security-test-password-only"
SECRET = "vault-security-test-sentinel"


class HttpSecurityTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.stack.enter_context(patch.object(accounts, "ITERATIONS", 1000))
        self.store = accounts.Store(str(Path(self.directory, "users.sqlite3")))
        self.store.initialize("admin", accounts.hash_password(PASSWORD))
        self.store.create("operator", PASSWORD, "operator")
        self.store.create("viewer", PASSWORD, "viewer")
        self.audit = Path(self.directory, "audit.log")
        state = Path(self.directory, "state.json")
        state.write_text(json.dumps({"updated": time.time(), "peers": {"100000001": {"name": "TEST-PC", "password": SECRET}}}))
        for name, value in (("USER_STORE", self.store), ("AUDIT_LOG", str(self.audit)), ("STATE_PATH", str(state)),
                            ("STATIC_DIR", str(Path(__file__).resolve().parents[1] / "app" / "static"))):
            self.stack.enter_context(patch.object(server, name, value))
        for mapping in (server._sessions, server._reveals, server._fails, server._basic_cache):
            self.stack.enter_context(patch.dict(mapping, {}, clear=True))
        self.lookup = self.stack.enter_context(patch.object(vault, "lookup", return_value={
            "status": "ok", "password": SECRET, "host": "TEST-PC", "id": "100000001", "set_at": "2026-10-14 10:00:00"}))
        self.httpd = server.Server(("127.0.0.1", 0), server.Handler)
        self.httpd.is_tls = True  # authorization transport flag; loopback fixture only
        self.worker = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.worker.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.worker.join(timeout=2)

    def request(self, path, method="GET", token=None, body=None, headers=None):
        headers = dict(headers or {})
        if token:
            headers["Cookie"] = server.COOKIE + "=" + token
        connection = http.client.HTTPConnection(*self.httpd.server_address, timeout=3)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        result = response.status, response.read(), dict(response.getheaders())
        connection.close()
        return result

    def reveal(self, role="operator", fields=None, csrf=None):
        token = server._new_session(self.store.get(role))
        return self.request("/api/reveal", "POST", token, json.dumps(fields or {"id": "100000001", "host": "TEST-PC"}),
                            {"X-CSRF-Token": csrf if csrf is not None else server._session_csrf(token)})

    def test_plain_http_refuses_login_basic_and_session_reads(self):
        self.httpd.is_tls = False
        token = server._new_session(self.store.get("admin"))
        self.assertEqual(self.request("/login", "POST", body="username=admin&password=" + PASSWORD)[0], 403)
        basic = "Basic " + base64.b64encode(("admin:" + PASSWORD).encode()).decode()
        self.assertEqual(self.request("/api/clients", headers={"Authorization": basic})[0], 403)
        self.assertEqual(self.request("/api/clients", token=token)[0], 403)
        self.assertEqual(self.request("/api/reveal", "POST", body="{}")[0], 401)
        self.lookup.assert_not_called()

    def test_cross_origin_login_is_rejected_without_creating_session(self):
        result = self.request("/login", "POST", body="username=admin&password=" + PASSWORD,
                              headers={"Origin": "https://attacker.example"})
        self.assertEqual(result[0], 403)
        self.assertNotIn("Set-Cookie", result[2])
        self.assertEqual(server._sessions, {})

    def test_invalid_csrf_and_injected_audit_fields_do_not_reveal(self):
        self.assertEqual(self.reveal(csrf="\xe9")[0], 403)
        self.assertEqual(self.reveal(fields={"id": "100000001", "host": "TEST-PC\nuser=admin"})[0], 400)
        self.lookup.assert_not_called()
        with patch.object(server, "AUDIT_MAX_BYTES", 100000):
            self.assertTrue(server.audit("operator", "127.0.0.1", "HOST\nforged-entry", "100000001", "ok"))
        lines = self.audit.read_text().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertNotIn("\nforged-entry", self.audit.read_text())
        self.assertNotIn(SECRET, self.audit.read_text())

    def test_audit_failure_blocks_the_secret(self):
        with patch.object(server, "audit", return_value=False):
            status, body, headers = self.reveal()
        self.assertEqual(status, 503)
        self.assertNotIn(SECRET.encode(), body)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_revocation_during_reveal_request_is_rechecked(self):
        def revoke(_token):
            self.store.update("operator", role="viewer")
            return True
        with patch.object(server, "_reveal_allowed", side_effect=revoke):
            self.assertEqual(self.reveal()[0], 401)
        self.lookup.assert_not_called()

    def test_viewer_csrf_basic_and_rate_limit_boundaries(self):
        self.assertEqual(self.reveal(role="viewer")[0], 403)
        self.assertEqual(self.reveal(csrf="wrong")[0], 403)
        basic = "Basic " + base64.b64encode(("operator:" + PASSWORD).encode()).decode()
        self.assertEqual(self.request("/api/reveal", "POST", body='{"id":"100000001"}', headers={"Authorization": basic})[0], 401)
        with patch.object(server, "REVEAL_LIMIT", 1):
            token = server._new_session(self.store.get("operator"))
            headers = {"X-CSRF-Token": server._session_csrf(token)}
            body = '{"id":"100000001"}'
            self.assertEqual(self.request("/api/reveal", "POST", token, body, headers)[0], 200)
            self.assertEqual(self.request("/api/reveal", "POST", token, body, headers)[0], 429)

    def test_html_hash_policy_and_polling_exclude_secrets(self):
        status, body, headers = self.request("/login")
        self.assertEqual(status, 200)
        policy = headers["Content-Security-Policy"]
        self.assertNotIn("'unsafe-inline'", policy.split("style-src")[0])
        for script in re.findall(r"<script\b[^>]*>(.*?)</script\s*>", body.decode().replace("\r\n", "\n"), re.I | re.S):
            digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
            self.assertIn("'sha256-" + digest + "'", policy)
        self.assertIn("frame-ancestors 'none'", policy)
        self.assertIn("Strict-Transport-Security", headers)
        token = server._new_session(self.store.get("viewer"))
        for path in ("/", "/api/clients"):
            status, body, headers = self.request(path, token=token)
            self.assertEqual(status, 200)
            self.assertNotIn(SECRET.encode(), body)

    def test_rejected_body_closes_connection(self):
        result = self.request("/api/users", "POST", body="not-json")
        self.assertEqual(result[0], 401)
        self.assertEqual(result[2]["Connection"], "close")

    def test_session_and_basic_caches_have_hard_limits(self):
        with patch.object(server, "MAX_SESSIONS", 3):
            for _ in range(20):
                server._new_session(self.store.get("operator"))
        self.assertEqual(len(server._sessions), 3)
        for index in range(100):
            with patch.object(server, "_check_password", return_value=self.store.get("operator")):
                server._check_basic("Basic " + base64.b64encode(("operator:fixture" + str(index)).encode()).decode())
        self.assertLessEqual(len(server._basic_cache), 64)

    def test_audit_rotation_bounds_disk_usage(self):
        with patch.object(server, "AUDIT_MAX_BYTES", 1), patch.object(server, "AUDIT_BACKUPS", 2):
            for _ in range(6):
                self.assertTrue(server.audit("operator", "127.0.0.1", "TEST-PC", "100000001", "ok"))
        self.assertEqual(len(list(Path(self.directory).glob("audit.log*"))), 3)


class VaultSecurityTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = self.stack.enter_context(tempfile.TemporaryDirectory())
        for module, name, value in ((vault, "ENABLED", True), (vault, "VAULT_DIR", self.directory),
                                    (vault, "NETBIOS", "EXAMPLE"), (vaultinfo, "HOME", self.directory)):
            self.stack.enter_context(patch.object(module, name, value))
        self.stack.enter_context(patch.object(vault.os.path, "ismount", return_value=True))
        self.stack.enter_context(patch.dict(vaultinfo._owners, {}, clear=True))
        self.owner = self.stack.enter_context(patch.object(vault, "_owner_of", side_effect=lambda filename, **_: "EXAMPLE\\" + filename.rsplit(".", 1)[0].upper() + "$"))

    def record(self, machine="TEST-PC", **fields):
        filename = Path(self.directory, machine + ".json")
        filename.write_text(json.dumps(dict({"rustdesk": True, "host": machine, "id": "100000001", "password": SECRET, "set_at": "2026-10-14 10:00:00"}, **fields)), encoding="utf-8-sig")
        return filename

    def test_owner_mismatch_and_unverifiable_owner_fail_closed(self):
        self.record()
        for owner in (None, "EXAMPLE\\ATTACKER$"):
            self.owner.side_effect = None
            self.owner.return_value = owner
            result = vault.lookup("100000001", "TEST-PC")
            self.assertEqual(result["status"], vault.BAD_OWNER)
            self.assertIsNone(result["password"])

    def test_duplicate_machine_ids_never_select_latest_attacker_record(self):
        self.record()
        self.record("OTHER-PC", set_at="2099-01-01 00:00:00")
        self.assertEqual(vault.lookup("100000001", "TEST-PC")["status"], vault.ID_MISMATCH)
        names, _ = vaultinfo.scan()
        self.assertNotIn("100000001", names)
        self.assertEqual(vaultinfo.diagnostics()["session_errors"]["TEST-PC"], "ID mismatch")

    def test_schema_and_oversize_records_are_rejected(self):
        for fields in ({"host": "OTHER-PC"}, {"id": "\u0661\u0662"}, {"password": [SECRET]}, {"password": "x" * (vault.MAX_RECORD + 1)}):
            self.record(**fields)
            self.assertIsNone(vault._read_record("TEST-PC.json"))
        self.assertIsNone(vault._read_record("../TEST-PC.json"))
        self.assertIsNone(vault._read_record("TEST-PC.json\n"))

    def test_changed_record_during_owner_query_is_rejected(self):
        path = self.record()
        def replace(filename, **_):
            replacement = self.record("NEW-PC")
            os.replace(replacement, path)
            return "EXAMPLE\\TEST-PC$"
        self.owner.side_effect = replace
        result = vault.lookup("100000001", "TEST-PC")
        self.assertEqual(result["status"], vault.BAD_OWNER)
        self.assertIsNone(result["password"])

    def test_unmounted_vault_is_unreachable(self):
        with patch.object(vault.os.path, "ismount", return_value=False):
            self.assertEqual(vault.lookup("100000001")["status"], vault.UNREACHABLE)

    def test_lookup_time_and_file_limits_fail_closed(self):
        self.record()
        with patch.object(vault.time, "monotonic", side_effect=[0, 100]):
            self.assertEqual(vault.lookup("100000001")["status"], vault.UNREACHABLE)
        self.record("OTHER-PC")
        with patch.object(vault, "MAX_FILES", 1):
            self.assertEqual(vault.lookup("100000001")["status"], vault.UNREACHABLE)

    @unittest.skipUnless(os.name == "posix", "production Linux no-follow file semantics")
    def test_symlinks_never_disclose_target_records(self):
        target = self.record("OTHER-PC")
        Path(self.directory, "TEST-PC.json").symlink_to(target)
        self.assertIsNone(vault._read_record("TEST-PC.json"))


class ResourceSecurityTest(unittest.TestCase):
    def test_per_ip_limit_does_not_consume_all_global_slots(self):
        with patch.object(server, "MAX_CONNECTIONS", 4), patch.object(server, "MAX_CONNECTIONS_PER_IP", 2):
            httpd = server.Server(("127.0.0.1", 0), server.Handler)
            worker = threading.Thread(target=httpd.serve_forever, daemon=True)
            worker.start()
            idle = []
            try:
                idle = [socket.create_connection(httpd.server_address, timeout=2) for _ in range(2)]
                deadline = time.monotonic() + 2
                while httpd._slots._value != 2 and time.monotonic() < deadline:
                    time.sleep(0.01)
                with socket.create_connection(httpd.server_address, timeout=2) as excess:
                    try:
                        self.assertEqual(excess.recv(1024), b"")
                    except ConnectionResetError:
                        pass
                self.assertEqual(httpd._slots._value, 2)
            finally:
                for connection in idle:
                    connection.close()
                httpd.shutdown()
                httpd.server_close()
                worker.join(timeout=2)

    def test_slow_header_connection_has_an_absolute_deadline(self):
        with patch.object(server, "TOTAL_CONNECTION_TIMEOUT", 0.2):
            httpd = server.Server(("127.0.0.1", 0), server.Handler)
            worker = threading.Thread(target=httpd.serve_forever, daemon=True)
            worker.start()
            try:
                with socket.create_connection(httpd.server_address, timeout=2) as slow:
                    slow.sendall(b"GET /healthz HTTP/1.1\r\nHost:")
                    began = time.monotonic()
                    self.assertEqual(slow.recv(1024), b"")
                    self.assertLess(time.monotonic() - began, 1.5)
            finally:
                httpd.shutdown()
                httpd.server_close()
                worker.join(timeout=2)

    def test_unregistered_heartbeats_have_bounded_memory_and_known_peers_still_update(self):
        header = {"dport": str(collector.RDV_PORT), "sport": "12345", "src": "192.0.2.10"}
        with patch.dict(collector._seen, {}, clear=True), patch.dict(collector._registry, {"999999999": {}}, clear=True), patch.object(collector, "MAX_UNKNOWN_PEERS", 3):
            for index in range(20):
                collector._commit(header, str(100000000 + index))
            self.assertEqual(len(collector._seen), 3)
            collector._commit(header, "999999999")
            self.assertEqual(len(collector._seen), 4)
            self.assertIn("999999999", collector._seen)

    def test_short_rustdesk_ids_are_detected_without_truncating_long_numbers(self):
        header = {"dport": str(collector.RDV_PORT), "sport": "12345", "src": "192.0.2.10"}
        with patch.dict(collector._seen, {}, clear=True), patch.dict(collector._registry, {}, clear=True):
            for rid in ("123456", "45316545", "100000001", "1234567890123456"):
                collector._commit(header, "\n." + rid + ".\n")
                self.assertIn(rid, collector._seen)
            before = dict(collector._seen)
            for invalid in ("12345", "12345678901234567"):
                collector._commit(header, invalid)
            self.assertEqual(collector._seen, before)

    def test_oversized_smb_response_is_rejected_before_reading_body(self):
        from unittest.mock import Mock
        peer = Mock()
        peer.gettimeout.return_value = 3
        peer.recv.return_value = b"\x00\xff\xff\xff"
        with self.assertRaises(ValueError):
            osdetect._txn(peer, b"probe")
        self.assertEqual(peer.recv.call_count, 1)

    def test_web_connection_workers_are_bounded(self):
        ready = threading.Event()
        lock = threading.Lock()
        count = [0]
        class ObservedHandler(server.Handler):
            def setup(self):
                super().setup()
                with lock:
                    count[0] += 1
                    if count[0] == 2:
                        ready.set()
        with patch.object(server, "MAX_CONNECTIONS", 2):
            httpd = server.Server(("127.0.0.1", 0), ObservedHandler)
        worker = threading.Thread(target=httpd.serve_forever, daemon=True)
        worker.start()
        idle = []
        try:
            for _ in range(2):
                idle.append(socket.create_connection(httpd.server_address, timeout=2))
            self.assertTrue(ready.wait(2))
            with socket.create_connection(httpd.server_address, timeout=2) as excess:
                try:
                    excess.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    self.assertEqual(excess.recv(1024), b"")
                except ConnectionResetError:
                    pass
            self.assertEqual(count[0], 2)
            for connection in idle:
                connection.close()
            deadline = time.monotonic() + 2
            while httpd._slots._value < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            client = http.client.HTTPConnection(*httpd.server_address, timeout=2)
            client.request("GET", "/healthz")
            response = client.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
            client.close()
        finally:
            for connection in idle:
                connection.close()
            httpd.shutdown()
            httpd.server_close()
            worker.join(timeout=2)


@unittest.skipUnless(os.name == "posix", "managed installer runs on Linux")
class InstallerSecurityTest(unittest.TestCase):
    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("rdmon_installer_under_test", Path(__file__).resolve().parents[1] / "install.py")
        self.installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.installer)

    def test_symlink_swap_cannot_truncate_another_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory, "target")
            target.write_text("preserve this file")
            link = Path(directory, "link")
            link.symlink_to(target)
            # Simulate a swap after the preliminary link check.
            with patch.object(Path, "is_symlink", return_value=False):
                with self.assertRaises(OSError):
                    self.installer.write(link, "overwrite", uid=os.getuid(), gid=os.getgid())
            self.assertEqual(target.read_text(), "preserve this file")

    def test_runtime_secret_file_has_private_permissions(self):
        import stat
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory, "credential")
            self.installer.write(target, "test-only-content", mode=0o600, uid=os.getuid(), gid=os.getgid())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
