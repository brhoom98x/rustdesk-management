import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import vaultinfo


class SessionReportsTest(unittest.TestCase):
    def setUp(self):
        self.enabled = patch.object(vaultinfo.vault, "ENABLED", True)
        self.domain = patch.object(vaultinfo.vault, "NETBIOS", "EXAMPLE")
        self.enabled.start()
        self.domain.start()
        self.addCleanup(self.enabled.stop)
        self.addCleanup(self.domain.stop)

    def test_replaced_file_invalidates_cached_owner(self):
        good_owner = vaultinfo.vault.NETBIOS + "\\TEST-PC$"
        bad_owner = vaultinfo.vault.NETBIOS + "\\OTHER-PC$"
        old = SimpleNamespace(st_ino=1, st_ctime_ns=1)
        new = SimpleNamespace(st_ino=2, st_ctime_ns=2)
        with patch.dict(vaultinfo._owners, {}, clear=True), \
             patch.object(vaultinfo.os, "stat", side_effect=[old, old, new]), \
             patch.object(vaultinfo.vault, "_owner_of", side_effect=[good_owner, bad_owner]) as owner:
            self.assertTrue(vaultinfo._trusted("TEST-PC.session"))
            self.assertTrue(vaultinfo._trusted("TEST-PC.session"))
            self.assertFalse(vaultinfo._trusted("TEST-PC.session"))
            self.assertEqual(owner.call_count, 2)

    def test_bom_session_with_and_without_os(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = "TEST-PC.session"
            record = {
                "rustdesk_session": True,
                "host": "TEST-PC",
                "users": ["DOMAIN\\test.user"],
                "at": 1700000000,
            }
            with patch.object(vaultinfo.vault, "VAULT_DIR", directory):
                for os_fields in ({}, {"os": "Windows 11 26H2", "os_build": "26300.9457"}):
                    with self.subTest(os_fields=os_fields):
                        Path(directory, filename).write_text(
                            json.dumps(dict(record, **os_fields)), encoding="utf-8-sig"
                        )
                        result = vaultinfo._session(filename)
                        self.assertEqual(result["users"], record["users"])
                        self.assertEqual(result["at"], record["at"])
                        for key, value in os_fields.items():
                            self.assertEqual(result[key], value)

    def test_scan_keeps_only_owner_verified_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            record = {"rustdesk_session": True, "users": [], "at": 1700000000}
            for hostname in ("TEST-PC", "OTHER-PC"):
                Path(directory, hostname + ".session").write_text(
                    json.dumps(dict(record, host=hostname)), encoding="utf-8-sig"
                )
            owner = vaultinfo.vault.NETBIOS + "\\TEST-PC$"
            with patch.object(vaultinfo.vault, "VAULT_DIR", directory), \
                 patch.object(vaultinfo, "HOME", directory), \
                 patch.object(vaultinfo.os.path, "ismount", return_value=True), \
                 patch.object(vaultinfo.vault, "_owner_of", return_value=owner), \
                 patch.dict(vaultinfo._owners, {}, clear=True), \
                 patch.object(vaultinfo, "_last_rejected", []):
                names, sessions = vaultinfo.scan()
                self.assertEqual(names, {})
                self.assertEqual(set(sessions), {"TEST-PC"})
                self.assertEqual(sessions["TEST-PC"]["users"], [])
                self.assertEqual(vaultinfo.diagnostics()["session_errors"], {"OTHER-PC": "owner mismatch"})

    def test_invalid_host_and_timestamp_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(vaultinfo.vault, "VAULT_DIR", directory):
            record = {"rustdesk_session": True, "host": "TEST-PC", "users": [], "at": 1700000000}
            for fields in ({"host": "OTHER-PC"}, {"at": float("nan")}, {"at": float("inf")}, {"users": "DOMAIN\\user"}):
                with self.subTest(fields=fields):
                    Path(directory, "TEST-PC.session").write_text(json.dumps(dict(record, **fields)), encoding="utf-8-sig")
                    self.assertIsNone(vaultinfo._session("TEST-PC.session"))

    def test_rename_rechecks_cached_owner_before_declaring_id_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            old, new, rid = "OLD-PC", "NEW-PC", "45316545"
            for host in (old, new):
                Path(directory, host + ".json").write_text(json.dumps({
                    "rustdesk": True, "host": host, "id": rid,
                    "password": "rename-test-only", "set_at": "2026-10-22 10:00:00",
                }), encoding="utf-8-sig")
            old_path = Path(directory, old + ".json").stat()
            cached = {old + ".json": (
                "EXAMPLE\\OLD-PC$", vaultinfo.time.time(),
                (old_path.st_ino, old_path.st_ctime_ns),
            )}
            with patch.object(vaultinfo.vault, "VAULT_DIR", directory), \
                 patch.object(vaultinfo, "HOME", directory), \
                 patch.object(vaultinfo.os.path, "ismount", return_value=True), \
                 patch.object(vaultinfo.vault, "_owner_of", return_value="EXAMPLE\\NEW-PC$") as owner, \
                 patch.dict(vaultinfo._owners, cached, clear=True), \
                 patch.object(vaultinfo, "_last_rejected", []):
                names, _ = vaultinfo.scan()
                self.assertEqual(names, {rid: new})
                self.assertNotIn(new, vaultinfo.diagnostics()["session_errors"])
                self.assertTrue(any(call.args[0] == old + ".json" for call in owner.call_args_list))

    def test_two_distinct_verified_computers_claiming_one_id_remain_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            for host in ("FIRST-PC", "SECOND-PC"):
                Path(directory, host + ".json").write_text(json.dumps({
                    "rustdesk": True, "host": host, "id": "45316545",
                    "password": "conflict-test-only", "set_at": "2026-10-22 10:00:00",
                }), encoding="utf-8-sig")
            with patch.object(vaultinfo.vault, "VAULT_DIR", directory), \
                 patch.object(vaultinfo, "HOME", directory), \
                 patch.object(vaultinfo.os.path, "ismount", return_value=True), \
                 patch.object(vaultinfo.vault, "_owner_of", side_effect=lambda filename, **kw: "EXAMPLE\\" + filename[:-5] + "$"), \
                 patch.dict(vaultinfo._owners, {}, clear=True):
                names, _ = vaultinfo.scan()
                self.assertEqual(names, {})
                self.assertEqual(set(vaultinfo.diagnostics()["session_errors"].values()), {"ID mismatch"})


if __name__ == "__main__":
    unittest.main()
