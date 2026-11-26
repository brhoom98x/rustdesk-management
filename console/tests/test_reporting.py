import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import collector
import server


class ReportingTest(unittest.TestCase):
    def test_statuses_and_payload_exclude_extra_fields(self):
        now = time.time()
        peers = {
            "1": {"users": ["DOMAIN\\user"], "users_at": now},
            "2": {"users": [], "users_at": now},
            "3": {"users": ["DOMAIN\\old"], "users_at": now - 1000},
            "4": {"users": None},
            "5": {"users": None, "report_error": "owner mismatch"},
        }
        peers["1"]["password"] = "test-only-sentinel"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "state.json")
            path.write_text(json.dumps({"updated": now, "peers": peers, "vault_health": {"status": "ok", "last_success": now}}))
            with patch.object(server, "STATE_PATH", str(path)):
                payload = server.build_payload()
        statuses = {p["id"]: p["report_status"] for p in payload["peers"]}
        self.assertEqual(statuses, {"1": "reported", "2": "nobody logged on", "3": "stale report", "4": "missing report", "5": "owner mismatch"})
        self.assertNotIn("test-only-sentinel", json.dumps(payload))
        self.assertNotIn("password", json.dumps(payload))
        self.assertEqual(payload["health"]["report_counts"]["owner mismatch"], 1)
        self.assertEqual(server.report_status(peers["1"], now, "unreachable"), "vault unavailable")
        self.assertEqual(server.report_status({"users": ["DOMAIN\\user"], "users_at": now + 600}, now), "clock skew")

    def test_display_alias_preserves_report_lookup_by_id(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(collector, "STATE_PATH", str(Path(directory, "state.json"))), \
             patch.dict(collector._registry, {"1": {}}, clear=True), \
             patch.dict(collector._seen, {}, clear=True), \
             patch.dict(collector._aliases, {"1": "Reception laptop"}, clear=True), \
             patch.dict(collector._vnames, {"1": "TEST-PC"}, clear=True), \
             patch.dict(collector._vsess, {"TEST-PC": {"users": ["DOMAIN\\user"], "at": time.time()}}, clear=True), \
             patch.object(collector.time, "sleep", side_effect=StopIteration):
            with self.assertRaises(StopIteration):
                collector.write_state()
            state = json.loads(Path(directory, "state.json").read_text())
            self.assertEqual(state["peers"]["1"]["name"], "Reception laptop")
            self.assertEqual(state["peers"]["1"]["report_host"], "TEST-PC")
            self.assertEqual(state["peers"]["1"]["users"], ["DOMAIN\\user"])


if __name__ == "__main__":
    unittest.main()
