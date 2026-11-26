from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import config
import vault
import vaultinfo


class CompanyConfigurationTest(unittest.TestCase):
    def test_two_company_configurations_without_source_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            for domain, owner, port in (("north.example.com", "NORTH", 9443), ("south.example.net", "SOUTH", 10443)):
                with self.subTest(domain=domain):
                    filename = Path(directory, "console.ini")
                    filename.write_text(f"[console]\nhttps_port={port}\npublic_url=https://rd.{domain}:{port}\n[collector]\ndatabase=/srv/{owner.lower()}/db_v2.sqlite3\n[vault]\nenabled=true\nshare=//dc.{domain}/RustDeskVault$\nowner_domain={owner}\n")
                    settings = config.load_config(str(filename))
                    self.assertEqual(settings.getint("console", "https_port"), port)
                    self.assertEqual(settings["vault"]["owner_domain"], owner)
                    self.assertIn(domain, settings["vault"]["share"])

    def test_incomplete_or_secret_configuration_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory, "console.ini")
            for content in ("[vault]\nenabled=true\n", "[vault]\npassword=do-not-store-this\n", "[console]\nhttp_port=8443\nhttps_port=8443\n"):
                with self.subTest(content=content):
                    filename.write_text(content)
                    with self.assertRaises(ValueError):
                        config.load_config(str(filename))

    def test_disabled_vault_performs_no_file_or_owner_reads(self):
        with patch.object(vault, "ENABLED", False), \
             patch.object(vault, "_list_files") as listing, \
             patch.object(vault, "_owner_of") as owner:
            self.assertEqual(vault.lookup("100000001")["status"], "vault disabled")
            self.assertIsNone(vaultinfo.scan())
            self.assertEqual(vaultinfo.diagnostics()["status"], "disabled")
            listing.assert_not_called()
            owner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
