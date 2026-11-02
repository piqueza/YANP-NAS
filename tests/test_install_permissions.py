# SPDX-License-Identifier: GPL-2.0-only
import os
from pathlib import Path
import stat
import tempfile
import unittest

from scripts.config_files import create_config


class InstallPermissionTests(unittest.TestCase):
    def test_web_config_retains_group_read_under_installer_umask(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "web.json"
            previous = os.umask(0o077)
            try:
                create_config(path, '{"test":true}', 0o640)
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            self.assertEqual(path.read_text(), '{"test":true}')

    def test_agent_credentials_and_setup_token_remain_owner_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.umask(0o077)
            try:
                for name in ("agent.json", "setup-token"):
                    path = Path(tmp) / name
                    create_config(path, "private", 0o600)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            finally:
                os.umask(previous)

    def test_existing_configuration_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "web.json"
            create_config(path, "original", 0o640)
            with self.assertRaises(FileExistsError):
                create_config(path, "replacement", 0o640)
            self.assertEqual(path.read_text(), "original")


if __name__ == "__main__":
    unittest.main()
